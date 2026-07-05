package nodetls

import (
	"context"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/qpoint-io/qtap/pkg/binutils"
)

// Offsets mirrors `struct node_tlswrap_symaddrs_t` in bpf/tap/nodetls.bpf.h.
// The field order and types (7 x uint32) must match exactly so it marshals
// into the node_tlswrap_symaddrs_map value.
type Offsets struct {
	TLSWrapStreamListener     uint32
	StreamListenerStream      uint32
	StreamBaseStreamResource  uint32
	LibuvStreamWrapStreamBase uint32
	LibuvStreamWrapStream     uint32
	UvStreamIOWatcher         uint32
	UvIOFd                    uint32
}

// SemVer is a minimal semantic version used to index the offset table.
type SemVer struct {
	Major, Minor, Patch int
}

func (v SemVer) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// lessEqual reports whether v <= o.
func (v SemVer) lessEqual(o SemVer) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch <= o.Patch
}

// versionedOffsets pairs a Node version with its struct offsets.
type versionedOffsets struct {
	ver     SemVer
	offsets Offsets
}

// nodeOffsetTable is ported from Pixie's kNodeVersionSymaddrs
// (src/stirling/source_connectors/socket_tracer/uprobe_symaddrs.cc, Apache-2.0).
// It is kept sorted ascending; resolveFromTable() does a floor lookup.
//
// The v15.0.0 entry has been verified by disassembly to also be correct for
// Node 18.20.8 (TLSWrap/StreamListener/LibuvStreamWrap layout unchanged).
var nodeOffsetTable = func() []versionedOffsets {
	t := []versionedOffsets{
		{SemVer{12, 3, 1}, Offsets{0x130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
		{SemVer{12, 16, 2}, Offsets{0x138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
		{SemVer{13, 0, 0}, Offsets{0x130, 0x08, 0x00, 0x50, 0x90, 0x88, 0x30}},
		{SemVer{13, 2, 0}, Offsets{0x138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
		{SemVer{13, 10, 1}, Offsets{0x140, 0x08, 0x00, 0x60, 0xa0, 0x88, 0x30}},
		{SemVer{14, 5, 0}, Offsets{0x138, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
		{SemVer{15, 0, 0}, Offsets{0x78, 0x08, 0x00, 0x58, 0x98, 0x88, 0x30}},
	}
	sort.Slice(t, func(i, j int) bool { return t[i].ver.lessEqual(t[j].ver) && t[i].ver != t[j].ver })
	return t
}()

// resolveFromTable returns the offsets for the greatest table version <= ver.
func resolveFromTable(ver SemVer) (Offsets, bool) {
	var (
		out   Offsets
		found bool
	)
	for _, e := range nodeOffsetTable {
		if e.ver.lessEqual(ver) {
			out = e.offsets
			found = true
		}
	}
	return out, found
}

// newestTableOffsets returns the offsets for the highest known Node version.
// Used as a last resort when the version cannot be determined but the process
// is confirmed to be Node (modern Node is the overwhelmingly common case).
func newestTableOffsets() Offsets {
	return nodeOffsetTable[len(nodeOffsetTable)-1].offsets
}

// nodeVersionRE matches a delimited "vX.Y.Z" token embedded in read-only data.
// The Node version appears many times (corepack paths, headers URL, report
// metadata, e.g. "node-v18.20.8-headers", "/release/v18.20.8/") but rarely as a
// standalone NUL-terminated string, so we scan for it as a substring bounded by
// non-version characters.
var nodeVersionRE = regexp.MustCompile(`[^0-9A-Za-z.]v([0-9]+)\.([0-9]+)\.([0-9]+)[^0-9.]`)

// DetectNodeVersion infers the Node version from the binary's read-only data.
// The real process.version dominates by frequency, so we pick the most common
// plausible "vX.Y.Z" (ties broken toward the higher version). Returns false if
// none is found.
func DetectNodeVersion(ctx context.Context, ef *binutils.Elf) (SemVer, bool) {
	f, err := ef.Elf(ctx)
	if err != nil {
		return SemVer{}, false
	}

	counts := make(map[SemVer]int)
	for _, name := range []string{".rodata", ".data.rel.ro"} {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for _, m := range nodeVersionRE.FindAllSubmatch(data, -1) {
			v := SemVer{atoiB(m[1]), atoiB(m[2]), atoiB(m[3])}
			// Node major versions we care about are >= 10; ignore stray matches
			// (dependency versions, ICU, etc. are far less frequent anyway).
			if v.Major < 10 || v.Major > 40 {
				continue
			}
			counts[v]++
		}
	}

	var best SemVer
	var bestCount int
	for v, c := range counts {
		if c > bestCount || (c == bestCount && best.lessEqual(v)) {
			best, bestCount = v, c
		}
	}
	return best, bestCount > 0
}

// ResolveOffsets determines the Node struct offsets for a target binary. It
// prefers offsets extracted from the target's own DWARF (accurate for any
// build that ships full C++ debug info), and falls back to the version-keyed
// table. Returns false only if neither source can supply offsets.
func ResolveOffsets(ctx context.Context, ef *binutils.Elf, ver SemVer, verKnown bool) (Offsets, string, bool) {
	if f, err := ef.Elf(ctx); err == nil {
		if off, ok := offsetsFromDWARF(f); ok {
			return off, "dwarf", true
		}
	}
	if verKnown {
		if off, ok := resolveFromTable(ver); ok {
			return off, "table:" + ver.String(), true
		}
	}
	// Node confirmed but version unknown and no C++ DWARF: best-effort with the
	// newest known layout.
	return newestTableOffsets(), "table:newest", true
}

// offsetsFromDWARF extracts all seven offsets from DWARF, handling both
// DW_TAG_member (field offsets) and DW_TAG_inheritance (base-class offsets),
// which the high-level debug/dwarf API does not expose. Returns false if any
// required type/member is missing (the common case for release Node builds,
// whose DWARF covers only libuv + CRT).
func offsetsFromDWARF(f *elf.File) (Offsets, bool) {
	d, err := f.DWARF()
	if err != nil {
		return Offsets{}, false
	}

	// member returns the DW_AT_data_member_location of the named member (or
	// inherited base type) of the named struct/class type.
	member := func(typeName, memberName string, byType bool) (uint32, bool) {
		r := d.Reader()
		for {
			ent, err := r.Next()
			if err != nil || ent == nil {
				return 0, false
			}
			if ent.Tag != dwarf.TagStructType && ent.Tag != dwarf.TagClassType {
				continue
			}
			name, _ := ent.Val(dwarf.AttrName).(string)
			if name != typeName {
				r.SkipChildren()
				continue
			}
			// scan direct children for the member/base
			for {
				child, err := r.Next()
				if err != nil || child == nil || child.Tag == 0 {
					break
				}
				var match bool
				if byType {
					if child.Tag == dwarf.TagInheritance {
						if bt := baseTypeName(d, child); bt == memberName {
							match = true
						}
					}
				} else if child.Tag == dwarf.TagMember {
					if cn, _ := child.Val(dwarf.AttrName).(string); cn == memberName {
						match = true
					}
				}
				if match {
					if off, ok := memberOffset(child); ok {
						return off, true
					}
				}
				r.SkipChildren()
			}
			return 0, false
		}
	}

	var (
		out Offsets
		ok  bool
	)
	if out.TLSWrapStreamListener, ok = member("node::crypto::TLSWrap", "node::StreamListener", true); !ok {
		return Offsets{}, false
	}
	if out.StreamListenerStream, ok = member("node::StreamListener", "stream_", false); !ok {
		return Offsets{}, false
	}
	if out.StreamBaseStreamResource, ok = member("node::StreamBase", "node::StreamResource", true); !ok {
		return Offsets{}, false
	}
	if out.LibuvStreamWrapStreamBase, ok = member("node::LibuvStreamWrap", "node::StreamBase", true); !ok {
		return Offsets{}, false
	}
	if out.LibuvStreamWrapStream, ok = member("node::LibuvStreamWrap", "stream_", false); !ok {
		return Offsets{}, false
	}
	if out.UvStreamIOWatcher, ok = member("uv_stream_s", "io_watcher", false); !ok {
		return Offsets{}, false
	}
	if out.UvIOFd, ok = member("uv__io_s", "fd", false); !ok {
		return Offsets{}, false
	}
	return out, true
}

// baseTypeName resolves the type name referenced by a DW_TAG_inheritance entry.
func baseTypeName(d *dwarf.Data, ent *dwarf.Entry) string {
	off, ok := ent.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return ""
	}
	t, err := d.Type(off)
	if err != nil {
		return ""
	}
	return t.String()
}

// memberOffset reads DW_AT_data_member_location, which may be encoded as a
// constant or (rarely for non-virtual bases) a location expression we skip.
func memberOffset(ent *dwarf.Entry) (uint32, bool) {
	v := ent.Val(dwarf.AttrDataMemberLoc)
	switch n := v.(type) {
	case int64:
		return uint32(n), true
	case uint64:
		return uint32(n), true
	default:
		return 0, false
	}
}

func atoiB(b []byte) int {
	n, _ := strconv.Atoi(string(b))
	return n
}
