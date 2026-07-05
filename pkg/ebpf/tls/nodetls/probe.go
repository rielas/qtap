// Package nodetls implements a tls.Probe that recovers the socket fd for
// Node.js TLS connections. Node drives OpenSSL through a memory BIO, so the
// generic OpenSSL probe can capture plaintext but cannot attribute it to a
// connection. This probe uprobes Node's TLSWrap member functions and feeds the
// BPF NodeTLS module the per-process struct offsets it needs to walk
// SSL* -> TLSWrap -> libuv stream -> fd. See bpf/tap/nodetls.bpf.c.
package nodetls

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/qpoint-io/qtap/pkg/binutils"
	"github.com/qpoint-io/qtap/pkg/ebpf/common"
	"github.com/qpoint-io/qtap/pkg/ebpf/tls"
	"github.com/qpoint-io/qtap/pkg/telemetry"
	"go.uber.org/zap"
)

var _ tls.Probe = (*Probe)(nil)

const Name = "nodetls"

var tracer = telemetry.Tracer()

// TLSWrap member functions we uprobe to learn the active `TLSWrap this`.
// These are mangled-name prefixes (the full symbol includes the argument
// signature). Both the modern (node::crypto) and legacy (node) namespaces are
// covered. Matched with binutils.MatchStrategyPrefix.
var tlsWrapSymbolPrefixes = []string{
	// Node >= 15: node::crypto::TLSWrap
	"_ZN4node6crypto7TLSWrapC2E",        // constructor
	"_ZN4node6crypto7TLSWrap7ClearInE",  // ClearIn()
	"_ZN4node6crypto7TLSWrap8ClearOutE", // ClearOut()
	// Node <= 14: node::TLSWrap
	"_ZN4node7TLSWrapC2E",
	"_ZN4node7TLSWrap7ClearInE",
	"_ZN4node7TLSWrap8ClearOutE",
}

// Probe implements tls.Probe for Node.js TLS fd recovery.
type Probe struct {
	logger      *zap.Logger
	probeFn     func() []*common.Uprobe
	symaddrsMap *ebpf.Map
}

// NewProbe creates a Node TLS probe. symaddrsMap is the node_tlswrap_symaddrs_map
// BPF map that struct offsets are written into (keyed by pid) during Attach.
func NewProbe(logger *zap.Logger, probeFn func() []*common.Uprobe, symaddrsMap *ebpf.Map) *Probe {
	return &Probe{
		logger:      logger,
		probeFn:     probeFn,
		symaddrsMap: symaddrsMap,
	}
}

func (s *Probe) Name() string { return Name }

// TLSWrapSymbolPrefixes returns the mangled-name prefixes of the Node TLSWrap
// member functions this probe uprobes. Callers building the ebpf.Uprobe list
// pair each prefix with the entry and return programs.
func TLSWrapSymbolPrefixes() []string {
	return tlsWrapSymbolPrefixes
}

// NodeTLSScanResult carries the TLSWrap symbols and resolved struct offsets.
type NodeTLSScanResult struct {
	Symbols      []elf.Symbol
	Offsets      Offsets
	OffsetSource string
	Version      string
}

func (r *NodeTLSScanResult) ProbeName() string   { return Name }
func (r *NodeTLSScanResult) ProbeDetected() bool { return len(r.Symbols) > 0 }

var symbolSearch = func() []binutils.SymbolSearch {
	var ss []binutils.SymbolSearch
	for _, p := range tlsWrapSymbolPrefixes {
		ss = append(ss, binutils.SymbolSearch{Name: p, MatchStrategy: binutils.MatchStrategyPrefix})
	}
	return ss
}()

// Scan detects Node, finds the TLSWrap member function symbols, and resolves
// the struct offsets for this binary.
func (s *Probe) Scan(ctx context.Context, target *tls.ExeElfScannable) (tls.ProbeScanResult, error) {
	ctx, span := tracer.Start(ctx, "NodeTLSScanner.Scan")
	defer span.End()

	syms, err := target.Elf.SearchSymbols(ctx, symbolSearch, elf.SHT_SYMTAB, elf.SHT_DYNSYM)
	if err != nil && !errors.Is(err, binutils.ErrNoSymbols) {
		return nil, fmt.Errorf("searching symbols: %w", err)
	}

	// Keep only real function entry points: drop out-of-line fragments
	// (.cold/.part.) and non-function symbols so each prefix resolves to a
	// single attachable entry (a uprobe on a .cold fragment would fire mid
	// function with the wrong register state).
	syms = filterEntrySymbols(syms)
	if len(syms) == 0 {
		// not a Node binary (or no TLSWrap) — probe stays inert
		return &NodeTLSScanResult{}, nil
	}

	syms = target.Elf.CalculateUprobeAddresses(ctx, syms)

	ver, verKnown := DetectNodeVersion(ctx, target.Elf)
	offsets, src, ok := ResolveOffsets(ctx, target.Elf, ver, verKnown)
	if !ok {
		// symbols present but no offsets: attaching would produce fd=0 anyway
		s.logger.Warn("nodetls: could not resolve struct offsets", zap.String("version", ver.String()))
		return &NodeTLSScanResult{}, nil
	}

	res := &NodeTLSScanResult{
		Symbols:      syms,
		Offsets:      offsets,
		OffsetSource: src,
	}
	if verKnown {
		res.Version = ver.String()
	}

	s.logger.Debug("nodetls: detected Node TLS",
		zap.String("version", res.Version),
		zap.String("offset_source", src),
		zap.Int("tlswrap_symbols", len(syms)),
	)

	return res, nil
}

// Attach attaches the TLSWrap uprobes and installs the struct offsets for this
// process into the BPF symaddrs map.
func (s *Probe) Attach(ctx context.Context, target *tls.ExeLinkAttachable, result tls.ProbeScanResult) (io.Closer, error) {
	ctx, span := tracer.Start(ctx, "NodeTLSScanner.Attach")
	defer span.End()

	ll := s.logger.With(zap.String("exe", target.Path), zap.Int("pid", target.PID))

	r, ok := result.(*NodeTLSScanResult)
	if !ok {
		ll.DPanic("invalid result type", zap.Any("result", result))
		return nil, errors.New("invalid result type: expected *NodeTLSScanResult")
	}
	if !r.ProbeDetected() {
		return nil, nil
	}

	// Install the per-process struct offsets before attaching the probes, so
	// get_fd_from_node() can succeed as soon as the first SSL_read fires.
	key := uint32(target.PID)
	offsets := r.Offsets
	if err := s.symaddrsMap.Put(key, &offsets); err != nil {
		return nil, fmt.Errorf("installing node struct offsets for pid %d: %w", target.PID, err)
	}

	closer, err := tls.AttachProbes(ctx, ll, target, r.Symbols, binutils.MatchStrategyPrefix, s.probeFn(), true)
	if err != nil {
		// best-effort cleanup of the map entry we just installed
		_ = s.symaddrsMap.Delete(key)
		return nil, fmt.Errorf("attaching probes: %w", err)
	}

	ll.Debug("attached NodeTLS probes",
		zap.String("offset_source", r.OffsetSource),
		zap.String("version", r.Version),
	)

	// closer removes the uprobes and the symaddrs entry on process exit
	return tls.MultiCloser{closer, tls.CloserFunc(func() error {
		if err := s.symaddrsMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	})}, nil
}

// Node statically links OpenSSL, so there is no shared library to attach to.
func (s *Probe) SharedLibraries() string { return "" }

func (s *Probe) ScanLibrary(ctx context.Context, ef *binutils.Elf) (tls.ProbeScanResult, error) {
	return &NodeTLSScanResult{}, nil
}

func (s *Probe) AttachLibrary(ctx context.Context, target *tls.ExeLibraryAttachable, result tls.ProbeScanResult) (io.Closer, error) {
	return nil, nil
}

func (s *Probe) Close() error { return nil }

// filterEntrySymbols keeps only defined STT_FUNC symbols that are real entry
// points, discarding out-of-line fragments emitted by the compiler.
func filterEntrySymbols(syms []elf.Symbol) []elf.Symbol {
	out := syms[:0]
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		if sym.Value == 0 || sym.Size == 0 {
			continue
		}
		if strings.Contains(sym.Name, ".cold") || strings.Contains(sym.Name, ".part") {
			continue
		}
		out = append(out, sym)
	}
	return out
}
