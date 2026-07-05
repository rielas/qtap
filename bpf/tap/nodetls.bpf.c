/*
 * This code runs using libbpf in the Linux kernel.
 * Copyright 2025 - The Qpoint Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

/*
 * NodeTLS module.
 *
 * This recovers the socket fd for Node.js TLS connections, which the generic
 * OpenSSL probe cannot do because Node drives OpenSSL through a memory BIO.
 * It plugs into the pluggable TLS helper interface declared in openssl.bpf.h
 * (ssl_register_handle / ssl_get_fd / ssl_remove_handle), which is compiled in
 * when ENABLE_NODETLS is defined.
 *
 * The technique mirrors Pixie's node_openssl_trace.c: uprobe Node's TLSWrap
 * member functions to learn the current `TLSWrap this`, associate it with the
 * SSL* that is created/used inside those calls, then walk Node's object graph
 * to reach the libuv fd. See nodetls.bpf.h for the offset chain.
 */

#include "common.bpf.h"
#include "trace.bpf.h"
#include "bpf_helpers.h"
#include "nodetls.bpf.h"

// ssl -> TLSWrap* (the Node C++ object that owns this SSL)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, uintptr_t); // ssl
	__type(value, uintptr_t); // TLSWrap*
	__uint(max_entries, 4096);
} node_ssl_tls_wrap_map SEC(".maps");

// pid_tgid -> TLSWrap* currently executing a TLSWrap member function on this thread
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint64_t); // pid_tgid
	__type(value, uintptr_t); // TLSWrap*
	__uint(max_entries, 1024);
} active_tls_wrap_memfn_map SEC(".maps");

// tgid -> struct node_tlswrap_symaddrs_t (populated from user space per process)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t); // tgid
	__type(value, struct node_tlswrap_symaddrs_t);
	__uint(max_entries, 1024);
} node_tlswrap_symaddrs_map SEC(".maps");

// Return the TLSWrap* for the member function currently executing on this thread, if any.
static __inline uintptr_t get_active_tls_wrap() {
	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uintptr_t *tls_wrap = bpf_map_lookup_elem(&active_tls_wrap_memfn_map, &pid_tgid);
	if (tls_wrap == NULL) {
		return 0;
	}
	return *tls_wrap;
}

// Walk TLSWrap* -> StreamListener::stream_ -> LibuvStreamWrap -> uv_stream_t -> io_watcher.fd
static __inline int32_t get_fd_from_tls_wrap(const struct node_tlswrap_symaddrs_t *symaddrs, uintptr_t tls_wrap) {
	// stream_ (a StreamResource*) lives in the StreamListener base of TLSWrap
	uintptr_t stream = 0;
	uintptr_t stream_ptr = tls_wrap + symaddrs->TLSWrap_StreamListener_offset + symaddrs->StreamListener_stream_offset;
	if (bpf_probe_read_user(&stream, sizeof(stream), (void *)stream_ptr) != 0 || stream == 0) {
		return 0;
	}

	// That StreamResource* is the StreamBase base of a LibuvStreamWrap. Recover the
	// LibuvStreamWrap and read its stream_ member (the uv_stream_t*).
	uintptr_t uv_stream = 0;
	uintptr_t uv_stream_ptr = stream - symaddrs->StreamBase_StreamResource_offset - symaddrs->LibuvStreamWrap_StreamBase_offset +
	                          symaddrs->LibuvStreamWrap_stream_offset;
	if (bpf_probe_read_user(&uv_stream, sizeof(uv_stream), (void *)uv_stream_ptr) != 0 || uv_stream == 0) {
		return 0;
	}

	// fd = uv_stream->io_watcher.fd
	int32_t fd = 0;
	uintptr_t fd_ptr = uv_stream + symaddrs->uv_stream_s_io_watcher_offset + symaddrs->uv__io_s_fd_offset;
	if (bpf_probe_read_user(&fd, sizeof(fd), (void *)fd_ptr) != 0) {
		return 0;
	}

	return fd;
}

// --- TLS helper interface (called from openssl.bpf.h under ENABLE_NODETLS) ---

// Associate an SSL* with the TLSWrap* currently executing on this thread.
int update_node_ssl_tls_wrap_map(uintptr_t ssl) {
	if (ssl == 0) {
		return 0;
	}

	uintptr_t tls_wrap = get_active_tls_wrap();
	if (tls_wrap == 0) {
		return 0;
	}

	bpf_map_update_elem(&node_ssl_tls_wrap_map, &ssl, &tls_wrap, BPF_ANY);

	uint32_t pid = bpf_get_current_pid_tgid() >> 32;
	TRACE_NODETLS(pid, "nodetls/associate", TRACE_POINTER("ssl", (void *)ssl), TRACE_POINTER("tls_wrap", (void *)tls_wrap));

	return 0;
}

// Recover the socket fd for a given SSL* using Node's object graph.
int32_t get_fd_from_node(uint64_t pid_tgid, uintptr_t ssl) {
	uint32_t tgid = pid_tgid >> 32;

	uintptr_t *tls_wrap = bpf_map_lookup_elem(&node_ssl_tls_wrap_map, &ssl);
	if (tls_wrap == NULL) {
		return 0;
	}

	struct node_tlswrap_symaddrs_t *symaddrs = bpf_map_lookup_elem(&node_tlswrap_symaddrs_map, &tgid);
	if (symaddrs == NULL) {
		TRACE_NODETLS(tgid, "nodetls/get_fd (no symaddrs)", TRACE_INT("tgid", tgid));
		return 0;
	}

	int32_t fd = get_fd_from_tls_wrap(symaddrs, *tls_wrap);
	TRACE_NODETLS(tgid, "nodetls/get_fd", TRACE_INT("fd", fd), TRACE_POINTER("ssl", (void *)ssl));

	return fd;
}

// Forget an SSL* when it is freed.
int remove_node_ssl_tls_wrap_map(uintptr_t ssl) {
	bpf_map_delete_elem(&node_ssl_tls_wrap_map, &ssl);
	return 0;
}

// --- TLSWrap member function probes ---

// On entry to a TLSWrap member function, the first argument is `this` (the TLSWrap*).
// Stash it for this thread so update_node_ssl_tls_wrap_map() can pick it up.
SEC("uprobe/node_tlswrap_memfn")
int BPF_UPROBE(nodetls_probe_entry_TLSWrap_memfn) {
	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uintptr_t tls_wrap = (uintptr_t)PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&active_tls_wrap_memfn_map, &pid_tgid, &tls_wrap, BPF_ANY);

	return 0;
}

SEC("uretprobe/node_tlswrap_memfn")
int BPF_URETPROBE(nodetls_probe_ret_TLSWrap_memfn) {
	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&active_tls_wrap_memfn_map, &pid_tgid);
	return 0;
}
