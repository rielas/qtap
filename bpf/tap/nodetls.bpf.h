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

#pragma once

#include "vmlinux.h"

/*
 * Node.js drives OpenSSL through a memory BIO, so the SSL object never owns a
 * socket fd directly. Instead the fd lives in Node's own object graph:
 *
 *   SSL*  ->  node::crypto::TLSWrap  ->  StreamListener::stream_ (a StreamResource*)
 *         ->  (that StreamResource is the StreamBase base of a LibuvStreamWrap)
 *         ->  LibuvStreamWrap::stream_ (uv_stream_t*)  ->  io_watcher.fd
 *
 * These struct offsets are version-specific and are supplied from user space
 * (see pkg/ebpf/tls/nodetls) into node_tlswrap_symaddrs_map, keyed by tgid.
 */
struct node_tlswrap_symaddrs_t {
	uint32_t TLSWrap_StreamListener_offset;
	uint32_t StreamListener_stream_offset;
	uint32_t StreamBase_StreamResource_offset;
	uint32_t LibuvStreamWrap_StreamBase_offset;
	uint32_t LibuvStreamWrap_stream_offset;
	uint32_t uv_stream_s_io_watcher_offset;
	uint32_t uv__io_s_fd_offset;
};
