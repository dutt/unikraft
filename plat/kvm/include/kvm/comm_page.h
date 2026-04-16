/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Cloddy contributors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#ifndef __KVM_COMM_PAGE_H__
#define __KVM_COMM_PAGE_H__

#include <uk/arch/types.h>
#include <uk/essentials.h>

/* Guest physical address of the comm page (2 pages).
 * Must match cloddy-vmm's COMM_REGION_ADDR (0x9000) and
 * COMM_REGION_SIZE (0x2000).
 * VMM marks this region E820_RESERVED.
 */
#define COMM_PAGE_GPA           0x9000
#define COMM_PAGE_SIZE          0x2000  /* 2 pages: header + mailbox */

/* Magic value: "CLODVMM\0" — checked as a single LE u64 for ISR safety */
#define COMM_PAGE_MAGIC         "CLODVMM\0"
#define COMM_PAGE_MAGIC_LE64    0x004D4D56444F4C43ULL

#define COMM_PAGE_VERSION       1

/* Flags (bitfield in header.flags) */
#define COMM_FLAG_RESUMED       (1 << 0)  /* VM resumed from snapshot */

/*
 * Header layout (page 1, at COMM_PAGE_GPA).
 *
 * Packed to guarantee byte-exact layout matching the VMM-side Rust struct.
 * All multi-byte integers are little-endian (x86 native).
 * Network addresses (ipv4_*) are in network byte order (big-endian).
 *
 * This struct is append-only: new fields go after mailbox_len,
 * and COMM_PAGE_VERSION is bumped. Readers check version >= N
 * before accessing version-N fields, so forward compat is maintained.
 */
struct comm_page_header {
	char     magic[8];        /* 0x000: "CLODVMM\0"                    */
	__u32    version;         /* 0x008: COMM_PAGE_VERSION               */
	__u32    flags;           /* 0x00C: COMM_FLAG_* bitfield            */
	__u8     entropy[32];     /* 0x010: 32 bytes host CSPRNG output     */
	__u32    ipv4_addr;       /* 0x030: network byte order              */
	__u32    ipv4_netmask;    /* 0x034: network byte order              */
	__u32    ipv4_gateway;    /* 0x038: network byte order              */
	__u8     mac[6];          /* 0x03C: MAC address                     */
	__u8     _pad1[2];        /* 0x042: alignment padding               */
	__u32    dns_addr;        /* 0x044: IPv4, network byte order        */
	__u32    mailbox_len;     /* 0x048: 0 = no mailbox                  */
} __packed;

/* Mailbox area (page 2, at COMM_PAGE_GPA + 0x1000) */
#define COMM_PAGE_MAILBOX_OFFSET  0x1000
#define COMM_PAGE_MAILBOX_MAX     4096

#endif /* __KVM_COMM_PAGE_H__ */
