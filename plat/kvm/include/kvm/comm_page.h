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
	/* Bidirectional snapshot label. Guest writes before
	 * uk_pm_syssuspend(); VMM writes (or zeros) on resume. See
	 * plans/wip/custom-vmm/resume-hooks-design.md "The label field and
	 * its invariant" for the full contract. */
	char     label[64];       /* 0x04C: NUL-terminated snapshot name    */
} __packed;                   /* header ends at 0x08C                    */

#define COMM_PAGE_LABEL_MAX     64

/* Mailbox area (page 2, at COMM_PAGE_GPA + 0x1000) */
#define COMM_PAGE_MAILBOX_OFFSET  0x1000
#define COMM_PAGE_MAILBOX_MAX     4096

/* Cloddy export table — function pointers delivered to userspace SDKs.
 *
 * Layout at COMM_PAGE_GPA + 0x100:
 *   u64 magic    = CLODDY_EXPORT_MAGIC
 *   u64 version  = CLODDY_EXPORT_VERSION
 *   u64 count    = N (number of entries)
 *   repeated { u64 id; u64 fn_ptr; } for N entries.
 *
 * id is a stable export-ID constant (see CLODDY_EXPORT_ID_*). fn_ptr is the
 * native-word function address. Callers MUST match the C-ABI signature
 * documented for each id. Any change to a signature requires a version
 * bump and an SDK-side compat shim.
 *
 * The export-table region (offset 0x100..0xFFF within the comm page) is
 * Unikraft-populated and must NOT be overwritten by the VMM after cold
 * boot. The VMM's comm_page::write only touches offsets 0x000..0x04C
 * (see control-plane/crates/cloddy-vmm/src/comm_page.rs).
 */
#define CLODDY_EXPORT_TABLE_OFFSET   0x100
#define CLODDY_EXPORT_MAGIC          0xC10DDEADEB10A81EULL
#define CLODDY_EXPORT_VERSION        1

/* IDs 1 (RECONFIG_NETWORK) and 2 (RESEED_CSPRNG) were removed: both are
 * now handled in-kernel by UK_PM_EVENT_RESUMED handlers (lwIP netif
 * reconfig in plat/kvm/x86/cloddy.c, CSPRNG reseed in
 * drivers/ukrandom/cloddy/init.c). The IDs are not reused so existing
 * SDK code that probes for them just gets a "not found" lookup. */

#define CLODDY_EXPORT_ID_SNAPSHOT_HERE  3
/* Signature: int(const char *label)
 * Cooperative snapshot point. Copies up to COMM_PAGE_LABEL_MAX-1 bytes
 * of `label` into comm_page_header.label, then quiesces the guest via
 * uk_pm_syssuspend(). Returns 0 when the VMM resumes the vCPU
 * (pass-through or snapshot-then-continue), <0 on errors.
 */

#endif /* __KVM_COMM_PAGE_H__ */
