/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Cloddy contributors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <uk/arch/types.h>
#include <uk/arch/util.h>
#include <uk/boot/earlytab.h>
#include <uk/pm.h>
#include <uk/prio.h>

/* PIO exit port — must match cloddy-vmm's device/exit_port.rs PORT constant.
 * Same port as QEMU's isa-debug-exit, but we write the raw exit code
 * instead of QEMU's shifted convention.
 */
#define CLODDY_EXIT_PORT	0x501

/* Crash sentinel — must match cloddy-vmm's CRASH_CODE constant.
 * Distinct from any valid POSIX exit code (0-255).
 */
#define CLODDY_EXIT_CRASH	0xFFFF

__isr static int cloddy_exit(void)
{
	/* Mask to 8 bits: POSIX exit codes are 0-255.
	 * This also guarantees no collision with CLODDY_EXIT_CRASH (0xFFFF).
	 */
	__u16 code = (__u16)(uk_pm_get_exit_code() & 0xFF);

	uk_arch_x86_64_outw(CLODDY_EXIT_PORT, code);

	/* Should not reach here — VMM exits the run loop on port write.
	 * Return error so uk_pm_syshalt falls back to HLT loop.
	 */
	return -EIO;
}

__isr static int cloddy_crash(void)
{
	uk_arch_x86_64_outw(CLODDY_EXIT_PORT, CLODDY_EXIT_CRASH);
	return -EIO;
}

static const struct uk_pm_ops cloddy_pm_ops = {
	.syshalt = cloddy_exit,
	.sysrestart = cloddy_exit,
	.syscrash = cloddy_crash,
};

__isr static int cloddy_register_pm_ops(struct ukplat_bootinfo __unused *bi)
{
	return uk_pm_ops_register(&cloddy_pm_ops);
}

UK_BOOT_EARLYTAB_ENTRY(cloddy_register_pm_ops, UK_PRIO_EARLIEST);
