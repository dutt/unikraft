/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Cloddy contributors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <errno.h>
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

/* --- Kernel CSPRNG reseed ---------------------------------------

   Exposed via the cloddy export table. SDK calls this on snapshot
   resume so uk_random_reseed() re-keys ChaCha20 from the comm page
   (the cloddy ukrandom driver reads GPA 0x9000 on every seed call).
   Without this, os.urandom / getrandom(2) / TLS nonces keep running
   the snapshot-frozen CSPRNG state across N resumed VMs — bad.
*/

#include <uk/random.h>

int uk_cloddy_reseed_csprng(void)
{
	return uk_random_reseed();
}

/* --- Resume-time netif reconfig --------------------------------- */

#if CONFIG_LIBLWIP
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/sys.h>
#include <lwip/tcpip.h>

/* lwIP 2.1.x's netif mutation APIs (netif_set_addr) are only safe to call
 * from the tcpip thread, or while holding LWIP_TCPIP_CORE_LOCKING (not
 * enabled in our build). The userspace SDK invokes uk_cloddy_reconfig_network
 * from whichever thread it happens to be on -- that's not the tcpip thread.
 * We use tcpip_callback() to post a callback onto the tcpip thread, and a
 * sys_sem_t to block the caller until the callback runs and reports its
 * result. This is lwIP's documented pattern for host-thread to tcpip-thread
 * work.
 *
 * tcpip_callback is upstream lwIP 2.1.x (declared in lwip/tcpip.h),
 * available because CONFIG_LWIP_THREADS: 'y' in both Kraftfiles starts the
 * tcpip thread at boot. */

struct cloddy_reconfig_args {
	__u32 addr, netmask, gateway;
	int rc;
	sys_sem_t done;
};

/* Runs on the tcpip thread (posted via tcpip_callback).
 *
 * Byte-order contract: a->addr / netmask / gateway are HOST-ORDER u32s
 * (e.g. 0x0A000002 represents 10.0.0.2). lwIP's ip4_addr_t.addr stores
 * bytes in network order, so we convert via lwip_htonl() -- the same
 * pattern every other lwIP caller uses (dhcp.c, ip4_addr.c, autoip.c).
 * This lets the SDKs pass the "natural" host-order u32 (what you get
 * from Python's int.from_bytes(packed, "big") or Rust's
 * u32::from_be_bytes(octets)) without having to know lwIP's internal
 * storage convention. */
static void cloddy_reconfig_cb(void *arg)
{
	struct cloddy_reconfig_args *a = arg;
	struct netif *nif = netif_default;
	if (!nif) {
		a->rc = -ENODEV;
	} else {
		ip4_addr_t ip, nm, gw;
		ip4_addr_set_u32(&ip, lwip_htonl(a->addr));
		ip4_addr_set_u32(&nm, lwip_htonl(a->netmask));
		ip4_addr_set_u32(&gw, lwip_htonl(a->gateway));
		netif_set_addr(nif, &ip, &nm, &gw);
		a->rc = 0;
	}
	sys_sem_signal(&a->done);
}

/* Called from the SDK via the cloddy export table on snapshot resume.
 * Blocks (bounded) until the tcpip thread has applied the new config.
 * Returns 0 on success, -ENODEV if no primary netif, -EAGAIN if the
 * callback couldn't be queued or the tcpip thread didn't run the
 * callback within RECONFIG_TIMEOUT_MS.
 *
 * Arguments are host-order u32s (see cloddy_reconfig_cb byte-order note). */
#define CLODDY_RECONFIG_TIMEOUT_MS 2000

int uk_cloddy_reconfig_network(__u32 addr, __u32 netmask, __u32 gateway)
{
	struct cloddy_reconfig_args args = {
		.addr = addr, .netmask = netmask, .gateway = gateway, .rc = 0,
		/* args.done left uninitialized -- sys_sem_new overwrites it. */
	};
	u32_t waited;

	if (sys_sem_new(&args.done, 0) != ERR_OK)
		return -EAGAIN;

	if (tcpip_callback(cloddy_reconfig_cb, &args) != ERR_OK) {
		sys_sem_free(&args.done);
		return -EAGAIN;
	}

	waited = sys_arch_sem_wait(&args.done, CLODDY_RECONFIG_TIMEOUT_MS);
	sys_sem_free(&args.done);
	if (waited == SYS_ARCH_TIMEOUT)
		return -EAGAIN;
	return args.rc;
}

#else  /* !CONFIG_LIBLWIP */

/* No lwIP linked -- the export-table entry still exists so SDKs can call
 * unconditionally, but reconfig is not possible. SDK should treat -ENODEV
 * as "no netif to reconfigure" and fall back to whatever cold-boot config
 * was provided. */
int uk_cloddy_reconfig_network(__u32 addr __unused, __u32 netmask __unused,
			       __u32 gateway __unused)
{
	return -ENODEV;
}

#endif /* CONFIG_LIBLWIP */
