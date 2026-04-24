/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Cloddy contributors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <errno.h>
#include <string.h>
#include <uk/arch/types.h>
#include <uk/arch/util.h>
#include <uk/boot/earlytab.h>
#include <uk/init.h>
#include <uk/libparam.h>
#include <uk/pm.h>
#include <uk/prio.h>
#include <uk/print.h>

#include <kvm/comm_page.h>

/* PIO exit port — must match cloddy-vmm's device/cloddy_ports.rs
 * EXIT_PORT constant. Same port as QEMU's isa-debug-exit, but we write
 * the raw exit code instead of QEMU's shifted convention.
 */
#define CLODDY_EXIT_PORT	0x501

/* PIO snapshot port — must match cloddy-vmm's SNAPSHOT_PORT constant.
 * Guest writes on entry to uk_pm_syssuspend() so the VMM can consult its
 * snapshot directive and (optionally) capture a snapshot. The VMM
 * resumes the vCPU; the halt below then returns.
 */
#define CLODDY_SNAPSHOT_PORT	0x502

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

static int cloddy_syssuspend(void)
{
	/* Port-out causes a VMEXIT; the VMM resumes us by re-entering the
	 * vCPU, at which point `return 0` runs and uk_pm_syssuspend raises
	 * UK_PM_EVENT_RESUMED. No HLT needed — KVM_RUN doesn't spin while
	 * the VMM is handling the exit. */
	uk_arch_x86_64_outw(CLODDY_SNAPSHOT_PORT, 0);
	return 0;
}

static const struct uk_pm_ops cloddy_pm_ops = {
	.syshalt = cloddy_exit,
	.sysrestart = cloddy_exit,
	.syssuspend = cloddy_syssuspend,
	.syscrash = cloddy_crash,
};

__isr static int cloddy_register_pm_ops(struct ukplat_bootinfo __unused *bi)
{
	return uk_pm_ops_register(&cloddy_pm_ops);
}

UK_BOOT_EARLYTAB_ENTRY(cloddy_register_pm_ops, UK_PRIO_EARLIEST);

/* --- Cooperative snapshot-point primitive -----------------------

   Exposed via the cloddy export table (id SNAPSHOT_HERE). Writes
   `label` into the comm-page header, then calls uk_pm_syssuspend()
   which triggers the VMM via CLODDY_SNAPSHOT_PORT. Returns when the
   VMM resumes the vCPU. See plans/wip/custom-vmm/resume-hooks-design.md
   for the full "label invariant" contract.
 */

int uk_cloddy_snapshot_here(const char *label)
{
	volatile struct comm_page_header *cp =
		(volatile struct comm_page_header *)COMM_PAGE_GPA;
	size_t n = label ? strnlen(label, COMM_PAGE_LABEL_MAX - 1) : 0;
	size_t i;

	/* Zero first, then copy. Guarantees NUL-termination and clears
	 * any trailing bytes from a prior label.
	 */
	for (i = 0; i < COMM_PAGE_LABEL_MAX; i++)
		cp->label[i] = 0;
	for (i = 0; i < n; i++)
		cp->label[i] = label[i];

	/* Quiesce. Returns when the VMM resumes us. On pass-through the
	 * VMM zeros cp->label before resuming; on snapshot-taken the VMM
	 * leaves (or sets) the label.
	 */
	return uk_pm_syssuspend();
}

/* --- Kernel CSPRNG reseed ---------------------------------------

   Exposed via the cloddy export table (id RESEED_CSPRNG). SDKs call
   this on snapshot resume so uk_random_reseed() re-keys ChaCha20 from
   the comm page (the cloddy ukrandom driver reads GPA 0x9000 on every
   seed call). Without this, os.urandom / getrandom(2) / TLS nonces
   keep running the snapshot-frozen CSPRNG state across N resumed VMs
   — bad.

   For snapshot_here()-based resumes the kernel's UK_PM_EVENT_RESUMED
   handler in drivers/ukrandom/cloddy/init.c runs this automatically;
   this export remains available for legacy serial-marker snapshot
   paths where the kernel event does not fire (the VMM captures the VM
   outside uk_pm_syssuspend).
*/

#include <uk/random.h>

int uk_cloddy_reseed_csprng(void)
{
	return uk_random_reseed();
}

/* --- Pre-main snapshot hook ------------------------------------

   Gated by the boot arg `cloddy.snapshot_here=1`. Fires in the late
   init class, after all other kernel init is done but before the main
   thread runs. The hook calls snapshot_here("premain"); the VMM
   (matching its directive) will typically snapshot + exit here.
*/

static char *cloddy_snapshot_here_arg;
UK_LIBPARAM_PARAM_ALIAS(snapshot_here, &cloddy_snapshot_here_arg, charp,
	"Call snapshot_here(\"premain\") from the premain hook when =1");

static int cloddy_premain_init(struct uk_init_ctx *ctx __unused)
{
	if (!cloddy_snapshot_here_arg || cloddy_snapshot_here_arg[0] != '1')
		return 0;
	uk_pr_info("cloddy: snapshot_here(\"premain\") from premain hook\n");
	uk_cloddy_snapshot_here("premain");
	return 0;  /* do NOT abort boot on resume */
}

/* Signature: (init_fn, term_fn, prio). 0x0 term_fn = no cleanup; the
 * macro token-pastes its args so a real NULL doesn't work here — match
 * existing callers (e.g. lib/posix-process/process.c:
 * uk_late_initcall(posix_process_init, 0x0)).
 * UK_PRIO_LATEST places us after other late-class entries but still
 * within the uk_inittab iteration before the main thread is unblocked.
 */
uk_late_initcall_prio(cloddy_premain_init, 0x0, UK_PRIO_LATEST);

/* --- Resume-time netif reconfig --------------------------------- */

#if CONFIG_LIBLWIP
#include <lwip/etharp.h>
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

		/* Refresh the netif's hwaddr from the comm page. The VMM writes
		 * the post-resume MAC at cp->mac (see control-plane/.../comm_page.rs);
		 * virtio_net_mac_on_resume (prio 4) already copied that into the
		 * driver's hwaddr cache, but lwIP caches its own copy on nif->hwaddr
		 * which netif_set_addr does not touch. Without this update the
		 * restored guest keeps the snapshot-time MAC on the wire while the
		 * host/bridge expect the fresh per-VM MAC — ARP/TCP traffic falls
		 * on the floor. Doing it here (on the tcpip thread) is race-safe
		 * with any concurrent lwIP netif access. */
		volatile struct comm_page_header *cp =
			(volatile struct comm_page_header *)COMM_PAGE_GPA;
		__u8 new_mac[6];
		unsigned int i;
		int mac_changed = 0;
		for (i = 0; i < 6; i++) {
			new_mac[i] = cp->mac[i];
			if (new_mac[i] != nif->hwaddr[i])
				mac_changed = 1;
		}
		if (mac_changed) {
			for (i = 0; i < 6; i++)
				nif->hwaddr[i] = new_mac[i];
		}

		netif_set_addr(nif, &ip, &nm, &gw);

		/* Emit a gratuitous ARP so the host bridge fdb and any peers
		 * that cached `(old_ip -> old_mac)` or `(new_ip -> old_mac)`
		 * see the fresh mapping immediately. Without this the first
		 * host→guest connect after resume fails until the bridge
		 * relearns from our own outbound traffic, which can be many
		 * seconds on an idle guest. */
		etharp_gratuitous(nif);
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

#include <uk/event.h>

/* Resume handler: re-apply the post-resume netif config the VMM wrote
 * into the comm page. Short-circuits on ladder-continue
 * (COMM_FLAG_RESUMED unset) — the VMM didn't touch the comm page.
 * Priority 5 so it runs *after* the virtio-net MAC refresh at prio 4
 * (lib-order is low-to-high), letting lwIP's netif_set_addr consult
 * the already-refreshed hwaddr. */
static int cloddy_netif_on_resume(void *data __unused)
{
	volatile struct comm_page_header *cp =
		(volatile struct comm_page_header *)COMM_PAGE_GPA;
	if (*(volatile __u64 *)cp->magic != COMM_PAGE_MAGIC_LE64)
		return UK_EVENT_NOT_HANDLED;
	if (!(cp->flags & COMM_FLAG_RESUMED))
		return UK_EVENT_NOT_HANDLED;
	uk_cloddy_reconfig_network(lwip_ntohl(cp->ipv4_addr),
				   lwip_ntohl(cp->ipv4_netmask),
				   lwip_ntohl(cp->ipv4_gateway));
	return UK_EVENT_NOT_HANDLED;
}
UK_EVENT_HANDLER_PRIO(UK_PM_EVENT_RESUMED, cloddy_netif_on_resume, 5);

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
