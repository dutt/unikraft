/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Cloddy ukrandom driver — seeds the kernel CSPRNG from the comm page
 * at GPA 0x9000. The comm page is the source of truth: the VMM writes
 * fresh entropy to it on every snapshot restore, so uk_random_reseed()
 * (triggered by the SDK on resume via the export table, or by the
 * periodic reseed thread if enabled) naturally picks up fresh bytes.
 * No local cache — a scrubbed cache would make reseed fail and silently
 * leave userspace with stale CSPRNG state.
 */
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/print.h>
#include <uk/random.h>
#include <uk/random/driver.h>
#include <uk/boot/earlytab.h>
#include <uk/event.h>
#include <uk/pm.h>

#include <kvm/comm_page.h>

static int cloddy_seed_bytes_fb(__u8 *buf, __sz len)
{
	volatile struct comm_page_header *cp =
		(volatile struct comm_page_header *)COMM_PAGE_GPA;

	/* Re-validate on every call — cheap and handles the case where the
	 * comm page got corrupted between init and a reseed. */
	if (*(volatile __u64 *)cp->magic != COMM_PAGE_MAGIC_LE64)
		return -ENODEV;
	if (len > sizeof(cp->entropy))
		return -ENODEV;

	memcpy(buf, (const void *)cp->entropy, len);
	return 0;
}

static struct uk_random_driver_ops cloddy_ops = {
	.seed_bytes_fb = cloddy_seed_bytes_fb,
};

static struct uk_random_driver cloddy_driver = {
	.name = "cloddy-commpage",
	.ops  = &cloddy_ops,
};

static int uk_random_cloddy_init(struct ukplat_bootinfo __unused *bi)
{
	volatile struct comm_page_header *cp =
		(volatile struct comm_page_header *)COMM_PAGE_GPA;

	/* Validate the comm page magic before trusting anything we read from
	 * it. If validation fails, we're running outside cloddy-vmm (or the
	 * VMM didn't populate the page) — return 0 WITHOUT calling
	 * uk_random_init, so the LCPU driver's early-tab entry gets a chance
	 * to register the fallback. */
	if (*(volatile __u64 *)cp->magic != COMM_PAGE_MAGIC_LE64)
		return 0;
	/* The fields we read (entropy[]) exist from comm page v1 onward.
	 * Newer versions can append fields after mailbox_len without invalidating
	 * this driver (comm_page.h documents append-only forward-compat), so we
	 * only need to reject v0 / zero-initialised headers whose magic somehow
	 * matched. */
	if (cp->version < 1)
		return 0;

	uk_pr_info("cloddy ukrandom: seeding from comm page\n");
	return uk_random_init(&cloddy_driver);
}

/* Priority EARLIER than LCPU (UK_RANDOM_EARLY_DRIVER_PRIO, defined in
 * lib/ukrandom/include/uk/random/driver.h as UK_PRIO_AFTER(3)). We want
 * to register first when the comm page is valid; if we return early, the
 * LCPU tab entry runs next with its own UK_RANDOM_EARLY_DRIVER_PRIO
 * slot and registers the fallback.
 *
 * UK_PRIO_BEFORE(UK_RANDOM_EARLY_DRIVER_PRIO) evaluates to prio 3. That's
 * also the prio of uk_random_early_init (lib/ukrandom/random.c:150), which
 * is only registered when CMDLINE_SEED || DTB_SEED. We disable CMDLINE_SEED
 * in the Kraftfile for all cloddy-vmm kernels (see
 * kernels/python-base/Kraftfile, kernels/rust-base/Kraftfile), and don't enable
 * DTB_SEED, so no other entry sits at prio 3 and there's no ordering ambiguity. */
UK_BOOT_EARLYTAB_ENTRY(uk_random_cloddy_init,
		       UK_PRIO_BEFORE(UK_RANDOM_EARLY_DRIVER_PRIO));

/* Resume handler: re-key ChaCha20 from the fresh entropy the VMM
 * wrote into the comm page before resume. Short-circuits when
 * COMM_FLAG_RESUMED is unset (ladder-continue case: the VMM left the
 * comm page untouched). */
static int cloddy_reseed_on_resume(void *data __unused)
{
	volatile struct comm_page_header *cp =
		(volatile struct comm_page_header *)COMM_PAGE_GPA;
	if (!(cp->flags & COMM_FLAG_RESUMED))
		return UK_EVENT_NOT_HANDLED;
	uk_random_reseed();
	return UK_EVENT_NOT_HANDLED;
}
UK_EVENT_HANDLER_PRIO(UK_PM_EVENT_RESUMED, cloddy_reseed_on_resume, 0);
