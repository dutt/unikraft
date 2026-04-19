/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <uk/plat/common/bootinfo.h>
#include <uk/print.h>
#include <uk/random/driver.h>
#include <uk/boot/earlytab.h>

#include <kvm/comm_page.h>

/* Driver-local state, populated once at early-tab entry time.
 * Scrubbed after the first seed_bytes_fb call so entropy doesn't linger. */
static __u8 cloddy_entropy[32];
static bool cloddy_entropy_valid;

static int cloddy_seed_bytes_fb(__u8 *buf, __sz len)
{
	if (!cloddy_entropy_valid || len > sizeof(cloddy_entropy))
		return -ENODEV;

	memcpy(buf, cloddy_entropy, len);
	/* First consumer wins — scrub so a second call (or a bug) can't
	 * deliver stale bytes. Subsequent uk_random_reseed() calls will see
	 * -ENODEV and the upper layer falls back to whatever the fallback
	 * driver provides, or degrades deterministically. */
	memset(cloddy_entropy, 0, sizeof(cloddy_entropy));
	cloddy_entropy_valid = false;
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
	/* The fields we read below (entropy[]) exist from comm page v1 onward.
	 * Newer versions can append fields after mailbox_len without invalidating
	 * this driver (comm_page.h documents append-only forward-compat), so we
	 * only need to reject v0 / zero-initialised headers whose magic somehow
	 * matched. */
	if (cp->version < 1)
		return 0;

	memcpy(cloddy_entropy, (const void *)cp->entropy, sizeof(cloddy_entropy));
	cloddy_entropy_valid = true;

	uk_pr_info("cloddy ukrandom: seeded from comm page (32 bytes)\n");
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
