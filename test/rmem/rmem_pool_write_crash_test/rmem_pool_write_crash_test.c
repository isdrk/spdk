/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/event.h"
#include "spdk/env.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/string.h"

#define RMEM_DBG_DO_CRASH(i) do { \
	if (g_write_test_crash && (i) == g_write_test_cp_num) { \
		SPDK_ERRLOG("Emulating crash at crash point %d\n", i); \
		abort(); \
	} \
} while (0)

static int g_write_test_cp_num;
static bool g_write_test_crash = false;
static long int g_action = (long int) -1;
static bool g_print_cp_num = false;

#include "lib/rmem/rmem.c"

#define RMEM_BACKEND_DIR "/tmp/rmem_test"
#define RMEM_POOL_NAME "rmem_pool_write_crash_test"
#define RMEM_POOL_SIZE 1
#define RMEM_POOL_GROWTH_DELTA 10
#define DATA_INITIAL_VALUE 0
#define DATA_MODIFIED_VALUE 100

struct rmem_pool_test_data {
	uint32_t id;
	uint32_t cp_num;
};

static void
rmem_pool_test_usage(void)
{
	printf(" -C                        print the number of crash points available and exit\n");
	printf(" -a                        test number like:\n");
	printf("                           0..%d - fill and simulate a crash at the corresponding crash point\n",
	       __RMEM_DBG_CRASH_POINT_LAST - 1);
	printf("                           %d - restore after a simulated crash\n",
	       __RMEM_DBG_CRASH_POINT_LAST);
}

static int
rmem_pool_test_parse_arg(int argc, char *argv)
{
	long int argval = 0;
	switch (argc) {
	case 'a':
		argval = spdk_strtol(optarg, 10);
		if (argval < 0) {
			SPDK_ERRLOG("-%c option must be non-negative\n", argc);
			rmem_pool_test_usage();
			return 1;
		}
		g_action = argval;
		break;
	case 'C':
		g_print_cp_num = true;
		return 0;
	default:
		rmem_pool_test_usage();
		return 1;
	};
	return 0;
}

static void
spdk_rmem_pool_test_shutdown_cb(void)
{
	SPDK_NOTICELOG("shutdown callback arrived\n");
}

static int
test_fill(enum rmem_dbg_crash_point cp_num)
{
	int rc;
	struct spdk_rmem_pool *pool;
	struct spdk_rmem_entry *entry;
	struct rmem_pool_test_data data;

	SPDK_NOTICELOG("rmem_pool fill\n");

	pool = spdk_rmem_pool_create(RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data),
				     RMEM_POOL_SIZE, RMEM_POOL_GROWTH_DELTA);
	if (!pool) {
		SPDK_ERRLOG("Cannot create rmem_pool (%s, %zu, %d, %d)\n", RMEM_POOL_NAME,
			    sizeof(struct rmem_pool_test_data), RMEM_POOL_SIZE, RMEM_POOL_GROWTH_DELTA);
		rc = -EINVAL;
		goto pool_create_failed;
	}

	SPDK_NOTICELOG("rmem_pool created (name=%s, entry_size=%zu num_entries=%d delta=%d)\n",
		       RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data), RMEM_POOL_SIZE,
		       RMEM_POOL_GROWTH_DELTA);

	entry = spdk_rmem_pool_get(pool);
	if (!entry) {
		SPDK_ERRLOG("Cannot get entry\n");
		rc = -EINVAL;
		goto cleanup;
	}

	SPDK_NOTICELOG("rmem_pool: entry taken, filling...\n");

	data.id = DATA_INITIAL_VALUE;
	data.cp_num = cp_num;
	spdk_rmem_entry_write(entry, &data);

	SPDK_NOTICELOG("rmem_pool: modifying entry with crash simulation...\n");

	g_write_test_crash = true;
	g_write_test_cp_num = cp_num;

	data.id = DATA_MODIFIED_VALUE;
	data.cp_num = cp_num;
	spdk_rmem_entry_write(entry, &data); /* Should "crash" */

	/* we do not do cleanup on purpose */
	return 0;

cleanup:
	SPDK_NOTICELOG("rmem_pool cleanup started\n");
	if (entry) {
		spdk_rmem_entry_release(entry);
	}
	spdk_rmem_pool_destroy(pool);
	SPDK_NOTICELOG("rmem_pool destroyed\n");
pool_create_failed:
	return rc;
}

struct rmem_pool_restore_ctx {
	struct spdk_rmem_entry *entry;
	uint32_t num_entries;
};

static int
rmem_pool_restore_entry_clb(struct spdk_rmem_entry *entry, void *_ctx)
{
	struct rmem_pool_restore_ctx *ctx = _ctx;
	struct rmem_pool_test_data data;

	if (ctx->num_entries) {
		SPDK_ERRLOG("Too many entries: %" PRIu32 "\n", ctx->num_entries);
		ctx->num_entries++;
		return 1;
	}

	if (!spdk_rmem_entry_read(entry, &data)) {
		SPDK_ERRLOG("Cannot read entry\n");
		return 1;
	}

	switch (data.cp_num) {
	case RMEM_DBG_CRASH_POINT_OLD_COPY:
		/* only old copy still exists */
		if (data.id != DATA_INITIAL_VALUE) {
			SPDK_ERRLOG("Wrong data read from entry %" PRIu32 "\n", data.id);
			return 1;
		}
		break;
	case RMEM_DBG_CRASH_POINT_BOTH_COPIES: /* both copies still present, but the new one shall prevail */
	case RMEM_DBG_CRASH_POINT_NEW_COPY: /* only new copy remained */
		if (data.id != DATA_MODIFIED_VALUE) {
			SPDK_ERRLOG("Wrong data read from entry %" PRIu32 "\n", data.id);
			return 1;
		}
		break;
	default:
		SPDK_ERRLOG("Wrong crash point number %" PRIu32 "\n", data.cp_num);
		return 1;
	}

	ctx->entry = entry;
	ctx->num_entries++;
	return 0;
}

static int
test_restore(void)
{
	int rc;
	struct spdk_rmem_pool *pool;
	struct rmem_pool_restore_ctx ctx = {
		.entry = NULL,
		.num_entries = 0,
	};

	SPDK_NOTICELOG("rmem_pool restore after crash\n");

	pool = spdk_rmem_pool_restore(RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data),
				      rmem_pool_restore_entry_clb, &ctx);
	if (!pool) {
		SPDK_ERRLOG("Cannot restore rmem_pool (%s, %zu)\n", RMEM_POOL_NAME,
			    sizeof(struct rmem_pool_test_data));
		rc = -EINVAL;
		goto pool_create_failed;
	}

	if (ctx.num_entries > 1) {
		SPDK_ERRLOG("Restored wrong number of entries (%" PRIu32 "\n", ctx.num_entries);
		rc = -EINVAL;
		goto bad_pool_restored;
	}

	SPDK_NOTICELOG("rmem_pool restored (name=%s, entry_size=%zu)\n",
		       RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data));

	SPDK_NOTICELOG("rmem_pool test completed successfully\n");
	rc = 0;

bad_pool_restored:
	SPDK_NOTICELOG("rmem_pool cleanup started\n");
	if (ctx.entry) {
		spdk_rmem_entry_release(ctx.entry);
	}

	spdk_rmem_pool_destroy(pool);

	SPDK_NOTICELOG("rmem_pool destroyed\n");
pool_create_failed:
	return rc;
}


static void
test_main(void *arg1)
{
	int rc;

	if (g_print_cp_num) {
		printf("%d", __RMEM_DBG_CRASH_POINT_LAST);
		rc = 0;
		goto out;
	}

	if (!spdk_rmem_enable(RMEM_BACKEND_DIR)) {
		SPDK_ERRLOG("Cannot enable rmem\n");
		rc = -EINVAL;
		goto out;
	}

	if (g_action < __RMEM_DBG_CRASH_POINT_LAST) {
		rc = test_fill(g_action);
	} else if (g_action == __RMEM_DBG_CRASH_POINT_LAST) {
		rc = test_restore();
	} else {
		SPDK_ERRLOG("Invalid action: %lu\n", g_action);
		rmem_pool_test_usage();
		rc = -EINVAL;
	}

	if (!spdk_rmem_enable(NULL)) {
		SPDK_ERRLOG("Cannot disable rmem\n");
		rc = -EINVAL;
	}

out:
	spdk_app_stop(rc);
}

int
main(int argc, char **argv)
{
	int			rc;
	struct spdk_app_opts	opts = {};

	rc = spdk_rmem_init();
	assert(rc == 0);

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "rmempoolwritecrashtest";
	opts.reactor_mask = "0x1";
	opts.shutdown_cb = spdk_rmem_pool_test_shutdown_cb;

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "a:C", NULL,
				      rmem_pool_test_parse_arg, rmem_pool_test_usage)) !=
	    SPDK_APP_PARSE_ARGS_SUCCESS) {
		return rc;
	}

	rc = spdk_app_start(&opts, test_main, NULL);
	spdk_app_fini();

	return rc;
}
