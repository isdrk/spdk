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
#include "spdk/rmem.h"

#define RMEM_BACKEND_DIR "/tmp/rmem_test"
#define RMEM_POOL_NAME "rmem_pool_test"
#define RMEM_POOL_INIT_SIZE 1000
#define RMEM_POOL_GROWTH_DELTA 100
#define RMEM_POOL_TEST_SIZE 1300

struct rmem_pool_test_data {
	uint32_t id;
};


enum rmem_pool_test_action {
	PMEM_TEST_ACTION_WRITE,
	PMEM_TEST_ACTION_WRITE_NO_CLEANUP,
	PMEM_TEST_ACTION_RESTORE,
	PMEM_TEST_ACTION_GET_RELEASE,
	__PMEM_TEST_ACTION_LAST
};

static const char *test_names[] = {
	"write",
	"write and crash",
	"restore",
	"get/release",
};

SPDK_STATIC_ASSERT(SPDK_COUNTOF(test_names) == __PMEM_TEST_ACTION_LAST, "Incorrect size");

static enum rmem_pool_test_action g_action = __PMEM_TEST_ACTION_LAST;

static void
rmem_pool_test_usage(void)
{
	int i;
	printf(" -a                        test number like :\n");
	for (i = PMEM_TEST_ACTION_WRITE; i < __PMEM_TEST_ACTION_LAST; i++) {
		printf("                           %d - %s test\n", i, test_names[i]);
	}
}

static int
rmem_pool_test_parse_arg(int argc, char *argv)
{
	int argval = 0;
	switch (argc) {
	case 'a':
		argval = spdk_strtol(optarg, 10);
		if (argval < 0) {
			SPDK_ERRLOG("-%c option must be non-negative.\n", argc);
			rmem_pool_test_usage();
			return 1;
		}
		g_action = argval;
		break;
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
test_write(bool do_cleanup)
{
	int rc;
	struct spdk_rmem_pool *pool;
	struct spdk_rmem_entry *entries[RMEM_POOL_TEST_SIZE] = {0};
	struct rmem_pool_test_data data;
	int i;

	SPDK_NOTICELOG("rmem_pool write test (do_cleanup=%d)\n", do_cleanup);

	pool = spdk_rmem_pool_create(RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data),
				     RMEM_POOL_INIT_SIZE,
				     RMEM_POOL_GROWTH_DELTA);
	if (!pool) {
		SPDK_ERRLOG("Cannot create rmem_pool (%s, %zu, %d, %d)\n", RMEM_POOL_NAME,
			    sizeof(struct rmem_pool_test_data), RMEM_POOL_INIT_SIZE, RMEM_POOL_GROWTH_DELTA);
		rc = -EINVAL;
		goto pool_create_failed;
	}

	SPDK_NOTICELOG("rmem_pool created (name=%s, entry_size=%zu num_entries=%d delta=%d)\n",
		       RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data), RMEM_POOL_INIT_SIZE,
		       RMEM_POOL_GROWTH_DELTA);

	for (i = 0; i < RMEM_POOL_TEST_SIZE; i++) {
		entries[i] = spdk_rmem_pool_get(pool);
		if (!entries[i]) {
			SPDK_ERRLOG("Cannot get entry %d\n", i);
			rc = -EINVAL;
			goto cleanup;
		}
	}

	SPDK_NOTICELOG("rmem_pool: %d entries taken, filling...\n", RMEM_POOL_TEST_SIZE);

	for (i = 0; i < RMEM_POOL_TEST_SIZE; i++) {
		data.id = (uint32_t)i;
		spdk_rmem_entry_write(entries[i], &data);
	}

	SPDK_NOTICELOG("rmem_pool: checking entries by read...\n");

	for (i = 0; i < RMEM_POOL_TEST_SIZE; i++) {
		rc = spdk_rmem_entry_read(entries[i], &data);
		if (rc) {
			SPDK_ERRLOG("Cannot read entry %d (err=%d)\n", i, rc);
			goto cleanup;
		}

		if (data.id != (uint32_t)i) {
			SPDK_ERRLOG("Wrong data read from entry %d\n", i);
			rc = -EINVAL;
			goto cleanup;
		}
	}

	SPDK_NOTICELOG("rmem_pool: modifying the entries...\n");

	for (i = 0; i < RMEM_POOL_TEST_SIZE; i++) {
		data.id = (uint32_t)i * 2;
		spdk_rmem_entry_write(entries[i], &data);
	}

	SPDK_NOTICELOG("rmem_pool: checking modified entries by read...\n");

	for (i = 0; i < RMEM_POOL_TEST_SIZE; i++) {
		rc = spdk_rmem_entry_read(entries[i], &data);
		if (rc) {
			SPDK_ERRLOG("Cannot read entry %d (err=%d)\n", i, rc);
			goto cleanup;
		}

		if (data.id != (uint32_t)i * 2) {
			SPDK_ERRLOG("Wrong data read from entry %d\n", i);
			rc = -EINVAL;
			goto cleanup;
		}
	}
	SPDK_NOTICELOG("rmem_pool test completed successfully\n");
	rc = 0;

cleanup:
	if (do_cleanup) {
		SPDK_NOTICELOG("rmem_pool cleanup started\n");
		for (i = 0; i < RMEM_POOL_TEST_SIZE && entries[i]; i++) {
			spdk_rmem_entry_release(entries[i]);
		}
		spdk_rmem_pool_destroy(pool);
		SPDK_NOTICELOG("rmem_pool destroyed\n");
	}
pool_create_failed:
	return rc;
}

struct rmem_pool_restore_ctx {
	struct spdk_rmem_entry *entries[RMEM_POOL_TEST_SIZE];
	uint32_t idx;
};

static int
rmem_pool_restore_entry_clb(struct spdk_rmem_entry *entry, void *_ctx)
{
	struct rmem_pool_restore_ctx *ctx = _ctx;
	struct rmem_pool_test_data data;
	int rc;

	if (ctx->idx >= SPDK_COUNTOF(ctx->entries)) {
		SPDK_ERRLOG("Too many entries (%" PRIu32 " >= %zu\n", ctx->idx, SPDK_COUNTOF(ctx->entries));
		ctx->idx++;
		return 1;
	}

	rc = spdk_rmem_entry_read(entry, &data);
	if (rc) {
		SPDK_ERRLOG("Cannot read entry %" PRIu32 " (err=%d)\n", ctx->idx, rc);
		return 1;
	}

	if (data.id != ctx->idx * 2) {
		SPDK_ERRLOG("Wrong data read from entry %" PRIu32 "\n", ctx->idx);
		return 1;
	}

	ctx->entries[ctx->idx] = entry;
	ctx->idx++;
	return 0;
}


static int
test_restore(void)
{
	int rc;
	struct spdk_rmem_pool *pool;
	struct rmem_pool_restore_ctx ctx = {0};
	int i;

	SPDK_NOTICELOG("rmem_pool restore test\n");

	pool = spdk_rmem_pool_restore(RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data),
				      rmem_pool_restore_entry_clb, &ctx);
	if (!pool) {
		SPDK_ERRLOG("Cannot restore rmem_pool (%s, %zu)\n", RMEM_POOL_NAME,
			    sizeof(struct rmem_pool_test_data));
		rc = -EINVAL;
		goto pool_restore_failed;
	}

	if (ctx.idx != RMEM_POOL_TEST_SIZE) {
		SPDK_ERRLOG("Wrong number of entries restored: %" PRIu32 " != %d)\n", ctx.idx, RMEM_POOL_TEST_SIZE);
		rc = -EINVAL;
		goto pool_restore_error;
	}

	SPDK_NOTICELOG("rmem_pool restored (name=%s, entry_size=%zu)\n",
		       RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data));

	SPDK_NOTICELOG("rmem_pool test completed successfully\n");
	rc = 0;

pool_restore_error:
	SPDK_NOTICELOG("rmem_pool cleanup started\n");
	for (i = 0; i < RMEM_POOL_TEST_SIZE; i++) {
		if (ctx.entries[i]) {
			spdk_rmem_entry_release(ctx.entries[i]);
		}
	}
	spdk_rmem_pool_destroy(pool);

	SPDK_NOTICELOG("rmem_pool destroyed\n");
pool_restore_failed:
	return rc;
}

static int
test_get_release(void)
{
	int rc;
	struct spdk_rmem_pool *pool;
	struct spdk_rmem_entry **entries = NULL;
	struct spdk_rmem_entry *ext_entry = NULL;
	uint32_t num_entries, i;

	SPDK_NOTICELOG("rmem_pool get/release test\n");

	pool = spdk_rmem_pool_create(RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data),
				     RMEM_POOL_INIT_SIZE,
				     RMEM_POOL_GROWTH_DELTA);
	if (!pool) {
		SPDK_ERRLOG("Cannot create rmem_pool (%s, %zu, %d, %d)\n", RMEM_POOL_NAME,
			    sizeof(struct rmem_pool_test_data), RMEM_POOL_INIT_SIZE, RMEM_POOL_GROWTH_DELTA);
		rc = -EINVAL;
		goto pool_create_failed;
	}

	num_entries = spdk_rmem_pool_num_entries(pool);

	SPDK_NOTICELOG("rmem_pool created (name=%s, entry_size=%zu num_entries=%" PRIu32 ")\n",
		       RMEM_POOL_NAME, sizeof(struct rmem_pool_test_data), num_entries);

	entries = calloc(num_entries, sizeof(entries[i]));
	if (!entries) {
		SPDK_ERRLOG("Cannot allocate %" PRIu32 " entry pointers\n", num_entries);
		rc = -ENOMEM;
		goto entries_alloc_failed;
	}

	/* Get all the pool entries */
	for (i = 0; i < num_entries; i++) {
		entries[i] = spdk_rmem_pool_get(pool);
		if (!entries[i]) {
			SPDK_ERRLOG("Cannot get entry %d\n", i);
			rc = -EINVAL;
			goto cleanup;
		}
	}

	/* Getting all the pool entries shouldn't result in pool extension */
	if (spdk_rmem_pool_num_entries(pool) != num_entries) {
		SPDK_ERRLOG("pool has been prematurely extended (%" PRIu32 " != %" PRIu32 ")\n",
			    spdk_rmem_pool_num_entries(pool), num_entries);
		rc = -EINVAL;
		goto cleanup;
	}

	/* Release half of entries */
	for (i = 0; i < num_entries / 2; i++) {
		spdk_rmem_entry_release(entries[i * 2]);
	}

	/* Releasing the pool entries shouldn't result in pool extension */
	if (spdk_rmem_pool_num_entries(pool) != num_entries) {
		SPDK_ERRLOG("pool has been extended upon release (%" PRIu32 " != %" PRIu32 ")\n",
			    spdk_rmem_pool_num_entries(pool), num_entries);
		rc = -EINVAL;
		goto cleanup;
	}

	/* Get the remain half of entries again */
	for (i = 0; i < num_entries / 2; i++) {
		entries[i * 2] = spdk_rmem_pool_get(pool);
		if (!entries[i]) {
			SPDK_ERRLOG("Cannot re-get entry %d\n", i * 2);
			rc = -EINVAL;
			goto cleanup;
		}
	}

	/* Getting the remain pool entries shouldn't result in pool extension */
	if (spdk_rmem_pool_num_entries(pool) != num_entries) {
		SPDK_ERRLOG("pool has been extended upon re-get (%" PRIu32 " != %" PRIu32 ")\n",
			    spdk_rmem_pool_num_entries(pool), num_entries);
		rc = -EINVAL;
		goto cleanup;
	}

	/* Get an additional entry */
	ext_entry = spdk_rmem_pool_get(pool);
	if (!ext_entry) {
		SPDK_ERRLOG("Cannot get an additional entry\n");
		rc = -EINVAL;
		goto cleanup;
	}

	/* Getting the remain pool entries should result in pool extension */
	if (spdk_rmem_pool_num_entries(pool) == num_entries) {
		SPDK_ERRLOG("pool has not been extended (%" PRIu32 " == %" PRIu32 ")\n",
			    spdk_rmem_pool_num_entries(pool), num_entries);
		rc = -EINVAL;
		goto cleanup;
	}

	SPDK_NOTICELOG("rmem_pool test completed successfully\n");
	rc = 0;

cleanup:
	SPDK_NOTICELOG("rmem_pool cleanup started\n");
	if (ext_entry) {
		spdk_rmem_entry_release(ext_entry);
	}
	for (i = 0; i < num_entries && entries[i]; i++) {
		spdk_rmem_entry_release(entries[i]);
	}
	free(entries);
entries_alloc_failed:
	spdk_rmem_pool_destroy(pool);
pool_create_failed:
	return rc;
}

static void
test_main(void *arg1)
{
	int rc;

	rc = spdk_rmem_set_backend_dir(RMEM_BACKEND_DIR);
	if (rc) {
		SPDK_ERRLOG("Cannot enable rmem (err=%d)\n", rc);
		goto out;
	}

	switch (g_action) {
	case PMEM_TEST_ACTION_WRITE:
		rc = test_write(true);
		break;
	case PMEM_TEST_ACTION_WRITE_NO_CLEANUP:
		rc = test_write(false);
		assert(rc == 0);
		SPDK_NOTICELOG("Imitating app crash...\n");
		abort(); /* simulate app crash */
	case PMEM_TEST_ACTION_RESTORE:
		rc = test_restore();
		break;
	case PMEM_TEST_ACTION_GET_RELEASE:
		rc = test_get_release();
		break;
	default:
		SPDK_ERRLOG("Invalid action: %d\n", g_action);
		rmem_pool_test_usage();
		rc = -EINVAL;
		break;
	}

out:
	spdk_app_stop(rc);
}

int
main(int argc, char **argv)
{
	int			rc;
	struct spdk_app_opts	opts = {};

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "rmempooltest";
	opts.reactor_mask = "0x1";
	opts.shutdown_cb = spdk_rmem_pool_test_shutdown_cb;

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "a:", NULL,
				      rmem_pool_test_parse_arg, rmem_pool_test_usage)) !=
	    SPDK_APP_PARSE_ARGS_SUCCESS) {
		return rc;
	}

	rc = spdk_app_start(&opts, test_main, NULL);
	spdk_app_fini();

	return rc;
}
