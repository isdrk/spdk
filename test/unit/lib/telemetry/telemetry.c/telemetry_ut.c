/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk_internal/cunit.h"

#include "common/lib/ut_multithread.c"
#include "unit/lib/json_mock.c"

#include "telemetry/telemetry.c"

/* ── Mock exporter ──────────────────────────────────────────────────────── */

static struct {
	int  register_type_count;
	int  unregister_type_count;
	int  register_source_count;
	int  unregister_source_count;
	int  report_stats_count;
	bool start_called;
	bool stop_called;
	bool report_stats_rc; /* return value for report_stats */
} g_mock;

static struct spdk_telemetry_exporter g_mock_exporter;
static uint8_t g_mock_type_handle_sentinel;
static uint8_t g_mock_source_handle_sentinel;

static struct spdk_telemetry_type_handle *
ut_mock_register_type(void *ctx, const struct spdk_telemetry_type_info *type_info)
{
	g_mock.register_type_count++;
	return (struct spdk_telemetry_type_handle *)&g_mock_type_handle_sentinel;
}

static void
ut_mock_unregister_type(void *ctx, struct spdk_telemetry_type_handle *handle)
{
	g_mock.unregister_type_count++;
}

static struct spdk_telemetry_source_handle *
ut_mock_register_source(void *ctx, struct spdk_telemetry_type_handle *type_handle,
			const char *name)
{
	g_mock.register_source_count++;
	return (struct spdk_telemetry_source_handle *)&g_mock_source_handle_sentinel;
}

static void
ut_mock_unregister_source(void *ctx, struct spdk_telemetry_source_handle *handle)
{
	g_mock.unregister_source_count++;
}

static bool
ut_mock_report_stats(void *ctx, struct spdk_telemetry_source_handle *handle,
		     const void *stats_buffer, uint64_t stats_buffer_size)
{
	g_mock.report_stats_count++;
	return g_mock.report_stats_rc;
}

static int
ut_mock_start(void *ctx)
{
	g_mock.start_called = true;
	return 0;
}

static void
ut_mock_stop(void *ctx)
{
	g_mock.stop_called = true;
}

static int
ut_mock_destruct(void *ctx)
{
	return spdk_telemetry_exporter_unregister(&g_mock_exporter);
}

static const struct spdk_telemetry_exporter_fn_table g_mock_fn_table = {
	.destruct          = ut_mock_destruct,
	.register_type     = ut_mock_register_type,
	.unregister_type   = ut_mock_unregister_type,
	.register_source   = ut_mock_register_source,
	.unregister_source = ut_mock_unregister_source,
	.report_stats      = ut_mock_report_stats,
	.start             = ut_mock_start,
	.stop              = ut_mock_stop,
};

static struct spdk_telemetry_exporter_module g_mock_module = {
	.name = "mock",
};

static void
ut_reset_mock(void)
{
	memset(&g_mock, 0, sizeof(g_mock));
	g_mock.report_stats_rc = true;
	g_mock_exporter.ctxt      = &g_mock_exporter;
	g_mock_exporter.fn_table  = &g_mock_fn_table;
	g_mock_exporter.module    = &g_mock_module;
}

/* ── Test helpers ───────────────────────────────────────────────────────── */

/* Pull callback: used only for source registration (API requires non-NULL) */
static void
ut_pull_cb(void *cb_arg, struct spdk_telemetry_source *src)
{
}

/* Completion callback for start/stop */
static int g_done_rc;
static void
ut_done_cb(void *arg, int rc)
{
	g_done_rc = rc;
}

static int g_pull_count;
static void
ut_counting_pull_cb(void *cb_arg, struct spdk_telemetry_source *src)
{
	(*(int *)cb_arg)++;
}

/*
 * Directly reset global telemetry state. Bypasses the proper lifecycle so
 * that tests are isolated without requiring a full init/fini cycle each time.
 */
static void
ut_telemetry_cleanup(void)
{
	struct spdk_telemetry_type   *type, *type_next;
	struct spdk_telemetry_source *src,  *src_next;

	if (g_telemetry_mgr.started) {
		spdk_poller_unregister(&g_telemetry_mgr.poller);
		g_telemetry_mgr.started = false;
	}

	TAILQ_FOREACH_SAFE(type, &g_telemetry_mgr.types, link, type_next) {
		TAILQ_FOREACH_SAFE(src, &type->sources, link, src_next) {
			TAILQ_REMOVE(&type->sources, src, link);
			free(src->name);
			free(src);
		}
		TAILQ_REMOVE(&g_telemetry_mgr.types, type, link);
		free(type);
	}

	g_telemetry_mgr.exporter         = NULL;
	g_telemetry_mgr.stop_done_cb     = NULL;
	g_telemetry_mgr.stop_done_cb_arg = NULL;
	g_telemetry_mgr.fini_cb_fn       = NULL;
	g_telemetry_mgr.fini_cb_arg      = NULL;
	g_telemetry_mgr.initialized      = false;
}

static void
test_telemetry_buffer_size_int64(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_INT64("signed_counter", 1),
		SPDK_TELEMETRY_STAT_INFO_INT64("offset",         4),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "buf_size_int64",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(type != NULL);
	/* 1 + 4 fields × 8 bytes — same footprint as UINT64 */
	CU_ASSERT_EQUAL(type->stats_buffer_size, 5 * sizeof(uint64_t));

	ut_telemetry_cleanup();
}

static void
test_telemetry_buffer_size_double(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_DOUBLE64("utilization", 1),
		SPDK_TELEMETRY_STAT_INFO_DOUBLE64("latency_us",  3),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "buf_size_double",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(type != NULL);
	/* 1 + 3 fields × 8 bytes */
	CU_ASSERT_EQUAL(type->stats_buffer_size, 4 * sizeof(uint64_t));

	ut_telemetry_cleanup();
}

/* ── Tests ──────────────────────────────────────────────────────────────── */

static void
test_telemetry_stat_type_name(void)
{
	CU_ASSERT_STRING_EQUAL(spdk_telemetry_stat_type_name(SPDK_TELEMETRY_STAT_TYPE_UINT64),
			       "uint64_t");
	CU_ASSERT_STRING_EQUAL(spdk_telemetry_stat_type_name(SPDK_TELEMETRY_STAT_TYPE_INT64),
			       "int64_t");
	CU_ASSERT_STRING_EQUAL(spdk_telemetry_stat_type_name(SPDK_TELEMETRY_STAT_TYPE_DOUBLE64),
			       "double");
	CU_ASSERT_STRING_EQUAL(spdk_telemetry_stat_type_name(SPDK_TELEMETRY_STAT_TYPE_SUBTYPE),
			       "subtype");
	CU_ASSERT_STRING_EQUAL(spdk_telemetry_stat_type_name(__SPDK_TELEMETRY_STAT_TYPE_LAST),
			       "unknown");
}

static void
test_telemetry_buffer_size_simple_uint64(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("bytes_read",  1),
		SPDK_TELEMETRY_STAT_INFO_UINT64("bytes_write", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "buf_size_simple",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(type != NULL);
	CU_ASSERT_EQUAL(type->stats_buffer_size, 2 * sizeof(uint64_t));

	ut_telemetry_cleanup();
}

static void
test_telemetry_buffer_size_array(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("latency_histogram", 8),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "buf_size_array",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(type != NULL);
	CU_ASSERT_EQUAL(type->stats_buffer_size, 8 * sizeof(uint64_t));

	ut_telemetry_cleanup();
}

static void
test_telemetry_buffer_size_nested(void)
{
	static const struct spdk_telemetry_stat_info sub_stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("read",  1),
		SPDK_TELEMETRY_STAT_INFO_UINT64("write", 1),
	};
	static const struct spdk_telemetry_type_info sub_type_info = {
		.name      = "buf_size_nested_sub",
		.num_stats = SPDK_COUNTOF(sub_stats),
		.stats     = sub_stats,
	};
	static const struct spdk_telemetry_stat_info parent_stats[] = {
		SPDK_TELEMETRY_STAT_INFO_SUBTYPE("io", 1, "buf_size_nested_sub"),
	};
	static const struct spdk_telemetry_type_info parent_type_info = {
		.name      = "buf_size_nested_parent",
		.num_stats = SPDK_COUNTOF(parent_stats),
		.stats     = parent_stats,
	};
	struct spdk_telemetry_type *sub_type = NULL, *parent_type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&sub_type_info, &sub_type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(sub_type != NULL);
	CU_ASSERT_EQUAL(sub_type->stats_buffer_size, 2 * sizeof(uint64_t));

	rc = spdk_telemetry_register_type(&parent_type_info, &parent_type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(parent_type != NULL);
	/* sub_type has 2 uint64_t fields: parent_type buffer = 2 * sizeof(uint64_t) */
	CU_ASSERT_EQUAL(parent_type->stats_buffer_size, 2 * sizeof(uint64_t));

	ut_telemetry_cleanup();
}

static void
test_telemetry_buffer_size_nested_array(void)
{
	static const struct spdk_telemetry_stat_info sub_stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("ops", 1),
	};
	static const struct spdk_telemetry_type_info sub_type_info = {
		.name      = "buf_size_sub_arr",
		.num_stats = SPDK_COUNTOF(sub_stats),
		.stats     = sub_stats,
	};
	static const struct spdk_telemetry_stat_info parent_stats[] = {
		SPDK_TELEMETRY_STAT_INFO_SUBTYPE("queues", 4, "buf_size_sub_arr"),
	};
	static const struct spdk_telemetry_type_info parent_type_info = {
		.name      = "buf_size_parent_arr",
		.num_stats = SPDK_COUNTOF(parent_stats),
		.stats     = parent_stats,
	};
	struct spdk_telemetry_type *sub_type = NULL, *parent_type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&sub_type_info, &sub_type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(sub_type != NULL);
	CU_ASSERT_EQUAL(sub_type->stats_buffer_size, sizeof(uint64_t));

	rc = spdk_telemetry_register_type(&parent_type_info, &parent_type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(parent_type != NULL);
	/* 4 instances of sub_type (1 uint64_t each): 4 * sizeof(uint64_t) */
	CU_ASSERT_EQUAL(parent_type->stats_buffer_size, 4 * sizeof(uint64_t));

	ut_telemetry_cleanup();
}

static void
test_telemetry_register_type_invalid_zero_count(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		{ .name = "bad_stat", .type = SPDK_TELEMETRY_STAT_TYPE_UINT64, .count = 0 },
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "zero_count_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, -EINVAL);
	CU_ASSERT(type == NULL);
	CU_ASSERT(TAILQ_EMPTY(&g_telemetry_mgr.types));

	ut_telemetry_cleanup();
}

static void
test_telemetry_register_type_missing_subtype(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_SUBTYPE("nested", 1, "nonexistent_type"),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "missing_sub_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, -EINVAL);
	CU_ASSERT(type == NULL);
	CU_ASSERT(TAILQ_EMPTY(&g_telemetry_mgr.types));

	ut_telemetry_cleanup();
}

/*
 * Verify that registering an exporter after types/sources are already
 * registered propagates them to the exporter immediately.
 */
static void
test_telemetry_exporter_propagation(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("counter", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "propagation_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	static int pull_cb_arg = 0;
	struct spdk_telemetry_type   *type = NULL;
	struct spdk_telemetry_source *src  = NULL;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	/* No exporter yet: handle must be NULL */
	CU_ASSERT(type->handle == NULL);

	rc = spdk_telemetry_register_source(type, "src0", ut_pull_cb, &pull_cb_arg, &src);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT(src->handle == NULL);
	CU_ASSERT_EQUAL(g_mock.register_type_count,   0);
	CU_ASSERT_EQUAL(g_mock.register_source_count, 0);

	/* Registering the exporter must propagate the existing type and source */
	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(g_mock.register_type_count,   1);
	CU_ASSERT_EQUAL(g_mock.register_source_count, 1);
	CU_ASSERT(type->handle != NULL);
	CU_ASSERT(src->handle  != NULL);

	ut_telemetry_cleanup();
}

/*
 * Simulate the pull→complete→report path without involving the real poller:
 * manually set the source state to PULLING and call pull_complete.
 */
static void
test_telemetry_pull_complete_sync(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("value", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "pull_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	static int pull_cb_arg = 0;
	struct spdk_telemetry_type   *type = NULL;
	struct spdk_telemetry_source *src  = NULL;
	uint64_t *stats_buf;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_register_source(type, "pull_src", ut_pull_cb, &pull_cb_arg, &src);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	CU_ASSERT_EQUAL(src->state, TELEMETRY_SOURCE_IDLE);

	/* Simulate the poller setting state to PULLING */
	src->state = TELEMETRY_SOURCE_PULLING;

	stats_buf = spdk_telemetry_source_get_stats_buffer(src);
	SPDK_CU_ASSERT_FATAL(stats_buf != NULL);
	stats_buf[0] = 99;

	/* Complete the pull; report_stats must be called once */
	spdk_telemetry_source_pull_complete(src, 0);

	CU_ASSERT_EQUAL(g_mock.report_stats_count, 1);
	/* report_stats returned true → source is back to IDLE */
	CU_ASSERT_EQUAL(src->state, TELEMETRY_SOURCE_IDLE);

	ut_telemetry_cleanup();
}

/*
 * When pull_complete is called with a non-zero status, report_stats must
 * not be invoked and the source must return to IDLE.
 */
static void
test_telemetry_pull_complete_error(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("value", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "pull_err_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	static int pull_cb_arg = 0;
	struct spdk_telemetry_type   *type = NULL;
	struct spdk_telemetry_source *src  = NULL;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_register_source(type, "err_src", ut_pull_cb, &pull_cb_arg, &src);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	src->state = TELEMETRY_SOURCE_PULLING;

	spdk_telemetry_source_pull_complete(src, -EIO);

	CU_ASSERT_EQUAL(g_mock.report_stats_count, 0);
	CU_ASSERT_EQUAL(src->state, TELEMETRY_SOURCE_IDLE);

	ut_telemetry_cleanup();
}

/*
 * Verify that start invokes the exporter's start callback and stop invokes
 * the stop callback, and that the started flag transitions correctly.
 */
static void
test_telemetry_start_stop(void)
{
	static const struct spdk_telemetry_opts opts = { .interval_ms = 1000 };
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	g_done_rc = -1;
	spdk_telemetry_start(&opts, ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, 0);
	CU_ASSERT(g_telemetry_mgr.started);
	CU_ASSERT(g_mock.start_called);

	g_done_rc = -1;
	spdk_telemetry_stop(ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, 0);
	CU_ASSERT(!g_telemetry_mgr.started);
	CU_ASSERT(g_mock.stop_called);

	ut_telemetry_cleanup();
}

/* start without a registered exporter must fail with -EINVAL */
static void
test_telemetry_start_no_exporter(void)
{
	static const struct spdk_telemetry_opts opts = { .interval_ms = 1000 };

	spdk_telemetry_init();

	g_done_rc = 0;
	spdk_telemetry_start(&opts, ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, -EINVAL);
	CU_ASSERT(!g_telemetry_mgr.started);

	ut_telemetry_cleanup();
}

/*
 * When report_stats returns false (async), the source stays REPORTING until the
 * exporter releases it via spdk_telemetry_exporter_release_stats().
 */
static void
test_telemetry_pull_complete_async(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("value", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "pull_async_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	static int pull_cb_arg = 0;
	struct spdk_telemetry_type   *type = NULL;
	struct spdk_telemetry_source *src  = NULL;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();
	g_mock.report_stats_rc = false;

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_register_source(type, "async_src", ut_pull_cb, &pull_cb_arg, &src);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	src->state = TELEMETRY_SOURCE_PULLING;
	spdk_telemetry_source_pull_complete(src, 0);

	/* report_stats returned false → source stays REPORTING */
	CU_ASSERT_EQUAL(g_mock.report_stats_count, 1);
	CU_ASSERT_EQUAL(src->state, TELEMETRY_SOURCE_REPORTING);

	/* exporter releases stats asynchronously → source back to IDLE */
	spdk_telemetry_exporter_release_stats(src->handle, src->stats_buffer,
					      src->type->stats_buffer_size);
	CU_ASSERT_EQUAL(src->state, TELEMETRY_SOURCE_IDLE);

	ut_telemetry_cleanup();
}

/* Registering a second exporter while one is already active must fail. */
static void
test_telemetry_exporter_register_duplicate(void)
{
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, -EEXIST);

	ut_telemetry_cleanup();
}

/* Registering a new type while telemetry is running must fail with -EBUSY. */
static void
test_telemetry_register_type_while_started(void)
{
	static const struct spdk_telemetry_opts opts = { .interval_ms = 1000 };
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("counter", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "busy_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	spdk_telemetry_start(&opts, ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, 0);

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, -EBUSY);
	CU_ASSERT(type == NULL);

	ut_telemetry_cleanup();
}

/*
 * Verify all three error paths and the enable/disable toggle for
 * telemetry_type_enable().
 */
static void
test_telemetry_type_enable_disable(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("x", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "enable_test_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type *type = NULL;
	int rc;

	spdk_telemetry_init();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	SPDK_CU_ASSERT_FATAL(type != NULL);
	CU_ASSERT(!type->enabled);

	rc = telemetry_type_enable("enable_test_type", true);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT(type->enabled);

	/* Already enabled → -EALREADY */
	rc = telemetry_type_enable("enable_test_type", true);
	CU_ASSERT_EQUAL(rc, -EALREADY);

	rc = telemetry_type_enable("enable_test_type", false);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT(!type->enabled);

	/* Already disabled → -EALREADY */
	rc = telemetry_type_enable("enable_test_type", false);
	CU_ASSERT_EQUAL(rc, -EALREADY);

	/* Non-existent type → -ENOENT */
	rc = telemetry_type_enable("nonexistent_type", true);
	CU_ASSERT_EQUAL(rc, -ENOENT);

	/* Type marked for deletion → -EBUSY */
	type->to_delete = true;
	rc = telemetry_type_enable("enable_test_type", true);
	CU_ASSERT_EQUAL(rc, -EBUSY);

	ut_telemetry_cleanup();
}

/*
 * Calling telemetry_poll_type() on a disabled type must not invoke pull_cb.
 * After enabling, the next poll must call pull_cb.
 */
static void
test_telemetry_poller_skips_disabled_type(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("x", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "poll_skip_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	struct spdk_telemetry_type   *type = NULL;
	struct spdk_telemetry_source *src  = NULL;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();
	g_pull_count = 0;

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_register_source(type, "poll_src", ut_counting_pull_cb,
					    &g_pull_count, &src);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	/* Type disabled by default → poll must not invoke pull_cb */
	telemetry_poll_type(type);
	CU_ASSERT_EQUAL(g_pull_count, 0);
	CU_ASSERT_EQUAL(src->state, TELEMETRY_SOURCE_IDLE);

	/* Enable → next poll must call pull_cb */
	telemetry_type_enable("poll_skip_type", true);
	telemetry_poll_type(type);
	CU_ASSERT_EQUAL(g_pull_count, 1);
	CU_ASSERT_EQUAL(src->state, TELEMETRY_SOURCE_PULLING);

	ut_telemetry_cleanup();
}

static void
test_telemetry_exporter_unregister_reregister(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("x", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "exporter_unreg_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	static int pull_cb_arg;
	struct spdk_telemetry_type *type = NULL;
	struct spdk_telemetry_source *src = NULL;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_register_source(type, "exporter_unreg_src", ut_pull_cb,
					    &pull_cb_arg, &src);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_PTR_NOT_NULL(type->handle);
	CU_ASSERT_PTR_NOT_NULL(src->handle);

	rc = spdk_telemetry_exporter_unregister(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(g_mock.unregister_source_count, 1);
	CU_ASSERT_EQUAL(g_mock.unregister_type_count, 1);
	CU_ASSERT_PTR_NULL(type->handle);
	CU_ASSERT_PTR_NULL(src->handle);

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(g_mock.register_type_count, 2);
	CU_ASSERT_EQUAL(g_mock.register_source_count, 2);
	CU_ASSERT_PTR_NOT_NULL(type->handle);
	CU_ASSERT_PTR_NOT_NULL(src->handle);

	rc = spdk_telemetry_exporter_unregister(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);
	CU_ASSERT_EQUAL(g_mock.unregister_source_count, 2);
	CU_ASSERT_EQUAL(g_mock.unregister_type_count, 2);
	CU_ASSERT_PTR_NULL(type->handle);
	CU_ASSERT_PTR_NULL(src->handle);

	ut_telemetry_cleanup();
}

/*
 * spdk_telemetry_unregister_type() marks the type and its sources for deletion.
 * The next telemetry_poll_type() invocation must delete them and invoke the
 * exporter's unregister callbacks.
 */
static void
test_telemetry_unregister_type_source(void)
{
	static const struct spdk_telemetry_stat_info stats[] = {
		SPDK_TELEMETRY_STAT_INFO_UINT64("x", 1),
	};
	static const struct spdk_telemetry_type_info type_info = {
		.name      = "unreg_type",
		.num_stats = SPDK_COUNTOF(stats),
		.stats     = stats,
	};
	static int pull_cb_arg = 0;
	struct spdk_telemetry_type   *type = NULL;
	struct spdk_telemetry_source *src  = NULL;
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_register_type(&type_info, &type);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_register_source(type, "unreg_src", ut_pull_cb, &pull_cb_arg, &src);
	CU_ASSERT_EQUAL(rc, 0);
	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	spdk_telemetry_unregister_type(type);
	CU_ASSERT(type->to_delete);
	CU_ASSERT(src->to_delete);

	/* Poll must delete source and type, invoking unregister callbacks */
	telemetry_poll_type(type);
	CU_ASSERT_EQUAL(g_mock.unregister_source_count, 1);
	CU_ASSERT_EQUAL(g_mock.unregister_type_count,   1);
	CU_ASSERT(TAILQ_EMPTY(&g_telemetry_mgr.types));

	ut_telemetry_cleanup();
}

/*
 * Full spdk_telemetry_fini() lifecycle when telemetry is not started:
 * destruct must be called, the done callback invoked with rc=0, and
 * initialized cleared.
 */
static void
test_telemetry_fini(void)
{
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	g_done_rc = -1;
	spdk_telemetry_fini(ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, 0);
	CU_ASSERT(!g_telemetry_mgr.initialized);
	CU_ASSERT(g_telemetry_mgr.exporter == NULL);
}

/* Calling start when telemetry is already running must return -EALREADY. */
static void
test_telemetry_start_already_started(void)
{
	static const struct spdk_telemetry_opts opts = { .interval_ms = 1000 };
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	g_done_rc = -1;
	spdk_telemetry_start(&opts, ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, 0);
	CU_ASSERT(g_telemetry_mgr.started);

	g_done_rc = -1;
	spdk_telemetry_start(&opts, ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, -EALREADY);
	CU_ASSERT(g_telemetry_mgr.started);

	ut_telemetry_cleanup();
}

/* Calling stop when telemetry has not been started must return -EINVAL. */
static void
test_telemetry_stop_not_started(void)
{
	int rc;

	spdk_telemetry_init();
	ut_reset_mock();

	rc = spdk_telemetry_exporter_register(&g_mock_exporter);
	CU_ASSERT_EQUAL(rc, 0);

	g_done_rc = 0;
	spdk_telemetry_stop(ut_done_cb, NULL);
	CU_ASSERT_EQUAL(g_done_rc, -EINVAL);
	CU_ASSERT(!g_telemetry_mgr.started);

	ut_telemetry_cleanup();
}

/* ── main ───────────────────────────────────────────────────────────────── */

int
main(int argc, char **argv)
{
	CU_pSuite    suite = NULL;
	unsigned int num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("telemetry", NULL, NULL);

	CU_ADD_TEST(suite, test_telemetry_stat_type_name);
	CU_ADD_TEST(suite, test_telemetry_buffer_size_simple_uint64);
	CU_ADD_TEST(suite, test_telemetry_buffer_size_int64);
	CU_ADD_TEST(suite, test_telemetry_buffer_size_double);
	CU_ADD_TEST(suite, test_telemetry_buffer_size_array);
	CU_ADD_TEST(suite, test_telemetry_buffer_size_nested);
	CU_ADD_TEST(suite, test_telemetry_buffer_size_nested_array);
	CU_ADD_TEST(suite, test_telemetry_register_type_invalid_zero_count);
	CU_ADD_TEST(suite, test_telemetry_register_type_missing_subtype);
	CU_ADD_TEST(suite, test_telemetry_exporter_propagation);
	CU_ADD_TEST(suite, test_telemetry_pull_complete_sync);
	CU_ADD_TEST(suite, test_telemetry_pull_complete_error);
	CU_ADD_TEST(suite, test_telemetry_pull_complete_async);
	CU_ADD_TEST(suite, test_telemetry_start_stop);
	CU_ADD_TEST(suite, test_telemetry_start_no_exporter);
	CU_ADD_TEST(suite, test_telemetry_start_already_started);
	CU_ADD_TEST(suite, test_telemetry_stop_not_started);
	CU_ADD_TEST(suite, test_telemetry_exporter_register_duplicate);
	CU_ADD_TEST(suite, test_telemetry_register_type_while_started);
	CU_ADD_TEST(suite, test_telemetry_type_enable_disable);
	CU_ADD_TEST(suite, test_telemetry_poller_skips_disabled_type);
	CU_ADD_TEST(suite, test_telemetry_exporter_unregister_reregister);
	CU_ADD_TEST(suite, test_telemetry_unregister_type_source);
	CU_ADD_TEST(suite, test_telemetry_fini);

	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	free_threads();

	CU_cleanup_registry();
	return num_failures;
}
