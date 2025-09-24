/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk_internal/cunit.h"
#include "spdk/thread.h"
#include "spdk/bdev_module.h"
#include "spdk_internal/bdev_qos_module.h"

#include "common/lib/ut_multithread.c"

#include "bdev_qos/hybrid/hybrid.c"

struct spdk_bdev_qos_desc {
	struct spdk_bdev_qos *qos;
};

DEFINE_STUB_V(spdk_bdev_qos_module_list_add, (struct spdk_bdev_qos_module *qos_module));

DEFINE_STUB(spdk_bdev_qos_module_list_find, struct spdk_bdev_qos_module *, (const char *name),
	    &hybrid_if);

DEFINE_STUB_V(spdk_bdev_qos_module_fini_done, (void));

uint32_t
spdk_bdev_io_get_block_size(struct spdk_bdev_io *bdev_io)
{
	return bdev_io->bdev->blocklen;
}

static void
bdev_io_complete(struct spdk_bdev_io *bdev_io, enum spdk_bdev_io_status status)
{
	bdev_io->internal.status = status;
	bdev_io->internal.cb(bdev_io, bdev_io->internal.status == SPDK_BDEV_IO_STATUS_SUCCESS,
			     bdev_io->internal.caller_ctx);
}

static void
bdev_io_init(struct spdk_bdev_io *bdev_io, struct spdk_bdev *bdev,
	     enum spdk_bdev_io_type io_type, uint32_t num_blocks,
	     void *cb_arg, spdk_bdev_io_completion_cb cb)
{
	bdev_io->bdev = bdev;
	bdev_io->type = io_type;
	bdev_io->u.bdev.num_blocks = num_blocks;
	bdev_io->internal.caller_ctx = cb_arg;
	bdev_io->internal.cb = cb;
	bdev_io->internal.status = SPDK_BDEV_IO_STATUS_PENDING;
}

bool
spdk_bdev_abort_queued_io(bdev_io_tailq_t *queue, struct spdk_bdev_io *bio_to_abort)
{
	struct spdk_bdev_io *bdev_io;

	TAILQ_FOREACH(bdev_io, queue, internal.link) {
		if (bdev_io == bio_to_abort) {
			TAILQ_REMOVE(queue, bio_to_abort, internal.link);
			bdev_io_complete(bio_to_abort, SPDK_BDEV_IO_STATUS_ABORTED);
			return true;
		}
	}

	return false;
}
void
spdk_bdev_abort_all_queued_io(bdev_io_tailq_t *queue, struct spdk_bdev_channel *bdev_ch)
{
	struct spdk_bdev_io *bdev_io, *tmp;

	TAILQ_FOREACH_SAFE(bdev_io, queue, internal.link, tmp) {
		TAILQ_REMOVE(queue, bdev_io, internal.link);
		bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_ABORTED);
	}
}

void
spdk_bdev_unblock_all_queued_io(bdev_io_tailq_t *queue, struct spdk_bdev_channel *bdev_ch)
{
	struct spdk_bdev_io *bdev_io;

	while (!TAILQ_EMPTY(queue)) {
		/* Re-submit the queued I/O. */
		bdev_io = TAILQ_FIRST(queue);
		TAILQ_REMOVE(queue, bdev_io, internal.link);
		bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	}
}

void
spdk_bdev_qos_module_allow_io(struct spdk_bdev_io *bdev_io)
{
	bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
}

struct spdk_bdev_qos_impl *
spdk_bdev_qos_find_impl(struct spdk_bdev_qos *qos, const struct spdk_bdev_qos_module *module)
{
	struct spdk_bdev_qos_impl *qos_impl;

	TAILQ_FOREACH(qos_impl, &qos->impl_list, link) {
		if (qos_impl->module == module) {
			return qos_impl;
		}
	}

	return NULL;
}

struct spdk_bdev_qos_channel_impl *
spdk_bdev_qos_channel_find_impl(struct spdk_bdev_qos_channel *qos_ch,
				const struct spdk_bdev_qos_module *module)
{
	struct spdk_bdev_qos_channel_impl *qos_ch_impl;

	TAILQ_FOREACH(qos_ch_impl, &qos_ch->impl_list, link) {
		if (qos_ch_impl->qos_impl->module == module) {
			return qos_ch_impl;
		}
	}

	return NULL;
}

static void
io_during_io_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	enum spdk_bdev_io_status *status = cb_arg;

	*status = bdev_io->internal.status;
}

static int
bdev_qos_channel_create(void *io_device, void *ctx_buf)
{
	struct spdk_bdev_qos *qos = io_device;
	struct spdk_bdev_qos_channel *qos_ch = ctx_buf;
	struct spdk_bdev_qos_impl *qos_impl;
	struct spdk_bdev_qos_channel_impl *qos_ch_impl;

	TAILQ_INIT(&qos_ch->impl_list);
	qos_ch->qos = qos;

	qos_impl = TAILQ_FIRST(&qos->impl_list);
	SPDK_CU_ASSERT_FATAL(qos_impl != NULL);

	qos_ch_impl = bdev_hybrid_qos_channel_get(qos_impl);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl != NULL);

	qos_ch_impl->qos_ch = qos_ch;

	TAILQ_INSERT_TAIL(&qos_ch->impl_list, qos_ch_impl, link);

	return 0;
}

static void
bdev_qos_channel_destroy(void *io_device, void *ctx_buf)
{
	struct spdk_bdev_qos_channel *qos_ch = ctx_buf;
	struct spdk_bdev_qos_channel_impl *qos_ch_impl;

	qos_ch_impl = TAILQ_FIRST(&qos_ch->impl_list);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl != NULL);

	TAILQ_REMOVE(&qos_ch->impl_list, qos_ch_impl, link);

	bdev_hybrid_qos_channel_put(qos_ch_impl);
}

static struct spdk_bdev_qos *
bdev_qos_create(const char *name)
{
	struct spdk_bdev_qos *qos;
	struct spdk_bdev_qos_impl *qos_impl;

	qos = calloc(1, sizeof(*qos));
	SPDK_CU_ASSERT_FATAL(qos != NULL);

	qos->name = strdup(name);
	SPDK_CU_ASSERT_FATAL(qos->name != NULL);

	TAILQ_INIT(&qos->impl_list);

	qos_impl = bdev_hybrid_qos_get();
	SPDK_CU_ASSERT_FATAL(qos_impl != NULL);

	qos_impl->qos = qos;
	TAILQ_INSERT_TAIL(&qos->impl_list, qos_impl, link);

	qos_impl->module = &hybrid_if;

	spdk_io_device_register(qos,
				bdev_qos_channel_create,
				bdev_qos_channel_destroy,
				sizeof(struct spdk_bdev_qos_channel),
				qos->name);

	return qos;
}

int
spdk_bdev_qos_create(const char *name, struct spdk_bdev_qos *parent,
		     const char **modules, int num_modules,
		     struct spdk_bdev_qos **_qos, struct spdk_bdev_qos_desc **_desc)
{
	struct spdk_bdev_qos *qos;
	struct spdk_bdev_qos_desc *desc;

	qos = bdev_qos_create(name);

	if (_qos != NULL) {
		*_qos = qos;
	}
	if (_desc != NULL) {
		desc = calloc(1, sizeof(*desc));
		SPDK_CU_ASSERT_FATAL(desc != NULL);

		desc->qos = qos;

		*_desc = desc;
	}

	return 0;
}

int
spdk_bdev_qos_destroy(struct spdk_bdev_qos *qos)
{
	struct spdk_bdev_qos_impl *qos_impl;

	qos_impl = TAILQ_FIRST(&qos->impl_list);
	SPDK_CU_ASSERT_FATAL(qos_impl != NULL);

	TAILQ_REMOVE(&qos->impl_list, qos_impl, link);

	bdev_hybrid_qos_put(qos_impl);

	spdk_io_device_unregister(qos, NULL);

	free(qos->name);
	free(qos);

	return 0;
}

static struct spdk_bdev_qos *
bdev_qos_get_by_name(const char *name)
{
	struct spdk_bdev_hybrid_qos *hqos;

	TAILQ_FOREACH(hqos, &g_qos_mgr.hqos_list, link) {
		if (strcmp(hqos->base.qos->name, name) == 0) {
			return hqos->base.qos;
		}
	}

	return NULL;
}

int
spdk_bdev_qos_open(const char *name, struct spdk_bdev_qos_desc **_desc)
{
	struct spdk_bdev_qos *qos;
	struct spdk_bdev_qos_desc *desc;

	qos = bdev_qos_get_by_name(name);
	if (qos == NULL) {
		return -ENODEV;
	}

	desc = calloc(1, sizeof(*desc));
	SPDK_CU_ASSERT_FATAL(desc != NULL);

	desc->qos = qos;

	*_desc = desc;

	return 0;
}

void
spdk_bdev_qos_close(struct spdk_bdev_qos_desc *desc)
{
	free(desc);
}

struct spdk_bdev_qos *
spdk_bdev_qos_desc_get_qos(struct spdk_bdev_qos_desc *desc)
{
	return desc->qos;
}

static void
bdev_qos_channel_impl_queue_io(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
			       struct spdk_bdev_io *bdev_io)
{
	bdev_io->internal.blocked_qos_ch_impl = qos_ch_impl;

	qos_ch_impl->qos_impl->module->queue_io(qos_ch_impl, bdev_io);
}

static void
qos_dynamic_enable_done(void *cb_arg, int status)
{
	int *rc = cb_arg;

	*rc = status;
}

static void
basic_qos(void)
{
	struct spdk_bdev_io bdev_io;
	struct spdk_bdev bdev;
	struct spdk_io_channel *io_ch[2];
	struct spdk_bdev_qos_channel *qos_ch[2];
	struct spdk_bdev_qos_channel_impl *qos_ch_impl[2];
	struct spdk_bdev_qos *qos = NULL;
	uint64_t limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES] = {};
	enum spdk_bdev_io_status status;
	int rc;

	g_qos_opts.timeslice_us = SPDK_BDEV_QOS_TIMESLICE_IN_USEC;
	g_qos_opts.io_slice = 1;
	g_qos_opts.byte_slice = 512;
	bdev_qos_hybrid_library_init();

	rc = spdk_bdev_qos_create("ut_qos", NULL, NULL, 0, &qos, NULL);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	SPDK_CU_ASSERT_FATAL(qos != NULL);

	/*
	 * Enable read/write IOPS, read only byte per second and
	 * read/write byte per second rate limits.
	 * In this case, all rate limits will take equal effect.
	 */
	/* 2000 read/write I/O per second, or 2 per millisecond */
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 2000;
	/* 8Mb read/write per second with 4K block size */
	limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT] = 8;
	/* 8Mb read only per second with 4K block size */
	limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT] = 8;

	rc = -1;
	bdev_hybrid_qos_set_rate_limits("ut_qos", limits, qos_dynamic_enable_done, &rc);
	poll_threads();
	CU_ASSERT(rc == 0);

	set_thread(0);

	io_ch[0] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[0] != NULL);
	qos_ch[0] = spdk_io_channel_get_ctx(io_ch[0]);

	qos_ch_impl[0] = spdk_bdev_qos_channel_find_impl(qos_ch[0], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[0] != NULL);

	set_thread(1);

	io_ch[1] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[1] != NULL);
	qos_ch[1] = spdk_io_channel_get_ctx(io_ch[1]);

	qos_ch_impl[1] = spdk_bdev_qos_channel_find_impl(qos_ch[1], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[1] != NULL);

	bdev.blocklen = 4096;

	/* Send an I/O on thread 0. */
	status = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io, &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[0], &bdev_io);
	CU_ASSERT(status == SPDK_BDEV_IO_STATUS_SUCCESS);

	/* Send an I/O on thread 1. */
	status = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io, &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[1], &bdev_io);
	CU_ASSERT(status == SPDK_BDEV_IO_STATUS_SUCCESS);

	/* Test abort when QoS is enabled. */

	status = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io, &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[0], &bdev_io);
	CU_ASSERT(status == SPDK_BDEV_IO_STATUS_PENDING);

	/* Simulate reset by executing abort_all_queued_io(). */
	bdev_hybrid_qos_channel_abort_all_queued_io(qos_ch_impl[0], NULL);

	CU_ASSERT(status == SPDK_BDEV_IO_STATUS_ABORTED);

	/* Tear down the channels */
	set_thread(0);
	spdk_put_io_channel(io_ch[0]);
	set_thread(1);
	spdk_put_io_channel(io_ch[1]);
	poll_threads();
	set_thread(0);

	spdk_bdev_qos_destroy(qos);

	poll_threads();

	bdev_qos_hybrid_library_fini();
	poll_threads();
}

static void
io_during_qos_queue(void)
{
	struct spdk_bdev_io bdev_io, bdev_io2, bdev_io3;
	struct spdk_bdev bdev;
	struct spdk_bdev_qos *qos = NULL;
	struct spdk_io_channel *io_ch[2];
	struct spdk_bdev_qos_channel *qos_ch[2];
	struct spdk_bdev_qos_channel_impl *qos_ch_impl[2];
	uint64_t limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES] = {};
	enum spdk_bdev_io_status status, status2, status3;
	int rc;

	set_thread(0);

	g_qos_opts.timeslice_us = 976;
	g_qos_opts.io_slice = 1;
	g_qos_opts.byte_slice = 512;
	bdev_qos_hybrid_library_init();

	rc = spdk_bdev_qos_create("ut_qos", NULL, NULL, 0, &qos, NULL);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	SPDK_CU_ASSERT_FATAL(qos != NULL);

	/*
	 * Enable read/write IOPS, read only byte per sec, write only
	 * byte per sec and read/write byte per sec rate limits.
	 * In this case, both read only and write only byte per sec
	 * rate limit will take effect.
	 */
	/* 4000 read/write I/O per second, or 4 per millisecond */
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 4000;
	/* 8Mb byte per second */
	limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT] = 8;
	/* 4Mb byte per second */
	limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT] = 4;
	/* 4Mb byte per second */
	limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT] = 4;

	bdev_hybrid_qos_set_rate_limits("ut_qos", limits, qos_dynamic_enable_done, &rc);
	poll_threads();
	CU_ASSERT(rc == 0);

	set_thread(0);

	io_ch[0] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[0] != NULL);
	qos_ch[0] = spdk_io_channel_get_ctx(io_ch[0]);

	qos_ch_impl[0] = spdk_bdev_qos_channel_find_impl(qos_ch[0], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[0] != NULL);

	set_thread(1);

	io_ch[1] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[1] != NULL);
	qos_ch[1] = spdk_io_channel_get_ctx(io_ch[1]);

	qos_ch_impl[1] = spdk_bdev_qos_channel_find_impl(qos_ch[1], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[1] != NULL);

	bdev.blocklen = 4096;

	/* Send two read I/Os and one write I/O.
	 * Then, only one of two read I/Os and one write I/O should complete. */

	status = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io, &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[1], &bdev_io);
	CU_ASSERT(status == SPDK_BDEV_IO_STATUS_SUCCESS);

	status2 = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io2, &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status2, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[0], &bdev_io2);
	CU_ASSERT(status2 == SPDK_BDEV_IO_STATUS_PENDING);

	status3 = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io3, &bdev, SPDK_BDEV_IO_TYPE_WRITE, 1, &status3, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[0], &bdev_io3);
	CU_ASSERT(status3 == SPDK_BDEV_IO_STATUS_SUCCESS);

	/* Advance one timeslice */
	spdk_delay_us(1000);

	poll_threads();
	poll_threads();

	CU_ASSERT(status2 == SPDK_BDEV_IO_STATUS_SUCCESS);

	/* Tear down the channels */
	set_thread(0);
	spdk_put_io_channel(io_ch[0]);
	set_thread(1);
	spdk_put_io_channel(io_ch[1]);

	poll_threads();

	set_thread(0);

	spdk_bdev_qos_destroy(qos);

	poll_threads();

	bdev_qos_hybrid_library_fini();
	poll_threads();
}

static void
io_during_qos_reset(void)
{
	struct spdk_bdev_io bdev_io, bdev_io2;
	struct spdk_bdev bdev;
	struct spdk_bdev_qos *qos;
	struct spdk_io_channel *io_ch[2];
	struct spdk_bdev_qos_channel *qos_ch[2];
	struct spdk_bdev_qos_channel_impl *qos_ch_impl[2];
	uint64_t limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES] = {};
	enum spdk_bdev_io_status status, status2;
	int rc;

	set_thread(0);

	g_qos_opts.timeslice_us = 976;
	g_qos_opts.io_slice = 1;
	g_qos_opts.byte_slice = 512;
	bdev_qos_hybrid_library_init();

	rc = spdk_bdev_qos_create("ut_qos", NULL, NULL, 0, &qos, NULL);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	SPDK_CU_ASSERT_FATAL(qos != NULL);

	/*
	 * Enable read/write IOPS, write only byte per sec and
	 * read/write byte per second rate limits.
	 * In this case, read/write byte per second rate limit will
	 * take effect first.
	 */
	/* 2000 read/write I/O per second, or 2 per millisecond */
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 2000;
	/* 4Mb per second with 4K block size */
	limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT] = 4;
	/* 8Mb per second with 4K block size */
	limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT] = 8;

	rc = -1;
	bdev_hybrid_qos_set_rate_limits("ut_qos", limits, qos_dynamic_enable_done, &rc);
	poll_threads();
	CU_ASSERT(rc == 0);

	set_thread(0);

	io_ch[0] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[0] != NULL);
	qos_ch[0] = spdk_io_channel_get_ctx(io_ch[0]);

	qos_ch_impl[0] = spdk_bdev_qos_channel_find_impl(qos_ch[0], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[0] != NULL);

	set_thread(1);

	io_ch[1] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[1] != NULL);
	qos_ch[1] = spdk_io_channel_get_ctx(io_ch[1]);

	qos_ch_impl[1] = spdk_bdev_qos_channel_find_impl(qos_ch[1], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[1] != NULL);

	bdev.blocklen = 4096;

	/* Send two read I/Os. The second I/O gets queued by QoS. */

	status = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io, &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[0], &bdev_io);
	CU_ASSERT(status == SPDK_BDEV_IO_STATUS_SUCCESS);

	status2 = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io2, &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status2, io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[1], &bdev_io2);
	CU_ASSERT(status2 == SPDK_BDEV_IO_STATUS_PENDING);

	/* Simulate reset by executing abort_all_queued_io(). */
	bdev_hybrid_qos_channel_abort_all_queued_io(qos_ch_impl[0], NULL);
	bdev_hybrid_qos_channel_abort_all_queued_io(qos_ch_impl[0], NULL);

	CU_ASSERT(status2 == SPDK_BDEV_IO_STATUS_ABORTED);

	/* Tear down the channels */
	set_thread(0);
	spdk_put_io_channel(io_ch[0]);
	set_thread(1);
	spdk_put_io_channel(io_ch[1]);

	poll_threads();

	set_thread(0);

	spdk_bdev_qos_destroy(qos);

	poll_threads();

	bdev_qos_hybrid_library_fini();
	poll_threads();
}

static bool
bdev_qos_limit_cache_is_disabled(struct bdev_qos_limit_cache *cache)
{
	return cache->remaining == INT64_MAX;
}

static bool
bdev_qos_limits_cache_is_disabled(struct bdev_qos_limits_cache *caches)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (!bdev_qos_limit_cache_is_disabled(&caches->rate_limits[i])) {
			return false;
		}
	}

	return true;
}

static bool
bdev_hybrid_qos_channel_is_disabled(struct spdk_bdev_qos_channel_impl *qos_ch_impl)
{
	struct spdk_bdev_hybrid_qos_channel *hqos_ch = bdev_hybrid_qos_channel(qos_ch_impl);

	return bdev_qos_limits_cache_is_disabled(&hqos_ch->limits);
}

static void
qos_dynamic_enable(void)
{
	struct spdk_bdev_io bdev_io[2];
	struct spdk_bdev bdev;
	struct spdk_bdev_qos *qos;
	struct spdk_bdev_qos_impl *qos_impl;
	struct spdk_io_channel *io_ch[2];
	struct spdk_bdev_qos_channel *qos_ch[2];
	struct spdk_bdev_qos_channel_impl *qos_ch_impl[2];
	uint64_t limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES] = {};
	enum spdk_bdev_io_status status[2];
	int i, rc;

	set_thread(0);

	g_qos_opts.timeslice_us = SPDK_BDEV_QOS_TIMESLICE_IN_USEC;
	g_qos_opts.io_slice = 1;
	g_qos_opts.byte_slice = 512;
	bdev_qos_hybrid_library_init();

	rc = spdk_bdev_qos_create("ut_qos", NULL, NULL, 0, &qos, NULL);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	SPDK_CU_ASSERT_FATAL(qos != NULL);

	/*
	 * Enable QoS: Read/Write IOPS, Read/Write byte,
	 * Read only byte and Write only byte per second
	 * rate limits.
	 * More than 10 I/Os allowed per timeslice.
	 */
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 10000;
	limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT] = 100;
	limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT] = 100;
	limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT] = 10;

	rc = -1;
	bdev_hybrid_qos_set_rate_limits("ut_qos", limits, qos_dynamic_enable_done, &rc);
	poll_threads();
	CU_ASSERT(rc == 0);

	set_thread(0);

	io_ch[0] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[0] != NULL);
	qos_ch[0] = spdk_io_channel_get_ctx(io_ch[0]);

	qos_ch_impl[0] = spdk_bdev_qos_channel_find_impl(qos_ch[0], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[0] != NULL);

	set_thread(1);

	io_ch[1] = spdk_get_io_channel(qos);
	SPDK_CU_ASSERT_FATAL(io_ch[1] != NULL);
	qos_ch[1] = spdk_io_channel_get_ctx(io_ch[1]);

	qos_ch_impl[1] = spdk_bdev_qos_channel_find_impl(qos_ch[1], &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_ch_impl[1] != NULL);

	bdev.blocklen = 4096;

	for (i = 0; i < 10; i++) {
		status[0] = SPDK_BDEV_IO_STATUS_PENDING;
		bdev_io_init(&bdev_io[0], &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status[0], io_during_io_done);

		bdev_qos_channel_impl_queue_io(qos_ch_impl[0], &bdev_io[0]);
		CU_ASSERT(status[0] == SPDK_BDEV_IO_STATUS_SUCCESS);
	}

	/*
	 * Send two more I/O.  These I/O will be queued since the current timeslice allotment has been
	 * filled already.  We want to test that when QoS is disabled that these two I/O:
	 *  1) are not aborted
	 *  2) are sent back to their original thread for resubmission
	 */
	status[0] = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io[0], &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status[0], io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[0], &bdev_io[0]);
	CU_ASSERT(status[0] == SPDK_BDEV_IO_STATUS_PENDING);

	status[1] = SPDK_BDEV_IO_STATUS_PENDING;
	bdev_io_init(&bdev_io[1], &bdev, SPDK_BDEV_IO_TYPE_READ, 1, &status[1], io_during_io_done);

	bdev_qos_channel_impl_queue_io(qos_ch_impl[1], &bdev_io[1]);
	CU_ASSERT(status[1] == SPDK_BDEV_IO_STATUS_PENDING);

	set_thread(0);

	/*
	 * Disable QoS: Read/Write IOPS, Read/Write byte,
	 * Read only byte rate limits
	 */
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT] = 10;

	rc = -1;
	bdev_hybrid_qos_set_rate_limits("ut_qos", limits, qos_dynamic_enable_done, &rc);
	poll_threads();
	CU_ASSERT(rc == 0);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[0]) == false);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[1]) == false);

	/* Disable QoS: Write only Byte per second rate limit */
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT] = 0;

	rc = -1;
	bdev_hybrid_qos_set_rate_limits("ut_qos", limits, qos_dynamic_enable_done, &rc);
	poll_threads();
	CU_ASSERT(rc == 0);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[0]) == true);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[1]) == true);

	spdk_delay_us(1000);

	poll_threads();

	/* Now all pending I/Os should be completed. */
	CU_ASSERT(status[0] == SPDK_BDEV_IO_STATUS_SUCCESS);
	CU_ASSERT(status[1] == SPDK_BDEV_IO_STATUS_SUCCESS);

	/* Enable QoS */
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT] = 0;
	limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT] = 10000;

	rc = -1;
	bdev_hybrid_qos_set_rate_limits("ut_qos", limits, qos_dynamic_enable_done, &rc);
	/* Don't poll yet. This should leave the channels with QoS disabled.
	 * But configuration should be updated. */
	CU_ASSERT(rc == -1);

	qos_impl = spdk_bdev_qos_find_impl(qos, &hybrid_if);
	SPDK_CU_ASSERT_FATAL(qos_impl != NULL);

	CU_ASSERT(_bdev_hybrid_qos_check_disabled(qos_impl) == false);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[0]) == true);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[1]) == true);

	/* Poll now. */
	poll_threads();
	CU_ASSERT(rc == 0);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[0]) == false);
	CU_ASSERT(bdev_hybrid_qos_channel_is_disabled(qos_ch_impl[1]) == false);

	/* Tear down the channels */
	set_thread(0);
	spdk_put_io_channel(io_ch[0]);
	set_thread(1);
	spdk_put_io_channel(io_ch[1]);
	poll_threads();
	set_thread(0);

	spdk_bdev_qos_destroy(qos);

	poll_threads();

	bdev_qos_hybrid_library_fini();
	poll_threads();
}

int
main(int argc, char **argv)
{
	CU_pSuite	suite = NULL;
	unsigned int	num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("bdev_hybrid_qos", NULL, NULL);

	CU_ADD_TEST(suite, basic_qos);
	CU_ADD_TEST(suite, io_during_qos_queue);
	CU_ADD_TEST(suite, io_during_qos_reset);
	CU_ADD_TEST(suite, qos_dynamic_enable);

	allocate_threads(3);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	set_thread(0);
	free_threads();

	CU_cleanup_registry();
	return num_failures;
}
