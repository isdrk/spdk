/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2016 Intel Corporation. All rights reserved.
 *   Copyright (c) 2019 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights
 * reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/log.h"
#include "spdk/util.h"
#include "spdk/bdev_module.h"

#include "spdk_internal/bdev.h"
#include "spdk_internal/bdev_qos_module.h"

#include "hybrid.h"

#define SPDK_BDEV_QOS_LIMIT_NOT_DEFINED		UINT64_MAX
#define SPDK_BDEV_QOS_TIMESLICE_IN_USEC		1000
#define SPDK_BDEV_QOS_MIN_IO_PER_TIMESLICE	1
#define SPDK_BDEV_QOS_MIN_BYTE_PER_TIMESLICE	512
#define SPDK_BDEV_QOS_MIN_IOS_PER_SEC		1000
#define SPDK_BDEV_QOS_MIN_BYTES_PER_SEC		(1024 * 1024)
#define SPDK_BDEV_QOS_IO_SLICE			1
#define SPDK_BDEV_QOS_BYTE_SLICE		512
#define SPDK_BDEV_QOS_TIMESLICE_IN_USEC		1000

/** bdev QoS rate limit type */
enum spdk_bdev_qos_rate_limit_type {
	/** IOPS rate limit for both read and write */
	SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT = 0,
	/** Byte per second rate limit for both read and write */
	SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT,
	/** Byte per second rate limit for read only */
	SPDK_BDEV_QOS_R_BPS_RATE_LIMIT,
	/** Byte per second rate limit for write only */
	SPDK_BDEV_QOS_W_BPS_RATE_LIMIT,
	/** Keep last */
	SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES
};

struct spdk_bdev_hybrid_qos;

struct spdk_bdev_hybrid_qos_mgr {
	uint64_t last_timeslice;

	uint64_t timeslice_size;

	struct spdk_poller *poller;

	TAILQ_HEAD(, spdk_bdev_hybrid_qos) hqos_list;
};

struct bdev_qos_limit {
	/** IOs or bytes allowed per second (i.e., 1s). */
	uint64_t limit;

	/** Remaining IOs or bytes allowed in current timeslice (e.g., 1ms).
	 *  For remaining bytes, allowed to run negative if an I/O is submitted when
	 *  some bytes are remaining, but the I/O is bigger than that amount. The
	 *  excess will be deducted from the next timeslice.
	 */
	volatile int64_t remaining_this_timeslice;

	/** Minimum allowed IOs or bytes to be issued in one timeslice (e.g., 1ms). */
	uint32_t min_per_timeslice;

	/** Maximum allowed IOs or bytes to be issued in one timeslice (e.g., 1ms). */
	uint32_t max_per_timeslice;

	/** Slice of IOs or bytes allocated from the global pool. */
	uint32_t slice_per_borrow;

	/** Function to check whether to queue the IO.
	 * If The IO is allowed to pass, the quota will be reduced correspondingly.
	 */
	bool (*queue_io)(struct bdev_qos_limit *limit, struct spdk_bdev_io *io);

	/** Function to rewind the quota once the IO was allowed to be sent by this
	 * limit but queued due to one of the further limits.
	 */
	void (*rewind_quota)(struct bdev_qos_limit *limit, struct spdk_bdev_io *io);

};

struct bdev_qos_limit_cache {
	/** Remaining IOs or bytes allocated from the global pool in the current
	 *  timeslice. If fully consumed, allocate another slice from the global
	 *  pool again.
	 */
	int64_t remaining;

	/** Function to check whether to queue the IO.
	 * If The IO is allowed to pass, the quota will be reduced correspondingly.
	 */
	bool (*queue_io)(struct bdev_qos_limit_cache *cache,
			 struct bdev_qos_limit *limit, struct spdk_bdev_io *io);

	/** Function to rewind the quota once the IO was allowed to be sent by this
	 * limit but queued due to one of the further limits.
	 */
	void (*rewind_quota)(struct bdev_qos_limit_cache *cache,
			     struct bdev_qos_limit *limit, struct spdk_bdev_io *io);
};

struct bdev_qos_limits {
	struct bdev_qos_limit rate_limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES];
};

struct bdev_qos_limits_cache {
	struct bdev_qos_limit_cache rate_limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES];
};

struct spdk_bdev_hybrid_qos {
	struct spdk_bdev_qos_impl base;

	/** QoS rate limits. */
	struct bdev_qos_limits limits;

	bdev_io_tailq_t queued_io;

	struct spdk_spinlock spinlock;

	TAILQ_ENTRY(spdk_bdev_hybrid_qos) link;
};

struct spdk_bdev_hybrid_qos_channel;

struct spdk_bdev_hybrid_qos_poll_group {
	/** List of QoS I/Os waiting for submission. */
	bdev_io_tailq_t allowed_io;

	struct spdk_spinlock spinlock;

	TAILQ_HEAD(, spdk_bdev_hybrid_qos_channel) hqos_ch_list;
};

struct spdk_bdev_hybrid_qos_channel {
	struct spdk_bdev_qos_channel_impl base;

	/** Borrowed QoS rate limits. */
	struct bdev_qos_limits_cache limits;

	struct spdk_bdev_hybrid_qos *hqos;

	struct spdk_bdev_hybrid_qos_poll_group *hgroup;

	TAILQ_ENTRY(spdk_bdev_hybrid_qos_channel) link;
};

static struct spdk_bdev_qos_module hybrid_if;

static const char *qos_rpc_type[] = {"rw_ios_per_sec",
				     "rw_mbytes_per_sec", "r_mbytes_per_sec", "w_mbytes_per_sec"
				    };

static struct bdev_hybrid_qos_opts g_qos_opts = {
	.io_slice = SPDK_BDEV_QOS_IO_SLICE,
	.byte_slice = SPDK_BDEV_QOS_BYTE_SLICE,
	.timeslice_us = SPDK_BDEV_QOS_TIMESLICE_IN_USEC,
};

static struct spdk_bdev_hybrid_qos_mgr g_qos_mgr = {
	.last_timeslice = 0,
	.timeslice_size = 0,
	.poller = NULL,
	.hqos_list = TAILQ_HEAD_INITIALIZER(g_qos_mgr.hqos_list),
};

static inline struct spdk_bdev_hybrid_qos *
bdev_hybrid_qos(struct spdk_bdev_qos_impl *qos_impl)
{
	return SPDK_CONTAINEROF(qos_impl, struct spdk_bdev_hybrid_qos, base);
}

static inline struct spdk_bdev_hybrid_qos_channel *
bdev_hybrid_qos_channel(struct spdk_bdev_qos_channel_impl *qos_ch_impl)
{
	return SPDK_CONTAINEROF(qos_ch_impl, struct spdk_bdev_hybrid_qos_channel, base);
}

void
bdev_hybrid_qos_get_opts(struct bdev_hybrid_qos_opts *opts)
{
	assert(opts != NULL);

	opts->io_slice = g_qos_opts.io_slice;
	opts->byte_slice = g_qos_opts.byte_slice;
	opts->timeslice_us = g_qos_opts.timeslice_us;
}

int
bdev_hybrid_qos_set_opts(struct bdev_hybrid_qos_opts *opts)
{
	if (opts == NULL) {
		SPDK_ERRLOG("opts cannot be NULL\n");
		return -1;
	}

	if (opts->io_slice == 0 || opts->byte_slice == 0) {
		SPDK_ERRLOG("0 is not allowed for io_slice or byte_slice\n");
		return -1;
	}

	if (opts->timeslice_us == 0) {
		SPDK_ERRLOG("0 is not allowed for timeslice_us\n");
		return -1;
	}

	g_qos_opts.io_slice = opts->io_slice;
	g_qos_opts.byte_slice = opts->byte_slice;
	g_qos_opts.timeslice_us = opts->timeslice_us;

	return 0;
}

static inline bool
bdev_qos_limit_is_iops_rate_limit(enum spdk_bdev_qos_rate_limit_type limit)
{
	assert(limit != SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES);

	switch (limit) {
	case SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT:
		return true;
	case SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT:
	case SPDK_BDEV_QOS_R_BPS_RATE_LIMIT:
	case SPDK_BDEV_QOS_W_BPS_RATE_LIMIT:
		return false;
	case SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES:
	default:
		return false;
	}
}

static inline uint64_t bdev_qos_limit_borrow_quota(struct bdev_qos_limit *limit,
		uint32_t min_slice);
static inline void bdev_qos_limit_return_quota(struct bdev_qos_limit *limit, uint64_t delta);

static inline bool
bdev_qos_limit_cache_rw_queue_io(struct bdev_qos_limit_cache *cache,
				 struct bdev_qos_limit *limit,
				 struct spdk_bdev_io *io,
				 uint64_t delta)
{
	if (cache->remaining == INT64_MAX) {
		/* The limit type is disabled */
		return false;
	}

	if (cache->remaining < 0) {
		/* No global quota is available in the current timeslice. */
		return true;
	}

	cache->remaining -= delta;

	if (cache->remaining <= 0) {
		cache->remaining += bdev_qos_limit_borrow_quota(limit, -cache->remaining);
	}

	if (cache->remaining < 0) {
		/* This IO should be queued because overrun is already accounted
		 * when borrowing slice of quota from the global pool.
		 */
		return true;
	}

	return false;
}

static inline void
bdev_qos_limit_cache_rw_rewind_io(struct bdev_qos_limit_cache *cache,
				  struct bdev_qos_limit *limit,
				  struct spdk_bdev_io *io,
				  uint64_t delta)
{
	if (cache->remaining == INT64_MAX) {
		/* This limit type is disabled */
		return;
	}

	cache->remaining += delta;

	bdev_qos_limit_return_quota(limit, cache->remaining);

	cache->remaining = 0;
}

static bool
bdev_qos_limit_cache_rw_iops_queue(struct bdev_qos_limit_cache *cache,
				   struct bdev_qos_limit *limit,
				   struct spdk_bdev_io *io)
{
	return bdev_qos_limit_cache_rw_queue_io(cache, limit, io, 1);
}

static void
bdev_qos_limit_cache_rw_iops_rewind_quota(struct bdev_qos_limit_cache *cache,
		struct bdev_qos_limit *limit,
		struct spdk_bdev_io *io)
{
	bdev_qos_limit_cache_rw_rewind_io(cache, limit, io, 1);
}

static bool
bdev_qos_limit_cache_rw_bps_queue(struct bdev_qos_limit_cache *cache,
				  struct bdev_qos_limit *limit,
				  struct spdk_bdev_io *io)
{
	return bdev_qos_limit_cache_rw_queue_io(cache, limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
}

static void
bdev_qos_limit_cache_rw_bps_rewind_quota(struct bdev_qos_limit_cache *cache,
		struct bdev_qos_limit *limit,
		struct spdk_bdev_io *io)
{
	bdev_qos_limit_cache_rw_rewind_io(cache, limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
}

static bool
bdev_qos_limit_cache_r_bps_queue(struct bdev_qos_limit_cache *cache,
				 struct bdev_qos_limit *limit,
				 struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) == false) {
		return false;
	}

	return bdev_qos_limit_cache_rw_bps_queue(cache, limit, io);
}

static void
bdev_qos_limit_cache_r_bps_rewind_quota(struct bdev_qos_limit_cache *cache,
					struct bdev_qos_limit *limit,
					struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) != false) {
		bdev_qos_limit_cache_rw_rewind_io(cache, limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
	}
}

static bool
bdev_qos_limit_cache_w_bps_queue(struct bdev_qos_limit_cache *cache,
				 struct bdev_qos_limit *limit,
				 struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) == true) {
		return false;
	}

	return bdev_qos_limit_cache_rw_bps_queue(cache, limit, io);
}

static void
bdev_qos_limit_cache_w_bps_rewind_quota(struct bdev_qos_limit_cache *cache,
					struct bdev_qos_limit *limit,
					struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) != true) {
		bdev_qos_limit_cache_rw_rewind_io(cache, limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
	}
}

static void
bdev_qos_limit_cache_init(struct bdev_qos_limit_cache *cache,
			  enum spdk_bdev_qos_rate_limit_type type,
			  struct bdev_qos_limit *limit)
{
	if (!limit->max_per_timeslice) {
		cache->remaining = INT64_MAX;
	} else {
		cache->remaining = 0;
	}

	switch (type) {
	case SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT:
		cache->queue_io = bdev_qos_limit_cache_rw_iops_queue;
		cache->rewind_quota = bdev_qos_limit_cache_rw_iops_rewind_quota;
		break;
	case SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT:
		cache->queue_io = bdev_qos_limit_cache_rw_bps_queue;
		cache->rewind_quota = bdev_qos_limit_cache_rw_bps_rewind_quota;
		break;
	case SPDK_BDEV_QOS_R_BPS_RATE_LIMIT:
		cache->queue_io = bdev_qos_limit_cache_r_bps_queue;
		cache->rewind_quota = bdev_qos_limit_cache_r_bps_rewind_quota;
		break;
	case SPDK_BDEV_QOS_W_BPS_RATE_LIMIT:
		cache->queue_io = bdev_qos_limit_cache_w_bps_queue;
		cache->rewind_quota = bdev_qos_limit_cache_w_bps_rewind_quota;
		break;
	default:
		break;
	}
}

static void
bdev_qos_limits_cache_init(struct bdev_qos_limits_cache *caches,
			   struct bdev_qos_limits *limits)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		bdev_qos_limit_cache_init(&caches->rate_limits[i], i, &limits->rate_limits[i]);
	}
}

static void
bdev_qos_limit_cache_reset(struct bdev_qos_limit_cache *cache,
			   struct bdev_qos_limit *limit)
{
	if (!limit->max_per_timeslice) {
		cache->remaining = INT64_MAX;
	} else {
		cache->remaining = 0;
	}
}

static void
bdev_qos_limits_cache_reset(struct bdev_qos_limits_cache *caches,
			    struct bdev_qos_limits *limits)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		bdev_qos_limit_cache_reset(&caches->rate_limits[i], &limits->rate_limits[i]);
	}
}

static inline bool
bdev_qos_limit_rw_queue_io(struct bdev_qos_limit *limit, struct spdk_bdev_io *io,
			   uint64_t delta)
{
	int64_t remaining;

	if (!limit->max_per_timeslice) {
		/* This limit type is disabled */
		return false;
	}

	remaining = __atomic_sub_fetch(&limit->remaining_this_timeslice, delta,
				       __ATOMIC_RELAXED);
	if (remaining + (int64_t)delta > 0) {
		return false;
	}

	__atomic_add_fetch(&limit->remaining_this_timeslice, delta, __ATOMIC_RELAXED);
	return true;
}

static inline void
bdev_qos_limit_rw_rewind_io(struct bdev_qos_limit *limit, struct spdk_bdev_io *io,
			    uint64_t delta)
{
	if (!limit->max_per_timeslice) {
		/* This limit type is disabled */
		return;
	}

	bdev_qos_limit_return_quota(limit, delta);
}

static bool
bdev_qos_limit_rw_iops_queue(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	return bdev_qos_limit_rw_queue_io(limit, io, 1);
}

static void
bdev_qos_limit_rw_iops_rewind_quota(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	bdev_qos_limit_rw_rewind_io(limit, io, 1);
}

static bool
bdev_qos_limit_rw_bps_queue(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	return bdev_qos_limit_rw_queue_io(limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
}

static void
bdev_qos_limit_rw_bps_rewind_quota(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	bdev_qos_limit_rw_rewind_io(limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
}

static bool
bdev_qos_limit_r_bps_queue(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) == false) {
		return false;
	}

	return bdev_qos_limit_rw_bps_queue(limit, io);
}

static void
bdev_qos_limit_r_bps_rewind_quota(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) != false) {
		bdev_qos_limit_rw_rewind_io(limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
	}
}

static void
bdev_qos_limit_w_bps_rewind_quota(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) != true) {
		bdev_qos_limit_rw_rewind_io(limit, io, spdk_bdev_io_get_io_size_in_bytes(io));
	}
}

static bool
bdev_qos_limit_w_bps_queue(struct bdev_qos_limit *limit, struct spdk_bdev_io *io)
{
	if (spdk_bdev_io_is_read_io(io) == true) {
		return false;
	}

	return bdev_qos_limit_rw_bps_queue(limit, io);
}

static void
bdev_qos_limit_init(struct bdev_qos_limit *limit, enum spdk_bdev_qos_rate_limit_type type,
		    uint32_t io_slice, uint32_t byte_slice)
{
	if (bdev_qos_limit_is_iops_rate_limit(type) == true) {
		limit->min_per_timeslice = SPDK_BDEV_QOS_MIN_IO_PER_TIMESLICE;
		limit->slice_per_borrow = io_slice;
	} else {
		limit->min_per_timeslice = SPDK_BDEV_QOS_MIN_BYTE_PER_TIMESLICE;
		limit->slice_per_borrow = byte_slice;
	}

	limit->limit = SPDK_BDEV_QOS_LIMIT_NOT_DEFINED;

	switch (type) {
	case SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT:
		limit->queue_io = bdev_qos_limit_rw_iops_queue;
		limit->rewind_quota = bdev_qos_limit_rw_iops_rewind_quota;
		break;
	case SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT:
		limit->queue_io = bdev_qos_limit_rw_bps_queue;
		limit->rewind_quota = bdev_qos_limit_rw_bps_rewind_quota;
		break;
	case SPDK_BDEV_QOS_R_BPS_RATE_LIMIT:
		limit->queue_io = bdev_qos_limit_r_bps_queue;
		limit->rewind_quota = bdev_qos_limit_r_bps_rewind_quota;
		break;
	case SPDK_BDEV_QOS_W_BPS_RATE_LIMIT:
		limit->queue_io = bdev_qos_limit_w_bps_queue;
		limit->rewind_quota = bdev_qos_limit_w_bps_rewind_quota;
		break;
	default:
		break;
	}
}

static void
bdev_qos_limits_init(struct bdev_qos_limits *limits, uint32_t io_slice, uint32_t byte_slice)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		bdev_qos_limit_init(&limits->rate_limits[i], i, io_slice, byte_slice);
	}
}

static void
bdev_qos_limit_get(struct bdev_qos_limit *limit, enum spdk_bdev_qos_rate_limit_type type,
		   uint64_t *value)
{
	if (limit->limit == SPDK_BDEV_QOS_LIMIT_NOT_DEFINED) {
		*value = 0;
	} else {
		*value = limit->limit;
		if (!bdev_qos_limit_is_iops_rate_limit(type)) {
			/* Change from Byte to Megabyte which is user visible. */
			*value = *value / 1024 / 1024;
		}
	}
}

static void
bdev_qos_limits_get(struct bdev_qos_limits *limits, uint64_t *values)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		bdev_qos_limit_get(&limits->rate_limits[i], i, &values[i]);
	}
}

static void
bdev_qos_limit_value_adjust(uint64_t *value, enum spdk_bdev_qos_rate_limit_type type)
{
	uint32_t limit_set_complement;
	uint64_t min_limit_per_sec;

	if (*value == SPDK_BDEV_QOS_LIMIT_NOT_DEFINED) {
		return;
	}

	if (bdev_qos_limit_is_iops_rate_limit(type) == true) {
		min_limit_per_sec = SPDK_BDEV_QOS_MIN_IOS_PER_SEC;
	} else {
		/* Change from mebibyte to byte rate limit */
		*value = *value * 1024 * 1024;
		min_limit_per_sec = SPDK_BDEV_QOS_MIN_BYTES_PER_SEC;
	}

	limit_set_complement = *value % min_limit_per_sec;
	if (limit_set_complement) {
		SPDK_WARNLOG("Requested rate limit %" PRIu64
			     " is not a multiple of %" PRIu64 "\n",
			     *value,
			     min_limit_per_sec);
		*value += min_limit_per_sec - limit_set_complement;
		SPDK_WARNLOG("Round up the rate limit to %" PRIu64 "\n", *value);
	}
}

static void
bdev_qos_limit_values_adjust(uint64_t *values)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		bdev_qos_limit_value_adjust(&values[i], i);
	}
}

static void
bdev_qos_limit_set(struct bdev_qos_limit *limit, uint64_t value)
{
	uint64_t max_per_timeslice;

	if (value == 0) {
		limit->limit = SPDK_BDEV_QOS_LIMIT_NOT_DEFINED;
	} else {
		limit->limit = value;
	}

	if (limit->limit == SPDK_BDEV_QOS_LIMIT_NOT_DEFINED) {
		limit->max_per_timeslice = 0;
		return;
	}

	max_per_timeslice = limit->limit * g_qos_opts.timeslice_us / SPDK_SEC_TO_USEC;

	limit->max_per_timeslice = spdk_max(max_per_timeslice, limit->min_per_timeslice);

	__atomic_store_n(&limit->remaining_this_timeslice, limit->max_per_timeslice,
			 __ATOMIC_RELEASE);
}

static void
bdev_qos_limits_set(struct bdev_qos_limits *limits, const uint64_t *values)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		bdev_qos_limit_set(&limits->rate_limits[i], values[i]);
	}
}

static inline void
bdev_qos_limit_cache_rewind(struct bdev_qos_limit_cache *cache, struct bdev_qos_limit *limit,
			    struct spdk_bdev_io *bdev_io)
{
	cache->rewind_quota(cache, limit, bdev_io);
}

static inline bool
bdev_qos_limit_cache_queue_io(struct bdev_qos_limit_cache *cache, struct bdev_qos_limit *limit,
			      struct spdk_bdev_io *bdev_io)
{
	return cache->queue_io(cache, limit, bdev_io);
}

static bool
bdev_qos_limits_cache_queue_io(struct bdev_qos_limits_cache *caches, struct bdev_qos_limits *limits,
			       struct spdk_bdev_io *bdev_io)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (bdev_qos_limit_cache_queue_io(&caches->rate_limits[i], &limits->rate_limits[i],
						  bdev_io) == true) {
			for (i -= 1; i >= 0 ; i--) {
				bdev_qos_limit_cache_rewind(&caches->rate_limits[i],
							    &limits->rate_limits[i], bdev_io);
			}
			return true;
		}
	}

	return false;
}

static inline void
bdev_qos_limit_rewind(struct bdev_qos_limit *limit, struct spdk_bdev_io *bdev_io)
{
	limit->rewind_quota(limit, bdev_io);
}

static inline bool
bdev_qos_limit_queue_io(struct bdev_qos_limit *limit, struct spdk_bdev_io *bdev_io)
{
	return limit->queue_io(limit, bdev_io);
}

static bool
bdev_qos_limits_queue_io(struct bdev_qos_limits *limits, struct spdk_bdev_io *bdev_io)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (bdev_qos_limit_queue_io(&limits->rate_limits[i], bdev_io) == true) {
			for (i -= 1; i >= 0 ; i--) {
				bdev_qos_limit_rewind(&limits->rate_limits[i], bdev_io);
			}
			return true;
		}
	}

	return false;
}

static inline void
bdev_qos_limit_reset_quota(struct bdev_qos_limit *limit, int timeslice_count)
{
	int64_t remaining_last_timeslice;

	/* We may have allowed the IOs or bytes to slightly overrun in the last
	 * timeslice. remaining_this_timeslice is signed, so if it's negative
	 * here, we'll account for the overrun so that the next timeslice will
	 * be appropriately reduced.
	 */
	remaining_last_timeslice = __atomic_exchange_n(&limit->remaining_this_timeslice,
				   0, __ATOMIC_RELAXED);
	if (remaining_last_timeslice < 0) {
		/* There could be a race condition here as both bdev_qos_rw_queue_io() and bdev_qos_poll()
		 * potentially use 2 atomic ops each, so they can intertwine.
		 * This race can potentialy cause the limits to be a little fuzzy but won't cause any real damage.
		 */
		__atomic_store_n(&limit->remaining_this_timeslice, remaining_last_timeslice,
				 __ATOMIC_RELAXED);
	}

	if (timeslice_count > 0) {
		__atomic_add_fetch(&limit->remaining_this_timeslice,
				   limit->max_per_timeslice * timeslice_count,
				   __ATOMIC_RELAXED);
	}
}

static void
bdev_qos_limits_reset_quota(struct bdev_qos_limits *limits, int timeslice_count)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		bdev_qos_limit_reset_quota(&limits->rate_limits[i], timeslice_count);
	}
}

static bool
bdev_qos_limit_values_check_disabled(const uint64_t *limits)
{
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (limits[i] != 0 && limits[i] != SPDK_BDEV_QOS_LIMIT_NOT_DEFINED) {
			return false;
		}
	}
	return true;
}

static bool
bdev_qos_limits_check_disabled(struct bdev_qos_limits *limits)
{
	struct bdev_qos_limit *limit;
	int i;

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		limit = &limits->rate_limits[i];
		if (limit->limit != 0 && limit->limit != SPDK_BDEV_QOS_LIMIT_NOT_DEFINED) {
			return false;
		}
	}
	return true;
}

static inline uint64_t
bdev_qos_limit_borrow_quota(struct bdev_qos_limit *limit, uint32_t min_slice)
{
	int64_t remaining_this_timeslice;
	uint64_t slice;

	slice = spdk_max(min_slice, limit->slice_per_borrow);

	if (!limit->max_per_timeslice) {
		return slice;
	}

	remaining_this_timeslice = __atomic_sub_fetch(&limit->remaining_this_timeslice,
				   slice, __ATOMIC_RELAXED);
	if (remaining_this_timeslice + (int64_t)slice > 0) {
		/* We allow a slight quota overrun here. Such overrun then taken into
		 * account in the QoS poller, where the next timeslice quota is caculated.
		 */
		return slice;
	}

	/* No quota available to allocate. Rewind remaining_this_timeslice. */
	__atomic_add_fetch(&limit->remaining_this_timeslice, slice,
			   __ATOMIC_RELAXED);
	return 0;
}

static inline void
bdev_qos_limit_return_quota(struct bdev_qos_limit *limit, uint64_t delta)
{
	__atomic_add_fetch(&limit->remaining_this_timeslice, delta, __ATOMIC_RELAXED);
}

static inline bool
_bdev_hybrid_qos_channel_queue_io(struct spdk_bdev_hybrid_qos_channel *hqos_ch,
				  struct spdk_bdev_io *bdev_io)
{
	struct spdk_bdev_hybrid_qos *hqos = hqos_ch->hqos;

	assert(hqos != NULL);

	if (bdev_qos_limits_cache_queue_io(&hqos_ch->limits, &hqos->limits, bdev_io)) {
		spdk_spin_lock(&hqos->spinlock);
		TAILQ_INSERT_TAIL(&hqos->queued_io, bdev_io, internal.link);
		spdk_spin_unlock(&hqos->spinlock);
		return true;
	} else {
		return false;
	}
}

static void
bdev_hybrid_qos_channel_queue_io(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
				 struct spdk_bdev_io *bdev_io)
{
	struct spdk_bdev_hybrid_qos_channel *hqos_ch = bdev_hybrid_qos_channel(qos_ch_impl);

	if (_bdev_hybrid_qos_channel_queue_io(hqos_ch, bdev_io)) {
		return;
	}

	/* For each limit type, it is ensured that there is no preceding
	 * queued I/Os. Hence, call submit function directly to avoid
	 * extra overhead.
	 */
	spdk_bdev_qos_channel_impl_queue_io_done(bdev_io);
}

static bool
bdev_hybrid_qos_channel_abort_queued_io(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
					struct spdk_bdev_io *bio_to_abort)
{
	struct spdk_bdev_hybrid_qos_channel *hqos_ch = bdev_hybrid_qos_channel(qos_ch_impl);
	struct spdk_bdev_hybrid_qos *hqos = hqos_ch->hqos;
	struct spdk_bdev_hybrid_qos_poll_group *hgroup = hqos_ch->hgroup;
	bool success;

	spdk_spin_lock(&hqos->spinlock);
	success = spdk_bdev_abort_queued_io(&hqos->queued_io, bio_to_abort);
	spdk_spin_unlock(&hqos->spinlock);

	if (!success) {
		spdk_spin_lock(&hgroup->spinlock);
		success = spdk_bdev_abort_queued_io(&hgroup->allowed_io, bio_to_abort);
		spdk_spin_unlock(&hgroup->spinlock);
	}

	return success;
}

static void
bdev_hybrid_qos_channel_abort_all_queued_io(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
		struct spdk_bdev_channel *bdev_ch)
{
	struct spdk_bdev_hybrid_qos_channel *hqos_ch = bdev_hybrid_qos_channel(qos_ch_impl);
	struct spdk_bdev_hybrid_qos *hqos = hqos_ch->hqos;
	struct spdk_bdev_hybrid_qos_poll_group *hgroup = hqos_ch->hgroup;

	assert(hqos != NULL);

	spdk_spin_lock(&hqos->spinlock);
	spdk_bdev_abort_all_queued_io(&hqos->queued_io, bdev_ch);
	spdk_spin_unlock(&hqos->spinlock);

	spdk_spin_lock(&hgroup->spinlock);
	spdk_bdev_abort_all_queued_io(&hgroup->allowed_io, bdev_ch);
	spdk_spin_unlock(&hgroup->spinlock);
}

static void
bdev_hybrid_qos_retry_queued_io(struct spdk_bdev_hybrid_qos *hqos)
{
	bdev_io_tailq_t tmp_head;
	struct spdk_bdev_io *bdev_io, *tmp;
	struct spdk_bdev_hybrid_qos_channel *hqos_ch;
	struct spdk_bdev_hybrid_qos_poll_group *hgroup;

	TAILQ_INIT(&tmp_head);

	spdk_spin_lock(&hqos->spinlock);
	TAILQ_SWAP(&tmp_head, &hqos->queued_io, spdk_bdev_io, internal.link);
	spdk_spin_unlock(&hqos->spinlock);

	TAILQ_FOREACH_SAFE(bdev_io, &tmp_head, internal.link, tmp) {
		if (!bdev_qos_limits_queue_io(&hqos->limits, bdev_io)) {
			TAILQ_REMOVE(&tmp_head, bdev_io, internal.link);

			hqos_ch = bdev_hybrid_qos_channel(bdev_io->internal.blocked_qos_ch_impl);
			hgroup = hqos_ch->hgroup;

			spdk_spin_lock(&hgroup->spinlock);
			TAILQ_INSERT_TAIL(&hgroup->allowed_io, bdev_io, internal.link);
			spdk_spin_unlock(&hgroup->spinlock);
		}
	}

	spdk_spin_lock(&hqos->spinlock);
	TAILQ_SWAP(&tmp_head, &hqos->queued_io, spdk_bdev_io, internal.link);
	TAILQ_CONCAT(&hqos->queued_io, &tmp_head, internal.link);
	spdk_spin_unlock(&hqos->spinlock);
}

static void
bdev_allow_all_queued_hybrid_qos_io(struct spdk_bdev_hybrid_qos_poll_group *hgroup)
{
	bdev_io_tailq_t tmp_head;
	struct spdk_bdev_io *bdev_io, *tmp_bdev_io;

	TAILQ_INIT(&tmp_head);

	spdk_spin_lock(&hgroup->spinlock);
	TAILQ_SWAP(&hgroup->allowed_io, &tmp_head, spdk_bdev_io, internal.link);
	spdk_spin_unlock(&hgroup->spinlock);

	TAILQ_FOREACH_SAFE(bdev_io, &tmp_head, internal.link, tmp_bdev_io) {
		TAILQ_REMOVE(&tmp_head, bdev_io, internal.link);

		spdk_bdev_qos_channel_impl_queue_io_done(bdev_io);
	}
}

static void
bdev_hybrid_qos_poll(struct spdk_bdev_hybrid_qos *hqos, int timeslice_count)
{
	/* Reset for next round of rate limiting */
	bdev_qos_limits_reset_quota(&hqos->limits, timeslice_count);

	bdev_hybrid_qos_retry_queued_io(hqos);
}

static void
bdev_hybrid_qos_channel_reset(struct spdk_bdev_hybrid_qos_channel *hqos_ch)
{
	struct spdk_bdev_hybrid_qos *hqos = hqos_ch->hqos;

	bdev_qos_limits_cache_reset(&hqos_ch->limits, &hqos->limits);
}

static void
bdev_reset_hybrid_qos_channels(struct spdk_bdev_hybrid_qos_poll_group *hgroup)
{
	struct spdk_bdev_hybrid_qos_channel *hqos_ch;

	TAILQ_FOREACH(hqos_ch, &hgroup->hqos_ch_list, link) {
		bdev_hybrid_qos_channel_reset(hqos_ch);
	}
}

static void
_bdev_reset_hybrid_qos(struct spdk_io_channel *ch, void *ctx)
{
	struct spdk_bdev_hybrid_qos_poll_group *hgroup = spdk_io_channel_get_ctx(ch);

	bdev_reset_hybrid_qos_channels(hgroup);
	bdev_allow_all_queued_hybrid_qos_io(hgroup);
}

static void
bdev_reset_hybrid_qos(void)
{
	spdk_for_each_channel_broadcast(&g_qos_mgr, _bdev_reset_hybrid_qos, NULL);
}

static void
bdev_hybrid_qos_channel_unblock_all_queued_io(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
		struct spdk_bdev_channel *bdev_ch)
{
	struct spdk_bdev_hybrid_qos_channel *hqos_ch = bdev_hybrid_qos_channel(qos_ch_impl);
	struct spdk_bdev_hybrid_qos *hqos = hqos_ch->hqos;

	spdk_spin_lock(&hqos->spinlock);
	spdk_bdev_unblock_all_queued_io(&hqos->queued_io, bdev_ch);
	spdk_spin_unlock(&hqos->spinlock);
}

static struct spdk_bdev_qos_channel_impl *
bdev_hybrid_qos_channel_get(struct spdk_bdev_qos_impl *qos_impl)
{
	struct spdk_bdev_hybrid_qos *hqos = bdev_hybrid_qos(qos_impl);
	struct spdk_bdev_hybrid_qos_channel *hqos_ch;
	struct spdk_io_channel *pg_io_ch;

	if (qos_impl->module != &hybrid_if) {
		return NULL;
	}

	hqos_ch = calloc(1, sizeof(*hqos_ch));
	if (hqos_ch == NULL) {
		return NULL;
	}

	hqos_ch->hqos = hqos;
	hqos_ch->base.qos_impl = qos_impl;

	bdev_qos_limits_cache_init(&hqos_ch->limits, &hqos->limits);

	pg_io_ch = spdk_get_io_channel(&g_qos_mgr);
	if (!pg_io_ch) {
		free(hqos_ch);
		return NULL;
	}

	hqos_ch->hgroup = spdk_io_channel_get_ctx(pg_io_ch);

	TAILQ_INSERT_TAIL(&hqos_ch->hgroup->hqos_ch_list, hqos_ch, link);

	return &hqos_ch->base;
}

static void
bdev_hybrid_qos_channel_put(struct spdk_bdev_qos_channel_impl *qos_ch_impl)
{
	struct spdk_bdev_hybrid_qos_channel *hqos_ch = bdev_hybrid_qos_channel(qos_ch_impl);
	struct spdk_bdev_hybrid_qos_poll_group *hgroup = hqos_ch->hgroup;

	TAILQ_REMOVE(&hgroup->hqos_ch_list, hqos_ch, link);

	spdk_put_io_channel(spdk_io_channel_from_ctx(hgroup));

	free(qos_ch_impl);
}

static struct spdk_bdev_qos_impl *
bdev_hybrid_qos_get(void)
{
	struct spdk_bdev_hybrid_qos *hqos;

	hqos = calloc(1, sizeof(*hqos));
	if (!hqos) {
		return NULL;
	}

	hqos->base.module = &hybrid_if;

	TAILQ_INIT(&hqos->queued_io);
	spdk_spin_init(&hqos->spinlock);

	bdev_qos_limits_init(&hqos->limits, g_qos_opts.io_slice, g_qos_opts.byte_slice);

	if (TAILQ_EMPTY(&g_qos_mgr.hqos_list)) {
		g_qos_mgr.last_timeslice = spdk_get_ticks();
		spdk_poller_resume(g_qos_mgr.poller);
	}

	TAILQ_INSERT_TAIL(&g_qos_mgr.hqos_list, hqos, link);

	return &hqos->base;
}

static void
bdev_hybrid_qos_put(struct spdk_bdev_qos_impl *qos_impl)
{
	struct spdk_bdev_hybrid_qos *hqos = bdev_hybrid_qos(qos_impl);

	TAILQ_REMOVE(&g_qos_mgr.hqos_list, hqos, link);

	if (TAILQ_EMPTY(&g_qos_mgr.hqos_list) && g_qos_mgr.poller) {
		spdk_poller_pause(g_qos_mgr.poller);
	}

	spdk_spin_destroy(&hqos->spinlock);

	free(qos_impl);
}

static void
bdev_hybrid_qos_poll_group_destroy(void *io_device, void *ctx_buf)
{
	struct spdk_bdev_hybrid_qos_poll_group *hgroup = ctx_buf;

	spdk_spin_destroy(&hgroup->spinlock);
}

static int
bdev_hybrid_qos_poll_group_create(void *io_device, void *ctx_buf)
{
	struct spdk_bdev_hybrid_qos_poll_group *hgroup = ctx_buf;

	TAILQ_INIT(&hgroup->allowed_io);
	TAILQ_INIT(&hgroup->hqos_ch_list);
	spdk_spin_init(&hgroup->spinlock);

	return 0;
}

static void bdev_hybrid_qos_poll(struct spdk_bdev_hybrid_qos *hqos, int timeslice_count);
static void bdev_reset_hybrid_qos(void);

static int
bdev_poll_hybrid_qos(void *arg)
{
	struct spdk_bdev_hybrid_qos *hqos;
	uint64_t now = spdk_get_ticks();
	uint64_t timeslice_size = g_qos_mgr.timeslice_size;
	int timeslice_count = 0;

	if (now < g_qos_mgr.last_timeslice + timeslice_size) {
		/* We received our callback earlier than expected - return
		 *  immediately and wait to do accounting until at least one
		 *  timeslice has actually expired.  This should never happen
		 *  with a well-behaved timer implementation.
		 */
		return SPDK_POLLER_IDLE;
	}

	while (now >= g_qos_mgr.last_timeslice + timeslice_size) {
		g_qos_mgr.last_timeslice += timeslice_size;
		timeslice_count++;
	}

	TAILQ_FOREACH(hqos, &g_qos_mgr.hqos_list, link) {
		bdev_hybrid_qos_poll(hqos, timeslice_count);
	}

	bdev_reset_hybrid_qos();

	return SPDK_POLLER_BUSY;
}

static void
bdev_hybrid_qos_get_rate_limits(struct spdk_bdev_qos_impl *qos_impl, uint64_t *limits)
{
	struct spdk_bdev_hybrid_qos *hqos = bdev_hybrid_qos(qos_impl);

	bdev_qos_limits_get(&hqos->limits, limits);
}

static void
_bdev_hybrid_qos_set_rate_limits(struct spdk_bdev_qos_impl *qos_impl, uint64_t *limits)
{
	struct spdk_bdev_hybrid_qos *hqos = bdev_hybrid_qos(qos_impl);

	bdev_qos_limits_set(&hqos->limits, limits);
}

static bool
_bdev_hybrid_qos_check_disabled(struct spdk_bdev_qos_impl *qos_impl)
{
	struct spdk_bdev_hybrid_qos *hqos = bdev_hybrid_qos(qos_impl);

	return bdev_qos_limits_check_disabled(&hqos->limits);
}

static void
bdev_qos_hybrid_library_config_json(struct spdk_json_write_ctx *w)
{
	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "method", "bdev_hybrid_qos_set_options");

	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_uint64(w, "io_slice", g_qos_opts.io_slice);
	spdk_json_write_named_uint64(w, "byte_slice", g_qos_opts.byte_slice);
	spdk_json_write_named_uint64(w, "timeslice_us", g_qos_opts.timeslice_us);
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}

static void
bdev_hybrid_qos_config_json(struct spdk_bdev_qos_impl *qos_impl, struct spdk_json_write_ctx *w)
{
	uint64_t limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES] = {};
	int i;

	bdev_hybrid_qos_get_rate_limits(qos_impl, limits);

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "method", "bdev_hybrid_qos_set_limit");

	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "name", qos_impl->qos->name);
	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (limits[i] > 0) {
			spdk_json_write_named_uint64(w, qos_rpc_type[i], limits[i]);
		}
	}
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}

static void
bdev_hybrid_qos_info_json(struct spdk_bdev_qos_impl *qos_impl, struct spdk_json_write_ctx *w)
{
	uint64_t limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES] = {};
	int i;

	bdev_hybrid_qos_get_rate_limits(qos_impl, limits);

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "name", "hybrid");

	spdk_json_write_named_object_begin(w, "assigned_rate_limits");
	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		spdk_json_write_named_uint64(w, qos_rpc_type[i], limits[i]);
	}
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}

static int
bdev_qos_hybrid_library_init(void)
{
	g_qos_mgr.timeslice_size = g_qos_opts.timeslice_us * spdk_get_ticks_hz() /
				   SPDK_SEC_TO_USEC;

	g_qos_mgr.last_timeslice = spdk_get_ticks();
	g_qos_mgr.poller = SPDK_POLLER_REGISTER(bdev_poll_hybrid_qos, NULL, g_qos_opts.timeslice_us);
	spdk_poller_pause(g_qos_mgr.poller);

	spdk_io_device_register(&g_qos_mgr, bdev_hybrid_qos_poll_group_create,
				bdev_hybrid_qos_poll_group_destroy,
				sizeof(struct spdk_bdev_hybrid_qos_poll_group),
				"qos_mgr");

	return 0;
}

static void
bdev_hybrid_qos_mgr_unregister_cb(void *io_device)
{
	spdk_bdev_qos_module_fini_done();
}

static void
bdev_qos_hybrid_library_fini(void)
{
	spdk_poller_unregister(&g_qos_mgr.poller);

	spdk_io_device_unregister(&g_qos_mgr, bdev_hybrid_qos_mgr_unregister_cb);
}

static struct spdk_bdev_qos_module hybrid_if = {
	.name = "hybrid",
	.module_init = bdev_qos_hybrid_library_init,
	.module_fini = bdev_qos_hybrid_library_fini,
	.module_config_json = bdev_qos_hybrid_library_config_json,
	.get_impl = bdev_hybrid_qos_get,
	.put_impl = bdev_hybrid_qos_put,
	.impl_config_json = bdev_hybrid_qos_config_json,
	.impl_info_json = bdev_hybrid_qos_info_json,
	.get_channel_impl = bdev_hybrid_qos_channel_get,
	.put_channel_impl = bdev_hybrid_qos_channel_put,
	.queue_io = bdev_hybrid_qos_channel_queue_io,
	.abort_queued_io = bdev_hybrid_qos_channel_abort_queued_io,
	.abort_all_queued_io = bdev_hybrid_qos_channel_abort_all_queued_io,
	.unblock_all_queued_io = bdev_hybrid_qos_channel_unblock_all_queued_io,
	.async_fini = true,
};

SPDK_BDEV_QOS_MODULE_REGISTER(hybrid, &hybrid_if)

struct set_qos_limit_ctx {
	spdk_bdev_qos_op_cb cb_fn;
	void *cb_arg;
	struct spdk_bdev *bdev;
	struct spdk_bdev_qos_desc *desc;
};

static void
bdev_set_qos_limit_done(struct set_qos_limit_ctx *ctx, int status)
{
	if (ctx->desc) {
		spdk_bdev_qos_close(ctx->desc);
	}

	if (ctx->cb_fn) {
		ctx->cb_fn(ctx->cb_arg, status);
	}
	free(ctx);
}

static void
set_qos_limit_reset_channel(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *_ch = spdk_io_channel_iter_get_channel(i);
	struct spdk_bdev_qos_channel *qos_ch = spdk_io_channel_get_ctx(_ch);
	struct spdk_bdev_qos_channel_impl *qos_ch_impl;
	struct spdk_bdev_hybrid_qos_channel *hqos_ch;

	qos_ch_impl = spdk_bdev_qos_channel_find_impl(qos_ch, &hybrid_if);
	if (qos_ch_impl == NULL) {
		assert(false);
		spdk_for_each_channel_continue(i, -EINVAL);
		return;
	}

	hqos_ch = bdev_hybrid_qos_channel(qos_ch_impl);

	bdev_hybrid_qos_channel_reset(hqos_ch);

	spdk_for_each_channel_continue(i, 0);
}

static void
set_qos_limit_reset_channel_done(struct spdk_io_channel_iter *i, int status)
{
	struct set_qos_limit_ctx *ctx = spdk_io_channel_iter_get_ctx(i);

	bdev_set_qos_limit_done(ctx, 0);
}

static void
set_qos_limit_delete_bdev_done(void *cb_arg, int status)
{
	struct set_qos_limit_ctx *ctx = cb_arg;
	struct spdk_bdev_qos *qos;

	if (status == 0) {
		qos = spdk_bdev_qos_desc_get_qos(ctx->desc);
		spdk_bdev_qos_destroy(qos);
	} else {
		SPDK_WARNLOG("Rate limit disable cannot be reverted.\n");
	}

	bdev_set_qos_limit_done(ctx, status);
}

static void
set_qos_limit_add_bdev_done(void *cb_arg, int status)
{
	struct set_qos_limit_ctx *ctx = cb_arg;
	struct spdk_bdev_qos *qos;

	if (status != 0) {
		qos = spdk_bdev_qos_desc_get_qos(ctx->desc);
		spdk_bdev_qos_destroy(qos);
	}

	bdev_set_qos_limit_done(ctx, status);
}

static void
bdev_set_hybrid_qos_rate_limits(struct spdk_bdev *bdev, uint64_t *new_limits,
				spdk_bdev_qos_op_cb cb_fn, void *cb_arg)
{
	struct set_qos_limit_ctx *ctx;
	struct spdk_bdev_qos *qos;
	struct spdk_bdev_qos_impl *qos_impl;
	int rc;

	if (spdk_bdev_qos_module_list_find(hybrid_if.name) == NULL) {
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	SPDK_DEBUGLOG(qos_hybrid, "Updating QoS limits for %s (new_limits=%p)\n",
		      bdev->name, new_limits);

	if (!spdk_thread_is_app_thread(NULL)) {
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	bdev_qos_limit_values_adjust(new_limits);

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		cb_fn(cb_arg, -ENOMEM);
		return;
	}

	ctx->cb_fn = cb_fn;
	ctx->cb_arg = cb_arg;
	ctx->bdev = bdev;

	rc = spdk_bdev_qos_open(bdev->name, &ctx->desc);
	if (rc == 0) {
		qos = spdk_bdev_qos_desc_get_qos(ctx->desc);

		qos_impl = spdk_bdev_qos_find_impl(qos, &hybrid_if);
		assert(qos_impl != NULL);

		/* Updating the limits */
		_bdev_hybrid_qos_set_rate_limits(qos_impl, new_limits);

		if (_bdev_hybrid_qos_check_disabled(qos_impl)) {
			/* Disabling */
			spdk_bdev_qos_remove_bdev(qos, bdev,
						  set_qos_limit_delete_bdev_done, ctx);
		} else {
			spdk_for_each_channel(qos, set_qos_limit_reset_channel, ctx,
					      set_qos_limit_reset_channel_done);
		}
	} else if (!bdev_qos_limit_values_check_disabled(new_limits)) {
		/* Enabling */
		rc = spdk_bdev_qos_create(bdev->name, NULL, NULL, 0, &qos, &ctx->desc);
		if (rc != 0) {
			bdev_set_qos_limit_done(ctx, rc);
			return;
		}

		qos_impl = spdk_bdev_qos_find_impl(qos, &hybrid_if);
		assert(qos_impl != NULL);

		_bdev_hybrid_qos_set_rate_limits(qos_impl, new_limits);

		spdk_bdev_qos_add_bdev(qos, bdev, set_qos_limit_add_bdev_done, ctx);
	} else {
		bdev_set_qos_limit_done(ctx, 0);
	}
}

struct rpc_bdev_set_qos_limit {
	uint64_t	limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES];
};

static const struct spdk_json_object_decoder rpc_bdev_set_qos_limit_decoders[] = {
	{
		"rw_ios_per_sec", offsetof(struct rpc_bdev_set_qos_limit,
					   limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"rw_mbytes_per_sec", offsetof(struct rpc_bdev_set_qos_limit,
					      limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"r_mbytes_per_sec", offsetof(struct rpc_bdev_set_qos_limit,
					     limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"w_mbytes_per_sec", offsetof(struct rpc_bdev_set_qos_limit,
					     limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
};

void
bdev_set_hybrid_qos_rate_limits_json(struct spdk_bdev *bdev, const struct spdk_json_val *params,
				     spdk_bdev_qos_op_cb cb_fn, void *cb_arg)
{
	struct rpc_bdev_set_qos_limit req = {{
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED,
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED,
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED,
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED
		}
	};
	int i;

	if (spdk_json_decode_object_relaxed(params, rpc_bdev_set_qos_limit_decoders,
					    SPDK_COUNTOF(rpc_bdev_set_qos_limit_decoders),
					    &req)) {
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (req.limits[i] != SPDK_BDEV_QOS_LIMIT_NOT_DEFINED) {
			break;
		}
	}
	if (i == SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES) {
		SPDK_ERRLOG("no rate limits specified\n");
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	bdev_set_hybrid_qos_rate_limits(bdev, req.limits, cb_fn, cb_arg);
}

static void
bdev_hybrid_qos_set_rate_limits(const char *name, uint64_t *new_limits,
				spdk_bdev_qos_op_cb cb_fn, void *cb_arg)
{
	struct set_qos_limit_ctx *ctx;
	struct spdk_bdev_qos *qos;
	struct spdk_bdev_qos_impl *qos_impl;
	int rc;

	if (spdk_bdev_qos_module_list_find(hybrid_if.name) == NULL) {
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	bdev_qos_limit_values_adjust(new_limits);

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		cb_fn(cb_arg, -ENOMEM);
		return;
	}

	ctx->cb_fn = cb_fn;
	ctx->cb_arg = cb_arg;

	rc = spdk_bdev_qos_open(name, &ctx->desc);
	if (rc != 0) {
		bdev_set_qos_limit_done(ctx, rc);
		return;
	}

	qos = spdk_bdev_qos_desc_get_qos(ctx->desc);

	qos_impl = spdk_bdev_qos_find_impl(qos, &hybrid_if);
	assert(qos_impl != NULL);

	_bdev_hybrid_qos_set_rate_limits(qos_impl, new_limits);

	spdk_for_each_channel(qos, set_qos_limit_reset_channel, ctx,
			      set_qos_limit_reset_channel_done);
}

void
bdev_hybrid_qos_set_rate_limits_json(const char *name, const struct spdk_json_val *params,
				     spdk_bdev_qos_op_cb cb_fn, void *cb_arg)
{
	struct rpc_bdev_set_qos_limit req = {{
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED,
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED,
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED,
			SPDK_BDEV_QOS_LIMIT_NOT_DEFINED
		}
	};
	int i;

	if (!spdk_thread_is_app_thread(NULL)) {
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	if (spdk_json_decode_object_relaxed(params, rpc_bdev_set_qos_limit_decoders,
					    SPDK_COUNTOF(rpc_bdev_set_qos_limit_decoders),
					    &req)) {
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (req.limits[i] != SPDK_BDEV_QOS_LIMIT_NOT_DEFINED) {
			break;
		}
	}
	if (i == SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES) {
		SPDK_ERRLOG("no rate limits specified\n");
		cb_fn(cb_arg, -EINVAL);
		return;
	}

	bdev_hybrid_qos_set_rate_limits(name, req.limits, cb_fn, cb_arg);
}

SPDK_LOG_REGISTER_COMPONENT(qos_hybrid)
