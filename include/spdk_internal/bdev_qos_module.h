/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_INTERNAL_BDEV_QOS_MODULE_H
#define SPDK_INTERNAL_BDEV_QOS_MODULE_H

#include "spdk/stdinc.h"
#include "spdk/bdev.h"

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

struct spdk_bdev_qos_desc;

struct spdk_bdev_qos {
	/** QoS rate limits. */
	struct bdev_qos_limits limits;

	bdev_io_tailq_t queued_io;

	struct spdk_spinlock spinlock;

	TAILQ_ENTRY(spdk_bdev_qos) tailq;

	/** Name of the QoS object. */
	char *name;

	bool pending_unregister;

	/** List of open descriptors for this QoS object. */
	TAILQ_HEAD(, spdk_bdev_qos_desc) open_descs;

	/** List of user bdevs of this QoS object. */
	TAILQ_HEAD(, spdk_bdev) bdevs;

	/** Parent QoS object. */
	struct spdk_bdev_qos *parent;

	/** Child QoS list. */
	TAILQ_HEAD(, spdk_bdev_qos) children;

	/** Link pointer to the sibling QoS list. */
	TAILQ_ENTRY(spdk_bdev_qos) sibling_link;
};

struct spdk_bdev_qos_channel;

struct spdk_bdev_qos_poll_group {
	/** List of QoS I/Os waiting for submission. */
	bdev_io_tailq_t allowed_io;

	struct spdk_spinlock spinlock;

	TAILQ_HEAD(, spdk_bdev_qos_channel) qos_ch_list;
};

struct spdk_bdev_qos_channel {
	/** Borrowed QoS rate limits. */
	struct bdev_qos_limits_cache limits;

	/** Global QoS rate limits pool */
	struct spdk_bdev_qos *qos;

	/** Poll group to which this cache belongs. */
	struct spdk_bdev_qos_poll_group *group;

	/** Pointer to parent QoS channel. */
	struct spdk_bdev_qos_channel *parent_ch;

	TAILQ_ENTRY(spdk_bdev_qos_channel) link;
};

/**
 * Notify that the bdev I/O passed the current QoS limit check
 * to move to the next QoS limit check.
 *
 * \param bdev_io The bdev_io
 */
void spdk_bdev_qos_module_allow_io(struct spdk_bdev_io *bdev_io);

#endif /* SPDK_INTERNAL_BDEV_QOS_MODULE_H */
