/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_INTERNAL_BDEV_QOS_MODULE_H
#define SPDK_INTERNAL_BDEV_QOS_MODULE_H

#include "spdk/stdinc.h"
#include "spdk/bdev.h"

struct spdk_bdev_qos_channel;
struct spdk_bdev_qos_impl;

/** Abstract base class for module-dependent object per QoS channel */
struct spdk_bdev_qos_channel_impl {
	struct spdk_bdev_qos_channel *qos_ch;

	struct spdk_bdev_qos_impl *qos_impl;
};

/** Abstract base class for module-dependent object per QoS device */
struct spdk_bdev_qos_impl {
	struct spdk_bdev_qos *qos;

	struct spdk_bdev_qos_module *module;
};

/** QoS module */
struct spdk_bdev_qos_module {
	const char *name;

	/**
	 * Initialization function for the module. Called by the bdev library during startup.
	 */
	int (*module_init)(void);

	/**
	 * Finish function for the module. Called by the bdev library after all QoS devices
	 * have been destroyed. This allows the module to do any final cleanup before the bdev
	 * library finishes operation.
	 */
	void (*module_fini)(void);

	/**
	 * Allocate a module-dependent object per QoS device.
	 */
	struct spdk_bdev_qos_impl *(*get_impl)(void);

	/**
	 * Free the module-dependent object per QoS device.
	 */
	void (*put_impl)(struct spdk_bdev_qos_impl *qos_impl);

	/**
	 * Output RPC configuration to a JSON stream for the module-dependent object of a QoS device.
	 */
	void (*config_json)(struct spdk_bdev_qos_impl *qos_impl, struct spdk_json_write_ctx *w);

	/**
	 * Output information to a JSON stream for the module-dependent object of a QoS device.
	 */
	void (*info_json)(struct spdk_bdev_qos_impl *qos_impl, struct spdk_json_write_ctx *w);

	/**
	 * Allocate a module-dependent object per QoS channel.
	 */
	struct spdk_bdev_qos_channel_impl *(*get_channel_impl)(struct spdk_bdev_qos_impl *qos_impl);

	/**
	 * Free the module-dependent object per QoS channel.
	 */
	void (*put_channel_impl)(struct spdk_bdev_qos_channel_impl *qos_ch_impl);

	/**
	 * Process the module's QoS rate limit check for the I/O. If the check passed, the module
	 * must call spdk_bdev_qos_module_allow_io() for the I/O.
	 */
	void (*queue_io)(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
			 struct spdk_bdev_io *bdev_io);

	/**
	 * Try aborting the I/O if it is queued in the module-dependent object per QoS channel.
	 * The bdev layer will use this function in spdk_bdev_abort().
	 * The module must use spdk_bdev_abort_queued_io() to actually abort the I/O.
	 */
	bool (*abort_queued_io)(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
				struct spdk_bdev_io *bdev_io);

	/**
	 * Unblock all I/Os queued in the module-dependent object per QoS channel.
	 * The bdev layer will call this function just before freeing the module-dependent object
	 * per QoS channel via put_channel_impl.
	 * The module must use spdk_bdev_unblock_queued_io() to actually unblock I/Os.
	 */
	void (*unblock_all_queued_io)(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
				      struct spdk_bdev_channel *bdev_ch);

	/*
	 * Abort all I/Os queued in the module-dependent object per QoS channel.
	 * The bdev layer will use this function during spdk_bdev_reset().
	 * The module must use spdk_bdev_abort_all_queued_io() to actually abort I/Os.
	 */
	void (*abort_all_queued_io)(struct spdk_bdev_qos_channel_impl *qos_ch_impl,
				    struct spdk_bdev_channel *bdev_ch);

	/**
	 * Denote if the module_fini function may complete asynchronously. If set to true
	 * finishing has to be explicitly completed by calling spdk_bdev_qos_module_fini_done().
	 */
	bool async_fini;
};

/**
 * Add the given module to the list of the registered modules.
 * This function should be invoked by referencing the macro
 * SPDK_BDEV_QOS_MODULE_REGISTER in the module c file.
 *
 * \param qos_module Module to be added.
 */
void spdk_bdev_qos_module_list_add(struct spdk_bdev_qos_module *qos_module);

/*
 *  Macro used to register module for later initialization.
 */
#define SPDK_BDEV_QOS_MODULE_REGISTER(name, module) \
static void __attribute__((constructor)) _spdk_bdev_qos_module_register_##name(void) \
{ \
        spdk_bdev_qos_module_list_add(module); \
}

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

	/** QoS implementation provided by QoS module. */
	struct spdk_bdev_qos_impl *impl;

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

	/** QoS channel implementation provided by QoS module. */
	struct spdk_bdev_qos_channel_impl *impl;

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
