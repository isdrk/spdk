/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Filesystem device internal APIs
 */

#ifndef SPDK_FSDEV_INT_H
#define SPDK_FSDEV_INT_H

#include "spdk/thread.h"

void fsdev_io_submit(struct spdk_fsdev_io *fsdev_io);
struct spdk_fsdev_io *fsdev_channel_get_io(struct spdk_fsdev_channel *channel);

#define __io_ch_to_fsdev_ch(io_ch)	((struct spdk_fsdev_channel *)spdk_io_channel_get_ctx(io_ch))

typedef TAILQ_HEAD(, spdk_fsdev_io) fsdev_io_tailq_t;

struct spdk_fsdev_channel {
	struct spdk_fsdev	*fsdev;

	/* The channel for the underlying device */
	struct spdk_io_channel	*channel;

	/* Per io_device per thread data */
	struct spdk_fsdev_shared_resource *shared_resource;

	/*
	 * Count of I/O submitted to the underlying dev module through this channel
	 * and waiting for completion.
	 */
	uint64_t		io_outstanding;

	/*
	 * List of all submitted I/Os.
	 */
	fsdev_io_tailq_t	io_submitted;

	/* Channel flags */
	uint32_t		flags;

	/* Stat */
	struct spdk_fsdev_io_stat *stat;
};

#endif /* SPDK_FSDEV_INT_H */
