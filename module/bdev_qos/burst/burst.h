/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_BDEV_BURST_QOS_H
#define SPDK_BDEV_BURST_QOS_H

#include "spdk/stdinc.h"
#include "spdk/bdev.h"

struct bdev_burst_qos_opts {
	/* Size of this structure in bytes. */
	size_t opts_size;

	/* The period of a single tick in microseconds. */
	uint64_t tick_period_us;

	/* Maximum batch size to withdraw for IOPS limiting. */
	uint64_t max_io_withdraw_batch_size;

	/* Step size to increase the IOPS withdraw batch on success. */
	uint64_t io_additive_increase_step;

	/* Maximum batch size (in bytes) to withdraw for bandwidth limiting. */
	uint64_t max_byte_withdraw_batch_size;

	/* Step size to increase the bandwidth withdraw batch on success. */
	uint64_t byte_additive_increase_step;
} __attribute__((packed));
SPDK_STATIC_ASSERT(sizeof(struct bdev_burst_qos_opts) == 48, "Incorrect size");

void bdev_burst_qos_get_opts(struct bdev_burst_qos_opts *opts, size_t opts_size);

int bdev_burst_qos_set_opts(struct bdev_burst_qos_opts *opts);

void bdev_burst_qos_set_limit_json(struct spdk_bdev_qos *qos,
				   const struct spdk_json_val *params,
				   spdk_bdev_qos_op_cb cb_fn, void *cb_arg);

#endif /* SPDK_BDEV_BURST_QOS_H */
