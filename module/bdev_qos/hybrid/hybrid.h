/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_BDEV_HYBRID_QOS_H
#define SPDK_BDEV_HYBRID_QOS_H

#include "spdk/stdinc.h"
#include "spdk/bdev.h"

void bdev_set_hybrid_qos_rate_limits_json(struct spdk_bdev *bdev,
		const struct spdk_json_val *params,
		spdk_bdev_qos_op_cb cb_fn, void *cb_arg);

void bdev_hybrid_qos_set_rate_limits_json(const char *name,
		const struct spdk_json_val *params,
		spdk_bdev_qos_op_cb cb_fn, void *cb_arg);

#endif /* SPDK_BDEV_HYBRID_QOS_H */
