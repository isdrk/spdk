/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2016 Intel Corporation. All rights reserved.
 *   Copyright (c) 2019 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights
 * reserved.
 */

#ifndef SPDK_BDEV_QOS_LIMIT_H
#define SPDK_BDEV_QOS_LIMIT_H

#include "spdk/stdinc.h"
#include "spdk/bdev.h"
#include "spdk_internal/bdev_qos_module.h"

#define SPDK_BDEV_QOS_LIMIT_NOT_DEFINED UINT64_MAX
#define SPDK_BDEV_QOS_TIMESLICE_IN_USEC 1000
#define SPDK_BDEV_QOS_MIN_IO_PER_TIMESLICE 1
#define SPDK_BDEV_QOS_MIN_BYTE_PER_TIMESLICE 512
#define SPDK_BDEV_QOS_MIN_IOS_PER_SEC		1000
#define SPDK_BDEV_QOS_MIN_BYTES_PER_SEC		(1024 * 1024)

void bdev_qos_limits_cache_init(struct bdev_qos_limits_cache *caches,
				struct bdev_qos_limits *limits);
void bdev_qos_limits_cache_reset(struct bdev_qos_limits_cache *caches,
				 struct bdev_qos_limits *limits);

void bdev_qos_limits_init(struct bdev_qos_limits *limits, uint32_t io_slice, uint32_t byte_slice);
void bdev_qos_limits_get(struct bdev_qos_limits *limits, uint64_t *values);
void bdev_qos_limits_set(struct bdev_qos_limits *limits, const uint64_t *values);
bool bdev_qos_limits_cache_queue_io(struct bdev_qos_limits_cache *cache,
				    struct bdev_qos_limits *limits,
				    struct spdk_bdev_io *bdev_io);
bool bdev_qos_limits_queue_io(struct bdev_qos_limits *limits,
			      struct spdk_bdev_io *bdev_io);
void bdev_qos_limits_reset_quota(struct bdev_qos_limits *limits, int timeslice_count);
bool bdev_qos_limit_values_check_disabled(const uint64_t *values);
void bdev_qos_limit_values_adjust(uint64_t *values);
bool bdev_qos_limits_check_disabled(struct bdev_qos_limits *limits);

#endif /* SPDK_BDEV_QOS_LIMIT_H */
