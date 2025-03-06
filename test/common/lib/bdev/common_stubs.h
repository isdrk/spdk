/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk_internal/mock.h"

DEFINE_STUB(spdk_notify_send, uint64_t, (const char *type, const char *ctx), 0);
DEFINE_STUB(spdk_notify_type_register, struct spdk_notify_type *, (const char *type), NULL);
DEFINE_STUB(spdk_memory_domain_get_dma_device_id, const char *, (struct spdk_memory_domain *domain),
	    "test_domain");
DEFINE_STUB(spdk_memory_domain_get_dma_device_type, enum spdk_dma_device_type,
	    (struct spdk_memory_domain *domain), 0);
