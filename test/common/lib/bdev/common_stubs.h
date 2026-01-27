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
DEFINE_STUB(spdk_telemetry_register_type, int, (const char *name, const char **stat_names,
		uint64_t num_stats, struct spdk_telemetry_type **type), 0);
DEFINE_STUB_V(spdk_telemetry_unregister_type, (struct spdk_telemetry_type *type));
DEFINE_STUB(spdk_telemetry_register_source, int, (struct spdk_telemetry_type *type,
		const char *name, spdk_telemetry_pull_cb pull_cb, void *pull_cb_arg,
		struct spdk_telemetry_source **src), 0);
DEFINE_STUB_V(spdk_telemetry_unregister_source, (struct spdk_telemetry_source *src));
DEFINE_STUB(spdk_telemetry_source_get_stats, uint64_t *, (struct spdk_telemetry_source *src), NULL);
DEFINE_STUB(spdk_telemetry_source_get_num_stats, uint64_t, (struct spdk_telemetry_source *src), 0);
DEFINE_STUB_V(spdk_telemetry_source_pull_complete, (struct spdk_telemetry_source *src, int status));
