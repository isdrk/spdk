/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk_internal/rdma_provider.h"
#include "spdk/init.h"

static void
rdma_provider_subsystem_initialize(void)
{
	spdk_subsystem_init_next(0);
}

static void
rdma_provider_subsystem_finish(void)
{
	spdk_subsystem_fini_next();
}

static void
rdma_provider_subsystem_config_json(struct spdk_json_write_ctx *w)
{
	spdk_rdma_provider_subsystem_config_json(w);
}

static struct spdk_subsystem g_spdk_subsystem_rdma_provider = {
	.name = "rdma_provider",
	.init = rdma_provider_subsystem_initialize,
	.fini = rdma_provider_subsystem_finish,
	.write_config_json = rdma_provider_subsystem_config_json,
};

SPDK_SUBSYSTEM_REGISTER(g_spdk_subsystem_rdma_provider);
