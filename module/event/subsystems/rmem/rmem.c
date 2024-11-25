/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/env.h"
#include "spdk/thread.h"

#include "spdk/init.h"
#include "spdk/env.h"
#include "spdk/rmem.h"

static void
rmem_subsystem_init(void)
{
	int rc = spdk_rmem_init();
	spdk_subsystem_init_next(rc);
}

static void
rmem_subsystem_fini(void)
{
	spdk_rmem_fini();
	spdk_subsystem_fini_next();
}

static void
rmem_subsystem_config_json(struct spdk_json_write_ctx *w)
{
	spdk_rmem_subsystem_config_json(w);
}

static struct spdk_subsystem g_spdk_subsystem_rmem = {
	.name = "rmem_pool",
	.init = rmem_subsystem_init,
	.fini = rmem_subsystem_fini,
	.write_config_json = rmem_subsystem_config_json,
};

SPDK_SUBSYSTEM_REGISTER(g_spdk_subsystem_rmem);
