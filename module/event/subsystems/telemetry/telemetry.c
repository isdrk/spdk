/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/telemetry.h"
#include "spdk/env.h"
#include "spdk/thread.h"

#include "spdk/init.h"

static void
telemetry_subsystem_init(void)
{
	int rc = spdk_telemetry_init();

	spdk_subsystem_init_next(rc);
}

static void
telemetry_subsystem_fini_done(void *cb_arg, int rc)
{
	spdk_subsystem_fini_next();
}

static void
telemetry_subsystem_fini(void)
{
	spdk_telemetry_fini(telemetry_subsystem_fini_done, NULL);
}

static void
telemetry_write_config_json(struct spdk_json_write_ctx *w)
{
	spdk_telemetry_write_config_json(w);
}

static struct spdk_subsystem g_spdk_subsystem_telemetry = {
	.name = "telemetry",
	.init = telemetry_subsystem_init,
	.fini = telemetry_subsystem_fini,
	.write_config_json = telemetry_write_config_json,
};

SPDK_SUBSYSTEM_REGISTER(g_spdk_subsystem_telemetry);
