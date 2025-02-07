/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/fuse.h"
#include "spdk/init.h"
#include "spdk/stdinc.h"

static void
fuse_subsystem_init(void)
{
	struct spdk_fuse_opts opts;
	int rc;

	spdk_fuse_get_opts(&opts, sizeof(opts));
	rc = spdk_fuse_init(&opts);

	spdk_subsystem_init_next(rc);
}

static void
fuse_subsystem_fini(void)
{
	spdk_fuse_cleanup();
	spdk_subsystem_fini_next();
}

static struct spdk_subsystem g_fuse_subsystem = {
	.name = "fuse",
	.init = fuse_subsystem_init,
	.fini = fuse_subsystem_fini,
};

SPDK_SUBSYSTEM_REGISTER(g_fuse_subsystem);
