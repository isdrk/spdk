/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/fuse.h"
#include "spdk/init.h"
#include "spdk/json.h"
#include "spdk/stdinc.h"

static void
fuse_subsystem_init(void)
{
	int rc;

	rc = spdk_fuse_init(NULL);

	spdk_subsystem_init_next(rc);
}

static void
fuse_subsystem_fini(void)
{
	spdk_fuse_cleanup();
	spdk_subsystem_fini_next();
}

static void
fuse_subsystem_write_config_json(struct spdk_json_write_ctx *w)
{
	struct spdk_fuse_opts opts;

	spdk_json_write_array_begin(w);

	spdk_fuse_get_opts(&opts, sizeof(opts));
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "method", "fuse_set_options");
	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_uint64(w, "max_io_depth", opts.max_io_depth);
	spdk_json_write_named_uint64(w, "max_xfer_size", opts.max_xfer_size);
	spdk_json_write_named_bool(w, "clone_fd", opts.clone_fd);
	spdk_json_write_named_string(w, "fstype", opts.fstype);
	spdk_json_write_object_end(w);
	spdk_json_write_object_end(w);

	spdk_json_write_array_end(w);
}

static struct spdk_subsystem g_fuse_subsystem = {
	.name = "fuse",
	.init = fuse_subsystem_init,
	.fini = fuse_subsystem_fini,
	.write_config_json = fuse_subsystem_write_config_json,
};

SPDK_SUBSYSTEM_REGISTER(g_fuse_subsystem);
