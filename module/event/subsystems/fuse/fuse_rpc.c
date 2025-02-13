/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/fuse.h"
#include "spdk/rpc.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/util.h"

struct rpc_fuse_set_options {
	struct spdk_fuse_opts opts;
	char *fstype;
};

#define opts_offsetof(opt) \
	(offsetof(struct rpc_fuse_set_options, opts) + offsetof(struct spdk_fuse_opts, opt))

static const struct spdk_json_object_decoder rpc_fuse_set_options_decoders[] = {
	{ "max_io_depth", opts_offsetof(max_io_depth), spdk_json_decode_uint64, true },
	{ "max_xfer_size", opts_offsetof(max_xfer_size), spdk_json_decode_uint64, true },
	{ "clone_fd", opts_offsetof(clone_fd), spdk_json_decode_bool, true },
	{ "fstype", offsetof(struct rpc_fuse_set_options, fstype), spdk_json_decode_string, true },
};

static void
free_rpc_fuse_set_options(struct rpc_fuse_set_options *rpc)
{
	free(rpc->fstype);
}

static void
rpc_fuse_set_options(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_fuse_set_options rpc = {};
	struct spdk_fuse_opts *opts = &rpc.opts;
	int rc;

	spdk_fuse_get_opts(&rpc.opts, sizeof(rpc.opts));
	if (spdk_json_decode_object_relaxed(params, rpc_fuse_set_options_decoders,
					    SPDK_COUNTOF(rpc_fuse_set_options_decoders),
					    &rpc)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(EINVAL));
		return;
	}

	opts->fstype = rpc.fstype ? rpc.fstype : opts->fstype;
	rc = spdk_fuse_set_opts(opts);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto out;
	}

	spdk_jsonrpc_send_bool_response(request, true);
out:
	free_rpc_fuse_set_options(&rpc);
}
SPDK_RPC_REGISTER("fuse_set_options", rpc_fuse_set_options, SPDK_RPC_STARTUP)
