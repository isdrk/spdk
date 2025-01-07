/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/rmem.h"

static void
rpc_rmem_get_config(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;

	if (params) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "'rmem_get_config' requires no arguments");
		return;
	}


	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_object_begin(w);
	spdk_rmem_dump_info_json(w);
	spdk_json_write_object_end(w);
	spdk_jsonrpc_end_result(request, w);
}
SPDK_RPC_REGISTER("rmem_get_config", rpc_rmem_get_config, SPDK_RPC_RUNTIME)

struct rpc_rmem_enable {
	char *backend_dir;
};

static const struct spdk_json_object_decoder rpc_rmem_enable_decoders[] = {
	{"backend_dir", offsetof(struct rpc_rmem_enable, backend_dir), spdk_json_decode_string, true},
};

static void
rpc_rmem_enable(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_rmem_enable req = {0};
	bool rc;

	if (params && spdk_json_decode_object(params, rpc_rmem_enable_decoders,
					      SPDK_COUNTOF(rpc_rmem_enable_decoders),
					      &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		return;
	}

	rc = spdk_rmem_enable(req.backend_dir);

	free(req.backend_dir);
	spdk_jsonrpc_send_bool_response(request, rc);
}
SPDK_RPC_REGISTER("rmem_enable", rpc_rmem_enable, SPDK_RPC_STARTUP)
