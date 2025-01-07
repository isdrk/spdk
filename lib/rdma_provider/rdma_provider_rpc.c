/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk_internal/rdma_provider.h"

static void
rpc_rdma_provider_get_opts(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;
	struct spdk_rdma_provider_opts opts = {};
	int rc;

	if (params) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "'rdma_provider_get_opts' requires no arguments");
		return;
	}

	rc = spdk_rdma_provider_get_opts(&opts, sizeof(opts));
	if (rc) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "spdk_rdma_provider_get_opts failed with %d", rc);
		return;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_object_begin(w);
	spdk_json_write_named_bool(w, "support_offload_on_qp", opts.support_offload_on_qp);
	spdk_json_write_object_end(w);
	spdk_jsonrpc_end_result(request, w);
}
SPDK_RPC_REGISTER("rdma_provider_get_opts", rpc_rdma_provider_get_opts, SPDK_RPC_RUNTIME)

static const struct spdk_json_object_decoder rpc_rdma_provider_set_opts_decoders[] = {
	{"support_offload_on_qp", offsetof(struct spdk_rdma_provider_opts, support_offload_on_qp), spdk_json_decode_bool, false},
};

static void
rpc_rdma_provider_set_opts(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	int rc;
	struct spdk_rdma_provider_opts opts = {};

	rc = spdk_rdma_provider_get_opts(&opts, sizeof(opts));
	if (rc) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "spdk_rdma_provider_get_opts failed with %d", rc);
		return;
	}

	if (spdk_json_decode_object(params, rpc_rdma_provider_set_opts_decoders,
				    SPDK_COUNTOF(rpc_rdma_provider_set_opts_decoders),
				    &opts)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		return;
	}

	rc = spdk_rdma_provider_set_opts(&opts);
	if (rc) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "spdk_rdma_provider_set_opts failed with %d", rc);
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}
SPDK_RPC_REGISTER("rdma_provider_set_opts", rpc_rdma_provider_set_opts, SPDK_RPC_STARTUP)
