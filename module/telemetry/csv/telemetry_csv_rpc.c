/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/rpc.h"
#include "spdk/json.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "telemetry_csv_internal.h"

struct rpc_telemetry_csv_create_ctx {
	char *dst_dir;
};

static const struct spdk_json_object_decoder rpc_telemetry_csv_create_ctx[] = {
	{"dst_dir", offsetof(struct rpc_telemetry_csv_create_ctx, dst_dir), spdk_json_decode_string},
};

static void
rpc_telemetry_csv_create(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	int res;

	struct rpc_telemetry_csv_create_ctx ctx = {};

	if (spdk_json_decode_object(params, rpc_telemetry_csv_create_ctx,
				    SPDK_COUNTOF(rpc_telemetry_csv_create_ctx),
				    &ctx)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");

		goto do_return;
	}

	res = telemetry_csv_create(ctx.dst_dir);
	if (res != 0) {
		SPDK_ERRLOG("telemetry_csv_create failed: %s\n", spdk_strerror(-res));
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, spdk_strerror(-res));
		goto do_return;
	}

	spdk_jsonrpc_send_bool_response(request, true);

do_return:
	free(ctx.dst_dir);
}
SPDK_RPC_REGISTER("telemetry_csv_create", rpc_telemetry_csv_create, SPDK_RPC_RUNTIME)

static void
rpc_telemetry_csv_delete(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	int res;

	if (params != NULL) {
		SPDK_ERRLOG("telemetry_csv_create requires no parameters\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "telemetry_csv_create requires no parameters");
		return;
	}

	res = telemetry_csv_delete();
	if (res != 0) {
		SPDK_ERRLOG("telemetry_csv_delete failed: %s\n", spdk_strerror(-res));
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, spdk_strerror(-res));
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}
SPDK_RPC_REGISTER("telemetry_csv_delete", rpc_telemetry_csv_delete, SPDK_RPC_RUNTIME)
