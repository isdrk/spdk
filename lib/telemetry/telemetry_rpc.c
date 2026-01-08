/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/telemetry.h"
#include "telemetry_internal.h"

struct rpc_telemetry_start_opts {
	struct spdk_telemetry_opts opts;
	struct spdk_jsonrpc_request *request;
};

static const struct spdk_json_object_decoder rpc_telemetry_start_opts[] = {
	{"interval_ms", offsetof(struct rpc_telemetry_start_opts, opts.interval_ms), spdk_json_decode_uint64, true},
};

static void
rpc_telemetry_start_done_cb(void *cb_arg, int rc)
{
	struct rpc_telemetry_start_opts *opts = cb_arg;

	if (rc) {
		SPDK_ERRLOG("Failed to start telemetry: rc %d\n", rc);
		spdk_jsonrpc_send_error_response_fmt(opts->request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						     "Failed to start telemetry: rc %d", rc);
		goto do_return;
	}

	spdk_jsonrpc_send_bool_response(opts->request, true);

do_return:
	free(opts);
}

static void
rpc_telemetry_start(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_telemetry_start_opts *opts;

	opts = calloc(1, sizeof(*opts));
	if (opts == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for opts\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "Failed to allocate memory for opts");
		return;
	}

	if (spdk_json_decode_object(params, rpc_telemetry_start_opts,
				    SPDK_COUNTOF(rpc_telemetry_start_opts),
				    opts)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		free(opts);
		return;
	}

	opts->request = request;

	spdk_telemetry_start(&opts->opts, rpc_telemetry_start_done_cb, opts);
}
SPDK_RPC_REGISTER("telemetry_start", rpc_telemetry_start, SPDK_RPC_RUNTIME);

static void
rpc_telemetry_stop_done_cb(void *cb_arg, int rc)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (rc) {
		SPDK_ERRLOG("Failed to stop telemetry: rc %d\n", rc);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, spdk_strerror(-rc));
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}

static void
rpc_telemetry_stop(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	if (params != NULL) {
		spdk_jsonrpc_send_error_response(request,
						 SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "No parameters required");
		return;
	}

	spdk_telemetry_stop(rpc_telemetry_stop_done_cb, request);
}
SPDK_RPC_REGISTER("telemetry_stop", rpc_telemetry_stop, SPDK_RPC_RUNTIME);

static void
rpc_telemetry_get_info(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;

	if (params != NULL) {
		spdk_jsonrpc_send_error_response(request,
						 SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "No parameters required");
		return;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_telemetry_dump_info_json(w);
	spdk_jsonrpc_end_result(request, w);
}
SPDK_RPC_REGISTER("telemetry_get_info", rpc_telemetry_get_info, SPDK_RPC_RUNTIME)

struct rpc_telemetry_type_opts {
	char *name;
};

static const struct spdk_json_object_decoder rpc_telemetry_type_opts[] = {
	{"name", offsetof(struct rpc_telemetry_type_opts, name), spdk_json_decode_string, false},
};

static void
rpc_telemetry_get_types(struct spdk_jsonrpc_request *request,
			const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;
	struct rpc_telemetry_type_opts opts = {};

	if (params && spdk_json_decode_object(params, rpc_telemetry_type_opts,
					      SPDK_COUNTOF(rpc_telemetry_type_opts),
					      &opts)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		goto do_return;
	}

	w = spdk_jsonrpc_begin_result(request);
	telemetry_dump_types_json(w, opts.name);
	spdk_jsonrpc_end_result(request, w);

do_return:
	free(opts.name);
}
SPDK_RPC_REGISTER("telemetry_get_types", rpc_telemetry_get_types,
		  SPDK_RPC_STARTUP | SPDK_RPC_RUNTIME)

static void
rpc_telemetry_enable_type(struct spdk_jsonrpc_request *request,
			  const struct spdk_json_val *params)
{
	struct rpc_telemetry_type_opts opts = {};
	int rc;

	if (spdk_json_decode_object(params, rpc_telemetry_type_opts,
				    SPDK_COUNTOF(rpc_telemetry_type_opts),
				    &opts)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		goto do_return;
	}


	rc = telemetry_type_enable(opts.name, true);
	if (rc) {
		SPDK_ERRLOG("Failed to enable telemetry type %s: rc %d\n", opts.name, rc);
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						     "Failed to enable telemetry type %s: %s", opts.name, spdk_strerror(-rc));
		goto do_return;
	}

	spdk_jsonrpc_send_bool_response(request, true);

do_return:
	free(opts.name);
}
SPDK_RPC_REGISTER("telemetry_enable_type", rpc_telemetry_enable_type, SPDK_RPC_RUNTIME)

static void
rpc_telemetry_disable_type(struct spdk_jsonrpc_request *request,
			   const struct spdk_json_val *params)
{
	struct rpc_telemetry_type_opts opts = {};
	int rc;

	if (spdk_json_decode_object(params, rpc_telemetry_type_opts,
				    SPDK_COUNTOF(rpc_telemetry_type_opts),
				    &opts)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		goto do_return;
	}


	rc = telemetry_type_enable(opts.name, false);
	if (rc) {
		SPDK_ERRLOG("Failed to disable telemetry type %s: rc %d\n", opts.name, rc);
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						     "Failed to disable telemetry type %s: %s", opts.name, spdk_strerror(-rc));
		goto do_return;
	}

	spdk_jsonrpc_send_bool_response(request, true);

do_return:
	free(opts.name);
}
SPDK_RPC_REGISTER("telemetry_disable_type", rpc_telemetry_disable_type, SPDK_RPC_RUNTIME)
