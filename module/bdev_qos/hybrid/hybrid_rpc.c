/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/bdev.h"

#include "spdk/env.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/bdev_module.h"

#include "spdk/log.h"

#include "spdk_internal/bdev_qos_module.h"

#include "hybrid.h"

static void
dummy_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *ctx)
{
}

static const struct spdk_json_object_decoder rpc_qos_set_opts_decoders[] = {
	{"io_slice", offsetof(struct bdev_hybrid_qos_opts, io_slice), spdk_json_decode_uint32, true},
	{"byte_slice", offsetof(struct bdev_hybrid_qos_opts, byte_slice), spdk_json_decode_uint32, true},
	{"timeslice_us", offsetof(struct bdev_hybrid_qos_opts, timeslice_us), spdk_json_decode_uint32, true},
};

static void
rpc_hybrid_qos_set_options(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct bdev_hybrid_qos_opts opts;
	int rc;

	bdev_hybrid_qos_get_opts(&opts);

	if (params != NULL) {
		if (spdk_json_decode_object(params, rpc_qos_set_opts_decoders,
					    SPDK_COUNTOF(rpc_qos_set_opts_decoders), &opts)) {
			SPDK_ERRLOG("spdk_json_decode_object() failed\n");
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
							 "Invalid parameters");
			return;
		}
	}

	rc = bdev_hybrid_qos_set_opts(&opts);
	if (rc == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
	}
}
SPDK_RPC_REGISTER("bdev_hybrid_qos_set_options", rpc_hybrid_qos_set_options, SPDK_RPC_STARTUP)

struct rpc_bdev_qos {
	char	*name;
};

static void
free_rpc_bdev_qos(struct rpc_bdev_qos *r)
{
	free(r->name);
}

static const struct spdk_json_object_decoder rpc_bdev_qos_decoders[] = {
	{"name", offsetof(struct rpc_bdev_qos, name), spdk_json_decode_string},
};

struct rpc_bdev_qos_ctx {
	struct spdk_jsonrpc_request	*request;
	struct spdk_bdev_desc		*desc;
};

static void
rpc_bdev_set_qos_limit_complete(void *cb_arg, int status)
{
	struct rpc_bdev_qos_ctx *ctx = cb_arg;

	if (status == 0) {
		spdk_jsonrpc_send_bool_response(ctx->request, true);
	} else {
		spdk_jsonrpc_send_error_response_fmt(ctx->request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Failed to configure rate limit: %s",
						     spdk_strerror(-status));
	}

	spdk_bdev_close(ctx->desc);
	free(ctx);
}

static void
rpc_bdev_set_qos_limit(struct spdk_jsonrpc_request *request,
		       const struct spdk_json_val *params)
{
	struct rpc_bdev_qos req = {NULL};
	struct spdk_bdev_desc *desc;
	struct rpc_bdev_qos_ctx *ctx;
	int rc;

	if (spdk_json_decode_object_relaxed(params, rpc_bdev_qos_decoders,
					    SPDK_COUNTOF(rpc_bdev_qos_decoders),
					    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = spdk_bdev_open_ext(req.name, false, dummy_bdev_event_cb, NULL, &desc);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to open bdev '%s': %d\n", req.name, rc);
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		spdk_bdev_close(desc);
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		goto cleanup;
	}

	ctx->request = request;
	ctx->desc = desc;

	bdev_set_hybrid_qos_rate_limits_json(spdk_bdev_desc_get_bdev(desc), params,
					     rpc_bdev_set_qos_limit_complete, ctx);

cleanup:
	free_rpc_bdev_qos(&req);
}

SPDK_RPC_REGISTER("bdev_set_qos_limit", rpc_bdev_set_qos_limit, SPDK_RPC_RUNTIME)

static void
rpc_bdev_hybrid_qos_set_limit_complete(void *cb_arg, int status)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (status == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Failed to configure rate limit: %s",
						     spdk_strerror(-status));
	}
}

static void
rpc_bdev_hybrid_qos_set_limit(struct spdk_jsonrpc_request *request,
			      const struct spdk_json_val *params)
{
	struct rpc_bdev_qos req = {NULL};

	if (spdk_json_decode_object_relaxed(params, rpc_bdev_qos_decoders,
					    SPDK_COUNTOF(rpc_bdev_qos_decoders),
					    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev_hybrid_qos_set_rate_limits_json(req.name, params,
					     rpc_bdev_hybrid_qos_set_limit_complete, request);

cleanup:
	free_rpc_bdev_qos(&req);
}

SPDK_RPC_REGISTER("bdev_hybrid_qos_set_limit", rpc_bdev_hybrid_qos_set_limit, SPDK_RPC_RUNTIME)
