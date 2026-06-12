/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk_internal/rdma_provider.h"
#include "spdk_internal/rdma_utils.h"

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

#define RPC_RDMA_PROVIDER_WC_STATUS_UNSET INT32_MIN

enum rdma_provider_error_type {
	RDMA_PROVIDER_ERROR_TYPE_CQ,
	RDMA_PROVIDER_ERROR_TYPE_MKEY,
	RDMA_PROVIDER_ERROR_TYPE_RQ,
	RDMA_PROVIDER_ERROR_TYPE_SQ,
	RDMA_PROVIDER_ERROR_TYPE_INVALID,
};

typedef enum rdma_provider_error_type rdma_provider_error_type_t;

static rdma_provider_error_type_t
rdma_provider_parse_error_type(const char *type)
{
	if (type == NULL) {
		return RDMA_PROVIDER_ERROR_TYPE_INVALID;
	}
	if (strcmp(type, "cq") == 0) {
		return RDMA_PROVIDER_ERROR_TYPE_CQ;
	}
	if (strcmp(type, "mkey") == 0) {
		return RDMA_PROVIDER_ERROR_TYPE_MKEY;
	}
	if (strcmp(type, "rq") == 0) {
		return RDMA_PROVIDER_ERROR_TYPE_RQ;
	}
	if (strcmp(type, "sq") == 0) {
		return RDMA_PROVIDER_ERROR_TYPE_SQ;
	}
	return RDMA_PROVIDER_ERROR_TYPE_INVALID;
}

struct rpc_rdma_provider_inject_error {
	char *type;
	uint32_t rate_num;
	uint32_t rate_denom;
	int32_t wc_status;
};

static const struct spdk_json_object_decoder rpc_rdma_provider_inject_error_decoders[] = {
	{"type", offsetof(struct rpc_rdma_provider_inject_error, type), spdk_json_decode_string},
	{"rate_num", offsetof(struct rpc_rdma_provider_inject_error, rate_num), spdk_json_decode_uint32},
	{"rate_denom", offsetof(struct rpc_rdma_provider_inject_error, rate_denom), spdk_json_decode_uint32},
	{"wc_status", offsetof(struct rpc_rdma_provider_inject_error, wc_status), spdk_json_decode_int32, true},
};

static void
rpc_rdma_provider_inject_error(struct spdk_jsonrpc_request *request,
			       const struct spdk_json_val *params)
{
	struct rpc_rdma_provider_inject_error req = {.wc_status = RPC_RDMA_PROVIDER_WC_STATUS_UNSET};
	enum rdma_provider_error_type error_type = RDMA_PROVIDER_ERROR_TYPE_INVALID;
	int rc = 0;

	if (spdk_json_decode_object(params, rpc_rdma_provider_inject_error_decoders,
				    SPDK_COUNTOF(rpc_rdma_provider_inject_error_decoders), &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		goto out;
	}

	error_type = rdma_provider_parse_error_type(req.type);

	if (error_type != RDMA_PROVIDER_ERROR_TYPE_CQ &&
	    req.wc_status != RPC_RDMA_PROVIDER_WC_STATUS_UNSET) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "'wc_status' is only valid for the 'cq' error type");
		goto out;
	}

	switch (error_type) {
	case RDMA_PROVIDER_ERROR_TYPE_CQ: {
		enum ibv_wc_status status = IBV_WC_GENERAL_ERR;

		if (req.wc_status != RPC_RDMA_PROVIDER_WC_STATUS_UNSET) {
			if (req.wc_status < IBV_WC_SUCCESS || req.wc_status > IBV_WC_TM_RNDV_INCOMPLETE) {
				spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
								     "Invalid wc_status %d", req.wc_status);
				goto out;
			}
			status = (enum ibv_wc_status)req.wc_status;
		}

		rc = spdk_rdma_utils_inject_wc_error(status, req.rate_num, req.rate_denom);
		break;
	}
	case RDMA_PROVIDER_ERROR_TYPE_MKEY:
		rc = spdk_rdma_utils_inject_memory_translation_error(req.rate_num, req.rate_denom);
		break;
	case RDMA_PROVIDER_ERROR_TYPE_RQ:
		rc = spdk_rdma_provider_inject_recv_wr_error(req.rate_num, req.rate_denom);
		break;
	case RDMA_PROVIDER_ERROR_TYPE_SQ:
		rc = spdk_rdma_provider_inject_send_wr_error(req.rate_num, req.rate_denom);
		break;
	default:
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Invalid error type '%s', expected 'cq', 'mkey', 'rq' or 'sq'", req.type);
		goto out;
	}

	if (rc) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto out;
	}

	spdk_jsonrpc_send_bool_response(request, true);
out:
	free(req.type);
}
SPDK_RPC_REGISTER("rdma_provider_inject_error", rpc_rdma_provider_inject_error, SPDK_RPC_RUNTIME)

struct rpc_rdma_provider_cancel_error {
	char *type;
};

static const struct spdk_json_object_decoder rpc_rdma_provider_cancel_error_decoders[] = {
	{"type", offsetof(struct rpc_rdma_provider_cancel_error, type), spdk_json_decode_string},
};

static void
rpc_rdma_provider_cancel_error(struct spdk_jsonrpc_request *request,
			       const struct spdk_json_val *params)
{
	struct rpc_rdma_provider_cancel_error req = {};

	if (spdk_json_decode_object(params, rpc_rdma_provider_cancel_error_decoders,
				    SPDK_COUNTOF(rpc_rdma_provider_cancel_error_decoders), &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		goto out;
	}

	switch (rdma_provider_parse_error_type(req.type)) {
	case RDMA_PROVIDER_ERROR_TYPE_CQ:
		spdk_rdma_utils_cancel_wc_error();
		break;
	case RDMA_PROVIDER_ERROR_TYPE_MKEY:
		spdk_rdma_utils_cancel_memory_translation_error();
		break;
	case RDMA_PROVIDER_ERROR_TYPE_RQ:
		spdk_rdma_provider_cancel_recv_wr_error();
		break;
	case RDMA_PROVIDER_ERROR_TYPE_SQ:
		spdk_rdma_provider_cancel_send_wr_error();
		break;
	default:
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Invalid error type '%s', expected 'cq', 'mkey', 'rq' or 'sq'", req.type);
		goto out;
	}

	spdk_jsonrpc_send_bool_response(request, true);
out:
	free(req.type);
}
SPDK_RPC_REGISTER("rdma_provider_cancel_error", rpc_rdma_provider_cancel_error, SPDK_RPC_RUNTIME)
