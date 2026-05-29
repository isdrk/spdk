/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "bdev_kvmalloc.h"
#include "spdk/rpc.h"
#include "spdk/string.h"
#include "spdk/log.h"

static void
free_rpc_construct_kvmalloc(struct kvmalloc_bdev_opts *r)
{
	free(r->name);
}

static const struct spdk_json_object_decoder rpc_bdev_kvmalloc_create_decoders[] = {
	{"name", offsetof(struct kvmalloc_bdev_opts, name), spdk_json_decode_string, true},
	{"uuid", offsetof(struct kvmalloc_bdev_opts, uuid), spdk_json_decode_uuid, true},
	{"max_key_size", offsetof(struct kvmalloc_bdev_opts, max_key_size), spdk_json_decode_uint32, true},
	{"max_value_size", offsetof(struct kvmalloc_bdev_opts, max_value_size), spdk_json_decode_uint32, true},
	{"optimal_value_granularity", offsetof(struct kvmalloc_bdev_opts, optimal_value_granularity), spdk_json_decode_uint32, true},
	{"numa_id", offsetof(struct kvmalloc_bdev_opts, numa_id), spdk_json_decode_int32, true},
};

static void
rpc_bdev_kvmalloc_create(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct kvmalloc_bdev_opts req = {NULL};
	struct spdk_json_write_ctx *w;
	struct spdk_bdev *bdev;
	int rc = 0;

	req.numa_id = SPDK_ENV_NUMA_ID_ANY;

	if (spdk_json_decode_object(params, rpc_bdev_kvmalloc_create_decoders,
				    SPDK_COUNTOF(rpc_bdev_kvmalloc_create_decoders),
				    &req)) {
		SPDK_DEBUGLOG(bdev_kvmalloc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	/* Validate parameters. A value of 0 means "not specified" (use default). */
	if (req.max_key_size > 16) {
		spdk_jsonrpc_send_error_response(request, -EINVAL,
						 "max_key_size must not exceed 16");
		goto cleanup;
	}

	if (req.max_value_size > 0 && req.optimal_value_granularity > req.max_value_size) {
		spdk_jsonrpc_send_error_response(request, -EINVAL,
						 "optimal_value_granularity must not exceed max_value_size");
		goto cleanup;
	}

	rc = create_kvmalloc_disk(&bdev, &req);
	if (rc) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	free_rpc_construct_kvmalloc(&req);

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, spdk_bdev_get_name(bdev));
	spdk_jsonrpc_end_result(request, w);
	return;

cleanup:
	free_rpc_construct_kvmalloc(&req);
}
SPDK_RPC_REGISTER("bdev_kvmalloc_create", rpc_bdev_kvmalloc_create, SPDK_RPC_RUNTIME)

struct rpc_delete_kvmalloc {
	char *name;
};

static void
free_rpc_delete_kvmalloc(struct rpc_delete_kvmalloc *r)
{
	free(r->name);
}

static const struct spdk_json_object_decoder rpc_bdev_kvmalloc_delete_decoders[] = {
	{"name", offsetof(struct rpc_delete_kvmalloc, name), spdk_json_decode_string},
};

static void
rpc_bdev_kvmalloc_delete_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_kvmalloc_delete(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct rpc_delete_kvmalloc req = {NULL};

	if (spdk_json_decode_object(params, rpc_bdev_kvmalloc_delete_decoders,
				    SPDK_COUNTOF(rpc_bdev_kvmalloc_delete_decoders),
				    &req)) {
		SPDK_DEBUGLOG(bdev_kvmalloc, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	delete_kvmalloc_disk(req.name, rpc_bdev_kvmalloc_delete_cb, request);

cleanup:
	free_rpc_delete_kvmalloc(&req);
}
SPDK_RPC_REGISTER("bdev_kvmalloc_delete", rpc_bdev_kvmalloc_delete, SPDK_RPC_RUNTIME)
