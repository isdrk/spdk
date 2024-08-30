/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/bdev_group.h"

#include "spdk/env.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/base64.h"
#include "spdk/bdev_module.h"

#include "spdk/log.h"

#include "bdev_internal.h"

struct group_bdev_opts {
	char *name;
	char *bdev;
};

static const struct spdk_json_object_decoder rpc_construct_group_decoders[] = {
	{"name", offsetof(struct group_bdev_opts, name), spdk_json_decode_string, false},
};

static void
free_rpc_construct_group(struct group_bdev_opts *r)
{
	free(r->name);
	free(r->bdev);
}

static void
rpc_bdev_group_create(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct group_bdev_opts req = {0};
	struct spdk_bdev_group *group;
	struct spdk_json_write_ctx *w;

	if (spdk_json_decode_object(params, rpc_construct_group_decoders,
				    SPDK_COUNTOF(rpc_construct_group_decoders),
				    &req)) {
		SPDK_DEBUGLOG(bdev, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	group = spdk_bdev_group_get_by_name(req.name);
	if (group) {
		SPDK_DEBUGLOG(bdev, "group %s already exists\n", req.name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "group already exists");
		goto cleanup;
	}

	group = spdk_bdev_group_create(req.name);
	if (!group) {
		SPDK_DEBUGLOG(bdev, "cannot create group %s\n", req.name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "cannot create group");
		goto cleanup;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, req.name);
	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_construct_group(&req);
}
SPDK_RPC_REGISTER("bdev_group_create", rpc_bdev_group_create, SPDK_RPC_RUNTIME)

static const struct spdk_json_object_decoder rpc_bdev_group_bdev_decoders[] = {
	{"name", offsetof(struct group_bdev_opts, name), spdk_json_decode_string, false},
	{"bdev", offsetof(struct group_bdev_opts, bdev), spdk_json_decode_string, false},
};

static void
rpc_bdev_group_bdev_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_group_add_bdev(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct group_bdev_opts req = {0};
	struct spdk_bdev_group *group = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_group_bdev_decoders,
				    SPDK_COUNTOF(rpc_bdev_group_bdev_decoders),
				    &req)) {
		SPDK_DEBUGLOG(bdev, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	group = spdk_bdev_group_get_by_name(req.name);
	if (!group) {
		SPDK_DEBUGLOG(bdev, "cannot find group %s\n", req.name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "group doesn't exist");
		goto cleanup;
	}

	spdk_bdev_group_add_bdev(group, req.bdev, rpc_bdev_group_bdev_cb, request);

cleanup:
	free_rpc_construct_group(&req);
}
SPDK_RPC_REGISTER("bdev_group_add_bdev", rpc_bdev_group_add_bdev, SPDK_RPC_RUNTIME)

static void
rpc_bdev_group_remove_bdev(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct group_bdev_opts req = {0};
	struct spdk_bdev_group *group = NULL;

	if (spdk_json_decode_object(params, rpc_bdev_group_bdev_decoders,
				    SPDK_COUNTOF(rpc_bdev_group_bdev_decoders),
				    &req)) {
		SPDK_DEBUGLOG(bdev, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	group = spdk_bdev_group_get_by_name(req.name);
	if (!group) {
		SPDK_DEBUGLOG(bdev, "cannot find group %s\n", req.name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "group doesn't exist");
		goto cleanup;
	}

	spdk_bdev_group_remove_bdev(group, req.bdev, rpc_bdev_group_bdev_cb, request);

cleanup:
	free_rpc_construct_group(&req);
}
SPDK_RPC_REGISTER("bdev_group_remove_bdev", rpc_bdev_group_remove_bdev, SPDK_RPC_RUNTIME)

static void
rpc_bdev_group_delete_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_group_delete(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct group_bdev_opts req = {0};
	struct spdk_bdev_group *group;

	if (spdk_json_decode_object(params, rpc_construct_group_decoders,
				    SPDK_COUNTOF(rpc_construct_group_decoders),
				    &req)) {
		SPDK_DEBUGLOG(bdev, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	group = spdk_bdev_group_get_by_name(req.name);
	if (!group) {
		SPDK_DEBUGLOG(bdev, "cannot find group %s\n", req.name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "group doesn't exist");
		goto cleanup;
	}

	spdk_bdev_group_destroy(group, rpc_bdev_group_delete_cb, request);

cleanup:
	free_rpc_construct_group(&req);
}
SPDK_RPC_REGISTER("bdev_group_delete", rpc_bdev_group_delete, SPDK_RPC_RUNTIME)

struct rpc_bdev_group_set_qos_limit {
	char		*name;
	uint64_t	limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES];
};

static void
free_rpc_bdev_group_set_qos_limit(struct rpc_bdev_group_set_qos_limit *r)
{
	free(r->name);
}

static const struct spdk_json_object_decoder rpc_bdev_set_qos_limit_decoders[] = {
	{"name", offsetof(struct rpc_bdev_group_set_qos_limit, name), spdk_json_decode_string},
	{
		"rw_ios_per_sec", offsetof(struct rpc_bdev_group_set_qos_limit,
					   limits[SPDK_BDEV_QOS_RW_IOPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"rw_mbytes_per_sec", offsetof(struct rpc_bdev_group_set_qos_limit,
					      limits[SPDK_BDEV_QOS_RW_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"r_mbytes_per_sec", offsetof(struct rpc_bdev_group_set_qos_limit,
					     limits[SPDK_BDEV_QOS_R_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
	{
		"w_mbytes_per_sec", offsetof(struct rpc_bdev_group_set_qos_limit,
					     limits[SPDK_BDEV_QOS_W_BPS_RATE_LIMIT]),
		spdk_json_decode_uint64, true
	},
};

static void
rpc_bdev_group_set_qos_limit_complete(void *cb_arg, int status)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (status != 0) {
		spdk_jsonrpc_send_error_response_fmt(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						     "Failed to configure rate limit: %s",
						     spdk_strerror(-status));
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}

static void
rpc_bdev_group_set_qos_limit(struct spdk_jsonrpc_request *request,
			     const struct spdk_json_val *params)
{
	struct rpc_bdev_group_set_qos_limit req = {NULL, {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX}};
	uint64_t limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES];
	struct spdk_bdev_group *group;
	int i;

	if (spdk_json_decode_object(params, rpc_bdev_set_qos_limit_decoders,
				    SPDK_COUNTOF(rpc_bdev_set_qos_limit_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	group = spdk_bdev_group_get_by_name(req.name);
	if (!group) {
		SPDK_DEBUGLOG(bdev, "cannot find group %s\n", req.name);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "group doesn't exist");
		goto cleanup;
	}

	/* Check if at least one new rate limit specified */
	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (req.limits[i] != UINT64_MAX) {
			break;
		}
	}

	/* Report error if no new rate limits specified */
	if (i == SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES) {
		SPDK_ERRLOG("no rate limits specified\n");
		spdk_jsonrpc_send_error_response(request, -EINVAL, "No rate limits specified");
		goto cleanup;
	}

	/* Get the old limits */
	spdk_bdev_group_get_qos_rate_limits(group, limits);

	/* Merge the new rate limits, so only the diff appears in the limits array */
	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		if (req.limits[i] != UINT64_MAX) {
			limits[i] = req.limits[i];
		}
	}

	spdk_bdev_group_set_qos_rate_limits(group, limits,
					    rpc_bdev_group_set_qos_limit_complete, request);

cleanup:
	free_rpc_bdev_group_set_qos_limit(&req);
}
SPDK_RPC_REGISTER("bdev_group_set_qos_limit", rpc_bdev_group_set_qos_limit, SPDK_RPC_RUNTIME)

static int
rpc_spdk_bdev_group_info_cb(void *cb_arg, struct spdk_bdev_group *group, struct spdk_bdev *bdev)
{
	struct spdk_json_write_ctx *w = cb_arg;

	spdk_json_write_string(w, spdk_bdev_get_name(bdev));

	return 0;
}

struct groups_get_ctx {
	struct spdk_json_write_ctx *w;
	char *name;
};

static int
rpc_spdk_get_bdev_groups_cb(void *cb_arg, struct spdk_bdev_group *group)
{
	struct groups_get_ctx *ctx = cb_arg;
	uint64_t qos_limits[SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES];
	int i;

	if (ctx->name && strcmp(ctx->name, spdk_bdev_group_get_name(group))) {
		return 0; /* we're seeking a specific group and this is not it, so just continue */
	}

	spdk_json_write_object_begin(ctx->w);
	spdk_json_write_named_string(ctx->w, "name", spdk_bdev_group_get_name(group));
	spdk_json_write_named_object_begin(ctx->w, "assigned_rate_limits");
	spdk_bdev_group_get_qos_rate_limits(group, qos_limits);
	for (i = 0; i < SPDK_BDEV_QOS_NUM_RATE_LIMIT_TYPES; i++) {
		spdk_json_write_named_uint64(ctx->w, spdk_bdev_get_qos_rpc_type(i), qos_limits[i]);
	}
	spdk_json_write_object_end(ctx->w);
	spdk_json_write_named_array_begin(ctx->w, "bdevs");
	spdk_bdev_group_for_each_bdev(group, ctx->w, rpc_spdk_bdev_group_info_cb);
	spdk_json_write_array_end(ctx->w);
	spdk_json_write_object_end(ctx->w);

	/* if this is the specific group we're required to report, return non-0 as there's no need to iterate further */
	/* otherwise, return 0 to continue to the next group */
	return ctx->name ? 1 : 0;
}

static const struct spdk_json_object_decoder rpc_groups_get_decoders[] = {
	{"name", offsetof(struct groups_get_ctx, name), spdk_json_decode_string, false},
};

static void
rpc_spdk_bdev_groups_get(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct groups_get_ctx ctx = {0};

	if (params && spdk_json_decode_object(params, rpc_groups_get_decoders,
					      SPDK_COUNTOF(rpc_groups_get_decoders),
					      &ctx)) {
		SPDK_DEBUGLOG(bdev, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		return;
	}

	ctx.w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_array_begin(ctx.w);
	spdk_for_each_bdev_group(&ctx, rpc_spdk_get_bdev_groups_cb);
	spdk_json_write_array_end(ctx.w);
	spdk_jsonrpc_end_result(request, ctx.w);

	free(ctx.name);
}
SPDK_RPC_REGISTER("bdev_groups_get", rpc_spdk_bdev_groups_get, SPDK_RPC_RUNTIME)

struct rpc_get_iostat_ctx {
	int group_count;
	int rc;
	struct spdk_jsonrpc_request *request;
	struct spdk_json_write_ctx *w;
	bool per_channel;
};

struct group_get_iostat_ctx {
	struct spdk_bdev_io_stat *stat;
	struct rpc_get_iostat_ctx *rpc_ctx;
	struct spdk_bdev_group_desc *desc;
};

static void
rpc_get_iostat_started(struct rpc_get_iostat_ctx *rpc_ctx)
{
	rpc_ctx->w = spdk_jsonrpc_begin_result(rpc_ctx->request);

	spdk_json_write_object_begin(rpc_ctx->w);
	spdk_json_write_named_uint64(rpc_ctx->w, "tick_rate", spdk_get_ticks_hz());
	spdk_json_write_named_uint64(rpc_ctx->w, "ticks", spdk_get_ticks());
}

static void
rpc_get_iostat_done(struct rpc_get_iostat_ctx *rpc_ctx)
{
	if (--rpc_ctx->group_count != 0) {
		return;
	}

	if (rpc_ctx->rc == 0) {
		spdk_json_write_array_end(rpc_ctx->w);
		spdk_json_write_object_end(rpc_ctx->w);
		spdk_jsonrpc_end_result(rpc_ctx->request, rpc_ctx->w);
	} else {
		/* Return error response after processing all specified bdevs
		 * completed or failed.
		 */
		spdk_jsonrpc_send_error_response(rpc_ctx->request, rpc_ctx->rc,
						 spdk_strerror(-rpc_ctx->rc));
	}

	free(rpc_ctx);
}

static struct group_get_iostat_ctx *
group_iostat_ctx_alloc(void)
{
	struct group_get_iostat_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->stat = bdev_alloc_io_stat(false);
	if (ctx->stat == NULL) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

static void
group_iostat_ctx_free(struct group_get_iostat_ctx *ctx)
{
	bdev_free_io_stat(ctx->stat);
	free(ctx);
}

static void
group_get_iostat_done(struct spdk_bdev_group *group, struct spdk_bdev_io_stat *stat,
		      void *cb_arg, int rc)
{
	struct group_get_iostat_ctx *group_ctx = cb_arg;
	struct rpc_get_iostat_ctx *rpc_ctx = group_ctx->rpc_ctx;
	struct spdk_json_write_ctx *w = rpc_ctx->w;

	if (rc != 0 || rpc_ctx->rc != 0) {
		if (rpc_ctx->rc == 0) {
			rpc_ctx->rc = rc;
		}
		goto done;
	}

	assert(stat == group_ctx->stat);

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "name", spdk_bdev_group_get_name(group));

	spdk_bdev_dump_io_stat_json(stat, w);

	spdk_json_write_object_end(w);

done:
	rpc_get_iostat_done(rpc_ctx);

	spdk_bdev_group_close(group_ctx->desc);
	group_iostat_ctx_free(group_ctx);
}

static int
group_get_iostat(void *ctx, struct spdk_bdev_group *group)
{
	struct rpc_get_iostat_ctx *rpc_ctx = ctx;
	struct group_get_iostat_ctx *group_ctx;
	int rc;

	group_ctx = group_iostat_ctx_alloc();
	if (group_ctx == NULL) {
		SPDK_ERRLOG("Failed to allocate group_iostat_ctx struct\n");
		return -ENOMEM;
	}

	rc = spdk_bdev_group_open(spdk_bdev_group_get_name(group), &group_ctx->desc);
	if (rc != 0) {
		group_iostat_ctx_free(group_ctx);
		return rc;
	}

	rpc_ctx->group_count++;
	group_ctx->rpc_ctx = rpc_ctx;
	spdk_bdev_group_get_device_stat(group, group_ctx->stat,
					group_get_iostat_done, group_ctx);

	return 0;
}

static void
group_get_per_channel_stat_done(struct spdk_io_channel_iter *i, int status)
{
	struct group_get_iostat_ctx *group_ctx = spdk_io_channel_iter_get_ctx(i);

	rpc_get_iostat_done(group_ctx->rpc_ctx);

	spdk_bdev_group_close(group_ctx->desc);

	group_iostat_ctx_free(group_ctx);
}

static void
group_get_per_channel_stat(struct spdk_io_channel_iter *i)
{
	struct group_get_iostat_ctx *group_ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_bdev_group *group = spdk_io_channel_iter_get_io_device(i);
	struct spdk_io_channel *ch = spdk_io_channel_iter_get_channel(i);
	struct spdk_json_write_ctx *w = group_ctx->rpc_ctx->w;

	spdk_bdev_group_get_io_stat(group, ch, group_ctx->stat);

	spdk_json_write_object_begin(w);
	spdk_json_write_named_uint64(w, "thread_id", spdk_thread_get_id(spdk_get_thread()));
	spdk_bdev_dump_io_stat_json(group_ctx->stat, w);
	spdk_json_write_object_end(w);

	spdk_for_each_channel_continue(i, 0);
}

struct rpc_group_get_iostat {
	char *name;
	bool per_channel;
};

static void
free_rpc_group_get_iostat(struct rpc_group_get_iostat *r)
{
	free(r->name);
}

static const struct spdk_json_object_decoder rpc_group_get_iostat_decoders[] = {
	{"name", offsetof(struct rpc_group_get_iostat, name), spdk_json_decode_string, true},
	{"per_channel", offsetof(struct rpc_group_get_iostat, per_channel), spdk_json_decode_bool, true},
};

static void
rpc_group_get_iostat(struct spdk_jsonrpc_request *request,
		     const struct spdk_json_val *params)
{
	struct rpc_group_get_iostat req = {};
	struct spdk_bdev_group_desc *desc = NULL;
	struct rpc_get_iostat_ctx *rpc_ctx;
	struct group_get_iostat_ctx *group_ctx;
	struct spdk_bdev_group *group;
	int rc;

	if (params != NULL) {
		if (spdk_json_decode_object(params, rpc_group_get_iostat_decoders,
					    SPDK_COUNTOF(rpc_group_get_iostat_decoders),
					    &req)) {
			SPDK_ERRLOG("spdk_json_decode_object failed\n");
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
							 "spdk_json_decode_object failed");
			free_rpc_group_get_iostat(&req);
			return;
		}

		if (req.per_channel == true && !req.name) {
			SPDK_ERRLOG("Group name is required for per channel IO statistics\n");
			spdk_jsonrpc_send_error_response(request, -EINVAL, spdk_strerror(EINVAL));
			free_rpc_group_get_iostat(&req);
			return;
		}

		if (req.name) {
			rc = spdk_bdev_group_open(req.name, &desc);
			if (rc != 0) {
				SPDK_ERRLOG("Failed to open group '%s': %d\n", req.name, rc);
				spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
				free_rpc_group_get_iostat(&req);
				return;
			}
		}
	}

	free_rpc_group_get_iostat(&req);

	rpc_ctx = calloc(1, sizeof(*rpc_ctx));
	if (rpc_ctx == NULL) {
		SPDK_ERRLOG("Failed to allocate rpc_iostat_ctx struct\n");
		if (desc != NULL) {
			spdk_bdev_group_close(desc);
		}
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		return;
	}

	/*
	 * Increment initial group_count so that it will never reach 0 in the middle
	 * of iterating.
	 */
	rpc_ctx->group_count++;
	rpc_ctx->request = request;
	rpc_ctx->per_channel = req.per_channel;

	if (desc != NULL) {
		group = spdk_bdev_group_desc_get_bdev_group(desc);

		group_ctx = group_iostat_ctx_alloc();
		if (group_ctx == NULL) {
			SPDK_ERRLOG("Failed to allocate bdev_iostat_ctx struct\n");
			rpc_ctx->rc = -ENOMEM;

			spdk_bdev_group_close(desc);
		} else {
			group_ctx->desc = desc;

			rpc_ctx->group_count++;
			group_ctx->rpc_ctx = rpc_ctx;
			if (req.per_channel == false) {
				spdk_bdev_group_get_device_stat(group, group_ctx->stat,
								group_get_iostat_done, group_ctx);
			} else {
				/* If per_channel is true, there is no failure after here and
				 * we have to start RPC response before executing
				 * spdk_bdev_for_each_channel().
				 */
				rpc_get_iostat_started(rpc_ctx);
				spdk_json_write_named_string(rpc_ctx->w, "name", spdk_bdev_group_get_name(group));
				spdk_json_write_named_array_begin(rpc_ctx->w, "channels");

				spdk_for_each_channel(group,
						      group_get_per_channel_stat,
						      group_ctx,
						      group_get_per_channel_stat_done);

				rpc_get_iostat_done(rpc_ctx);
				return;
			}
		}
	} else {
		rc = spdk_for_each_bdev_group(rpc_ctx, group_get_iostat);
		if (rc != 0 && rpc_ctx->rc == 0) {
			rpc_ctx->rc = rc;
		}
	}

	if (rpc_ctx->rc == 0) {
		/* We want to fail the RPC for all failures. If per_channel is false,
		 * it is enough to defer starting RPC response until it is ensured that
		 * all spdk_for_each_channel() calls will succeed or there is no bdev.
		 */
		rpc_get_iostat_started(rpc_ctx);
		spdk_json_write_named_array_begin(rpc_ctx->w, "groups");
	}

	rpc_get_iostat_done(rpc_ctx);
}
SPDK_RPC_REGISTER("bdev_group_get_iostat", rpc_group_get_iostat, SPDK_RPC_RUNTIME)
