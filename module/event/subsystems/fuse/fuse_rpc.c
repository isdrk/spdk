/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/fuse.h"
#include "spdk/rpc.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/util.h"

struct rpc_fuse_mount {
	struct spdk_jsonrpc_request	*request;
	char				*fsdev;
	char				*mountpoint;
	char				*fstype;
	struct spdk_fuse_mount_opts	opts;
};

struct rpc_fuse_mount_option {
	char *name;
};

static void
rpc_fuse_free_mount_option(struct rpc_fuse_mount_option *opt)
{
	free(opt->name);
}

static const struct spdk_json_object_decoder rpc_fuse_mount_option_decoders[] = {
	{ "name", offsetof(struct rpc_fuse_mount_option, name), spdk_json_decode_string },
};

struct rpc_fuse_mount_flag {
	const char	*enable;
	const char	*disable;
	uint64_t	flag;
};

static int
rpc_fuse_parse_mount_flag(struct rpc_fuse_mount_option *opt, uint64_t *flag)
{
	struct rpc_fuse_mount_flag flags[] = {
		{ "ro",			"rw",			MS_RDONLY },
		{ "nosuid",		"suid",			MS_NOSUID },
		{ "nodev",		"dev",			MS_NODEV },
		{ "noexec",		"exec",			MS_NOEXEC },
		{ "sync",		"async",		MS_SYNCHRONOUS },
		{ "dirsync",		"nodirsync",		MS_DIRSYNC },
		{ "nosymfollow",	"symfollow",		MS_NOSYMFOLLOW },
		{ "noatime",		"atime",		MS_NOATIME },
		{ "nodiratime",		"diratime",		MS_NODIRATIME },
		{ "silent",		"loud",			MS_SILENT },
		{ "relatime",		"norelatime",		MS_RELATIME },
		{ "strictatime",	"nostrictatime",	MS_STRICTATIME },
		{ "lazytime",		"nolazytime",		MS_LAZYTIME },
		{ "remount",		NULL,			MS_REMOUNT }
	};
	size_t i;

	for (i = 0; i < SPDK_COUNTOF(flags); i++) {
		if (strcmp(flags[i].enable, opt->name) == 0) {
			*flag |= flags[i].flag;
			return 0;
		}
		if (flags[i].disable && strcmp(flags[i].disable, opt->name) == 0) {
			return 0;
		}
	}

	return -EINVAL;
}

static int
rpc_fuse_decode_mount_option(const struct spdk_json_val *val, void *out)
{
	struct rpc_fuse_mount *fm = out;
	struct rpc_fuse_mount_option opt = {};
	int rc;

	rc = spdk_json_decode_object(val, rpc_fuse_mount_option_decoders,
				     SPDK_COUNTOF(rpc_fuse_mount_option_decoders), &opt);
	if (rc != 0) {
		return rc;
	}

	rc = rpc_fuse_parse_mount_flag(&opt, &fm->opts.flags);
	if (rc != 0) {
		SPDK_ERRLOG("Unknown flag: %s\n", opt.name);
	}
	rpc_fuse_free_mount_option(&opt);
	return rc;
}

static int
rpc_fuse_decode_mount_options(const struct spdk_json_val *val, void *out)
{
	return spdk_json_decode_array(val, rpc_fuse_decode_mount_option, out, SIZE_MAX, NULL, 0);
}

#define opts_offsetof(opt) \
	(offsetof(struct rpc_fuse_mount, opts) + offsetof(struct spdk_fuse_mount_opts, opt))

static const struct spdk_json_object_decoder rpc_fuse_mount_opts_decoders[] = {
	{ "max_io_depth", opts_offsetof(max_io_depth), spdk_json_decode_uint64, true },
	{ "max_xfer_size", opts_offsetof(max_xfer_size), spdk_json_decode_uint64, true },
	{ "clone_fd", opts_offsetof(clone_fd), spdk_json_decode_bool, true },
	{ "fake_memory_domain", opts_offsetof(fake_memory_domain), spdk_json_decode_bool, true },
	{ "options", 0, rpc_fuse_decode_mount_options, true },
	{ "fstype", offsetof(struct rpc_fuse_mount, fstype), spdk_json_decode_string, true },
};

#undef opts_offsetof

static int
rpc_fuse_decode_mount_opts(const struct spdk_json_val *val, void *out)
{
	return spdk_json_decode_object(val, rpc_fuse_mount_opts_decoders,
				       SPDK_COUNTOF(rpc_fuse_mount_opts_decoders), out);
}

static const struct spdk_json_object_decoder rpc_fuse_mount_decoders[] = {
	{ "fsdev", offsetof(struct rpc_fuse_mount, fsdev), spdk_json_decode_string },
	{ "mountpoint", offsetof(struct rpc_fuse_mount, mountpoint), spdk_json_decode_string },
	{ "options", 0, rpc_fuse_decode_mount_opts, true },
};

static void
free_rpc_fuse_mount(struct rpc_fuse_mount *rpc)
{
	free(rpc->fsdev);
	free(rpc->mountpoint);
	free(rpc->fstype);
	free(rpc);
}

static void
rpc_fuse_mount_cb(void *_ctx, struct spdk_fuse_mount *mount, int status)
{
	struct rpc_fuse_mount *ctx = _ctx;
	struct spdk_jsonrpc_request *request = ctx->request;

	if (status != 0) {
		spdk_jsonrpc_send_error_response(request, status, spdk_strerror(-status));
		goto out;
	}

	spdk_jsonrpc_send_bool_response(request, true);
out:
	free_rpc_fuse_mount(ctx);
}

static void
rpc_fuse_mount(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_fuse_mount *ctx;
	int rc;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		spdk_jsonrpc_send_error_response(request, -ENOMEM, spdk_strerror(ENOMEM));
		return;
	}

	spdk_fuse_get_default_mount_opts(&ctx->opts, sizeof(ctx->opts));
	if (spdk_json_decode_object_relaxed(params, rpc_fuse_mount_decoders,
					    SPDK_COUNTOF(rpc_fuse_mount_decoders), ctx)) {
		rc = -EINVAL;
		goto error;
	}

	ctx->request = request;
	ctx->opts.fstype = ctx->fstype ? ctx->fstype : ctx->opts.fstype;
	rc = spdk_fuse_mount(ctx->fsdev, ctx->mountpoint, &ctx->opts, rpc_fuse_mount_cb, ctx);
	if (rc == 0) {
		return;
	}
error:
	spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
	free_rpc_fuse_mount(ctx);
}
SPDK_RPC_REGISTER("fuse_mount", rpc_fuse_mount, SPDK_RPC_RUNTIME)

struct rpc_fuse_umount {
	struct spdk_fuse_mount	*mount;
	char			*name;
};

static const struct spdk_json_object_decoder rpc_fuse_umount_decoders[] = {
	{ "mount", offsetof(struct rpc_fuse_umount, name), spdk_json_decode_string },
};

static void
free_rpc_fuse_umount(struct rpc_fuse_umount *rpc)
{
	free(rpc->name);
}

static void
rpc_fuse_umount_cb(void *ctx)
{
	struct spdk_jsonrpc_request *request = ctx;

	spdk_jsonrpc_send_bool_response(request, true);
}

static int
rpc_fuse_umount_for_each_mount(struct spdk_fuse_mount *mount, void *_ctx)
{
	struct rpc_fuse_umount *ctx = _ctx;
	struct spdk_fsdev *fsdev = spdk_fuse_mount_get_fsdev(mount);

	if (strcmp(ctx->name, spdk_fsdev_get_name(fsdev)) == 0) {
		ctx->mount = mount;
		return 1;
	}
	if (strcmp(ctx->name, spdk_fuse_mount_get_mountpoint(mount)) == 0) {
		ctx->mount = mount;
		return 1;
	}

	return 0;
}

static void
rpc_fuse_umount(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_fuse_umount ctx = {};
	int rc;

	if (spdk_json_decode_object_relaxed(params, rpc_fuse_umount_decoders,
					    SPDK_COUNTOF(rpc_fuse_umount_decoders), &ctx)) {
		rc = -EINVAL;
		goto error;
	}

	rc = spdk_fuse_for_each_mount(rpc_fuse_umount_for_each_mount, &ctx);
	if (rc != 1) {
		rc = -ENOENT;
		goto error;
	}

	rc = spdk_fuse_umount(ctx.mount, rpc_fuse_umount_cb, request);
	if (rc == 0) {
		free_rpc_fuse_umount(&ctx);
		return;
	}
error:
	spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
	free_rpc_fuse_umount(&ctx);
}
SPDK_RPC_REGISTER("fuse_umount", rpc_fuse_umount, SPDK_RPC_RUNTIME)

static int
rpc_fuse_get_mounts_for_each_mount_cb(struct spdk_fuse_mount *mount, void *ctx)
{
	struct spdk_json_write_ctx *w = ctx;
	struct spdk_fsdev *fsdev = spdk_fuse_mount_get_fsdev(mount);

	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "fsdev", spdk_fsdev_get_name(fsdev));
	spdk_json_write_named_string(w, "mountpoint", spdk_fuse_mount_get_mountpoint(mount));
	spdk_json_write_object_end(w);

	return 0;
}

static void
rpc_fuse_get_mounts(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct spdk_json_write_ctx *w;

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_array_begin(w);
	spdk_fuse_for_each_mount(rpc_fuse_get_mounts_for_each_mount_cb, w);
	spdk_json_write_array_end(w);
	spdk_jsonrpc_end_result(request, w);
}
SPDK_RPC_REGISTER("fuse_get_mounts", rpc_fuse_get_mounts, SPDK_RPC_RUNTIME)

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

#undef opts_offsetof

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
