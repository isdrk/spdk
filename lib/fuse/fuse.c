/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/fuse.h"
#include "spdk/fuse_dispatcher.h"
#include "spdk/log.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"

#include <sys/mount.h>

struct spdk_fuse_mount {
	struct spdk_fsdev_desc		*fsdev_desc;
	struct spdk_fuse_dispatcher	*dispatcher;
	int				fd;
	bool				mounted;
	char				*name;
	char				*mountpoint;
	TAILQ_ENTRY(spdk_fuse_mount)	tailq;
};

struct fsdev_fuse_channel {
	struct spdk_fuse_mount		*mount;
	struct spdk_fuse_poll_group	*poll_group;
	TAILQ_ENTRY(fsdev_fuse_channel)	tailq;
};

struct spdk_fuse_poll_group {
	TAILQ_HEAD(, fsdev_fuse_channel)	active_channels;
	TAILQ_HEAD(, fsdev_fuse_channel)	inactive_channels;
};

struct {
	TAILQ_HEAD(, spdk_fuse_mount)	mounts;
} g_fuse = {
	.mounts = TAILQ_HEAD_INITIALIZER(g_fuse.mounts),
};

static void
fsdev_fuse_channel_destroy(struct fsdev_fuse_channel *ch)
{
	spdk_put_io_channel(spdk_io_channel_from_ctx(ch->poll_group));
	free(ch);
}

static struct fsdev_fuse_channel *
fsdev_fuse_channel_create(struct spdk_fuse_mount *mount)
{
	struct fsdev_fuse_channel *ch;

	ch = calloc(1, sizeof(*ch));
	if (ch == NULL) {
		return NULL;
	}

	/* Bump poll group's refcount to make sure it doesn't disappear */
	ch->poll_group = spdk_io_channel_get_ctx(spdk_get_io_channel(&g_fuse));
	ch->mount = mount;
	return ch;
}

static void
fsdev_fuse_mount_cleanup(struct spdk_fuse_mount *mount)
{
	struct spdk_fuse_mount *tmp;
	int rc;

	TAILQ_FOREACH(tmp, &g_fuse.mounts, tailq) {
		if (tmp == mount) {
			TAILQ_REMOVE(&g_fuse.mounts, tmp, tailq);
			break;
		}
	}

	if (mount->fd >= 0) {
		close(mount->fd);
	}
	if (mount->mounted) {
		rc = umount2(mount->mountpoint, MNT_DETACH);
		if (rc != 0) {
			SPDK_ERRLOG("%s: failed to umount %s: %s\n", mount->name,
				    mount->mountpoint, spdk_strerror(errno));
		}
	}
	if (mount->dispatcher != NULL) {
		spdk_fuse_dispatcher_delete(mount->dispatcher);
	}
	if (mount->fsdev_desc != NULL) {
		spdk_fsdev_close(mount->fsdev_desc);
	}

	free(mount->name);
	free(mount->mountpoint);
	free(mount);
}

static void
fsdev_fuse_fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *ctx)
{
	SPDK_ERRLOG("%s: unhandled event %d\n", spdk_fsdev_get_name(fsdev), type);
}

static int
fsdev_fuse_mount_init(struct spdk_fuse_mount **_mnt, const char *name, const char *mountpoint,
		      struct spdk_fuse_mount_opts *opts)
{
	struct spdk_fuse_mount *mnt;
	struct stat st;
	char mopts[128];
	int rc;

	mnt = calloc(1, sizeof(*mnt));
	if (mnt == NULL) {
		return -ENOMEM;
	}

	mnt->fd = -1;
	mnt->name = strdup(name);
	if (mnt->name == NULL) {
		rc = -ENOMEM;
		goto error;
	}

	mnt->mountpoint = strdup(mountpoint);
	if (mnt->mountpoint == NULL) {
		rc = -ENOMEM;
		goto error;
	}

	rc = spdk_fsdev_open(name, fsdev_fuse_fsdev_event_cb, NULL, &mnt->fsdev_desc);
	if (rc != 0) {
		SPDK_ERRLOG("%s: failed to open fsdev: %s\n", mnt->name, spdk_strerror(-rc));
		goto error;
	}

	mnt->dispatcher = spdk_fuse_dispatcher_create(mnt->fsdev_desc, false, NULL, NULL);
	if (mnt->dispatcher == NULL) {
		rc = -ENOMEM;
		goto error;
	}

	rc = stat(mnt->mountpoint, &st);
	if (rc != 0) {
		rc = -errno;
		SPDK_ERRLOG("%s: failed to access %s: %s\n", mnt->name, mnt->mountpoint,
			    spdk_strerror(-rc));
		goto error;
	}

	mnt->fd = open("/dev/fuse", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (mnt->fd < 0) {
		rc = -errno;
		SPDK_ERRLOG("%s: failed to open /dev/fuse: %s\n", mnt->name, spdk_strerror(-rc));
		goto error;
	}

	rc = snprintf(mopts, sizeof(mopts), "fd=%d,rootmode=%o,user_id=%u,group_id=%u",
		      mnt->fd, st.st_mode, getuid(), getgid());
	if (rc < 0 || rc >= (int)sizeof(mopts)) {
		rc = -EINVAL;
		goto error;
	}

	rc = mount(mnt->name, mnt->mountpoint, "fuse.spdk", 0, mopts);
	if (rc != 0) {
		rc = -errno;
		SPDK_ERRLOG("%s: failed to mount fsdev at %s\n", mnt->name, mnt->mountpoint);
		goto error;
	}

	SPDK_INFOLOG(fuse, "%s: mounted fsdev at %s\n", mnt->name, mnt->mountpoint);
	TAILQ_INSERT_TAIL(&g_fuse.mounts, mnt, tailq);
	mnt->mounted = true;
	*_mnt = mnt;

	return 0;
error:
	fsdev_fuse_mount_cleanup(mnt);
	return rc;
}

struct fsdev_fuse_mount_ctx {
	struct spdk_fuse_mount	*mount;
	int			status;
	spdk_fuse_mount_cb	cb_fn;
	void			*cb_ctx;
};

static void
fsdev_fuse_create_channels_cleanup_done(struct spdk_io_channel_iter *i, int status)
{
	struct fsdev_fuse_mount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);

	assert(ctx->status != 0);
	fsdev_fuse_mount_cleanup(ctx->mount);
	ctx->cb_fn(ctx->cb_ctx, NULL, ctx->status);
	free(ctx);
}

static void
fsdev_fuse_create_channels_cleanup(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *ioch = spdk_io_channel_iter_get_channel(i);
	struct spdk_fuse_poll_group *group = spdk_io_channel_get_ctx(ioch);
	struct fsdev_fuse_mount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct fsdev_fuse_channel *ch;

	TAILQ_FOREACH(ch, &group->inactive_channels, tailq) {
		if (ch->mount == ctx->mount) {
			TAILQ_REMOVE(&group->inactive_channels, ch, tailq);
			fsdev_fuse_channel_destroy(ch);
			break;
		}
	}

	spdk_for_each_channel_continue(i, 0);
}

static void
fsdev_fuse_enable_channels_done(struct spdk_io_channel_iter *i, int status)
{
}

static void
fsdev_fuse_enable_channels(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *ioch = spdk_io_channel_iter_get_channel(i);
	struct spdk_fuse_poll_group *group = spdk_io_channel_get_ctx(ioch);
	struct spdk_fuse_mount *mount = spdk_io_channel_iter_get_ctx(i);
	struct fsdev_fuse_channel *ch;

	TAILQ_FOREACH(ch, &group->inactive_channels, tailq) {
		if (ch->mount == mount) {
			TAILQ_REMOVE(&group->inactive_channels, ch, tailq);
			TAILQ_INSERT_TAIL(&group->active_channels, ch, tailq);
			break;
		}
	}

	spdk_for_each_channel_continue(i, 0);
}

static void
fsdev_fuse_create_channels_done(struct spdk_io_channel_iter *i, int status)
{
	struct fsdev_fuse_mount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fuse_mount *mount = ctx->mount;

	if (status != 0) {
		spdk_for_each_channel(&g_fuse, fsdev_fuse_create_channels_cleanup, ctx,
				      fsdev_fuse_create_channels_cleanup_done);
		return;
	}

	ctx->cb_fn(ctx->cb_ctx, mount, 0);
	free(ctx);

	spdk_for_each_channel(&g_fuse, fsdev_fuse_enable_channels, mount,
			      fsdev_fuse_enable_channels_done);
}

static void
fsdev_fuse_create_channels(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *ioch = spdk_io_channel_iter_get_channel(i);
	struct spdk_fuse_poll_group *group = spdk_io_channel_get_ctx(ioch);
	struct fsdev_fuse_mount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct fsdev_fuse_channel *ch;

	ch = fsdev_fuse_channel_create(ctx->mount);
	if (ch != NULL) {
		TAILQ_INSERT_TAIL(&group->inactive_channels, ch, tailq);
	} else {
		ctx->status = -ENOMEM;
	}

	spdk_for_each_channel_continue(i, ctx->status);
}

int
spdk_fuse_mount(const char *name, const char *mountpoint, struct spdk_fuse_mount_opts *opts,
		spdk_fuse_mount_cb cb_fn, void *cb_ctx)
{
	struct spdk_fuse_mount *mount = NULL;
	struct fsdev_fuse_mount_ctx *ctx = NULL;
	int rc;

	rc = fsdev_fuse_mount_init(&mount, name, mountpoint, opts);
	if (rc != 0) {
		return rc;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		rc = -ENOMEM;
		goto error;
	}

	ctx->mount = mount;
	ctx->cb_fn = cb_fn;
	ctx->cb_ctx = cb_ctx;

	spdk_for_each_channel(&g_fuse, fsdev_fuse_create_channels, ctx,
			      fsdev_fuse_create_channels_done);
	return 0;
error:
	fsdev_fuse_mount_cleanup(mount);
	free(ctx);
	return rc;
}

struct fsdev_fuse_umount_ctx {
	struct spdk_fuse_mount	*mount;
	spdk_fuse_umount_cb	cb_fn;
	void			*cb_ctx;
};

static void
fsdev_fuse_destroy_channels_done(struct spdk_io_channel_iter *i, int status)
{
	struct fsdev_fuse_umount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);

	fsdev_fuse_mount_cleanup(ctx->mount);
	ctx->cb_fn(ctx->cb_ctx);
	free(ctx);
}

static void
fsdev_fuse_destroy_channels(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *ioch = spdk_io_channel_iter_get_channel(i);
	struct spdk_fuse_poll_group *group = spdk_io_channel_get_ctx(ioch);
	struct fsdev_fuse_umount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct fsdev_fuse_channel *ch;

	TAILQ_FOREACH(ch, &group->inactive_channels, tailq) {
		if (ch->mount == ctx->mount) {
			TAILQ_REMOVE(&group->inactive_channels, ch, tailq);
			fsdev_fuse_channel_destroy(ch);
			break;
		}
	}

	TAILQ_FOREACH(ch, &group->active_channels, tailq) {
		if (ch->mount == ctx->mount) {
			TAILQ_REMOVE(&group->active_channels, ch, tailq);
			fsdev_fuse_channel_destroy(ch);
			break;
		}
	}

	spdk_for_each_channel_continue(i, 0);
}

int
spdk_fuse_umount(struct spdk_fuse_mount *mount, spdk_fuse_umount_cb cb_fn, void *cb_ctx)
{
	struct fsdev_fuse_umount_ctx *ctx = NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return -ENOMEM;
	}

	ctx->mount = mount;
	ctx->cb_fn = cb_fn;
	ctx->cb_ctx = cb_ctx;

	spdk_for_each_channel(&g_fuse, fsdev_fuse_destroy_channels, ctx,
			      fsdev_fuse_destroy_channels_done);
	return 0;
}

void
spdk_fuse_get_default_mount_opts(struct spdk_fuse_mount_opts *opts, size_t size)
{
	opts->size = size;
}

int
spdk_fuse_poll_group_poll(struct spdk_fuse_poll_group *group,
			  spdk_fuse_mount_error_cb cb_fn, void *cb_ctx)
{
	return -ENOTSUP;
}

struct spdk_fuse_poll_group *
spdk_fuse_poll_group_create(void)
{
	struct spdk_io_channel *ioch;

	ioch = spdk_get_io_channel(&g_fuse);
	if (ioch == NULL) {
		return NULL;
	}

	return spdk_io_channel_get_ctx(ioch);
}

void
spdk_fuse_poll_group_destroy(struct spdk_fuse_poll_group *group)
{
	if (group == NULL) {
		return;
	}

	spdk_put_io_channel(spdk_io_channel_from_ctx(group));
}

static int
fsdev_fuse_poll_group_create_cb(void *io_device, void *ctx)
{
	struct spdk_fuse_poll_group *group = ctx;

	TAILQ_INIT(&group->active_channels);
	TAILQ_INIT(&group->inactive_channels);
	return 0;
}

static void
fsdev_fuse_poll_group_destroy_cb(void *io_device, void *ctx)
{
	struct spdk_fuse_poll_group *group __attribute__((unused)) = ctx;

	assert(TAILQ_EMPTY(&group->active_channels));
	assert(TAILQ_EMPTY(&group->inactive_channels));
}

int
spdk_fuse_init(struct spdk_fuse_opts *opts)
{
	spdk_io_device_register(&g_fuse, fsdev_fuse_poll_group_create_cb,
				fsdev_fuse_poll_group_destroy_cb,
				sizeof(struct spdk_fuse_poll_group), "fuse");
	return 0;
}

void
spdk_fuse_cleanup(void)
{
	spdk_io_device_unregister(&g_fuse, NULL);
}

void
spdk_fuse_get_opts(struct spdk_fuse_opts *opts, size_t size)
{
	opts->size = size;
}

SPDK_LOG_REGISTER_COMPONENT(fuse);
