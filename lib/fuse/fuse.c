/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/fuse.h"
#include "spdk/fuse_dispatcher.h"
#include "spdk/log.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"

#include "linux/fuse_kernel.h"

#include <sys/mount.h>

struct spdk_fuse_mount {
	struct spdk_fsdev_desc		*fsdev_desc;
	struct spdk_fuse_dispatcher	*dispatcher;
	int				fd;
	bool				mounted;
	char				*name;
	char				*mountpoint;
	size_t				max_io_depth;
	size_t				max_xfer_size;
	TAILQ_ENTRY(spdk_fuse_mount)	tailq;
};

struct fsdev_fuse_channel;

struct fsdev_fuse_request {
	struct fsdev_fuse_channel	*ch;
	uint64_t			unique;
	void				*buf;
	uint32_t			len;
	struct iovec			in_iovs[2];
	struct iovec			out_iovs[2];
	int				in_iovcnt;
	int				out_iovcnt;
	TAILQ_ENTRY(fsdev_fuse_request)	tailq;
	char				ctx[0];
};

typedef void (*fsdev_fuse_channel_drained_cb)(void *ctx, struct fsdev_fuse_channel *ch);

struct fsdev_fuse_channel {
	struct spdk_fuse_mount			*mount;
	struct spdk_io_channel			*ioch;
	struct spdk_fuse_dispatcher		*dispatcher;
	int					fd;
	uint32_t				num_outstanding;
	TAILQ_HEAD(, fsdev_fuse_request)	free_requests;
	TAILQ_HEAD(, fsdev_fuse_request)	pending_requests;
	TAILQ_ENTRY(fsdev_fuse_channel)		tailq;
	struct {
		fsdev_fuse_channel_drained_cb	cb_fn;
		void				*cb_ctx;
	} drain;
	void					*request_pool;
	struct spdk_fuse_poll_group		*poll_group;
};

struct spdk_fuse_poll_group {
	TAILQ_HEAD(, fsdev_fuse_channel)	active_channels;
	TAILQ_HEAD(, fsdev_fuse_channel)	inactive_channels;
};

struct {
	TAILQ_HEAD(, spdk_fuse_mount)	mounts;
	struct spdk_fuse_opts		opts;
} g_fuse = {
	.mounts = TAILQ_HEAD_INITIALIZER(g_fuse.mounts),
	.opts = {
		.max_io_depth = 8,
		.max_xfer_size = 128 * 1024,
	},
};

#define FSDEV_FUSE_MIN_MAX_XFER_SIZE 4096

static const char *
fsdev_fuse_request_get_name(struct fsdev_fuse_request *req)
{
	struct fuse_in_header *in = req->buf;
	const char *name;

	name = spdk_fuse_dispatcher_get_operation_name(in->opcode);
	if (name != NULL) {
		return name;
	}

	return "UNKNOWN";
}

static struct fuse_in_header *
fsdev_fuse_request_get_inhdr(struct fsdev_fuse_request *req)
{
	assert(req->in_iovs[0].iov_len >= sizeof(struct fuse_in_header));
	return req->in_iovs[0].iov_base;
}

static struct fuse_out_header *
fsdev_fuse_request_get_outhdr(struct fsdev_fuse_request *req)
{
	assert(req->out_iovs[0].iov_len >= sizeof(struct fuse_out_header));
	return req->out_iovs[0].iov_base;
}

static void
fsdev_fuse_request_complete(struct fsdev_fuse_request *req)
{
	struct fsdev_fuse_channel *ch = req->ch;
	struct spdk_fuse_mount *mount = ch->mount;
	struct fuse_in_header *in = fsdev_fuse_request_get_inhdr(req);
	struct fuse_out_header *out = fsdev_fuse_request_get_outhdr(req);
	struct fuse_init_out *init_out;
	bool do_reply = true;
	int rc, errsv;

	switch (in->opcode) {
	case FUSE_INIT:
		init_out = (void *)(out + 1);
		if (init_out->max_write > mount->max_xfer_size) {
			SPDK_INFOLOG(fuse, "%s: limiting max_write %u -> %zu\n", mount->name,
				     init_out->max_write, mount->max_xfer_size);
			init_out->max_write = mount->max_xfer_size;
		}
		break;
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
	case FUSE_NOTIFY_REPLY:
		do_reply = false;
		break;
	default:
		break;
	}

	if (do_reply) {
		assert(out->len <= spdk_iov_length(req->out_iovs, req->out_iovcnt));
		rc = write(ch->fd, out, out->len);
		if (rc < 0) {
			errsv = errno;
			SPDK_ERRLOG("%s: failed to write %s response: %s\n", mount->name,
				    fsdev_fuse_request_get_name(req), spdk_strerror(errsv));
		}
	}

	TAILQ_INSERT_HEAD(&ch->free_requests, req, tailq);
}

static void
fsdev_fuse_request_complete_manual(struct fsdev_fuse_request *req, int error)
{
	struct fuse_out_header *hdr = fsdev_fuse_request_get_outhdr(req);

	memset(hdr, 0, sizeof(*hdr));
	hdr->len = sizeof(*hdr);
	hdr->error = error;
	hdr->unique = req->unique;

	fsdev_fuse_request_complete(req);
}

static void *
fsdev_fuse_set_iov(struct iovec *iov, int *iovcnt, void *buf, size_t len,
		   size_t alignment, size_t *total)
{
	void *aligned = NULL;
	uintptr_t padding = 0;

	if (len > 0) {
		aligned = (void *)SPDK_ALIGN_CEIL((uintptr_t)buf, alignment);
		padding = (uintptr_t)aligned - (uintptr_t)buf;
		(*iovcnt)++;
	}

	iov->iov_base = aligned;
	iov->iov_len = len;
	*total += len + padding;

	return (char *)buf + len + padding;
}

static int
fsdev_fuse_request_prep_generic(struct fsdev_fuse_request *req, size_t inlen)
{
	void *buf = req->buf;
	size_t total = 0;

	/* Some of the fuse dispatcher code assumes that the buffer is always split across mutliple
	 * iovs, so put the generic in/out headers in separate iovs.  This appears to be enough for
	 * most operations.
	 */
	buf = fsdev_fuse_set_iov(&req->in_iovs[0], &req->in_iovcnt, buf,
				 sizeof(struct fuse_in_header), 1, &total);
	buf = fsdev_fuse_set_iov(&req->in_iovs[1], &req->in_iovcnt, buf,
				 inlen - sizeof(struct fuse_in_header), 1, &total);
	/* Make sure the out header is 8B aligned */
	buf = fsdev_fuse_set_iov(&req->out_iovs[0], &req->out_iovcnt, buf,
				 sizeof(struct fuse_out_header), 8, &total);
	buf = fsdev_fuse_set_iov(&req->out_iovs[1], &req->out_iovcnt, buf,
				 req->len - total, 1, &total);

	assert((uintptr_t)buf - (uintptr_t)req->buf <= req->len);
	assert(spdk_iov_length(req->in_iovs, req->in_iovcnt) +
	       spdk_iov_length(req->out_iovs, req->out_iovcnt) <= req->len);

	return 0;
}

static int
fsdev_fuse_request_prep_read(struct fsdev_fuse_request *req, size_t inlen)
{
	struct spdk_fuse_mount *mount = req->ch->mount;
	struct fuse_in_header *in = req->buf;
	struct fuse_read_in *hdr = (void *)(in + 1);
	void *buf = req->buf;
	size_t total = 0;

	if (inlen < sizeof(*in) + sizeof(*hdr)) {
		SPDK_ERRLOG("%s: unexpected READ request length: %zu < %zu\n",
			    mount->name, inlen, sizeof(*in) + sizeof(*hdr));
		return -EBADMSG;
	}

	if (hdr->size > mount->max_xfer_size) {
		SPDK_ERRLOG("%s: unexpected READ size: %u > %zu\n",
			    mount->name, hdr->size, mount->max_xfer_size);
		return -EINVAL;
	}

	buf = fsdev_fuse_set_iov(&req->in_iovs[0], &req->in_iovcnt, buf,
				 sizeof(*in) + sizeof(*hdr), 1, &total);
	/* Make sure the out header is 8B aligned */
	buf = fsdev_fuse_set_iov(&req->out_iovs[0], &req->out_iovcnt, buf,
				 sizeof(struct fuse_out_header), 8, &total);
	/* Make sure the out iov is limited to the requested size, as fuse_dispatcher and some
	 * fsdevs only rely on the iovs and don't look at the size */
	buf = fsdev_fuse_set_iov(&req->out_iovs[1], &req->out_iovcnt, buf,
				 spdk_min(hdr->size, req->len - total), 1, &total);

	assert((uintptr_t)buf - (uintptr_t)req->buf <= req->len);
	assert(spdk_iov_length(req->in_iovs, req->in_iovcnt) +
	       spdk_iov_length(req->out_iovs, req->out_iovcnt) <= req->len);

	return 0;
}

static int
fsdev_fuse_request_prep_write(struct fsdev_fuse_request *req, size_t inlen)
{
	struct spdk_fuse_mount *mount = req->ch->mount;
	void *buf = req->buf;
	size_t total = 0;

	if (inlen < sizeof(struct fuse_in_header) + sizeof(struct fuse_write_in)) {
		SPDK_ERRLOG("%s: unexpected WRITE request length: %zu < %zu\n",
			    mount->name, inlen, sizeof(struct fuse_in_header) +
			    sizeof(struct fuse_write_in));
		return -EBADMSG;
	}

	buf = fsdev_fuse_set_iov(&req->in_iovs[0], &req->in_iovcnt, buf,
				 sizeof(struct fuse_in_header) +
				 sizeof(struct fuse_write_in), 1, &total);
	buf = fsdev_fuse_set_iov(&req->in_iovs[1], &req->in_iovcnt, buf,
				 inlen - sizeof(struct fuse_in_header) -
				 sizeof(struct fuse_write_in), 1, &total);
	/* Make sure the out header is 8B aligned */
	buf = fsdev_fuse_set_iov(&req->out_iovs[0], &req->out_iovcnt, buf,
				 sizeof(struct fuse_out_header) +
				 sizeof(struct fuse_write_out), 8, &total);

	assert((uintptr_t)buf - (uintptr_t)req->buf <= req->len);
	assert(spdk_iov_length(req->in_iovs, req->in_iovcnt) +
	       spdk_iov_length(req->out_iovs, req->out_iovcnt) <= req->len);

	return 0;
}

static int
fsdev_fuse_request_prep(struct fsdev_fuse_request *req, size_t inlen)
{
	struct fuse_in_header *hdr = req->buf;
	int rc = 0;

	req->unique = hdr->unique;
	req->in_iovcnt = req->out_iovcnt = 0;

	switch (hdr->opcode) {
	case FUSE_READ:
		rc = fsdev_fuse_request_prep_read(req, inlen);
		break;
	case FUSE_WRITE:
		rc = fsdev_fuse_request_prep_write(req, inlen);
		break;
	default:
		rc = fsdev_fuse_request_prep_generic(req, inlen);
		break;
	}

	return rc;
}

static void
fsdev_fuse_channel_destroy(struct fsdev_fuse_channel *ch)
{
	struct fsdev_fuse_request *req;

	assert(ch->num_outstanding == 0);
	TAILQ_FOREACH(req, &ch->free_requests, tailq) {
		spdk_free(req->buf);
	}
	if (ch->ioch != NULL) {
		spdk_put_io_channel(ch->ioch);
	}
	if (ch->poll_group != NULL) {
		spdk_put_io_channel(spdk_io_channel_from_ctx(ch->poll_group));
	}
	free(ch->request_pool);
	free(ch);
}

static struct fsdev_fuse_channel *
fsdev_fuse_channel_create(struct spdk_fuse_mount *mount)
{
	struct fsdev_fuse_channel *ch;
	struct fsdev_fuse_request *req;
	size_t i, reqsize;

	ch = calloc(1, sizeof(*ch));
	if (ch == NULL) {
		return NULL;
	}

	ch->ioch = spdk_fsdev_get_io_channel(mount->fsdev_desc);
	if (ch->ioch == NULL) {
		goto error;
	}

	TAILQ_INIT(&ch->free_requests);
	TAILQ_INIT(&ch->pending_requests);

	/* Bump poll group's refcount to make sure it doesn't disappear */
	ch->poll_group = spdk_io_channel_get_ctx(spdk_get_io_channel(&g_fuse));
	ch->mount = mount;
	ch->fd = mount->fd;
	ch->dispatcher = mount->dispatcher;

	reqsize = sizeof(*req) + spdk_fuse_dispatcher_get_io_ctx_size();
	ch->request_pool = calloc(mount->max_io_depth, reqsize);
	if (ch->request_pool == NULL) {
		goto error;
	}

	for (i = 0; i < mount->max_io_depth; i++) {
		req = (void *)((uintptr_t)ch->request_pool + i * reqsize);
		/* Reserve an extra page for the headers */
		req->len = mount->max_xfer_size + 4096;
		req->ch = ch;
		req->buf = spdk_zmalloc(req->len, 4096, NULL, SPDK_ENV_NUMA_ID_ANY,
					SPDK_MALLOC_DMA);
		if (req->buf == NULL) {
			goto error;
		}

		TAILQ_INSERT_TAIL(&ch->free_requests, req, tailq);
	}

	return ch;
error:
	fsdev_fuse_channel_destroy(ch);
	return NULL;
}

static void
fsdev_fuse_request_submit_cb(void *ctx, int status)
{
	struct fsdev_fuse_request *req = ctx;
	struct fsdev_fuse_channel *ch = req->ch;
	struct spdk_fuse_mount *mount __attribute__((unused));

	if (status != 0) {
		mount = req->ch->mount;
		SPDK_DEBUGLOG(fuse, "%s: %s failed: %s\n", fsdev_fuse_request_get_name(req),
			      mount->name, spdk_strerror(-status));
	}

	/* Ignore the error, it should be encoded in the FUSE response too */
	fsdev_fuse_request_complete(req);

	assert(ch->num_outstanding > 0);
	ch->num_outstanding--;
	if (ch->drain.cb_fn != NULL && ch->num_outstanding == 0) {
		ch->drain.cb_fn(ch->drain.cb_ctx, ch);
	}
}

static int
fsdev_fuse_channel_poll(struct fsdev_fuse_channel *ch)
{
	struct spdk_fuse_mount *mount = ch->mount;
	struct fsdev_fuse_request *req;
	int rc = 0, count = 0;

	while (1) {
		req = TAILQ_FIRST(&ch->pending_requests);
		if (req != NULL) {
			TAILQ_REMOVE(&ch->pending_requests, req, tailq);
		} else {
			req = TAILQ_FIRST(&ch->free_requests);
			if (req == NULL) {
				break;
			}

			rc = read(ch->fd, req->buf, req->len);
			if (rc < 0) {
				if (errno == EAGAIN) {
					rc = 0;
					break;
				}

				SPDK_ERRLOG("%s: %s\n", mount->name, spdk_strerror(errno));
				break;
			}

			if (rc < (int)sizeof(struct fuse_in_header)) {
				SPDK_ERRLOG("%s: read partial request (%d < %zu)\n",
					    mount->name, rc, sizeof(struct fuse_in_header));
				rc = -EBADMSG;
				break;
			}

			TAILQ_REMOVE(&ch->free_requests, req, tailq);
			rc = fsdev_fuse_request_prep(req, (size_t)rc);
			if (rc != 0) {
				fsdev_fuse_request_complete_manual(req, rc);
				break;
			}
		}

		ch->num_outstanding++;
		SPDK_DEBUGLOG(fuse, "%s: processing %s\n", mount->name,
			      fsdev_fuse_request_get_name(req));

		rc = spdk_fuse_dispatcher_submit_request(ch->dispatcher, ch->ioch,
				req->in_iovs, req->in_iovcnt, req->out_iovs, req->out_iovcnt,
				req->ctx, fsdev_fuse_request_submit_cb, req);
		if (rc != 0) {
			ch->num_outstanding--;
			if (rc == -ENOBUFS) {
				TAILQ_INSERT_HEAD(&ch->pending_requests, req, tailq);
				break;
			}
			SPDK_ERRLOG("%s: failed to submit %s: %s\n", mount->name,
				    fsdev_fuse_request_get_name(req), spdk_strerror(-rc));
			fsdev_fuse_request_complete_manual(req, rc);
			break;
		}

		count++;
	}

	return rc == 0 ? count : rc;
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
	mnt->max_io_depth = SPDK_GET_FIELD(opts, max_io_depth, g_fuse.opts.max_io_depth);
	if (mnt->max_io_depth == 0) {
		SPDK_ERRLOG("max_io_depth must be greater than zero\n");
		rc = -EINVAL;
		goto error;
	}

	mnt->max_xfer_size = SPDK_GET_FIELD(opts, max_xfer_size, g_fuse.opts.max_xfer_size);
	if (mnt->max_xfer_size < FSDEV_FUSE_MIN_MAX_XFER_SIZE) {
		SPDK_ERRLOG("max_xfer_size must be greater than %u\n",
			    FSDEV_FUSE_MIN_MAX_XFER_SIZE);
		rc = -EINVAL;
		goto error;
	}

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

	rc = snprintf(mopts, sizeof(mopts), "fd=%d,rootmode=%o,user_id=%u,group_id=%u,max_read=%zu",
		      mnt->fd, st.st_mode, getuid(), getgid(), mnt->max_xfer_size);
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
	struct spdk_fuse_mount		*mount;
	struct spdk_io_channel_iter	*iter;
	spdk_fuse_umount_cb		cb_fn;
	void				*cb_ctx;
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
fsdev_fuse_destroy_drained_channel_cb(void *_ctx, struct fsdev_fuse_channel *ch)
{
	struct fsdev_fuse_umount_ctx *ctx = _ctx;
	struct spdk_io_channel *ioch = spdk_io_channel_iter_get_channel(ctx->iter);
	struct spdk_fuse_poll_group *group = spdk_io_channel_get_ctx(ioch);

	assert(ch->num_outstanding == 0);
	TAILQ_REMOVE(&group->inactive_channels, ch, tailq);
	fsdev_fuse_channel_destroy(ch);

	spdk_for_each_channel_continue(ctx->iter, 0);
}

static void
fsdev_fuse_destroy_channels(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *ioch = spdk_io_channel_iter_get_channel(i);
	struct spdk_fuse_poll_group *group = spdk_io_channel_get_ctx(ioch);
	struct fsdev_fuse_umount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct fsdev_fuse_channel *ch;
	bool do_continue = true;

	ctx->iter = i;
	TAILQ_FOREACH(ch, &group->active_channels, tailq) {
		if (ch->mount == ctx->mount) {
			TAILQ_REMOVE(&group->active_channels, ch, tailq);
			TAILQ_INSERT_TAIL(&group->inactive_channels, ch, tailq);
			break;
		}
	}

	TAILQ_FOREACH(ch, &group->inactive_channels, tailq) {
		if (ch->mount == ctx->mount) {
			if (ch->num_outstanding > 0) {
				ch->drain.cb_fn = fsdev_fuse_destroy_drained_channel_cb;
				ch->drain.cb_ctx = ctx;
				do_continue = false;
			} else {
				TAILQ_REMOVE(&group->inactive_channels, ch, tailq);
				fsdev_fuse_channel_destroy(ch);
			}
			break;
		}
	}

	if (do_continue) {
		spdk_for_each_channel_continue(i, 0);
	}
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
	struct spdk_fuse_mount_opts local = {};

	local.size = spdk_min(sizeof(local), size);
	local.max_io_depth = g_fuse.opts.max_io_depth;
	local.max_xfer_size = g_fuse.opts.max_xfer_size;

	memcpy(opts, &local, local.size);
}

int
spdk_fuse_poll_group_poll(struct spdk_fuse_poll_group *group,
			  spdk_fuse_mount_error_cb cb_fn, void *cb_ctx)
{
	struct fsdev_fuse_channel *tmp, *ch;
	int rc, count = 0;

	TAILQ_FOREACH_SAFE(ch, &group->active_channels, tailq, tmp) {
		rc = fsdev_fuse_channel_poll(ch);
		if (rc < 0) {
			TAILQ_REMOVE(&group->active_channels, ch, tailq);
			TAILQ_INSERT_TAIL(&group->inactive_channels, ch, tailq);
			cb_fn(cb_ctx, ch->mount, rc);
			continue;
		}
		count += rc;
	}

	return count;
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
	if (opts != NULL) {
		if (SPDK_GET_FIELD(opts, max_io_depth, g_fuse.opts.max_io_depth) == 0) {
			SPDK_ERRLOG("max_io_depth must be greater than zero\n");
			return -EINVAL;
		}

		memcpy(&g_fuse.opts, opts, spdk_min(opts->size, sizeof(g_fuse.opts)));
	}

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
	size = spdk_min(size, sizeof(g_fuse.opts));
	memcpy(opts, &g_fuse.opts, size);
	opts->size = size;
}

SPDK_LOG_REGISTER_COMPONENT(fuse);
