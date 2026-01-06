/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/config.h"
#include "spdk/dma.h"
#include "spdk/fuse.h"
#include "spdk/fuse_dispatcher.h"
#include "spdk/log.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"

#ifdef SPDK_CONFIG_RDMA
#include "spdk_internal/rdma_utils.h"
#endif

#include "spdk/linux/fuse.h"

struct fuse_notify_request {
	size_t					len;
	void					*buf;
	struct spdk_thread			*thread;
	struct spdk_fsdev_notify_reply_data	reply_data;
	spdk_fsdev_notify_reply_cb_t		reply_cb;
	void					*reply_ctx;
	TAILQ_ENTRY(fuse_notify_request)	tailq;
};

struct spdk_fuse_mount {
	struct spdk_fsdev_desc		*fsdev_desc;
	struct spdk_fuse_dispatcher	*dispatcher;
	struct spdk_memory_domain	*domain;
	int				fd;
	bool				mounted;
	bool				clone_fd;
	bool				removing;
	char				*name;
	char				*mountpoint;
	size_t				max_io_depth;
	size_t				max_xfer_size;
	struct spdk_thread		*thread;
	struct iovec			notify_iov;
	TAILQ_ENTRY(spdk_fuse_mount)	tailq;
	pthread_mutex_t			mutex;
	pthread_t			notify_thread;
	pthread_cond_t			notify_cond;
	TAILQ_HEAD(, fuse_notify_request) notify_queue;
	bool				notify_thread_shutdown;
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

struct fsdev_fuse_domain {
	struct spdk_memory_domain		*domain;
#ifdef SPDK_CONFIG_RDMA
	struct spdk_rdma_utils_mem_map		*map;
#endif
	STAILQ_ENTRY(fsdev_fuse_domain)		stailq;
};

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
	int					clone_fd;
	void					*request_pool;
	struct spdk_fuse_poll_group		*poll_group;
	uint16_t				source_id;
	uint64_t				source_unique;
	STAILQ_HEAD(, fsdev_fuse_domain)	domains;
};

struct spdk_fuse_poll_group {
	TAILQ_HEAD(, fsdev_fuse_channel)	active_channels;
	TAILQ_HEAD(, fsdev_fuse_channel)	inactive_channels;
};

struct {
	TAILQ_HEAD(, spdk_fuse_mount)	mounts;
	pthread_mutex_t			mutex;
	char				*fstype;
	struct spdk_fuse_opts		opts;
	struct {
		spdk_fuse_cleanup_cb	cb_fn;
		void			*cb_ctx;
	} cleanup;
} g_fuse = {
	.mounts = TAILQ_HEAD_INITIALIZER(g_fuse.mounts),
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.opts = {
		.max_io_depth = 8,
		.max_xfer_size = 128 * 1024,
		.clone_fd = true,
		.fstype = "fuse.spdk",
	},
};

#define FSDEV_FUSE_MIN_MAX_XFER_SIZE 4096

static const char *
fsdev_fuse_request_get_name(struct fsdev_fuse_request *req)
{
	struct fuse_in_header *in = req->buf;

	return spdk_fsdev_get_opcode_name(in->opcode);
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
	if (req->out_iovcnt == 0) {
		return NULL;
	}

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
	case FUSE_INTERRUPT:
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

	if (hdr != NULL) {
		memset(hdr, 0, sizeof(*hdr));
		hdr->len = sizeof(*hdr);
		hdr->error = error;
		hdr->unique = req->unique;
	}

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
fsdev_fuse_request_prep_noreply(struct fsdev_fuse_request *req, size_t inlen)
{
	void *buf = req->buf;
	size_t total = 0;

	buf = fsdev_fuse_set_iov(&req->in_iovs[0], &req->in_iovcnt, buf,
				 sizeof(struct fuse_in_header), 1, &total);
	buf = fsdev_fuse_set_iov(&req->in_iovs[1], &req->in_iovcnt, buf,
				 inlen - sizeof(struct fuse_in_header), 1, &total);

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
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
		rc = fsdev_fuse_request_prep_noreply(req, inlen);
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
	struct fsdev_fuse_domain *domain;

	assert(ch->num_outstanding == 0);
	TAILQ_FOREACH(req, &ch->free_requests, tailq) {
		spdk_free(req->buf);
	}
	if (ch->ioch != NULL) {
		spdk_put_io_channel(ch->ioch);
	}
	if (ch->clone_fd > 0) {
		close(ch->clone_fd);
	}
	if (ch->poll_group != NULL) {
		spdk_put_io_channel(spdk_io_channel_from_ctx(ch->poll_group));
	}
	while (!STAILQ_EMPTY(&ch->domains)) {
		domain = STAILQ_FIRST(&ch->domains);
		STAILQ_REMOVE_HEAD(&ch->domains, stailq);
#ifdef SPDK_CONFIG_RDMA
		spdk_rdma_utils_free_mem_map(&domain->map);
#endif
		free(domain);
	}
	free(ch->request_pool);
	free(ch);
}

static int
fsdev_fuse_clone_fuse_fd(struct spdk_fuse_mount *mount)
{
	int rc, fd, mainfd = mount->fd;

	fd = open("/dev/fuse", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		SPDK_WARNLOG("%s: failed to open /dev/fuse: %s\n", mount->name,
			     spdk_strerror(errno));
		return -1;
	}

	rc = ioctl(fd, FUSE_DEV_IOC_CLONE, &mainfd);
	if (rc != 0) {
		SPDK_WARNLOG("%s: failed to clone /dev/fuse: %s\n", mount->name,
			     spdk_strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
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

	ch->clone_fd = -1;
	if (mount->clone_fd) {
		ch->clone_fd = fsdev_fuse_clone_fuse_fd(mount);
	}

	ch->ioch = spdk_fsdev_get_io_channel(mount->fsdev_desc);
	if (ch->ioch == NULL) {
		goto error;
	}

	TAILQ_INIT(&ch->free_requests);
	TAILQ_INIT(&ch->pending_requests);
	STAILQ_INIT(&ch->domains);

	/* Bump poll group's refcount to make sure it doesn't disappear */
	ch->poll_group = spdk_io_channel_get_ctx(spdk_get_io_channel(&g_fuse));
	ch->mount = mount;
	/* If we can't manage to clone the fd, just fall back to using the main fd */
	ch->fd = ch->clone_fd >= 0 ? ch->clone_fd : mount->fd;
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

	ch->source_id = (uint16_t)spdk_env_get_core_index(spdk_env_get_current_core());

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

static bool
fsdev_fuse_request_check_zcopy(struct fsdev_fuse_request *req,
			       struct fuse_in_header **inhdr,
			       struct iovec **in_iovs, int *in_iovcnt,
			       struct fuse_out_header **outhdr,
			       struct iovec **out_iovs, int *out_iovcnt)
{
	struct spdk_fuse_mount *mount = req->ch->mount;

	if (mount->domain != NULL) {
		*inhdr = fsdev_fuse_request_get_inhdr(req);
		*outhdr = fsdev_fuse_request_get_outhdr(req);
		switch ((*inhdr)->opcode) {
		case FUSE_READ:
			/* We prepare reqs in a way that the payload always starts at out_iovs[1] */
			*out_iovs = &req->out_iovs[1];
			*out_iovcnt = req->out_iovcnt - 1;
			*in_iovs = NULL;
			*in_iovcnt = 0;
			return true;
		case FUSE_WRITE:
			/* We prepare reqs in a way that the payload always starts at in_iovs[1] */
			*in_iovs = &req->in_iovs[1];
			*in_iovcnt = req->in_iovcnt - 1;
			*out_iovs = NULL;
			*out_iovcnt = 0;
			return true;
		default:
			break;
		}
	}

	*in_iovs = req->in_iovs;
	*in_iovcnt = req->in_iovcnt;
	/* Some requests don't have a reply */
	*out_iovs = req->out_iovcnt > 0 ? req->out_iovs : NULL;
	*out_iovcnt = req->out_iovcnt;

	return false;
}

static int
fsdev_fuse_channel_submit_request(struct fsdev_fuse_channel *ch, struct fsdev_fuse_request *req)
{
	struct spdk_fuse_mount *mount = ch->mount;
	struct fuse_in_header *in_hdr;
	struct fuse_out_header *out_hdr;
	struct iovec *in_iovs, *out_iovs;
	int in_iovcnt, out_iovcnt;
	bool do_zcopy;

	do_zcopy = fsdev_fuse_request_check_zcopy(req, &in_hdr, &in_iovs, &in_iovcnt,
			&out_hdr, &out_iovs, &out_iovcnt);
	if (do_zcopy) {
		return spdk_fuse_dispatcher_submit_zcopy(ch->dispatcher, ch->ioch,
				in_hdr, in_iovs, in_iovcnt, out_hdr, out_iovs, out_iovcnt,
				mount->domain, ch, req->ctx, ch->source_id,
				ch->source_unique, fsdev_fuse_request_submit_cb, req);
	} else {
		return spdk_fuse_dispatcher_submit_request(ch->dispatcher, ch->ioch,
				in_iovs, in_iovcnt, out_iovs, out_iovcnt,
				req->ctx, ch->source_id, ch->source_unique,
				fsdev_fuse_request_submit_cb, req);
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
				} else if (errno != ENODEV) {
					SPDK_ERRLOG("%s: %s\n", mount->name, spdk_strerror(errno));
				}
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
		ch->source_unique++;
		SPDK_DEBUGLOG(fuse, "%s: processing %s\n", mount->name,
			      fsdev_fuse_request_get_name(req));

		rc = fsdev_fuse_channel_submit_request(ch, req);
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

static void fsdev_fuse_notify_reply_msg(void *ctx);

static void
fsdev_fuse_notify_thread_cleanup(struct spdk_fuse_mount *mount)
{
	struct fuse_notify_request *work, *tmp;

	pthread_mutex_lock(&mount->mutex);
	mount->notify_thread_shutdown = true;
	pthread_cond_signal(&mount->notify_cond);
	pthread_mutex_unlock(&mount->mutex);

	pthread_join(mount->notify_thread, NULL);

	pthread_mutex_lock(&mount->mutex);
	TAILQ_FOREACH_SAFE(work, &mount->notify_queue, tailq, tmp) {
		TAILQ_REMOVE(&mount->notify_queue, work, tailq);
		if (work->reply_cb != NULL) {
			assert(work->thread != NULL);
			work->reply_data.status = -ESHUTDOWN;
			spdk_thread_send_msg(work->thread, fsdev_fuse_notify_reply_msg, work);
		} else {
			free(work->buf);
			free(work);
		}
	}
	pthread_mutex_unlock(&mount->mutex);

	pthread_cond_destroy(&mount->notify_cond);
}

static void
fsdev_fuse_mount_cleanup(struct spdk_fuse_mount *mount)
{
	struct spdk_fuse_mount *tmp;
	int rc;

	pthread_mutex_lock(&g_fuse.mutex);
	TAILQ_FOREACH(tmp, &g_fuse.mounts, tailq) {
		if (tmp == mount) {
			TAILQ_REMOVE(&g_fuse.mounts, tmp, tailq);
			break;
		}
	}
	pthread_mutex_unlock(&g_fuse.mutex);

	fsdev_fuse_notify_thread_cleanup(mount);
	if (mount->fd >= 0) {
		close(mount->fd);
	}
	if (mount->mounted) {
		rc = umount2(mount->mountpoint, MNT_DETACH);
		if (rc != 0) {
			SPDK_INFOLOG(fuse, "%s: failed to umount %s: %s\n", mount->name,
				     mount->mountpoint, spdk_strerror(errno));
		}
	}
	if (mount->dispatcher != NULL) {
		spdk_fuse_dispatcher_delete(mount->dispatcher);
	}
	if (mount->fsdev_desc != NULL) {
		spdk_fsdev_close(mount->fsdev_desc);
	}

	spdk_memory_domain_destroy(mount->domain);

	pthread_mutex_destroy(&mount->mutex);
	free(mount->notify_iov.iov_base);
	free(mount->name);
	free(mount->mountpoint);
	free(mount);
}

static void
fsdev_fuse_remove_umount_cb(void *_ctx)
{
}

static void
fsdev_fuse_fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *ctx)
{
	struct spdk_fuse_mount *mount = ctx;
	int rc;

	switch (type) {
	case SPDK_FSDEV_EVENT_REMOVE:
		rc = spdk_fuse_umount(mount, fsdev_fuse_remove_umount_cb, NULL);
		if (rc != 0) {
			SPDK_ERRLOG("%s: failed to umount %s: %s\n", mount->name,
				    mount->mountpoint, spdk_strerror(-rc));
		}
		break;
	default:
		SPDK_ERRLOG("%s: unhandled event %d\n", spdk_fsdev_get_name(fsdev), type);
		break;
	}
}

static void
fsdev_fuse_notify_reply_msg(void *ctx)
{
	struct fuse_notify_request *work = ctx;

	assert(work->reply_cb != NULL);
	work->reply_cb(&work->reply_data, work->reply_ctx);

	free(work->buf);
	free(work);
}

static void *
fsdev_fuse_notify_thread_fn(void *arg)
{
	struct spdk_fuse_mount *mount = arg;
	struct fuse_notify_request *work;
	int rc;

	pthread_mutex_lock(&mount->mutex);

	/* Continue while not shutting down OR queue has items. The TAILQ_EMPTY check ensures
	 * we process all queued items even after shutdown is signaled.
	 */
	while (!mount->notify_thread_shutdown || !TAILQ_EMPTY(&mount->notify_queue)) {
		while (!mount->notify_thread_shutdown && TAILQ_EMPTY(&mount->notify_queue)) {
			pthread_cond_wait(&mount->notify_cond, &mount->mutex);
		}

		work = TAILQ_FIRST(&mount->notify_queue);
		if (work == NULL) {
			continue;
		}

		TAILQ_REMOVE(&mount->notify_queue, work, tailq);
		pthread_mutex_unlock(&mount->mutex);

		rc = write(mount->fd, work->buf, work->len);
		if (rc < 0) {
			SPDK_ERRLOG("%s: failed to write notification: %s\n", mount->name,
				    spdk_strerror(errno));
			rc = -errno;
		} else {
			rc = 0;
		}

		if (work->reply_cb != NULL) {
			assert(work->thread != NULL);
			work->reply_data.status = rc;
			spdk_thread_send_msg(work->thread, fsdev_fuse_notify_reply_msg, work);
		} else {
			free(work->buf);
			free(work);
		}
		pthread_mutex_lock(&mount->mutex);
	}

	pthread_mutex_unlock(&mount->mutex);
	return NULL;
}

static void
fsdev_fuse_notify_cb(struct spdk_fsdev *fsdev, void *ctx,
		     const struct spdk_fsdev_notify_data *notify_data,
		     spdk_fsdev_notify_reply_cb_t reply_cb, void *reply_ctx)
{
	struct spdk_fuse_mount *mount = ctx;
	struct spdk_fsdev_notify_reply_data reply_data = {};
	struct fuse_out_header *outhdr = mount->notify_iov.iov_base;
	struct fuse_notify_request *work;
	bool has_reply;
	int rc;

	rc = spdk_fuse_dispatcher_encode_notify(mount->dispatcher, &mount->notify_iov, 1,
						notify_data, 0, &has_reply);
	if (rc != 0) {
		SPDK_ERRLOG("%s: failed to encode notification: %s\n", mount->name,
			    spdk_strerror(-rc));
		goto reply;
	}

	work = calloc(1, sizeof(*work));
	if (work == NULL) {
		SPDK_ERRLOG("%s: failed to allocate notify work\n", mount->name);
		rc = -ENOMEM;
		goto reply;
	}

	work->len = outhdr->len;
	work->buf = malloc(work->len);
	if (work->buf == NULL) {
		SPDK_ERRLOG("%s: failed to allocate notify buffer\n", mount->name);
		free(work);
		rc = -ENOMEM;
		goto reply;
	}

	memcpy(work->buf, outhdr, work->len);
	work->thread = spdk_get_thread();
	work->reply_cb = reply_cb;
	work->reply_ctx = reply_ctx;

	pthread_mutex_lock(&mount->mutex);
	if (mount->notify_thread_shutdown) {
		pthread_mutex_unlock(&mount->mutex);
		free(work->buf);
		free(work);
		rc = -ESHUTDOWN;
		goto reply;
	}
	TAILQ_INSERT_TAIL(&mount->notify_queue, work, tailq);
	pthread_cond_signal(&mount->notify_cond);
	pthread_mutex_unlock(&mount->mutex);
	return;

reply:
	if (reply_cb != NULL) {
		reply_data.status = rc;
		reply_cb(&reply_data, reply_ctx);
	}
}

static int
normalize_hard_path(char *dst, size_t dst_size, const char *path)
{
	char tmp_path[PATH_MAX];
	bool is_absolute;
	size_t written = 0, token_len, len;
	char *tokens[PATH_MAX / 2];
	char *token, *str;
	int levels[PATH_MAX / 2];
	int i, token_count = 0, current_level = 0;

	if (dst == NULL || dst_size == 0 || path == NULL || strlen(path) >= PATH_MAX) {
		return -1;
	}

	/* Create a modifiable copy of the input path */
	snprintf(tmp_path, PATH_MAX, "%s", path);

	/* Initialize destination buffer */
	dst[0] = '\0';

	is_absolute = (path[0] == '/');

	if (is_absolute) {
		if (dst_size == 1) {
			return -1;
		}
		dst[0] = '/';
		dst[1] = '\0';
		written = 1;
	}

	/* Parse components using strsep */
	str = tmp_path;
	while ((token = strsep(&str, "/")) != NULL) {
		if (*token == '\0') {
			/* Skip empty components (consecutive slashes) */
			continue;
		} else if (strcmp(token, ".") == 0) {
			/* Skip "." components */
			continue;
		} else if (strcmp(token, "..") == 0) {
			if (!is_absolute && current_level <= 0) {
				/* In relative paths, keep ".." if we cannot go up further */
				if (token_count >= PATH_MAX / 2) {
					return -1;
				}
				tokens[token_count] = "..";
				levels[token_count] = --current_level;
				token_count++;
			} else if (current_level > 0) {
				/* Remove last component if possible */
				while (token_count > 0 &&
				       levels[token_count - 1] != current_level - 1) {
					token_count--;
				}
				if (token_count > 0) {
					token_count--;
				}
				current_level--;
			}
		} else {
			/* Add normal component */
			if (token_count >= PATH_MAX / 2) {
				return -1;
			}
			tokens[token_count] = token;
			levels[token_count] = current_level++;
			token_count++;
		}
	}

	/* Rebuild path from components */
	for (i = 0; i < token_count; i++) {
		if (i > 0) {
			/* Add separator between components */
			if (written < dst_size - 1) {
				dst[written++] = '/';
				dst[written] = '\0';
			} else {
				/* Buffer overflow */
				return -1;
			}
		}

		token_len = strlen(tokens[i]);
		if (written + token_len < dst_size) {
			memcpy(dst + written, tokens[i], token_len);
			written += token_len;
			dst[written] = '\0';
		} else {
			/* Buffer overflow */
			return -1;
		}
	}

	/* Handle special cases */
	if (dst[0] == '\0') {
		if (path[0] == '\0') {
			if (dst_size > 1) {
				snprintf(dst, dst_size, ".");
			} else {
				return -1;
			}
		} else if (is_absolute) {
			if (dst_size > 1) {
				snprintf(dst, dst_size, "/");
			} else {
				return -1;
			}
		} else {
			if (dst_size > 1) {
				snprintf(dst, dst_size, ".");
			} else {
				return -1;
			}
		}
	}

	/* Remove trailing slash if not root */
	len = strlen(dst);
	if (len > 1 && dst[len - 1] == '/') {
		dst[len - 1] = '\0';
	}

	return 0;
}

#ifdef SPDK_CONFIG_RDMA
static struct fsdev_fuse_domain *
fsdev_fuse_get_domain(struct fsdev_fuse_channel *ch, struct spdk_memory_domain *domain,
		      struct spdk_memory_domain_translation_ctx *ctx)
{
	struct spdk_fuse_mount *mount = ch->mount;
	struct fsdev_fuse_domain *fd;
	struct ibv_qp *qp;
	uint64_t flags;

	STAILQ_FOREACH(fd, &ch->domains, stailq) {
		if (fd->domain == domain) {
			return fd;
		}
	}

	fd = calloc(1, sizeof(*fd));
	if (fd == NULL) {
		return NULL;
	}

	qp = SPDK_GET_FIELD(ctx, rdma.ibv_qp, NULL);
	flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

	fd->domain = domain;
	fd->map = spdk_rdma_utils_create_mem_map(qp->pd, NULL, flags);
	if (fd->map == NULL) {
		SPDK_ERRLOG("%s: failed to create memory map\n", mount->name);
		free(fd);
		return NULL;
	}

	STAILQ_INSERT_TAIL(&ch->domains, fd, stailq);
	return fd;
}

static int
fsdev_fuse_translate_addr(struct spdk_memory_domain *src_domain,
			  void *src_domain_ctx, struct spdk_memory_domain *dst_domain,
			  struct spdk_memory_domain_translation_ctx *dst_domain_ctx,
			  void *addr, size_t len,
			  struct spdk_memory_domain_translation_result *result)
{
	struct fsdev_fuse_channel *ch = src_domain_ctx;
	struct spdk_fuse_mount *mount = ch->mount;
	struct spdk_rdma_utils_memory_translation tr;
	struct fsdev_fuse_domain *fd;
	int rc;

	assert(spdk_memory_domain_get_dma_device_type(dst_domain) == SPDK_DMA_DEVICE_TYPE_RDMA);
	fd = fsdev_fuse_get_domain(ch, dst_domain, dst_domain_ctx);
	if (spdk_unlikely(fd == NULL)) {
		return -ENOMEM;
	}

	rc = spdk_rdma_utils_get_translation(fd->map, addr, len, &tr);
	if (spdk_unlikely(rc != 0)) {
		SPDK_ERRLOG("%s: failed to translate addr=%p: %s\n", mount->name, addr,
			    spdk_strerror(-rc));
		return rc;
	}

	assert(result->size >= SPDK_SIZEOF(result, rdma));
	result->iov_count = 1;
	result->iov.iov_base = addr;
	result->iov.iov_len = len;
	result->dst_domain = dst_domain;
	result->rdma.lkey = spdk_rdma_utils_memory_translation_get_lkey(&tr);
	result->rdma.rkey = spdk_rdma_utils_memory_translation_get_rkey(&tr);

	return 0;
}
#else
static int
fsdev_fuse_translate_addr(struct spdk_memory_domain *src_domain,
			  void *src_domain_ctx, struct spdk_memory_domain *dst_domain,
			  struct spdk_memory_domain_translation_ctx *dst_domain_ctx,
			  void *addr, size_t len,
			  struct spdk_memory_domain_translation_result *result)
{
	return -ENOTSUP;
}
#endif

static int
fsdev_fuse_validate_mountpoint(const char *mountpoint)
{
	struct spdk_fuse_mount *mnt;
	char normalized1[PATH_MAX], normalized2[PATH_MAX];
	size_t n1len, n2len;
	int rc;

	rc = normalize_hard_path(normalized1, PATH_MAX, mountpoint);
	if (rc != 0) {
		SPDK_ERRLOG("Normalizing %s failed, rc=%d\n", mountpoint, rc);
		return rc;
	}

	n1len = strlen(normalized1);
	TAILQ_FOREACH(mnt, &g_fuse.mounts, tailq) {
		rc = normalize_hard_path(normalized2, PATH_MAX, mnt->mountpoint);
		if (rc != 0) {
			SPDK_ERRLOG("Normalizing %s failed, rc=%d\n", mnt->mountpoint, rc);
			return rc;
		}

		n2len = strlen(normalized2);
		if (strstr(normalized1, normalized2) == normalized1 &&
		    (n1len == n2len || (n1len > n2len && normalized1[n2len] == '/'))) {
			SPDK_ERRLOG("Mounting %s in FUSE fsdev %s is not supported.\n",
				    normalized1, normalized2);
			return -ENOTSUP;
		}
	}

	return 0;
}

static int
fsdev_fuse_mount_init(struct spdk_fuse_mount **_mnt, const char *name, const char *mountpoint,
		      struct spdk_fuse_mount_opts *opts)
{
	struct spdk_fuse_mount *mnt;
	struct spdk_fsdev *fsdev;
	struct stat st;
	char mopts[128];
	int rc;

	if (spdk_env_get_core_count() == 1) {
		/* Deadlock will occur if a file is mounted inside a FUSE file system
		 * when number of CPU cores is 1. Detect this case and return error
		 * to avoid deadlock. But, this operation works if number of CPU cores
		 * is 2 or more. Hence, enable the check only with 1 CPU core case.
		 */
		rc = fsdev_fuse_validate_mountpoint(mountpoint);
		if (rc != 0) {
			return rc;
		}
	}

	mnt = calloc(1, sizeof(*mnt));
	if (mnt == NULL) {
		return -ENOMEM;
	}

	rc = pthread_mutex_init(&mnt->mutex, NULL);
	if (rc != 0) {
		free(mnt);
		return -rc;
	}

	mnt->thread = spdk_get_thread();
	mnt->fd = -1;
	mnt->clone_fd = SPDK_GET_FIELD(opts, clone_fd, g_fuse.opts.clone_fd);
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

	rc = spdk_fsdev_open(name, fsdev_fuse_fsdev_event_cb, mnt, &mnt->fsdev_desc);
	if (rc != 0) {
		SPDK_ERRLOG("%s: failed to open fsdev: %s\n", mnt->name, spdk_strerror(-rc));
		goto error;
	}

	fsdev = spdk_fsdev_desc_get_fsdev(mnt->fsdev_desc);
	if (SPDK_GET_FIELD(opts, fake_memory_domain, false)) {
		if (spdk_fsdev_get_memory_domain_types(fsdev, NULL, 0) <= 0) {
			SPDK_ERRLOG("%s: fsdev doesn't support memory domains\n", name);
			rc = -EINVAL;
			goto error;
		}
		rc = spdk_memory_domain_create(&mnt->domain, SPDK_DMA_DEVICE_TYPE_DMA, NULL,
					       "fuse");
		if (rc != 0) {
			SPDK_ERRLOG("%s: failed to create fuse memory domain: %s\n", name,
				    spdk_strerror(-rc));
			goto error;
		}

		spdk_memory_domain_set_translation(mnt->domain, fsdev_fuse_translate_addr);
	}

	mnt->dispatcher = spdk_fuse_dispatcher_create(mnt->fsdev_desc, NULL, NULL);
	if (mnt->dispatcher == NULL) {
		rc = -ENOMEM;
		goto error;
	}

	mnt->notify_iov.iov_len = spdk_fuse_dispatcher_get_notify_buf_size(mnt->dispatcher);
	if (mnt->notify_iov.iov_len > 0) {
		mnt->notify_iov.iov_base = calloc(1, mnt->notify_iov.iov_len);
		if (mnt->notify_iov.iov_base == NULL) {
			SPDK_ERRLOG("%s: failed to allocate notify buffer\n", mnt->name);
			goto error;
		}

		rc = spdk_fsdev_enable_notifications(mnt->fsdev_desc, fsdev_fuse_notify_cb, mnt);
		if (rc != 0) {
			SPDK_ERRLOG("%s: failed to enable notifications: %s\n", mnt->name,
				    spdk_strerror(-rc));
			goto error;
		}
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

	mnt->notify_thread_shutdown = false;
	TAILQ_INIT(&mnt->notify_queue);
	rc = pthread_cond_init(&mnt->notify_cond, NULL);
	if (rc != 0) {
		SPDK_ERRLOG("%s: failed to initialize notify condition variable: %s\n", mnt->name,
			    spdk_strerror(rc));
		rc = -rc;
		goto error;
	}

	rc = pthread_create(&mnt->notify_thread, NULL, fsdev_fuse_notify_thread_fn, mnt);
	if (rc != 0) {
		SPDK_ERRLOG("%s: failed to create notify thread: %s\n", mnt->name,
			    spdk_strerror(rc));
		pthread_cond_destroy(&mnt->notify_cond);
		rc = -rc;
		goto error;
	}

	rc = snprintf(mopts, sizeof(mopts), "fd=%d,rootmode=%o,user_id=%u,group_id=%u,max_read=%zu,"
		      "allow_other,default_permissions", mnt->fd, st.st_mode, getuid(), getgid(),
		      mnt->max_xfer_size);
	if (rc < 0 || rc >= (int)sizeof(mopts)) {
		rc = -EINVAL;
		goto error;
	}

	rc = mount(mnt->name, mnt->mountpoint,
		   SPDK_GET_FIELD(opts, fstype, g_fuse.opts.fstype),
		   SPDK_GET_FIELD(opts, flags, 0), mopts);
	if (rc != 0) {
		rc = -errno;
		SPDK_ERRLOG("%s: failed to mount fsdev at %s\n", mnt->name, mnt->mountpoint);
		goto error;
	}

	SPDK_INFOLOG(fuse, "%s: mounted fsdev at %s\n", mnt->name, mnt->mountpoint);
	pthread_mutex_lock(&g_fuse.mutex);
	TAILQ_INSERT_TAIL(&g_fuse.mounts, mnt, tailq);
	pthread_mutex_unlock(&g_fuse.mutex);
	mnt->mounted = true;
	*_mnt = mnt;

	return 0;
error:
	fsdev_fuse_mount_cleanup(mnt);
	return rc;
}

struct fsdev_fuse_mount_ctx {
	struct spdk_fuse_mount		*mount;
	struct spdk_fuse_mount_opts	opts;
	const char			*name;
	const char			*mountpoint;
	int				status;
	spdk_fuse_mount_cb		cb_fn;
	void				*cb_ctx;
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

static void
fsdev_fuse_remount_umount_cb(void *_ctx)
{
	struct fsdev_fuse_mount_ctx *ctx = _ctx;
	struct spdk_fuse_mount_opts *opts = &ctx->opts;
	int rc;

	opts->flags &= ~MS_REMOUNT;
	rc = spdk_fuse_mount(ctx->name, ctx->mountpoint, opts, ctx->cb_fn, ctx->cb_ctx);
	if (rc != 0) {
		ctx->cb_fn(ctx->cb_ctx, ctx->mount, rc);
	}
	free(ctx);
}

int
spdk_fuse_mount(const char *name, const char *mountpoint, struct spdk_fuse_mount_opts *opts,
		spdk_fuse_mount_cb cb_fn, void *cb_ctx)
{
	struct spdk_fuse_mount *mount = NULL;
	struct fsdev_fuse_mount_ctx *ctx = NULL;
	int rc = 0;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return -ENOMEM;
	}

	ctx->cb_fn = cb_fn;
	ctx->cb_ctx = cb_ctx;
	ctx->name = name;
	ctx->mountpoint = mountpoint;
	memcpy(&ctx->opts, opts, opts->size);

	if (SPDK_GET_FIELD(opts, flags, 0) & MS_REMOUNT) {
		pthread_mutex_lock(&g_fuse.mutex);
		TAILQ_FOREACH(mount, &g_fuse.mounts, tailq) {
			if (strcmp(mount->name, name) == 0 &&
			    strcmp(mount->mountpoint, mountpoint) == 0) {
				ctx->mount = mount;
				break;
			}
		}
		pthread_mutex_unlock(&g_fuse.mutex);
		if (mount == NULL) {
			goto error;
		}

		rc = spdk_fuse_umount(mount, fsdev_fuse_remount_umount_cb, ctx);
		if (rc != 0) {
			goto error;
		}
	} else {
		rc = fsdev_fuse_mount_init(&mount, name, mountpoint, opts);
		if (rc != 0) {
			goto error;
		}

		ctx->mount = mount;
		spdk_for_each_channel(&g_fuse, fsdev_fuse_create_channels, ctx,
				      fsdev_fuse_create_channels_done);
	}

	return 0;
error:
	free(ctx);
	return rc;
}

struct fsdev_fuse_umount_ctx {
	struct spdk_fuse_mount		*mount;
	struct spdk_io_channel_iter	*iter;
	struct spdk_thread		*thread;
	struct {
		struct spdk_io_channel	*ioch;
		struct iovec		in_iov;
		struct fuse_in_header	in_hdr;
		struct iovec		out_iov;
		struct fuse_in_header	out_hdr;
		void			*ctx;
	} destroy;
	spdk_fuse_umount_cb		cb_fn;
	void				*cb_ctx;
};

static void
fsdev_fuse_umount_exec_user_cb(void *_ctx)
{
	struct fsdev_fuse_umount_ctx *ctx = _ctx;

	if (ctx->cb_fn != NULL) {
		ctx->cb_fn(ctx->cb_ctx);
	}
	free(ctx->destroy.ctx);
	free(ctx);
}

static void
fsdev_fuse_umount_cleanup(void *_ctx)
{
	struct fsdev_fuse_umount_ctx *ctx = _ctx;

	fsdev_fuse_mount_cleanup(ctx->mount);
	spdk_thread_exec_msg(ctx->thread, fsdev_fuse_umount_exec_user_cb, ctx);
}

static void
fsdev_fuse_umount_fuse_destroy_cb(void *cb_ctx, int status)
{
	struct fsdev_fuse_umount_ctx *ctx = cb_ctx;

	if (status != 0) {
		SPDK_WARNLOG("FUSE_DESTROY failed: %s\n", spdk_strerror(-status));
	}
	if (ctx->destroy.ioch) {
		spdk_put_io_channel(ctx->destroy.ioch);
		ctx->destroy.ioch = NULL;
	}
	/* The cleanup needs to be done on the same thread as the initial mount */
	spdk_thread_exec_msg(ctx->mount->thread, fsdev_fuse_umount_cleanup, ctx);
}

static void
fsdev_fuse_destroy_channels_done(struct spdk_io_channel_iter *i, int status)
{
	struct fsdev_fuse_umount_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fuse_mount *mount = ctx->mount;
	int rc;

	ctx->destroy.ctx = calloc(1, spdk_fuse_dispatcher_get_io_ctx_size());
	if (ctx->destroy.ctx == NULL) {
		fsdev_fuse_umount_fuse_destroy_cb(ctx, -ENOMEM);
		return;
	}

	ctx->destroy.ioch = spdk_fsdev_get_io_channel(mount->fsdev_desc);
	if (ctx->destroy.ioch == NULL) {
		fsdev_fuse_umount_fuse_destroy_cb(ctx, -ENOMEM);
		return;
	}

	ctx->destroy.in_hdr.len = sizeof(ctx->destroy.in_hdr);
	ctx->destroy.in_hdr.opcode = FUSE_DESTROY;
	ctx->destroy.in_iov.iov_base = &ctx->destroy.in_hdr;
	ctx->destroy.in_iov.iov_len = sizeof(ctx->destroy.in_hdr);
	ctx->destroy.out_iov.iov_base = &ctx->destroy.out_hdr;
	ctx->destroy.out_iov.iov_len = sizeof(ctx->destroy.out_hdr);
	rc = spdk_fuse_dispatcher_submit_request(mount->dispatcher, ctx->destroy.ioch,
			&ctx->destroy.in_iov, 1, &ctx->destroy.out_iov, 1, ctx->destroy.ctx, 0, 0,
			fsdev_fuse_umount_fuse_destroy_cb, ctx);
	if (rc != 0) {
		fsdev_fuse_umount_fuse_destroy_cb(ctx, rc);
	}
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
	struct fsdev_fuse_umount_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return -ENOMEM;
	}

	pthread_mutex_lock(&mount->mutex);
	if (mount->removing) {
		pthread_mutex_unlock(&mount->mutex);
		free(ctx);
		return -EINPROGRESS;
	}
	mount->removing = true;
	pthread_mutex_unlock(&mount->mutex);

	ctx->mount = mount;
	ctx->cb_fn = cb_fn;
	ctx->cb_ctx = cb_ctx;
	ctx->thread = spdk_get_thread();

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
	local.clone_fd = g_fuse.opts.clone_fd;
	local.fstype = g_fuse.opts.fstype;
	local.fake_memory_domain = false;

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
spdk_fuse_for_each_mount(spdk_fuse_for_each_mount_cb cb_fn, void *ctx)
{
	struct spdk_fuse_mount *mount;
	int rc = 0;

	pthread_mutex_lock(&g_fuse.mutex);
	TAILQ_FOREACH(mount, &g_fuse.mounts, tailq) {
		rc = cb_fn(mount, ctx);
		if (rc != 0) {
			break;
		}
	}
	pthread_mutex_unlock(&g_fuse.mutex);

	return rc;
}

struct spdk_fsdev *
spdk_fuse_mount_get_fsdev(struct spdk_fuse_mount *mount)
{
	return spdk_fsdev_desc_get_fsdev(mount->fsdev_desc);
}

const char *
spdk_fuse_mount_get_mountpoint(struct spdk_fuse_mount *mount)
{
	return mount->mountpoint;
}

int
spdk_fuse_init(struct spdk_fuse_opts *opts)
{
	int rc;

	if (opts != NULL) {
		rc = spdk_fuse_set_opts(opts);
		if (rc != 0) {
			return rc;
		}
	}

	spdk_io_device_register(&g_fuse, fsdev_fuse_poll_group_create_cb,
				fsdev_fuse_poll_group_destroy_cb,
				sizeof(struct spdk_fuse_poll_group), "fuse");
	return 0;
}

static void
fsdev_fuse_unregister_done(void *io_device)
{
	free(g_fuse.fstype);
	g_fuse.fstype = NULL;

	if (g_fuse.cleanup.cb_fn != NULL) {
		g_fuse.cleanup.cb_fn(g_fuse.cleanup.cb_ctx);
	}

	g_fuse.cleanup.cb_fn = NULL;
	g_fuse.cleanup.cb_ctx = NULL;
}

static void
fsdev_fuse_cleanup(void *unused)
{
	struct spdk_fuse_mount *mount;
	int rc;

	pthread_mutex_lock(&g_fuse.mutex);
	TAILQ_FOREACH(mount, &g_fuse.mounts, tailq) {
		rc = spdk_fuse_umount(mount, fsdev_fuse_cleanup, NULL);
		if (rc == 0) {
			pthread_mutex_unlock(&g_fuse.mutex);
			return;
		} else if (rc == -EINPROGRESS) {
			pthread_mutex_unlock(&g_fuse.mutex);
			spdk_thread_send_msg(spdk_get_thread(), fsdev_fuse_cleanup, NULL);
			return;
		}

		SPDK_WARNLOG("%s: failed to umount %s: %s\n", mount->name, mount->mountpoint,
			     spdk_strerror(-rc));
	}
	pthread_mutex_unlock(&g_fuse.mutex);

	spdk_io_device_unregister(&g_fuse, fsdev_fuse_unregister_done);
}

void
spdk_fuse_cleanup(spdk_fuse_cleanup_cb cb_fn, void *cb_ctx)
{
	g_fuse.cleanup.cb_fn = cb_fn;
	g_fuse.cleanup.cb_ctx = cb_ctx;
	fsdev_fuse_cleanup(NULL);
}

void
spdk_fuse_get_opts(struct spdk_fuse_opts *opts, size_t size)
{
	size = spdk_min(size, sizeof(g_fuse.opts));
	memcpy(opts, &g_fuse.opts, size);
	opts->size = size;
}

int
spdk_fuse_set_opts(struct spdk_fuse_opts *opts)
{
	if (SPDK_GET_FIELD(opts, max_io_depth, g_fuse.opts.max_io_depth) == 0) {
		SPDK_ERRLOG("max_io_depth must be greater than zero\n");
		return -EINVAL;
	}
	if (SPDK_GET_FIELD(opts, fstype, NULL) != NULL) {
		char *fstype = strdup(opts->fstype);
		if (fstype == NULL) {
			return -ENOMEM;
		}

		free(g_fuse.fstype);
		g_fuse.fstype = fstype;
	}

	memcpy(&g_fuse.opts, opts, spdk_min(opts->size, sizeof(g_fuse.opts)));
	g_fuse.opts.fstype = g_fuse.fstype;

	return 0;
}

SPDK_LOG_REGISTER_COMPONENT(fuse);
