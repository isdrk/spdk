/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/fsdev.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/util.h"
#include "spdk/thread.h"
#include "spdk/likely.h"
#include "spdk/fuse_dispatcher.h"
#include "spdk/rmem.h"
#include "spdk/linux/fuse.h"

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

struct fuse_io {
	struct iovec *in_iov;
	int in_iovcnt;
	struct iovec *out_iov;
	int out_iovcnt;

	struct iovec orig_in_iov[2];
	struct iovec orig_out_iov[1];

	spdk_fuse_dispatcher_submit_cpl_cb cpl_cb;
	void *cpl_cb_arg;
	struct spdk_fuse_dispatcher *disp;
};

/* To make sure that the fsdev_io that follows the fuse_io is aligned to 8 */
#define ALIGNED_FUSE_IO_SIZE SPDK_ALIGN_CEIL(sizeof(struct fuse_io), 8)

struct spdk_fuse_dispatcher {
	/**
	 * fsdev descriptor
	 */
	struct spdk_fsdev_desc *desc;

	/**
	 * Callback to handle FUSE_NOTIFY_REPLY requests.
	 */
	spdk_fuse_dispatcher_notify_reply_cb notify_reply_cb;

	/**
	 * Context for notify_reply_cb.
	 */
	void *notify_reply_cb_arg;
};

struct fuse_notify_reply_in {
	int32_t error; /* 0 on success, negated errno for error */
	uint32_t padding;
};

static inline struct spdk_fsdev_io *
fuse_to_fsdev_io(struct fuse_io *fuse_io)
{
	return (struct spdk_fsdev_io *)(((char *)fuse_io) + ALIGNED_FUSE_IO_SIZE);
}

static bool
_fuse_op_requires_reply(uint32_t opcode)
{
	switch (opcode) {
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
	case FUSE_NOTIFY_REPLY:
	case FUSE_INTERRUPT:
		return false;
	default:
		return true;
	}
}


static void
fuse_dispatcher_fill_outhdr(struct fuse_io *fuse_io, struct fuse_out_header *hdr,
			    size_t out_len, int error)
{
	struct spdk_fsdev_io *fsdev_io = fuse_to_fsdev_io(fuse_io);
	struct spdk_fuse_in *in = &fsdev_io->u_in.fuse;
	uint32_t len;

	assert(error > -1000 && error <= 0);
	len = sizeof(*hdr);
	if (error == 0) {
		len += out_len;
	}

	memset(hdr, 0, sizeof(*hdr));
	hdr->unique = in->hdr->unique;
	hdr->error = error;
	hdr->len = len;
}

static void
fuse_io_save_iovs(struct fuse_io *fuse_io)
{
	size_t in_iovcnt_to_copy, out_iovcnt_to_copy;

	in_iovcnt_to_copy = spdk_min((uint32_t)fuse_io->in_iovcnt, SPDK_COUNTOF(fuse_io->orig_in_iov));
	if (in_iovcnt_to_copy > 0) {
		assert(fuse_io->in_iov != NULL);
		memcpy(fuse_io->orig_in_iov, fuse_io->in_iov, in_iovcnt_to_copy * sizeof(struct iovec));
	}

	out_iovcnt_to_copy = spdk_min((uint32_t)fuse_io->out_iovcnt, SPDK_COUNTOF(fuse_io->orig_out_iov));
	if (out_iovcnt_to_copy > 0) {
		assert(fuse_io->out_iov != NULL);
		memcpy(fuse_io->orig_out_iov, fuse_io->out_iov, out_iovcnt_to_copy * sizeof(struct iovec));
	}
}

static void
fuse_io_restore_iovs(struct fuse_io *fuse_io)
{
	size_t in_iovcnt_to_copy, out_iovcnt_to_copy;

	in_iovcnt_to_copy = spdk_min((uint32_t)fuse_io->in_iovcnt, SPDK_COUNTOF(fuse_io->orig_in_iov));
	if (in_iovcnt_to_copy > 0) {
		assert(fuse_io->in_iov != NULL);
		memcpy(fuse_io->in_iov, fuse_io->orig_in_iov, in_iovcnt_to_copy * sizeof(struct iovec));
	}

	out_iovcnt_to_copy = spdk_min((uint32_t)fuse_io->out_iovcnt, SPDK_COUNTOF(fuse_io->orig_out_iov));
	if (out_iovcnt_to_copy > 0) {
		assert(fuse_io->out_iov != NULL);
		memcpy(fuse_io->out_iov, fuse_io->orig_out_iov, out_iovcnt_to_copy * sizeof(struct iovec));
	}
}

static void
fuse_dispatcher_cpl_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_io_restore_iovs(fuse_io);
	assert(fsdev_io->u_out.fuse.hdr == NULL || status == fsdev_io->u_out.fuse.hdr->error);
	assert(spdk_fsdev_io_get_type(fsdev_io) == SPDK_FSDEV_IO_FUSE);
	fuse_io->cpl_cb(fuse_io->cpl_cb_arg, status);
}

/*
 * Static FUSE commands handlers
 */
static inline void
fuse_init_fsdev_io_ex(struct fuse_io *fuse_io, struct spdk_io_channel *ch,
		      uint16_t source_id, uint64_t source_unique)
{
	struct spdk_fuse_dispatcher *disp = fuse_io->disp;
	struct spdk_fsdev_io *fsdev_io = fuse_to_fsdev_io(fuse_io);

	spdk_fsdev_io_init(fsdev_io, disp->desc, ch, 0,
			   SPDK_FSDEV_IO_FUSE, source_id,
			   source_unique, fuse_dispatcher_cpl_cb, fuse_io);
}

/* FUSE opcodes that define both a command-specific IN header and have IN
 * payload must return the size of their IN header here. This is used to
 * adjust the data iov appropriately.
 */
static size_t
fuse_get_in_size(struct fuse_in_header *in_hdr)
{
	switch (in_hdr->opcode) {
	case FUSE_CREATE:
		return sizeof(struct fuse_create_in);
	case FUSE_BATCH_FORGET:
		return sizeof(struct fuse_batch_forget_in);
	case FUSE_LINK:
		return sizeof(struct fuse_link_in);
	case FUSE_MKNOD:
		return sizeof(struct fuse_mknod_in);
	case FUSE_MKDIR:
		return sizeof(struct fuse_mkdir_in);
	case FUSE_RENAME:
		return sizeof(struct fuse_rename_in);
	case FUSE_RENAME2:
		return sizeof(struct fuse_rename2_in);
	case FUSE_WRITE:
		return sizeof(struct fuse_write_in);
	case FUSE_IOCTL:
		return sizeof(struct fuse_ioctl_in);
	default:
		return 0;
	}
}

static int
fuse_dispatcher_fill_fuse(struct fuse_io *fuse_io,
			  struct spdk_io_channel *ch,
			  int in_iovcnt, int out_iovcnt,
			  uint16_t source_id, uint64_t source_unique,
			  struct spdk_memory_domain *domain, void *domain_ctx)
{
	struct spdk_fsdev_io *fsdev_io = fuse_to_fsdev_io(fuse_io);
	struct spdk_fuse_in *in = &fsdev_io->u_in.fuse;
	struct spdk_fuse_out *out = &fsdev_io->u_out.fuse;
	struct iovec *in_iov = fuse_io->in_iov;
	struct iovec *out_iov = fuse_io->out_iov;
	struct fuse_in_header *in_hdr;
	struct fuse_out_header *out_hdr;
	size_t in_size;

	in_hdr = in_iov->iov_base;

	/* We may need to modify the iovs, for example if one iov contains both header
	 * and payload. For now we just always save off the iovs and restore them later.
	 * A future optimization could be saving them off only when necessary, but this
	 * still adds extra bits that need to be checked which may end up being a wash from
	 * a cacheline perspective.
	 */
	fuse_io_save_iovs(fuse_io);

	in->hdr = in_hdr;
	if (in_iov->iov_len == sizeof(*in_hdr)) {
		in_iov++;
		in_iovcnt--;
	} else {
		in_iov->iov_base += sizeof(*in_hdr);
		in_iov->iov_len -= sizeof(*in_hdr);
	}
	in->op.raw = in_iov->iov_base;
	in_size = fuse_get_in_size(in_hdr);
	if (in_size > 0) {
		assert(in_iov->iov_len >= in_size);
		if (in_iov->iov_len == in_size) {
			in_iov++;
			in_iovcnt--;
		} else {
			in_iov->iov_base += in_size;
			in_iov->iov_len -= in_size;
		}
	}
	in->iov = in_iov;
	in->iovcnt = in_iovcnt;
	in->memory_domain = domain;
	in->memory_domain_ctx = domain_ctx;

	/* Done preparing in headers, now move to out headers if they exist. */

	if (out_iov != NULL) {
		out_hdr = out_iov->iov_base;
		out->hdr = out_hdr;
		if (out_iov->iov_len == sizeof(*out_hdr)) {
			out_iov++;
			out_iovcnt--;
		} else {
			out_iov->iov_base += sizeof(*out_hdr);
			out_iov->iov_len -= sizeof(*out_hdr);
		}
		out->op.raw = out_iov->iov_base;
		out->iov = out_iov;
		out->iovcnt = out_iovcnt;
	} else {
		out->hdr = NULL;
		out->op.raw = NULL;
		out->iov = NULL;
		out->iovcnt = 0;
	}
	out->memory_domain = domain;
	out->memory_domain_ctx = domain_ctx;

	fuse_init_fsdev_io_ex(fuse_io, ch, source_id, source_unique);
	return 0;
}

struct spdk_fuse_dispatcher *
spdk_fuse_dispatcher_create(struct spdk_fsdev_desc *desc,
			    spdk_fuse_dispatcher_notify_reply_cb notify_reply_cb,
			    void *notify_reply_cb_arg)
{
	struct spdk_fuse_dispatcher *disp;

	disp = calloc(1, sizeof(*disp));
	if (!disp) {
		SPDK_ERRLOG("could not allocate disp\n");
		return NULL;
	}

	disp->desc = desc;
	disp->notify_reply_cb = notify_reply_cb;
	disp->notify_reply_cb_arg = notify_reply_cb_arg;
	return disp;
}

size_t
spdk_fuse_dispatcher_get_io_ctx_size(void)
{
	return ALIGNED_FUSE_IO_SIZE + spdk_fsdev_get_io_ctx_size();
}

static void
fuse_dispatcher_init_io(struct spdk_fuse_dispatcher *disp, struct fuse_io *fuse_io,
			struct iovec *in_iov, int in_iovcnt, struct iovec *out_iov, int out_iovcnt,
			spdk_fuse_dispatcher_submit_cpl_cb cb_fn, void *cb_arg)
{
	fuse_io->disp = disp;
	fuse_io->in_iov = in_iov;
	fuse_io->in_iovcnt = in_iovcnt;
	fuse_io->out_iov = out_iov;
	fuse_io->out_iovcnt = out_iovcnt;
	fuse_io->cpl_cb = cb_fn;
	fuse_io->cpl_cb_arg = cb_arg;
}

int
spdk_fuse_dispatcher_submit_request(struct spdk_fuse_dispatcher *disp,
				    struct spdk_io_channel *ch,
				    struct iovec *in_iov, int in_iovcnt,
				    struct iovec *out_iov, int out_iovcnt, void *io_ctx,
				    uint16_t source_id, uint64_t source_unique,
				    struct spdk_memory_domain *domain, void *domain_ctx,
				    spdk_fuse_dispatcher_submit_cpl_cb clb, void *cb_arg)
{
	struct fuse_io *fuse_io = (struct fuse_io *) io_ctx;
	int rc;

	if (!fuse_io) {
		SPDK_ERRLOG("Invalid argument, fuse_io is NULL\n");
		return -ENOBUFS;
	}

	fuse_dispatcher_init_io(disp, fuse_io, in_iov, in_iovcnt, out_iov, out_iovcnt, clb, cb_arg);
	rc = fuse_dispatcher_fill_fuse(fuse_io, ch, in_iovcnt, out_iovcnt,
				       source_id, source_unique, domain, domain_ctx);
	if (rc) {
		struct spdk_fsdev_io *fsdev_io = fuse_to_fsdev_io(fuse_io);
		struct spdk_fuse_in *in = &fsdev_io->u_in.fuse;

		if (_fuse_op_requires_reply(in->hdr->opcode)) {
			struct fuse_out_header *hdr = fuse_io->out_iov[0].iov_base;

			fuse_dispatcher_fill_outhdr(fuse_io, hdr, 0, rc);
		}
		fuse_io->cpl_cb(fuse_io->cpl_cb_arg, rc);
	} else {
		spdk_fsdev_io_submit(fuse_to_fsdev_io(fuse_io));
	}
	return 0;
}

void
spdk_fuse_dispatcher_delete(struct spdk_fuse_dispatcher *disp)
{
	free(disp);
}

static int
fuse_dispatcher_encode_notify_fuse(struct spdk_fuse_dispatcher *disp,
				   struct fuse_out_header *out_hdr,
				   size_t buf_size,
				   const struct spdk_fsdev_notify_data *notify_data)
{
	struct spdk_fuse_notify_request *req = notify_data->fuse;
	struct fuse_out_header *req_out = req->iovs[0].iov_base;
	uint64_t unique = out_hdr->unique;

	if (req_out->len > buf_size) {
		SPDK_ERRLOG("Buffer is too small for notification, buf_size %lu, notify_size %d\n",
			    buf_size, req_out->len);
		return -ENOMEM;
	}

	spdk_copy_iovs_to_buf(out_hdr, buf_size, req->iovs, req->iovcnt);
	out_hdr->unique = unique;

	return 0;
}

int
spdk_fuse_dispatcher_encode_notify(struct spdk_fuse_dispatcher *disp,
				   struct iovec *iov, int iovcnt,
				   const struct spdk_fsdev_notify_data *notify_data,
				   uint64_t unique_id,
				   bool *has_reply)
{
	struct fuse_out_header *out_hdr;
	size_t buf_size;
	bool tmp_has_reply = false;
	int i;
	int rc = 0;

	for (i = 0, buf_size = 0; i < iovcnt; buf_size += iov[i].iov_len, ++i);
	assert(buf_size >= sizeof(struct fuse_out_header));
	out_hdr = malloc(buf_size);
	if (!out_hdr) {
		SPDK_ERRLOG("Failed to allocate bounce buffer for fuse notification, buf_size %lu\n", buf_size);
		return -ENOMEM;
	}

	if (notify_data) {
		out_hdr->unique = unique_id;
		if (notify_data->type == SPDK_FSDEV_NOTIFY_FUSE) {
			rc = fuse_dispatcher_encode_notify_fuse(disp, out_hdr, buf_size, notify_data);
		} else {
			SPDK_ERRLOG("Unsupported notify type %d\n", notify_data->type);
			rc = -EINVAL;
		}
	} else {
		/* error and unique set to zero indicate device reset to driver */
		out_hdr->len = sizeof(*out_hdr);
		out_hdr->error = 0;
		out_hdr->unique = 0;
	}

	if (rc == 0) {
		*has_reply = tmp_has_reply;
		spdk_copy_buf_to_iovs(iov, iovcnt, out_hdr, out_hdr->len);
	}

	free(out_hdr);
	return rc;
}

uint32_t
spdk_fuse_dispatcher_get_notify_buf_size(struct spdk_fuse_dispatcher *disp)
{
	const uint32_t max_header_size = sizeof(struct fuse_out_header) +
					 sizeof(struct fuse_notify_retrieve_out);
	uint32_t buf_size = spdk_fsdev_get_notify_max_data_size(spdk_fsdev_desc_get_fsdev(disp->desc));

	if (buf_size) {
		buf_size += max_header_size;
	}

	return buf_size;
}

SPDK_LOG_REGISTER_COMPONENT(fuse_dispatcher)
