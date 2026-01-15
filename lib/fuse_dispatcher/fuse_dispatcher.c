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
	spdk_fuse_dispatcher_submit_cpl_cb cpl_cb;
	void *cpl_cb_arg;
};

/* To make sure that the fsdev_io that follows the fuse_io is aligned to 8 */
#define ALIGNED_FUSE_IO_SIZE SPDK_ALIGN_CEIL(sizeof(struct fuse_io), 8)

static inline struct spdk_fsdev_io *
fuse_to_fsdev_io(struct fuse_io *fuse_io)
{
	return (struct spdk_fsdev_io *)(((char *)fuse_io) + ALIGNED_FUSE_IO_SIZE);
}

static void
fuse_io_save_iovs(struct spdk_fsdev_io *fsdev_io)
{
	size_t in_iovcnt_to_copy, out_iovcnt_to_copy;

	in_iovcnt_to_copy = spdk_min(fsdev_io->internal.in_iovcnt,
				     SPDK_COUNTOF(fsdev_io->internal.orig_in_iov));
	if (in_iovcnt_to_copy > 0) {
		assert(fsdev_io->internal.in_iov != NULL);
		memcpy(fsdev_io->internal.orig_in_iov, fsdev_io->internal.in_iov,
		       in_iovcnt_to_copy * sizeof(struct iovec));
	}

	out_iovcnt_to_copy = spdk_min(fsdev_io->internal.out_iovcnt,
				      SPDK_COUNTOF(fsdev_io->internal.orig_out_iov));
	if (out_iovcnt_to_copy > 0) {
		assert(fsdev_io->internal.out_iov != NULL);
		memcpy(fsdev_io->internal.orig_out_iov, fsdev_io->internal.out_iov,
		       out_iovcnt_to_copy * sizeof(struct iovec));
	}
}

static void
fuse_io_restore_iovs(struct spdk_fsdev_io *fsdev_io)
{
	size_t in_iovcnt_to_copy, out_iovcnt_to_copy;

	in_iovcnt_to_copy = spdk_min(fsdev_io->internal.in_iovcnt,
				     SPDK_COUNTOF(fsdev_io->internal.orig_in_iov));
	if (in_iovcnt_to_copy > 0) {
		assert(fsdev_io->internal.in_iov != NULL);
		memcpy(fsdev_io->internal.in_iov, fsdev_io->internal.orig_in_iov,
		       in_iovcnt_to_copy * sizeof(struct iovec));
	}

	out_iovcnt_to_copy = spdk_min(fsdev_io->internal.out_iovcnt,
				      SPDK_COUNTOF(fsdev_io->internal.orig_out_iov));
	if (out_iovcnt_to_copy > 0) {
		assert(fsdev_io->internal.out_iov != NULL);
		memcpy(fsdev_io->internal.out_iov, fsdev_io->internal.orig_out_iov,
		       out_iovcnt_to_copy * sizeof(struct iovec));
	}
}

static void
fuse_dispatcher_cpl_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fuse_io *fuse_io = cb_arg;

	fuse_io_restore_iovs(fsdev_io);
	assert(fsdev_io->u_out.fuse.hdr == NULL || status == fsdev_io->u_out.fuse.hdr->error);
	assert(spdk_fsdev_io_get_type(fsdev_io) == SPDK_FSDEV_IO_FUSE);
	fuse_io->cpl_cb(fuse_io->cpl_cb_arg, status);
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

static void
fuse_dispatcher_fill_fuse(struct fuse_io *fuse_io,
			  struct spdk_fsdev_desc *desc,
			  struct spdk_io_channel *ch,
			  int in_iovcnt, int out_iovcnt,
			  uint16_t source_id, uint64_t source_unique,
			  struct spdk_memory_domain *domain, void *domain_ctx)
{
	struct spdk_fsdev_io *fsdev_io = fuse_to_fsdev_io(fuse_io);
	struct spdk_fuse_in *in = &fsdev_io->u_in.fuse;
	struct spdk_fuse_out *out = &fsdev_io->u_out.fuse;
	struct iovec *in_iov = fsdev_io->internal.in_iov;
	struct iovec *out_iov = fsdev_io->internal.out_iov;
	size_t in_size;

	/* We may need to modify the iovs, for example if one iov contains both header
	 * and payload. For now we just always save off the iovs and restore them later.
	 * A future optimization could be saving them off only when necessary, but this
	 * still adds extra bits that need to be checked which may end up being a wash from
	 * a cacheline perspective.
	 */
	fuse_io_save_iovs(fsdev_io);

	in->hdr = in_iov->iov_base;
	if (in_iov->iov_len == sizeof(*in->hdr)) {
		in_iov++;
		in_iovcnt--;
	} else {
		in_iov->iov_base += sizeof(*in->hdr);
		in_iov->iov_len -= sizeof(*in->hdr);
	}
	in->op.raw = in_iov->iov_base;
	in_size = fuse_get_in_size(in->hdr);
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
		out->hdr = out_iov->iov_base;
		if (out_iov->iov_len == sizeof(*out->hdr)) {
			out_iov++;
			out_iovcnt--;
		} else {
			out_iov->iov_base += sizeof(*out->hdr);
			out_iov->iov_len -= sizeof(*out->hdr);
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

	spdk_fsdev_io_init(fsdev_io, desc, ch, 0,
			   SPDK_FSDEV_IO_FUSE, source_id,
			   source_unique, fuse_dispatcher_cpl_cb, fuse_io);
}

size_t
spdk_fuse_dispatcher_get_io_ctx_size(void)
{
	return ALIGNED_FUSE_IO_SIZE + spdk_fsdev_get_io_ctx_size();
}

static void
fuse_dispatcher_init_io(struct fuse_io *fuse_io,
			struct iovec *in_iov, int in_iovcnt, struct iovec *out_iov, int out_iovcnt,
			spdk_fuse_dispatcher_submit_cpl_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_io *fsdev_io = fuse_to_fsdev_io(fuse_io);

	fsdev_io->internal.in_iov = in_iov;
	fsdev_io->internal.in_iovcnt = in_iovcnt;
	fsdev_io->internal.out_iov = out_iov;
	fsdev_io->internal.out_iovcnt = out_iovcnt;
	fuse_io->cpl_cb = cb_fn;
	fuse_io->cpl_cb_arg = cb_arg;
}

int
spdk_fuse_dispatcher_submit_request(struct spdk_fsdev_desc *desc,
				    struct spdk_io_channel *ch,
				    struct iovec *in_iov, int in_iovcnt,
				    struct iovec *out_iov, int out_iovcnt, void *io_ctx,
				    uint16_t source_id, uint64_t source_unique,
				    struct spdk_memory_domain *domain, void *domain_ctx,
				    spdk_fuse_dispatcher_submit_cpl_cb clb, void *cb_arg)
{
	struct fuse_io *fuse_io = (struct fuse_io *) io_ctx;

	if (!fuse_io) {
		SPDK_ERRLOG("Invalid argument, fuse_io is NULL\n");
		return -ENOBUFS;
	}

	fuse_dispatcher_init_io(fuse_io, in_iov, in_iovcnt, out_iov, out_iovcnt, clb, cb_arg);
	fuse_dispatcher_fill_fuse(fuse_io, desc, ch, in_iovcnt, out_iovcnt,
				  source_id, source_unique, domain, domain_ctx);
	spdk_fsdev_io_submit(fuse_to_fsdev_io(fuse_io));
	return 0;
}

int
spdk_fuse_dispatcher_encode_notify(struct iovec *iov, int iovcnt,
				   const struct spdk_fsdev_notify_data *notify_data,
				   uint64_t unique_id)
{
	struct fuse_out_header *out_hdr;
	size_t buf_size;
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
		if (notify_data->type == SPDK_FSDEV_NOTIFY_FUSE) {
			struct spdk_fuse_notify_request *req = notify_data->fuse;
			struct fuse_out_header *req_out = req->iovs[0].iov_base;

			if (req_out->len > buf_size) {
				SPDK_ERRLOG("Buffer is too small for notification, buf_size %lu, notify_size %d\n",
					    buf_size, req_out->len);
				rc = -ENOMEM;
			} else {
				spdk_copy_iovs_to_buf(out_hdr, buf_size, req->iovs, req->iovcnt);
				out_hdr->unique = unique_id;
				rc = 0;
			}
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
		spdk_copy_buf_to_iovs(iov, iovcnt, out_hdr, out_hdr->len);
	}

	free(out_hdr);
	return rc;
}

uint32_t
spdk_fuse_dispatcher_get_notify_buf_size(struct spdk_fsdev_desc *desc)
{
	const uint32_t max_header_size = sizeof(struct fuse_out_header) +
					 sizeof(struct fuse_notify_retrieve_out);
	uint32_t buf_size = spdk_fsdev_get_notify_max_data_size(spdk_fsdev_desc_get_fsdev(desc));

	if (buf_size) {
		buf_size += max_header_size;
	}

	return buf_size;
}

SPDK_LOG_REGISTER_COMPONENT(fuse_dispatcher)
