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
	struct spdk_fsdev_io *fsdev_io = fuse_to_fsdev_io(fuse_io);
	struct spdk_fuse_in *in = &fsdev_io->u_in.fuse;
	struct spdk_fuse_out *out = &fsdev_io->u_out.fuse;
	size_t in_size;

	if (!fuse_io) {
		SPDK_ERRLOG("Invalid argument, fuse_io is NULL\n");
		return -ENOBUFS;
	}

	spdk_fsdev_io_init(fsdev_io, desc, ch, 0,
			   SPDK_FSDEV_IO_FUSE, source_id,
			   source_unique, fuse_dispatcher_cpl_cb, fuse_io);
	fsdev_io->internal.in_iov = in_iov;
	fsdev_io->internal.in_iovcnt = in_iovcnt;
	fsdev_io->internal.out_iov = out_iov;
	fsdev_io->internal.out_iovcnt = out_iovcnt;
	fuse_io->cpl_cb = clb;
	fuse_io->cpl_cb_arg = cb_arg;

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

	spdk_fsdev_io_submit(fuse_to_fsdev_io(fuse_io));
	return 0;
}

size_t
spdk_fuse_dispatcher_get_io_ctx_size(void)
{
	return ALIGNED_FUSE_IO_SIZE + spdk_fsdev_get_io_ctx_size();
}

SPDK_LOG_REGISTER_COMPONENT(fuse_dispatcher)
