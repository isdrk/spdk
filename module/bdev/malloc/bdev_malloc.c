/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "bdev_malloc.h"
#include "spdk/endian.h"
#include "spdk/env.h"
#include "spdk/accel.h"
#include "spdk/dma.h"
#include "spdk/likely.h"
#include "spdk/string.h"

#include "spdk/log.h"

struct malloc_disk {
	struct spdk_bdev		disk;
	void				*malloc_buf;
	void				*malloc_md_buf;
	bool				enable_io_channel_weight;
	bool				disable_accel_support;
	TAILQ_ENTRY(malloc_disk)	link;
};

struct malloc_task {
	struct iovec			iov;
	int				num_outstanding;
	enum spdk_bdev_io_status	status;
	TAILQ_ENTRY(malloc_task)	tailq;
};

struct malloc_channel {
	struct spdk_io_channel		*accel_channel;
	struct spdk_poller		*completion_poller;
	TAILQ_HEAD(, malloc_task)	completed_tasks;
};

static int
malloc_verify_pi(struct spdk_bdev_io *bdev_io)
{
	struct spdk_bdev *bdev = bdev_io->bdev;
	struct spdk_dif_ctx dif_ctx;
	struct spdk_dif_error err_blk;
	int rc;
	struct spdk_dif_ctx_init_ext_opts dif_opts;

	assert(bdev_io->u.bdev.memory_domain == NULL);
	dif_opts.size = SPDK_SIZEOF(&dif_opts, dif_pi_format);
	dif_opts.dif_pi_format = SPDK_DIF_PI_FORMAT_16;
	rc = spdk_dif_ctx_init(&dif_ctx,
			       bdev->blocklen,
			       bdev->md_len,
			       bdev->md_interleave,
			       bdev->dif_is_head_of_md,
			       bdev->dif_type,
			       bdev->dif_check_flags,
			       bdev_io->u.bdev.offset_blocks & 0xFFFFFFFF,
			       0xFFFF, 0, 0, 0, &dif_opts);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to initialize DIF/DIX context\n");
		return rc;
	}

	if (spdk_bdev_is_md_interleaved(bdev)) {
		rc = spdk_dif_verify(bdev_io->u.bdev.iovs,
				     bdev_io->u.bdev.iovcnt,
				     bdev_io->u.bdev.num_blocks,
				     &dif_ctx,
				     &err_blk);
	} else {
		struct iovec md_iov = {
			.iov_base	= bdev_io->u.bdev.md_buf,
			.iov_len	= bdev_io->u.bdev.num_blocks * bdev->md_len,
		};

		if (bdev_io->u.bdev.md_buf == NULL) {
			return 0;
		}

		rc = spdk_dix_verify(bdev_io->u.bdev.iovs,
				     bdev_io->u.bdev.iovcnt,
				     &md_iov,
				     bdev_io->u.bdev.num_blocks,
				     &dif_ctx,
				     &err_blk);
	}

	if (rc != 0) {
		SPDK_ERRLOG("DIF/DIX verify failed: lba %" PRIu64 ", num_blocks %" PRIu64 ", "
			    "err_type %u, expected %lu, actual %lu, err_offset %u\n",
			    bdev_io->u.bdev.offset_blocks,
			    bdev_io->u.bdev.num_blocks,
			    err_blk.err_type,
			    err_blk.expected,
			    err_blk.actual,
			    err_blk.err_offset);
	}

	return rc;
}

static int
malloc_unmap_write_zeroes_generate_pi(struct spdk_bdev_io *bdev_io)
{
	struct spdk_bdev *bdev = bdev_io->bdev;
	struct malloc_disk *mdisk = bdev_io->bdev->ctxt;
	uint32_t block_size = bdev_io->bdev->blocklen;
	struct spdk_dif_ctx dif_ctx;
	struct spdk_dif_ctx_init_ext_opts dif_opts;
	int rc;

	dif_opts.size = SPDK_SIZEOF(&dif_opts, dif_pi_format);
	dif_opts.dif_pi_format = SPDK_DIF_PI_FORMAT_16;
	rc = spdk_dif_ctx_init(&dif_ctx,
			       bdev->blocklen,
			       bdev->md_len,
			       bdev->md_interleave,
			       bdev->dif_is_head_of_md,
			       bdev->dif_type,
			       bdev->dif_check_flags,
			       SPDK_DIF_REFTAG_IGNORE,
			       0xFFFF, SPDK_DIF_APPTAG_IGNORE,
			       0, 0, &dif_opts);
	if (rc != 0) {
		SPDK_ERRLOG("Initialization of DIF/DIX context failed\n");
		return rc;
	}

	if (bdev->md_interleave) {
		struct iovec iov = {
			.iov_base	= mdisk->malloc_buf + bdev_io->u.bdev.offset_blocks * block_size,
			.iov_len	= bdev_io->u.bdev.num_blocks * block_size,
		};

		rc = spdk_dif_generate(&iov, 1, bdev_io->u.bdev.num_blocks, &dif_ctx);
	} else {
		struct iovec iov = {
			.iov_base	= mdisk->malloc_buf + bdev_io->u.bdev.offset_blocks * block_size,
			.iov_len	= bdev_io->u.bdev.num_blocks * block_size,
		};

		struct iovec md_iov = {
			.iov_base	= mdisk->malloc_md_buf + bdev_io->u.bdev.offset_blocks * bdev->md_len,
			.iov_len	= bdev_io->u.bdev.num_blocks * bdev->md_len,
		};

		rc = spdk_dix_generate(&iov, 1, &md_iov, bdev_io->u.bdev.num_blocks, &dif_ctx);
	}

	if (rc != 0) {
		SPDK_ERRLOG("Formatting by DIF/DIX failed\n");
	}


	return rc;
}

static void
malloc_done(void *ref, int status)
{
	struct malloc_task *task = (struct malloc_task *)ref;
	struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(task);
	int rc;

	if (status != 0) {
		if (status == -ENOMEM) {
			if (task->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
				task->status = SPDK_BDEV_IO_STATUS_NOMEM;
			}
		} else {
			task->status = SPDK_BDEV_IO_STATUS_FAILED;
		}
	}

	if (--task->num_outstanding != 0) {
		return;
	}

	if (bdev_io->bdev->dif_type != SPDK_DIF_DISABLE &&
	    bdev_io->type == SPDK_BDEV_IO_TYPE_READ &&
	    task->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
		rc = malloc_verify_pi(bdev_io);
		if (rc != 0) {
			task->status = SPDK_BDEV_IO_STATUS_FAILED;
		}
	}

	if (bdev_io->bdev->dif_type != SPDK_DIF_DISABLE &&
	    (bdev_io->type == SPDK_BDEV_IO_TYPE_UNMAP || bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE_ZEROES) &&
	    task->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
		rc = malloc_unmap_write_zeroes_generate_pi(bdev_io);
		if (rc != 0) {
			task->status = SPDK_BDEV_IO_STATUS_FAILED;
		}
	}

	assert(!bdev_io->u.bdev.accel_sequence || task->status == SPDK_BDEV_IO_STATUS_NOMEM);
	spdk_bdev_io_complete(spdk_bdev_io_from_ctx(task), task->status);
}

static void
malloc_complete_task(struct malloc_task *task, struct malloc_channel *mch,
		     enum spdk_bdev_io_status status)
{
	task->status = status;
	TAILQ_INSERT_TAIL(&mch->completed_tasks, task, tailq);
}

static TAILQ_HEAD(, malloc_disk) g_malloc_disks = TAILQ_HEAD_INITIALIZER(g_malloc_disks);

int malloc_disk_count = 0;

static int bdev_malloc_initialize(void);
static void bdev_malloc_deinitialize(void);

static int
bdev_malloc_get_ctx_size(void)
{
	return sizeof(struct malloc_task);
}

static struct spdk_bdev_module malloc_if = {
	.name = "malloc",
	.module_init = bdev_malloc_initialize,
	.module_fini = bdev_malloc_deinitialize,
	.get_ctx_size = bdev_malloc_get_ctx_size,

};

SPDK_BDEV_MODULE_REGISTER(malloc, &malloc_if)

static void
malloc_disk_free(struct malloc_disk *malloc_disk)
{
	if (!malloc_disk) {
		return;
	}

	free(malloc_disk->disk.name);
	spdk_free(malloc_disk->malloc_buf);
	spdk_free(malloc_disk->malloc_md_buf);
	free(malloc_disk);
}

static int
bdev_malloc_destruct(void *ctx)
{
	struct malloc_disk *malloc_disk = ctx;

	TAILQ_REMOVE(&g_malloc_disks, malloc_disk, link);
	malloc_disk_free(malloc_disk);
	return 0;
}

static int
bdev_malloc_check_iov_len(struct iovec *iovs, int iovcnt, size_t nbytes)
{
	int i;

	for (i = 0; i < iovcnt; i++) {
		if (nbytes < iovs[i].iov_len) {
			return 0;
		}

		nbytes -= iovs[i].iov_len;
	}

	return nbytes != 0;
}

static void
malloc_sequence_fail(struct malloc_task *task, int status)
{
	struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(task);

	/* For ENOMEM, the IO will be retried by the bdev layer, so we don't abort the sequence */
	if (status != -ENOMEM) {
		spdk_accel_sequence_abort(bdev_io->u.bdev.accel_sequence);
		bdev_io->u.bdev.accel_sequence = NULL;
	}

	malloc_done(task, status);
}

static void
malloc_sequence_done(void *ctx, int status)
{
	struct malloc_task *task = ctx;
	struct spdk_bdev_io *bdev_io = spdk_bdev_io_from_ctx(task);

	bdev_io->u.bdev.accel_sequence = NULL;
	/* Prevent bdev layer from retrying the request if the sequence failed with ENOMEM */
	malloc_done(task, status != -ENOMEM ? status : -EFAULT);
}

static void
bdev_malloc_readv(struct malloc_disk *mdisk, struct spdk_io_channel *ch,
		  struct malloc_task *task, struct spdk_bdev_io *bdev_io)
{
	uint64_t len, offset, md_offset;
	int res = 0;
	size_t md_len;

	len = bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen;
	offset = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->blocklen;

	if (bdev_malloc_check_iov_len(bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt, len)) {
		spdk_bdev_io_complete(spdk_bdev_io_from_ctx(task),
				      SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	task->status = SPDK_BDEV_IO_STATUS_SUCCESS;
	task->num_outstanding = 0;
	task->iov.iov_base = mdisk->malloc_buf + offset;
	task->iov.iov_len = len;

	SPDK_DEBUGLOG(bdev_malloc, "read %zu bytes from offset %#" PRIx64 ", iovcnt=%d\n",
		      len, offset, bdev_io->u.bdev.iovcnt);

	task->num_outstanding++;
	res = spdk_accel_append_copy(&bdev_io->u.bdev.accel_sequence, ch,
				     bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
				     bdev_io->u.bdev.memory_domain,
				     bdev_io->u.bdev.memory_domain_ctx,
				     &task->iov, 1, NULL, NULL, NULL, NULL);
	if (spdk_unlikely(res != 0)) {
		malloc_sequence_fail(task, res);
		return;
	}

	spdk_accel_sequence_reverse(bdev_io->u.bdev.accel_sequence);
	spdk_accel_sequence_finish(bdev_io->u.bdev.accel_sequence, malloc_sequence_done, task);

	if (bdev_io->u.bdev.md_buf == NULL) {
		return;
	}

	md_len = bdev_io->u.bdev.num_blocks * bdev_io->bdev->md_len;
	md_offset = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->md_len;

	SPDK_DEBUGLOG(bdev_malloc, "read metadata %zu bytes from offset%#" PRIx64 "\n",
		      md_len, md_offset);

	task->num_outstanding++;
	res = spdk_accel_submit_copy(ch, bdev_io->u.bdev.md_buf, mdisk->malloc_md_buf + md_offset,
				     md_len, malloc_done, task);
	if (res != 0) {
		malloc_done(task, res);
	}
}

static void
bdev_malloc_writev(struct malloc_disk *mdisk, struct spdk_io_channel *ch,
		   struct malloc_task *task, struct spdk_bdev_io *bdev_io)
{
	uint64_t len, offset, md_offset;
	int res = 0;
	size_t md_len;

	len = bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen;
	offset = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->blocklen;

	if (bdev_malloc_check_iov_len(bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt, len)) {
		spdk_bdev_io_complete(spdk_bdev_io_from_ctx(task),
				      SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	task->status = SPDK_BDEV_IO_STATUS_SUCCESS;
	task->num_outstanding = 0;
	task->iov.iov_base = mdisk->malloc_buf + offset;
	task->iov.iov_len = len;

	SPDK_DEBUGLOG(bdev_malloc, "wrote %zu bytes to offset %#" PRIx64 ", iovcnt=%d\n",
		      len, offset, bdev_io->u.bdev.iovcnt);

	task->num_outstanding++;
	res = spdk_accel_append_copy(&bdev_io->u.bdev.accel_sequence, ch, &task->iov, 1, NULL, NULL,
				     bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
				     bdev_io->u.bdev.memory_domain,
				     bdev_io->u.bdev.memory_domain_ctx, NULL, NULL);
	if (spdk_unlikely(res != 0)) {
		malloc_sequence_fail(task, res);
		return;
	}

	spdk_accel_sequence_finish(bdev_io->u.bdev.accel_sequence, malloc_sequence_done, task);

	if (bdev_io->u.bdev.md_buf == NULL) {
		return;
	}

	md_len = bdev_io->u.bdev.num_blocks * bdev_io->bdev->md_len;
	md_offset = bdev_io->u.bdev.offset_blocks * bdev_io->bdev->md_len;

	SPDK_DEBUGLOG(bdev_malloc, "wrote metadata %zu bytes to offset %#" PRIx64 "\n",
		      md_len, md_offset);

	task->num_outstanding++;
	res = spdk_accel_submit_copy(ch, mdisk->malloc_md_buf + md_offset, bdev_io->u.bdev.md_buf,
				     md_len, malloc_done, task);
	if (res != 0) {
		malloc_done(task, res);
	}
}

static int
bdev_malloc_unmap(struct malloc_disk *mdisk,
		  struct spdk_io_channel *ch,
		  struct malloc_task *task,
		  uint64_t offset,
		  uint64_t byte_count)
{
	task->status = SPDK_BDEV_IO_STATUS_SUCCESS;
	task->num_outstanding = 1;

	return spdk_accel_submit_fill(ch, mdisk->malloc_buf + offset, 0,
				      byte_count, malloc_done, task);
}

static void
bdev_malloc_copy(struct malloc_disk *mdisk, struct spdk_io_channel *ch,
		 struct malloc_task *task,
		 uint64_t dst_offset, uint64_t src_offset, size_t len)
{
	int64_t res = 0;
	void *dst = mdisk->malloc_buf + dst_offset;
	void *src = mdisk->malloc_buf + src_offset;

	SPDK_DEBUGLOG(bdev_malloc, "Copy %zu bytes from offset %#" PRIx64 " to offset %#" PRIx64 "\n",
		      len, src_offset, dst_offset);

	task->status = SPDK_BDEV_IO_STATUS_SUCCESS;
	task->num_outstanding = 1;

	res = spdk_accel_submit_copy(ch, dst, src, len, malloc_done, task);
	if (res != 0) {
		malloc_done(task, res);
	}
}

static int
_bdev_malloc_submit_request(struct malloc_channel *mch, struct spdk_bdev_io *bdev_io)
{
	struct malloc_task *task = (struct malloc_task *)bdev_io->driver_ctx;
	struct malloc_disk *disk = bdev_io->bdev->ctxt;
	uint32_t block_size = bdev_io->bdev->blocklen;
	int rc;

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		if (bdev_io->u.bdev.iovs[0].iov_base == NULL) {
			assert(bdev_io->u.bdev.iovcnt == 1);
			assert(bdev_io->u.bdev.memory_domain == NULL);
			bdev_io->u.bdev.iovs[0].iov_base =
				disk->malloc_buf + bdev_io->u.bdev.offset_blocks * block_size;
			bdev_io->u.bdev.iovs[0].iov_len = bdev_io->u.bdev.num_blocks * block_size;
			malloc_complete_task(task, mch, SPDK_BDEV_IO_STATUS_SUCCESS);
			return 0;
		}

		bdev_malloc_readv(disk, mch->accel_channel, task, bdev_io);
		return 0;

	case SPDK_BDEV_IO_TYPE_WRITE:
		if (bdev_io->bdev->dif_type != SPDK_DIF_DISABLE) {
			rc = malloc_verify_pi(bdev_io);
			if (rc != 0) {
				malloc_complete_task(task, mch, SPDK_BDEV_IO_STATUS_FAILED);
				return 0;
			}
		}

		bdev_malloc_writev(disk, mch->accel_channel, task, bdev_io);
		return 0;

	case SPDK_BDEV_IO_TYPE_RESET:
		malloc_complete_task(task, mch, SPDK_BDEV_IO_STATUS_SUCCESS);
		return 0;

	case SPDK_BDEV_IO_TYPE_FLUSH:
		malloc_complete_task(task, mch, SPDK_BDEV_IO_STATUS_SUCCESS);
		return 0;

	case SPDK_BDEV_IO_TYPE_UNMAP:
		return bdev_malloc_unmap(disk, mch->accel_channel, task,
					 bdev_io->u.bdev.offset_blocks * block_size,
					 bdev_io->u.bdev.num_blocks * block_size);

	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		/* bdev_malloc_unmap is implemented with a call to mem_cpy_fill which zeroes out all of the requested bytes. */
		return bdev_malloc_unmap(disk, mch->accel_channel, task,
					 bdev_io->u.bdev.offset_blocks * block_size,
					 bdev_io->u.bdev.num_blocks * block_size);

	case SPDK_BDEV_IO_TYPE_ZCOPY:
		if (bdev_io->u.bdev.zcopy.start) {
			void *buf;
			size_t len;

			buf = disk->malloc_buf + bdev_io->u.bdev.offset_blocks * block_size;
			len = bdev_io->u.bdev.num_blocks * block_size;
			spdk_bdev_io_set_buf(bdev_io, buf, len);

		}
		malloc_complete_task(task, mch, SPDK_BDEV_IO_STATUS_SUCCESS);
		return 0;
	case SPDK_BDEV_IO_TYPE_ABORT:
		malloc_complete_task(task, mch, SPDK_BDEV_IO_STATUS_FAILED);
		return 0;
	case SPDK_BDEV_IO_TYPE_COPY:
		bdev_malloc_copy(disk, mch->accel_channel, task,
				 bdev_io->u.bdev.offset_blocks * block_size,
				 bdev_io->u.bdev.copy.src_offset_blocks * block_size,
				 bdev_io->u.bdev.num_blocks * block_size);
		return 0;

	default:
		return -1;
	}
	return 0;
}

static void
bdev_malloc_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct malloc_channel *mch = spdk_io_channel_get_ctx(ch);

	if (_bdev_malloc_submit_request(mch, bdev_io) != 0) {
		malloc_complete_task((struct malloc_task *)bdev_io->driver_ctx, mch,
				     SPDK_BDEV_IO_STATUS_FAILED);
	}
}

static bool
bdev_malloc_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	switch (io_type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_RESET:
	case SPDK_BDEV_IO_TYPE_UNMAP:
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
	case SPDK_BDEV_IO_TYPE_ZCOPY:
	case SPDK_BDEV_IO_TYPE_ABORT:
	case SPDK_BDEV_IO_TYPE_COPY:
		return true;

	default:
		return false;
	}
}

static struct spdk_io_channel *
bdev_malloc_get_io_channel(void *ctx)
{
	struct malloc_disk *mdisk = ctx;

	if (mdisk->enable_io_channel_weight) {
		spdk_bdev_notify_io_channel_weight_change(&mdisk->disk);
	}

	return spdk_get_io_channel(&g_malloc_disks);
}

static void
bdev_malloc_write_json_config(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	struct malloc_disk *malloc_disk = bdev->ctxt;

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "method", "bdev_malloc_create");

	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "name", bdev->name);
	spdk_json_write_named_uint64(w, "num_blocks", bdev->blockcnt);
	spdk_json_write_named_uint32(w, "block_size", bdev->blocklen);
	spdk_json_write_named_uint32(w, "physical_block_size", bdev->phys_blocklen);
	spdk_json_write_named_uuid(w, "uuid", &bdev->uuid);
	spdk_json_write_named_uint32(w, "optimal_io_boundary", bdev->optimal_io_boundary);
	spdk_json_write_named_bool(w, "enable_io_channel_weight", malloc_disk->enable_io_channel_weight);
	spdk_json_write_named_bool(w, "disable_accel_support", malloc_disk->disable_accel_support);

	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}

static int
bdev_malloc_get_memory_domains(void *ctx, struct spdk_memory_domain **domains, int array_size)
{
	struct malloc_disk *malloc_disk = ctx;
	struct spdk_memory_domain *domain;
	int num_domains = 0;

	if (malloc_disk->disk.dif_type != SPDK_DIF_DISABLE) {
		return 0;
	}

	/* Report support for every memory domain */
	for (domain = spdk_memory_domain_get_first(NULL); domain != NULL;
	     domain = spdk_memory_domain_get_next(domain, NULL)) {
		if (domains != NULL && num_domains < array_size) {
			domains[num_domains] = domain;
		}
		num_domains++;
	}

	return num_domains;
}

static bool
bdev_malloc_accel_sequence_supported(void *ctx, enum spdk_bdev_io_type type)
{
	struct malloc_disk *malloc_disk = ctx;

	if (malloc_disk->disk.dif_type != SPDK_DIF_DISABLE) {
		return false;
	}

	if (malloc_disk->disable_accel_support) {
		return false;
	}

	switch (type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
		return true;
	default:
		return false;
	}
}


static uint32_t
bdev_malloc_io_channel_get_weight(struct spdk_io_channel *ch)
{
	return 1;
}

static bool
bdev_malloc_event_type_supported(void *ctx, enum spdk_bdev_event_type event_type)
{
	struct malloc_disk *mdisk = ctx;

	switch (event_type) {
	case SPDK_BDEV_EVENT_REMOVE:
		return true;
	case SPDK_BDEV_EVENT_RESIZE:
		return false;
	case SPDK_BDEV_EVENT_MEDIA_MANAGEMENT:
		return false;
	case SPDK_BDEV_EVENT_IO_CHANNEL_WEIGHT_CHANGE:
		return mdisk->enable_io_channel_weight;
	default:
		return false;
	}
}

static const struct spdk_bdev_fn_table malloc_fn_table = {
	.destruct			= bdev_malloc_destruct,
	.submit_request			= bdev_malloc_submit_request,
	.io_type_supported		= bdev_malloc_io_type_supported,
	.get_io_channel			= bdev_malloc_get_io_channel,
	.write_config_json		= bdev_malloc_write_json_config,
	.get_memory_domains		= bdev_malloc_get_memory_domains,
	.accel_sequence_supported	= bdev_malloc_accel_sequence_supported,
	.io_channel_get_weight		= bdev_malloc_io_channel_get_weight,
	.event_type_supported		= bdev_malloc_event_type_supported,
};

static int
malloc_disk_setup_pi(struct malloc_disk *mdisk)
{
	struct spdk_bdev *bdev = &mdisk->disk;
	struct spdk_dif_ctx dif_ctx;
	struct iovec iov, md_iov;
	int rc;
	struct spdk_dif_ctx_init_ext_opts dif_opts;

	dif_opts.size = SPDK_SIZEOF(&dif_opts, dif_pi_format);
	dif_opts.dif_pi_format = SPDK_DIF_PI_FORMAT_16;
	/* Set APPTAG|REFTAG_IGNORE to PI fields after creation of malloc bdev */
	rc = spdk_dif_ctx_init(&dif_ctx,
			       bdev->blocklen,
			       bdev->md_len,
			       bdev->md_interleave,
			       bdev->dif_is_head_of_md,
			       bdev->dif_type,
			       bdev->dif_check_flags,
			       SPDK_DIF_REFTAG_IGNORE,
			       0xFFFF, SPDK_DIF_APPTAG_IGNORE,
			       0, 0, &dif_opts);
	if (rc != 0) {
		SPDK_ERRLOG("Initialization of DIF/DIX context failed\n");
		return rc;
	}

	iov.iov_base = mdisk->malloc_buf;
	iov.iov_len = bdev->blockcnt * bdev->blocklen;

	if (mdisk->disk.md_interleave) {
		rc = spdk_dif_generate(&iov, 1, bdev->blockcnt, &dif_ctx);
	} else {
		md_iov.iov_base = mdisk->malloc_md_buf;
		md_iov.iov_len = bdev->blockcnt * bdev->md_len;

		rc = spdk_dix_generate(&iov, 1, &md_iov, bdev->blockcnt, &dif_ctx);
	}

	if (rc != 0) {
		SPDK_ERRLOG("Formatting by DIF/DIX failed\n");
	}

	return rc;
}

int
create_malloc_disk(struct spdk_bdev **bdev, const struct malloc_bdev_opts *opts)
{
	struct malloc_disk *mdisk;
	uint32_t block_size;
	int rc;

	assert(opts != NULL);

	if (opts->num_blocks == 0) {
		SPDK_ERRLOG("Disk num_blocks must be greater than 0");
		return -EINVAL;
	}

	if (opts->block_size % 512) {
		SPDK_ERRLOG("Data block size must be 512 bytes aligned\n");
		return -EINVAL;
	}

	if (opts->physical_block_size % 512) {
		SPDK_ERRLOG("Physical block must be 512 bytes aligned\n");
		return -EINVAL;
	}

	switch (opts->md_size) {
	case 0:
	case 8:
	case 16:
	case 32:
	case 64:
	case 128:
		break;
	default:
		SPDK_ERRLOG("metadata size %u is not supported\n", opts->md_size);
		return -EINVAL;
	}

	if (opts->md_interleave) {
		block_size = opts->block_size + opts->md_size;
	} else {
		block_size = opts->block_size;
	}

	if (opts->dif_type < SPDK_DIF_DISABLE || opts->dif_type > SPDK_DIF_TYPE3) {
		SPDK_ERRLOG("DIF type is invalid\n");
		return -EINVAL;
	}

	if (opts->dif_type != SPDK_DIF_DISABLE && opts->md_size == 0) {
		SPDK_ERRLOG("Metadata size should not be zero if DIF is enabled\n");
		return -EINVAL;
	}

	mdisk = calloc(1, sizeof(*mdisk));
	if (!mdisk) {
		SPDK_ERRLOG("mdisk calloc() failed\n");
		return -ENOMEM;
	}

	/*
	 * Allocate the large backend memory buffer from pinned memory.
	 *
	 * TODO: need to pass a hint so we know which socket to allocate
	 *  from on multi-socket systems.
	 */
	mdisk->malloc_buf = spdk_zmalloc(opts->num_blocks * block_size, 2 * 1024 * 1024, NULL,
					 SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
	if (!mdisk->malloc_buf) {
		SPDK_ERRLOG("malloc_buf spdk_zmalloc() failed\n");
		malloc_disk_free(mdisk);
		return -ENOMEM;
	}

	if (!opts->md_interleave && opts->md_size != 0) {
		mdisk->malloc_md_buf = spdk_zmalloc(opts->num_blocks * opts->md_size, 2 * 1024 * 1024, NULL,
						    SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
		if (!mdisk->malloc_md_buf) {
			SPDK_ERRLOG("malloc_md_buf spdk_zmalloc() failed\n");
			malloc_disk_free(mdisk);
			return -ENOMEM;
		}
	}

	if (opts->name) {
		mdisk->disk.name = strdup(opts->name);
	} else {
		/* Auto-generate a name */
		mdisk->disk.name = spdk_sprintf_alloc("Malloc%d", malloc_disk_count);
		malloc_disk_count++;
	}
	if (!mdisk->disk.name) {
		malloc_disk_free(mdisk);
		return -ENOMEM;
	}
	mdisk->disk.product_name = "Malloc disk";

	mdisk->disk.write_cache = 1;
	mdisk->disk.blocklen = block_size;
	mdisk->disk.phys_blocklen = opts->physical_block_size;
	mdisk->disk.blockcnt = opts->num_blocks;
	mdisk->disk.md_len = opts->md_size;
	mdisk->disk.md_interleave = opts->md_interleave;
	mdisk->disk.dif_type = opts->dif_type;
	mdisk->disk.dif_is_head_of_md = opts->dif_is_head_of_md;
	/* Current block device layer API does not propagate
	 * any DIF related information from user. So, we can
	 * not generate or verify Application Tag.
	 */
	switch (opts->dif_type) {
	case SPDK_DIF_TYPE1:
	case SPDK_DIF_TYPE2:
		mdisk->disk.dif_check_flags = SPDK_DIF_FLAGS_GUARD_CHECK |
					      SPDK_DIF_FLAGS_REFTAG_CHECK;
		break;
	case SPDK_DIF_TYPE3:
		mdisk->disk.dif_check_flags = SPDK_DIF_FLAGS_GUARD_CHECK;
		break;
	case SPDK_DIF_DISABLE:
		break;
	}

	if (opts->dif_type != SPDK_DIF_DISABLE) {
		rc = malloc_disk_setup_pi(mdisk);
		if (rc) {
			SPDK_ERRLOG("Failed to set up protection information.\n");
			malloc_disk_free(mdisk);
			return rc;
		}
	}

	if (opts->optimal_io_boundary) {
		mdisk->disk.optimal_io_boundary = opts->optimal_io_boundary;
		mdisk->disk.split_on_optimal_io_boundary = true;
	}
	if (!spdk_uuid_is_null(&opts->uuid)) {
		spdk_uuid_copy(&mdisk->disk.uuid, &opts->uuid);
	}

	mdisk->enable_io_channel_weight = opts->enable_io_channel_weight;
	mdisk->disable_accel_support = opts->disable_accel_support;

	mdisk->disk.max_copy = 0;
	mdisk->disk.ctxt = mdisk;
	mdisk->disk.fn_table = &malloc_fn_table;
	mdisk->disk.module = &malloc_if;

	rc = spdk_bdev_register(&mdisk->disk);
	if (rc) {
		malloc_disk_free(mdisk);
		return rc;
	}

	*bdev = &(mdisk->disk);

	TAILQ_INSERT_TAIL(&g_malloc_disks, mdisk, link);

	return rc;
}

void
delete_malloc_disk(const char *name, spdk_delete_malloc_complete cb_fn, void *cb_arg)
{
	int rc;

	rc = spdk_bdev_unregister_by_name(name, &malloc_if, cb_fn, cb_arg);
	if (rc != 0) {
		cb_fn(cb_arg, rc);
	}
}

static int
malloc_completion_poller(void *ctx)
{
	struct malloc_channel *ch = ctx;
	struct malloc_task *task;
	TAILQ_HEAD(, malloc_task) completed_tasks;
	uint32_t num_completions = 0;

	TAILQ_INIT(&completed_tasks);
	TAILQ_SWAP(&completed_tasks, &ch->completed_tasks, malloc_task, tailq);

	while (!TAILQ_EMPTY(&completed_tasks)) {
		task = TAILQ_FIRST(&completed_tasks);
		TAILQ_REMOVE(&completed_tasks, task, tailq);
		spdk_bdev_io_complete(spdk_bdev_io_from_ctx(task), task->status);
		num_completions++;
	}

	return num_completions > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int
malloc_create_channel_cb(void *io_device, void *ctx)
{
	struct malloc_channel *ch = ctx;

	ch->accel_channel = spdk_accel_get_io_channel();
	if (!ch->accel_channel) {
		SPDK_ERRLOG("Failed to get accel framework's IO channel\n");
		return -ENOMEM;
	}

	ch->completion_poller = SPDK_POLLER_REGISTER(malloc_completion_poller, ch, 0);
	if (!ch->completion_poller) {
		SPDK_ERRLOG("Failed to register malloc completion poller\n");
		spdk_put_io_channel(ch->accel_channel);
		return -ENOMEM;
	}

	TAILQ_INIT(&ch->completed_tasks);

	return 0;
}

static void
malloc_destroy_channel_cb(void *io_device, void *ctx)
{
	struct malloc_channel *ch = ctx;

	assert(TAILQ_EMPTY(&ch->completed_tasks));

	spdk_put_io_channel(ch->accel_channel);
	spdk_poller_unregister(&ch->completion_poller);
}

static int
bdev_malloc_initialize(void)
{
	/* This needs to be reset for each reinitialization of submodules.
	 * Otherwise after enough devices or reinitializations the value gets too high.
	 * TODO: Make malloc bdev name mandatory and remove this counter. */
	malloc_disk_count = 0;

	spdk_io_device_register(&g_malloc_disks, malloc_create_channel_cb,
				malloc_destroy_channel_cb, sizeof(struct malloc_channel),
				"bdev_malloc");

	return 0;
}

static void
bdev_malloc_deinitialize(void)
{
	spdk_io_device_unregister(&g_malloc_disks, NULL);
}

SPDK_LOG_REGISTER_COMPONENT(bdev_malloc)
