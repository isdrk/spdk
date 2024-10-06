/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation. All rights reserved.
 *   Copyright (c) 2019 Mellanox Technologies LTD. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/json.h"
#include "spdk/string.h"
#include "spdk/likely.h"
#include "spdk/dma.h"
#include "spdk/bdev_module.h"
#include "spdk/log.h"
#include "spdk/config.h"

#include "bdev_null.h"

struct null_bdev_io {
	TAILQ_ENTRY(null_bdev_io) link;
};

#ifdef SPDK_CONFIG_RDMA
#include <infiniband/verbs.h>
#include "spdk_internal/rdma_utils.h"

struct null_bdev_domain_ctx {
	struct spdk_memory_domain			*domain;
	struct spdk_memory_domain_translation_ctx	translation_ctx;
	struct ibv_pd					*pd;
	struct ibv_qp					*qp;
	bool						use_available_device;
};
#endif

struct null_bdev {
	struct spdk_bdev	bdev;
	TAILQ_ENTRY(null_bdev)	tailq;
	struct null_bdev_domain_ctx	*domain_ctx;
};

struct null_io_channel {
	struct spdk_poller		*poller;
	TAILQ_HEAD(, null_bdev_io)	io;
};

static TAILQ_HEAD(, null_bdev) g_null_bdev_head = TAILQ_HEAD_INITIALIZER(g_null_bdev_head);
static void *g_null_read_buf;

static int bdev_null_initialize(void);
static void bdev_null_finish(void);

static int
bdev_null_get_ctx_size(void)
{
	return sizeof(struct null_bdev_io);
}

static struct spdk_bdev_module null_if = {
	.name = "null",
	.module_init = bdev_null_initialize,
	.module_fini = bdev_null_finish,
	.async_fini = true,
	.get_ctx_size = bdev_null_get_ctx_size,
};

SPDK_BDEV_MODULE_REGISTER(null, &null_if)


#ifdef SPDK_CONFIG_RDMA
static int
bdev_null_create_memory_domain(struct null_bdev *null_disk, const char *ib_device_name)
{
	struct null_bdev_domain_ctx *domain_ctx;
	int num_devices = 0, index;
	struct ibv_context **contexts;

	domain_ctx = calloc(1, sizeof(struct null_bdev_domain_ctx));
	if (!domain_ctx) {
		SPDK_ERRLOG("Failed to allocate null domain context\n");
		goto return_failure;
	}

	contexts = rdma_get_devices(&num_devices);
	if (!contexts || num_devices == 0) {
		SPDK_ERRLOG("Failed to create RDMA devices list\n");
		goto free_context;
	}

	if (strlen(ib_device_name)) {
		for (index = 0; index < num_devices; index++) {
			if (!strcmp(ib_device_name, ibv_get_device_name(contexts[index]->device))) {
				break;
			}
		}

		if (index == num_devices) {
			SPDK_ERRLOG("Couldn't find an IB device with the requested name\n");
			goto free_dev_list;
		}
	} else {
		/*
		 * If a device name wasn't given, we choose the first device available to us.
		 */
		index = 0;
		domain_ctx->use_available_device = true;
	}

	domain_ctx->pd = spdk_rdma_utils_get_pd(contexts[index]);
	if (!domain_ctx->pd) {
		SPDK_ERRLOG("Failed to alloc pd\n");
		goto free_dev_list;
	}

	domain_ctx->qp = calloc(1, sizeof(struct ibv_qp));
	if (!domain_ctx->qp) {
		SPDK_ERRLOG("Failed to create qp\n");
		goto free_pd;
	}

	/*
	 * This assignment was added to allow a user of the memory domain to access the PD.
	 */
	domain_ctx->qp->pd = domain_ctx->pd;
	domain_ctx->translation_ctx.size = sizeof(struct spdk_memory_domain_translation_ctx);
	domain_ctx->translation_ctx.rdma.ibv_qp = domain_ctx->qp;


	domain_ctx->domain = spdk_rdma_utils_get_memory_domain(domain_ctx->pd,
			     SPDK_DMA_DEVICE_TYPE_RDMA);
	if (!domain_ctx->domain) {
		SPDK_ERRLOG("Failed to create memory_domain\n");
		goto free_qp;
	}

	rdma_free_devices(contexts);
	null_disk->domain_ctx = domain_ctx;
	return 0;

free_qp:
	free(domain_ctx->qp);
free_pd:
	spdk_rdma_utils_put_pd(domain_ctx->pd);
free_dev_list:
	rdma_free_devices(contexts);
free_context:
	free(domain_ctx);
return_failure:
	return -ENOMEM;
}

static void
bdev_null_destroy_memory_domain(struct null_bdev *null_disk)
{
	struct null_bdev_domain_ctx *ctx = null_disk->domain_ctx;

	if (ctx) {
		spdk_rdma_utils_put_memory_domain(ctx->domain);
		free(ctx->qp);
		spdk_rdma_utils_put_pd(ctx->pd);
		free(ctx);
	}
}


static int
bdev_null_get_memory_domains(void *ctx, struct spdk_memory_domain **domains, int array_size)
{
	struct null_bdev *null_bdev = (struct null_bdev *)ctx;

	if (null_bdev && null_bdev->domain_ctx && null_bdev->domain_ctx->domain) {
		if (domains) {
			domains[0] = null_bdev->domain_ctx->domain;
		}
		return 1;
	}
	return 0;
}

static void
bdev_null_json_write_ib_device_name(struct null_bdev *null_bdev, struct spdk_json_write_ctx *w)
{
	if (null_bdev->domain_ctx) {
		if (null_bdev->domain_ctx->use_available_device == true) {
			spdk_json_write_named_string(w, "zero_copy", "");
		} else {
			spdk_json_write_named_string(w, "zero_copy",
						     ibv_get_device_name(null_bdev->domain_ctx->pd->context->device));
		}
	}
}

static int
spdk_memory_domain_translate_data_aux(struct spdk_bdev_io *bdev_io, struct null_bdev *null_bdev,
				      int i)
{
	struct spdk_memory_domain_translation_result translation;
	struct null_bdev_domain_ctx *ctx;

	if (!null_bdev->domain_ctx) {
		return -ENOENT;
	}

	ctx = null_bdev->domain_ctx;

	return spdk_memory_domain_translate_data(bdev_io->u.bdev.memory_domain,
			bdev_io->u.bdev.memory_domain_ctx,
			ctx->domain,
			&ctx->translation_ctx,
			bdev_io->u.bdev.iovs[i].iov_base,
			bdev_io->u.bdev.iovs[i].iov_len,
			&translation);
}

#else

static int
bdev_null_create_memory_domain(struct null_bdev *null_disk, const char *ib_device_name)
{
	SPDK_ERRLOG("No RDMA support\n");
	return -ENOTSUP;
}

static int
bdev_null_get_memory_domains(void *ctx, struct spdk_memory_domain **domains, int array_size)
{
	return 0;
}

static void
bdev_null_destroy_memory_domain(struct null_bdev *null_disk)
{
}

static void
bdev_null_json_write_ib_device_name(struct null_bdev *null_bdev, struct spdk_json_write_ctx *w)
{
}

static int
spdk_memory_domain_translate_data_aux(struct spdk_bdev_io *bdev_io, struct null_bdev *null_bdev,
				      int i)
{
	SPDK_ERRLOG("Logical error, this message should never be printed!\n");
	return -EINVAL;
}

#endif


static int
bdev_null_destruct(void *ctx)
{
	struct null_bdev *bdev = ctx;

	TAILQ_REMOVE(&g_null_bdev_head, bdev, tailq);
	bdev_null_destroy_memory_domain(bdev);
	free(bdev->bdev.name);
	free(bdev);

	return 0;
}

static bool
bdev_null_abort_io(struct null_io_channel *ch, struct spdk_bdev_io *bio_to_abort)
{
	struct null_bdev_io *null_io;
	struct spdk_bdev_io *bdev_io;

	TAILQ_FOREACH(null_io, &ch->io, link) {
		bdev_io = spdk_bdev_io_from_ctx(null_io);

		if (bdev_io == bio_to_abort) {
			TAILQ_REMOVE(&ch->io, null_io, link);
			spdk_bdev_io_complete(bio_to_abort, SPDK_BDEV_IO_STATUS_ABORTED);
			return true;
		}
	}

	return false;
}

static void
bdev_null_submit_request(struct spdk_io_channel *_ch, struct spdk_bdev_io *bdev_io)
{
	struct null_bdev_io *null_io = (struct null_bdev_io *)bdev_io->driver_ctx;
	struct null_io_channel *ch = spdk_io_channel_get_ctx(_ch);
	struct spdk_bdev *bdev = bdev_io->bdev;
	struct null_bdev *null_bdev = SPDK_CONTAINEROF(bdev, struct null_bdev, bdev);
	struct spdk_dif_ctx dif_ctx;
	struct spdk_dif_error err_blk;
	int rc;
	struct spdk_dif_ctx_init_ext_opts dif_opts;

	if (SPDK_DIF_DISABLE != bdev->dif_type &&
	    (SPDK_BDEV_IO_TYPE_READ == bdev_io->type ||
	     SPDK_BDEV_IO_TYPE_WRITE == bdev_io->type)) {
		dif_opts.size = SPDK_SIZEOF(&dif_opts, dif_pi_format);
		dif_opts.dif_pi_format = bdev->dif_pi_format;
		rc = spdk_dif_ctx_init(&dif_ctx,
				       bdev->blocklen,
				       bdev->md_len,
				       bdev->md_interleave,
				       bdev->dif_is_head_of_md,
				       bdev->dif_type,
				       bdev_io->u.bdev.dif_check_flags,
				       bdev_io->u.bdev.offset_blocks & 0xFFFFFFFF,
				       0xFFFF, 0, 0, 0, &dif_opts);
		if (0 != rc) {
			SPDK_ERRLOG("Failed to initialize DIF context, error %d\n", rc);
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
			return;
		}
	}

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		if (bdev_io->u.bdev.iovs[0].iov_base == NULL) {
			assert(bdev_io->u.bdev.iovcnt == 1);
			if (spdk_likely(bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen <=
					SPDK_BDEV_LARGE_BUF_MAX_SIZE)) {
				bdev_io->u.bdev.iovs[0].iov_base = g_null_read_buf;
				bdev_io->u.bdev.iovs[0].iov_len = bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen;
			} else {
				SPDK_ERRLOG("Overflow occurred. Read I/O size %" PRIu64 " was larger than permitted %d\n",
					    bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen,
					    SPDK_BDEV_LARGE_BUF_MAX_SIZE);
				spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
				return;
			}
		}
		if (SPDK_DIF_DISABLE != bdev->dif_type) {
			rc = spdk_dif_generate(bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
					       bdev_io->u.bdev.num_blocks, &dif_ctx);
			if (0 != rc) {
				SPDK_ERRLOG("IO DIF generation failed: lba %" PRIu64 ", num_block %" PRIu64 "\n",
					    bdev_io->u.bdev.offset_blocks,
					    bdev_io->u.bdev.num_blocks);
				spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
				return;
			}
		}
		if (bdev_io->u.bdev.memory_domain && bdev_io->u.bdev.memory_domain_ctx) {
			for (int i = 0; i < bdev_io->u.bdev.iovcnt; i++) {
				rc = spdk_memory_domain_translate_data_aux(bdev_io, null_bdev, i);
				if (rc != 0) {
					SPDK_ERRLOG("Failed to translate data for Read I/O\n");
					spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
					return;
				}
			}
		}
		TAILQ_INSERT_TAIL(&ch->io, null_io, link);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
		if (SPDK_DIF_DISABLE != bdev->dif_type) {
			rc = spdk_dif_verify(bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
					     bdev_io->u.bdev.num_blocks, &dif_ctx, &err_blk);
			if (0 != rc) {
				SPDK_ERRLOG("IO DIF verification failed: lba %" PRIu64 ", num_blocks %" PRIu64 ", "
					    "err_type %u, expected %lu, actual %lu, err_offset %u\n",
					    bdev_io->u.bdev.offset_blocks,
					    bdev_io->u.bdev.num_blocks,
					    err_blk.err_type,
					    err_blk.expected,
					    err_blk.actual,
					    err_blk.err_offset);
				spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
				return;
			}
		}
		if (bdev_io->u.bdev.memory_domain && bdev_io->u.bdev.memory_domain_ctx) {
			for (int i = 0; i < bdev_io->u.bdev.iovcnt; i++) {
				rc = spdk_memory_domain_translate_data_aux(bdev_io, null_bdev, i);
				if (rc != 0) {
					SPDK_ERRLOG("Failed to translate data for Write I/O\n");
					spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
					return;
				}
			}
		}
		TAILQ_INSERT_TAIL(&ch->io, null_io, link);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
	case SPDK_BDEV_IO_TYPE_RESET:
		TAILQ_INSERT_TAIL(&ch->io, null_io, link);
		break;
	case SPDK_BDEV_IO_TYPE_ABORT:
		if (bdev_null_abort_io(ch, bdev_io->u.abort.bio_to_abort)) {
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
		} else {
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
		break;
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_UNMAP:
	default:
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		break;
	}
}

static bool
bdev_null_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	switch (io_type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
	case SPDK_BDEV_IO_TYPE_RESET:
	case SPDK_BDEV_IO_TYPE_ABORT:
		return true;
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_UNMAP:
	default:
		return false;
	}
}

static struct spdk_io_channel *
bdev_null_get_io_channel(void *ctx)
{
	return spdk_get_io_channel(&g_null_bdev_head);
}

static void
bdev_null_write_config_json(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	struct null_bdev *null_bdev = SPDK_CONTAINEROF(bdev, struct null_bdev, bdev);

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "method", "bdev_null_create");

	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "name", bdev->name);
	spdk_json_write_named_uint64(w, "num_blocks", bdev->blockcnt);
	spdk_json_write_named_uint32(w, "block_size", bdev->blocklen);
	spdk_json_write_named_uint32(w, "physical_block_size", bdev->phys_blocklen);
	spdk_json_write_named_uint32(w, "md_size", bdev->md_len);
	spdk_json_write_named_uint32(w, "dif_type", bdev->dif_type);
	spdk_json_write_named_bool(w, "dif_is_head_of_md", bdev->dif_is_head_of_md);
	spdk_json_write_named_uint32(w, "dif_pi_format", bdev->dif_pi_format);
	spdk_json_write_named_uuid(w, "uuid", &bdev->uuid);
	bdev_null_json_write_ib_device_name(null_bdev, w);
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}

static const struct spdk_bdev_fn_table null_fn_table = {
	.destruct		= bdev_null_destruct,
	.submit_request		= bdev_null_submit_request,
	.io_type_supported	= bdev_null_io_type_supported,
	.get_io_channel		= bdev_null_get_io_channel,
	.write_config_json	= bdev_null_write_config_json,
	.get_memory_domains	= bdev_null_get_memory_domains,
};

/* Use a dummy DIF context to validate DIF configuration of the
 * craeted bdev.
 */
static int
_bdev_validate_dif_config(struct spdk_bdev *bdev)
{
	struct spdk_dif_ctx dif_ctx;
	struct spdk_dif_ctx_init_ext_opts dif_opts;

	dif_opts.size = SPDK_SIZEOF(&dif_opts, dif_pi_format);
	dif_opts.dif_pi_format = bdev->dif_pi_format;

	return spdk_dif_ctx_init(&dif_ctx,
				 bdev->blocklen,
				 bdev->md_len,
				 true,
				 bdev->dif_is_head_of_md,
				 bdev->dif_type,
				 bdev->dif_check_flags,
				 SPDK_DIF_REFTAG_IGNORE,
				 0xFFFF, SPDK_DIF_APPTAG_IGNORE,
				 0, 0, &dif_opts);
}

int
bdev_null_create(struct spdk_bdev **bdev, const struct null_bdev_opts *opts)
{
	struct null_bdev *null_disk;
	uint32_t block_size;
	int rc;

	if (!opts) {
		SPDK_ERRLOG("No options provided for Null bdev.\n");
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

	if (opts->block_size % 512 != 0) {
		SPDK_ERRLOG("Data block size %u is not a multiple of 512.\n", opts->block_size);
		return -EINVAL;
	}

	if (opts->physical_block_size % 512 != 0) {
		SPDK_ERRLOG("Physical block must be 512 bytes aligned\n");
		return -EINVAL;
	}

	block_size = opts->block_size + opts->md_size;

	if (opts->num_blocks == 0) {
		SPDK_ERRLOG("Disk must be more than 0 blocks\n");
		return -EINVAL;
	}

	null_disk = calloc(1, sizeof(*null_disk));
	if (!null_disk) {
		SPDK_ERRLOG("could not allocate null_bdev\n");
		return -ENOMEM;
	}

	null_disk->bdev.name = strdup(opts->name);
	if (!null_disk->bdev.name) {
		free(null_disk);
		return -ENOMEM;
	}
	null_disk->bdev.product_name = "Null disk";

	null_disk->bdev.write_cache = 0;
	null_disk->bdev.blocklen = block_size;
	null_disk->bdev.phys_blocklen = opts->physical_block_size;
	null_disk->bdev.blockcnt = opts->num_blocks;
	null_disk->bdev.md_len = opts->md_size;
	null_disk->bdev.md_interleave = true;
	null_disk->bdev.dif_type = opts->dif_type;
	null_disk->bdev.dif_is_head_of_md = opts->dif_is_head_of_md;
	/* Current block device layer API does not propagate
	 * any DIF related information from user. So, we can
	 * not generate or verify Application Tag.
	 */
	switch (opts->dif_type) {
	case SPDK_DIF_TYPE1:
	case SPDK_DIF_TYPE2:
		null_disk->bdev.dif_check_flags = SPDK_DIF_FLAGS_GUARD_CHECK |
						  SPDK_DIF_FLAGS_REFTAG_CHECK;
		break;
	case SPDK_DIF_TYPE3:
		null_disk->bdev.dif_check_flags = SPDK_DIF_FLAGS_GUARD_CHECK;
		break;
	case SPDK_DIF_DISABLE:
		break;
	}
	null_disk->bdev.dif_pi_format = opts->dif_pi_format;

	if (opts->dif_type != SPDK_DIF_DISABLE) {
		rc = _bdev_validate_dif_config(&null_disk->bdev);
		if (rc != 0) {
			SPDK_ERRLOG("DIF configuration was wrong\n");
			free(null_disk);
			return -EINVAL;
		}
	}

	if (!spdk_uuid_is_null(&opts->uuid)) {
		spdk_uuid_copy(&null_disk->bdev.uuid, &opts->uuid);
	}

	null_disk->bdev.ctxt = null_disk;
	null_disk->bdev.fn_table = &null_fn_table;
	null_disk->bdev.module = &null_if;

	if (opts->ib_device_name) {
		if (opts->dif_type != SPDK_DIF_DISABLE) {
			SPDK_ERRLOG("Null memory domains while DIF is enabled is not supported\n");
			free(null_disk->bdev.name);
			free(null_disk);
			return -EINVAL;
		}
		rc = bdev_null_create_memory_domain(null_disk, opts->ib_device_name);
		if (rc) {
			free(null_disk->bdev.name);
			free(null_disk);
			return rc;
		}
	}

	rc = spdk_bdev_register(&null_disk->bdev);
	if (rc) {
		bdev_null_destroy_memory_domain(null_disk);
		free(null_disk->bdev.name);
		free(null_disk);
		return rc;
	}

	*bdev = &(null_disk->bdev);

	TAILQ_INSERT_TAIL(&g_null_bdev_head, null_disk, tailq);

	return rc;
}

void
bdev_null_delete(const char *bdev_name, spdk_delete_null_complete cb_fn, void *cb_arg)
{
	int rc;

	rc = spdk_bdev_unregister_by_name(bdev_name, &null_if, cb_fn, cb_arg);
	if (rc != 0) {
		cb_fn(cb_arg, rc);
	}
}

static int
null_io_poll(void *arg)
{
	struct null_io_channel		*ch = arg;
	TAILQ_HEAD(, null_bdev_io)	io;
	struct null_bdev_io		*null_io;

	TAILQ_INIT(&io);
	TAILQ_SWAP(&ch->io, &io, null_bdev_io, link);

	if (TAILQ_EMPTY(&io)) {
		return SPDK_POLLER_IDLE;
	}

	while (!TAILQ_EMPTY(&io)) {
		null_io = TAILQ_FIRST(&io);
		TAILQ_REMOVE(&io, null_io, link);
		spdk_bdev_io_complete(spdk_bdev_io_from_ctx(null_io), SPDK_BDEV_IO_STATUS_SUCCESS);
	}

	return SPDK_POLLER_BUSY;
}

static int
null_bdev_create_cb(void *io_device, void *ctx_buf)
{
	struct null_io_channel *ch = ctx_buf;

	TAILQ_INIT(&ch->io);
	ch->poller = SPDK_POLLER_REGISTER(null_io_poll, ch, 0);

	return 0;
}

static void
null_bdev_destroy_cb(void *io_device, void *ctx_buf)
{
	struct null_io_channel *ch = ctx_buf;

	spdk_poller_unregister(&ch->poller);
}

static int
bdev_null_initialize(void)
{
	/*
	 * This will be used if upper layer expects us to allocate the read buffer.
	 *  Instead of using a real rbuf from the bdev pool, just always point to
	 *  this same zeroed buffer.
	 */
	g_null_read_buf = spdk_zmalloc(SPDK_BDEV_LARGE_BUF_MAX_SIZE, 0, NULL,
				       SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);
	if (g_null_read_buf == NULL) {
		return -1;
	}

	/*
	 * We need to pick some unique address as our "io device" - so just use the
	 *  address of the global tailq.
	 */
	spdk_io_device_register(&g_null_bdev_head, null_bdev_create_cb, null_bdev_destroy_cb,
				sizeof(struct null_io_channel), "null_bdev");

	return 0;
}

static void
dummy_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *ctx)
{
}

int
bdev_null_resize(const char *bdev_name, const uint64_t new_size_in_mb)
{
	struct spdk_bdev_desc *desc;
	struct spdk_bdev *bdev;
	uint64_t current_size_in_mb;
	uint64_t new_size_in_byte;
	int rc = 0;

	rc = spdk_bdev_open_ext(bdev_name, false, dummy_bdev_event_cb, NULL, &desc);
	if (rc != 0) {
		SPDK_ERRLOG("failed to open bdev; %s.\n", bdev_name);
		return rc;
	}

	bdev = spdk_bdev_desc_get_bdev(desc);

	if (bdev->module != &null_if) {
		rc = -EINVAL;
		goto exit;
	}

	current_size_in_mb = bdev->blocklen * bdev->blockcnt / (1024 * 1024);
	if (new_size_in_mb < current_size_in_mb) {
		SPDK_ERRLOG("The new bdev size must not be smaller than current bdev size.\n");
		rc = -EINVAL;
		goto exit;
	}

	new_size_in_byte = new_size_in_mb * 1024 * 1024;

	rc = spdk_bdev_notify_blockcnt_change(bdev, new_size_in_byte / bdev->blocklen);
	if (rc != 0) {
		SPDK_ERRLOG("failed to notify block cnt change.\n");
	}

exit:
	spdk_bdev_close(desc);
	return rc;
}

static void
_bdev_null_finish_cb(void *arg)
{
	spdk_free(g_null_read_buf);
	spdk_bdev_module_fini_done();
}

static void
bdev_null_finish(void)
{
	if (g_null_read_buf == NULL) {
		spdk_bdev_module_fini_done();
		return;
	}
	spdk_io_device_unregister(&g_null_bdev_head, _bdev_null_finish_cb);
}

SPDK_LOG_REGISTER_COMPONENT(bdev_null)
