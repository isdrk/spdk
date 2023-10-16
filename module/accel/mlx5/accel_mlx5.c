/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/queue.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/likely.h"
#include "spdk/dma.h"
#include "spdk/json.h"
#include "spdk/util.h"
#include "spdk/dma.h"
#include "spdk/tree.h"
#include "spdk/accel_module.h"

#include "spdk_internal/mlx5.h"
#include "spdk_internal/rdma_utils.h"
#include "spdk_internal/assert.h"
#include "spdk_internal/sgl.h"
#include "accel_mlx5.h"

#include <infiniband/mlx5dv.h>
#include <rdma/rdma_cma.h>

#define ACCEL_MLX5_QP_SIZE (256u)
#define ACCEL_MLX5_NUM_MKEYS (2048u)

#define ACCEL_MLX5_MAX_SGE (16u)
#define ACCEL_MLX5_MAX_WC (64u)
#define ACCEL_MLX5_TASK_CACHE_LINES (SPDK_CEIL_DIV(sizeof(struct accel_mlx5_task), 64))
#define ACCEL_MLX5_MAX_MKEYS_IN_TASK (32)

#define ACCEL_MLX5_RECOVER_POLLER_PERIOD_US (10000)

/* TODO: after review with Achiad:
 * 1. try to reduce number of pointer redirections like task->dev->dev_ctx
 */

struct accel_mlx5_iov_sgl {
	struct iovec	*iov;
	int		iovcnt;
	uint32_t        iov_offset;
};

struct accel_mlx5_io_channel;
struct accel_mlx5_task;

struct accel_mlx5_cryptodev_memory_domain {
	struct spdk_memory_domain_rdma_ctx rdma_ctx;
	struct spdk_memory_domain *domain;
};

/* TODO: rename structures to remove 'crypto' word */
struct accel_mlx5_crypto_dev_ctx {
	struct spdk_mempool *mkey_pool;
	struct spdk_mlx5_indirect_mkey **mkeys;
	struct spdk_mempool *sig_mkey_pool;
	struct spdk_mlx5_indirect_mkey **sig_mkeys;
	struct spdk_mempool *psv_pool;
	struct spdk_mlx5_psv **psvs;
	struct ibv_context *context;
	struct ibv_pd *pd;
	struct accel_mlx5_cryptodev_memory_domain domain;
	uint32_t num_mkeys;
	bool crypto_multi_block;
	RB_HEAD(mkeys_tree, accel_mlx5_sig_key_wrapper) sig_mkey_tree;
};

struct accel_mlx5_module {
	struct spdk_accel_module_if module;
	struct accel_mlx5_crypto_dev_ctx *crypto_ctxs;
	uint32_t num_crypto_ctxs;
	uint16_t qp_size;
	uint32_t num_requests;
	uint32_t split_mb_blocks;
	bool siglast;
	char **allowed_crypto_devs;
	size_t allowed_crypto_devs_count;
	bool enabled;
	bool crypto_supported;
	bool enable_crc;
	bool merge;
};

enum accel_mlx5_wrid_type {
	ACCEL_MLX5_WRID_MKEY,
	ACCEL_MLX5_WRID_WRITE,
};

struct accel_mlx5_wrid {
	uint8_t wrid;
};

struct accel_mlx5_klm {
	uint32_t src_klm_count;
	uint32_t dst_klm_count;
	struct mlx5_wqe_data_seg src_klm[ACCEL_MLX5_MAX_SGE];
	struct mlx5_wqe_data_seg dst_klm[ACCEL_MLX5_MAX_SGE];
};

struct accel_mlx5_crypto_key_wrapper {
	uint32_t mkey;
};

struct accel_mlx5_sig_key_wrapper {
	uint32_t mkey;
	uint32_t sigerr_count;
	bool sigerr;
	RB_ENTRY(accel_mlx5_sig_key_wrapper) node;
};

static int
accel_mlx5_sig_key_wrapper_compare(struct accel_mlx5_sig_key_wrapper *key1, struct accel_mlx5_sig_key_wrapper *key2)
{
	return key1->mkey < key2->mkey ? -1 : key1->mkey > key2->mkey;
}

RB_GENERATE_STATIC(mkeys_tree, accel_mlx5_sig_key_wrapper, node, accel_mlx5_sig_key_wrapper_compare);

struct accel_mlx5_psv_wrapper {
	uint32_t psv_index;
	struct {
		uint32_t error : 1;
		uint32_t reserved : 31;
	} bits;
};

enum accel_mlx5_opcode {
	ACCEL_MLX5_OPC_COPY,
	ACCEL_MLX5_OPC_CRYPTO,
	ACCEL_MLX5_OPC_CRC32C,
	ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C,
};

struct accel_mlx5_task {
	struct spdk_accel_task base;
	/* Add padding to have dev pointer first element in new cache line.
	 * Last 2 cache lines in base structure are occupied by bounce buffer structure
	 * which are only used when the module doesn't support memory domains - that is not
	 * our case
	uint8_t padding[8];
	*/
	struct accel_mlx5_dev *dev;
	uint16_t num_reqs;
	uint16_t num_completed_reqs;
	uint16_t num_submitted_reqs;
	/* If set, memory data will be encrypted during TX and wire data will be
	 decrypted during RX.
	 If not set, memory data will be decrypted during TX and wire data will
	 be encrypted during RX. */
	uint8_t enc_order;
	struct accel_mlx5_wrid write_wrid;
	union {
		uint8_t raw;
		struct {
			uint8_t inplace : 1;
			/* Set if the task is executed as a part of the previous task. */
			uint8_t merged : 1;
			uint8_t reserved : 6;
		} bits;
	} flags;
	uint8_t mlx5_opcode;
	union {
		/* The struct is used for crypto */
		struct {
			/* Number of data blocks per crypto operation */
			uint16_t blocks_per_req;
			/* total num_blocks in this task */
			uint16_t num_blocks;
		};
		/* Number of bytes per signature operation. It is used for crc32c. */
		 uint32_t nbytes;
	};
	/* for crypto op - number of allocated mkeys
	 * for crypto and copy - number of operations allowed to be submitted to qp */
	uint16_t num_ops;
	struct accel_mlx5_iov_sgl src;
	struct accel_mlx5_iov_sgl dst;
	struct accel_mlx5_psv_wrapper *psv;
	STAILQ_ENTRY(accel_mlx5_task) link;
	/* Keep this array last since not all elements might be accessed, this reduces amount of data to be
	 * cached */
	union {
		struct accel_mlx5_crypto_key_wrapper *crypto_mkeys[ACCEL_MLX5_MAX_MKEYS_IN_TASK];
		struct accel_mlx5_sig_key_wrapper *sig_mkeys[ACCEL_MLX5_MAX_MKEYS_IN_TASK];
	};
};

SPDK_STATIC_ASSERT(offsetof(struct accel_mlx5_task, dev) % 64 == 0, "dev pointer is not cache line aligned");

struct accel_mlx5_dev_stats {
	uint64_t tasks;
	uint64_t umrs;
	uint64_t rdma_writes;
	uint64_t polls;
	uint64_t idle_polls;
	uint64_t completions;
};

struct accel_mlx5_dev {
	struct spdk_mlx5_dma_qp *dma_qp;
	struct spdk_rdma_utils_mem_map *mmap;
	/* Points to a pool owned by dev_ctx */
	struct spdk_mempool *mkey_pool_ref;
	/* Points to a pool owned by dev_ctx */
	struct spdk_mempool *sig_mkey_pool_ref;
	/* Points to a pool owned by dev_ctx */
	struct spdk_mempool *psv_pool_ref;
	/* Points to a PD owned by dev_ctx */
	struct ibv_pd *pd_ref;
	/* Points to a memory domain owned by dev_ctx */
	struct spdk_memory_domain *domain_ref;
	uint16_t reqs_submitted;
	uint16_t max_reqs;
	bool crypto_multi_block;
	bool recovering;
	struct accel_mlx5_dev_stats stats;
	/* Pending tasks waiting for requests resources */
	STAILQ_HEAD(, accel_mlx5_task) nomem;
	/* tasks submitted to HW. We can't complete a task even in error case until we reap completions for all
	 * submitted requests */
	STAILQ_HEAD(, accel_mlx5_task) in_hw;
	/* tasks waiting for device recovery */
	STAILQ_HEAD(, accel_mlx5_task) recover;
	struct spdk_poller *recover_poller;
	STAILQ_HEAD(, accel_mlx5_task) merged;
	struct mkeys_tree *sig_mkey_tree_ref;
};

struct accel_mlx5_io_channel {
	struct accel_mlx5_dev *devs;
	struct spdk_poller *poller;
	uint32_t num_devs;
	/* Index in \b devs to be used for crypto in round-robin way */
	uint32_t dev_idx;
};

static struct accel_mlx5_module g_accel_mlx5;
static void(*g_accel_mlx5_process_cpl_fn)(struct accel_mlx5_dev *dev, struct spdk_mlx5_cq_completion *wc, int reaped);

static inline void
accel_mlx5_iov_sgl_init(struct accel_mlx5_iov_sgl *s, struct iovec *iov, int iovcnt)
{
	s->iov = iov;
	s->iovcnt = iovcnt;
	s->iov_offset = 0;
}

static inline void
accel_mlx5_iov_sgl_advance(struct accel_mlx5_iov_sgl *s, uint32_t step)
{
	s->iov_offset += step;
	while (s->iovcnt > 0) {
		assert(s->iov != NULL);
		if (s->iov_offset < s->iov->iov_len) {
			break;
		}

		s->iov_offset -= s->iov->iov_len;
		s->iov++;
		s->iovcnt--;
	}
}

static inline int
accel_mlx5_task_check_sigerr(struct accel_mlx5_task *task)
{
	unsigned i;
	int rc;

	if (task->base.op_code != ACCEL_OPC_CHECK_CRC32C) {
		return 0;
	}

	rc = 0;
	for (i = 0; i < task->num_ops; i++) {
		if (task->sig_mkeys[i]->sigerr) {
			task->sig_mkeys[i]->sigerr = false;
			rc = -EIO;
		}
	}

	if (spdk_likely(!rc)) {
		return 0;
	}

	task->psv->bits.error = 1;

	if (task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C) {
		struct spdk_accel_task *task_next = TAILQ_NEXT(&task->base, seq_link);
		struct accel_mlx5_task *mlx5_task_next = SPDK_CONTAINEROF(task_next, struct accel_mlx5_task, base);

		/* The accel will not submit the next task because the current one is failed.
		 * That's why the merged flag is reset here.
		 */
		mlx5_task_next->flags.bits.merged = 0;
	}

	return rc;
}

static inline void
accel_mlx5_task_release_mkeys(struct accel_mlx5_task *mlx5_task)
{
	if (mlx5_task->num_ops) {
		if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO) {
			spdk_mempool_put_bulk(mlx5_task->dev->mkey_pool_ref, (void **) mlx5_task->crypto_mkeys,
					      mlx5_task->num_ops);
		}
		if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C ||
		    mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C) {
			spdk_mempool_put_bulk(mlx5_task->dev->sig_mkey_pool_ref, (void **) mlx5_task->sig_mkeys,
					      mlx5_task->num_ops);
			spdk_mempool_put(mlx5_task->dev->psv_pool_ref, mlx5_task->psv);
		}
	}
}

static inline void
accel_mlx5_task_complete(struct accel_mlx5_task *task, int rc)
{
	assert(task->num_reqs == task->num_completed_reqs || rc);
	SPDK_DEBUGLOG(accel_mlx5, "Complete task %p, opc %d, rc %d\n", task, task->base.op_code, rc);
	int sigerr;

	if (task->flags.bits.merged) {
		task->flags.bits.merged = 0;
		spdk_accel_task_complete(&task->base, rc);
		return;
	}

	sigerr = accel_mlx5_task_check_sigerr(task);
	rc = rc ? rc : sigerr;
	accel_mlx5_task_release_mkeys(task);
	spdk_accel_task_complete(&task->base, rc);
}

static int
accel_mlx5_translate_addr(void *addr, size_t size, struct spdk_memory_domain *domain, void *domain_ctx,
			 struct accel_mlx5_dev *dev, struct mlx5_wqe_data_seg *klm)
{
	struct spdk_rdma_utils_memory_translation map_translation;
	struct spdk_memory_domain_translation_result domain_translation;
	struct spdk_memory_domain_translation_ctx local_ctx;
	int rc;

	if (domain) {
		domain_translation.size = sizeof(struct spdk_memory_domain_translation_result);
		local_ctx.size = sizeof(local_ctx);
		local_ctx.rdma.ibv_qp = dev->dma_qp->qp.verbs_qp;
		rc = spdk_memory_domain_translate_data(domain, domain_ctx, dev->domain_ref,
						       &local_ctx, addr, size, &domain_translation);
		if (spdk_unlikely(rc || domain_translation.iov_count != 1)) {
			SPDK_ERRLOG("Memory domain translation failed, addr %p, length %zu\n", addr, size);
			if (rc == 0) {
				rc = -EINVAL;
			}

			return rc;
		}
		klm->lkey = domain_translation.rdma.lkey;
		klm->addr = (uint64_t) domain_translation.iov.iov_base;
		klm->byte_count = domain_translation.iov.iov_len;
		/*SPDK_NOTICELOG("Translation addr=%p, klm->lkey=%lu, klm->addr=%p, klm-byte_count=%lu, "
				"domain=%p, domain_ctx=%p\n", addr, domain_translation.rdma.lkey,
				(void *)klm->addr, klm->byte_count, domain, domain_ctx);*/
	} else {
		rc = spdk_rdma_utils_get_translation(dev->mmap, addr, size,
						     &map_translation);
		if (spdk_unlikely(rc)) {
			SPDK_ERRLOG("Memory translation failed, addr %p, length %zu\n", addr, size);
			return rc;
		}
		klm->lkey = spdk_rdma_utils_memory_translation_get_lkey(&map_translation);
		klm->addr = (uint64_t)addr;
		klm->byte_count = size;
	}

	return 0;
}

static int
accel_mlx5_fill_block_sge(struct accel_mlx5_dev *dev, struct mlx5_wqe_data_seg *klm,
			  struct accel_mlx5_iov_sgl *iovs, struct spdk_memory_domain *domain, void *domain_ctx,
			  uint32_t lkey, uint32_t block_len, uint32_t *_remaining)
{
	void *addr;
	uint32_t remaining;
	uint32_t size;
	int i = 0;
	int rc;
	remaining = block_len;

	while (remaining && i < (int)ACCEL_MLX5_MAX_SGE) {
		size = spdk_min(remaining, iovs->iov->iov_len - iovs->iov_offset);
		addr = (void *)iovs->iov->iov_base + iovs->iov_offset;
		if (!lkey) {
			/* No pre-translated lkey */
			rc = accel_mlx5_translate_addr(addr, size, domain, domain_ctx, dev, &klm[i]);
			if (spdk_unlikely(rc)) {
				return rc;
			}
		} else {
			klm[i].lkey = lkey;
			klm[i].addr = (uint64_t) addr;
			klm[i].byte_count = size;
		}

		SPDK_DEBUGLOG(accel_mlx5, "\t klm[%d] lkey %u, addr %p, len %u\n", i, klm[i].lkey, (void*)klm[i].addr, klm[i].byte_count);
		accel_mlx5_iov_sgl_advance(iovs, size);
		i++;
		assert(remaining >= size);
		remaining -= size;
	}
	*_remaining = remaining;

	return i;
}

static inline bool
accel_mlx5_compare_iovs(struct iovec *v1, struct iovec *v2, uint32_t iovcnt)
{
	uint32_t i;

	for (i = 0; i < iovcnt; i++) {
		if (v1[i].iov_base != v2[i].iov_base || v1[i].iov_len != v2[i].iov_len) {
			return false;
		}
	}

	return true;
}

static inline int
accel_mlx5_task_alloc_mkeys(struct accel_mlx5_task *task, struct spdk_mempool *mkey_pool)
{
	/* Each request consists of UMR and RDMA, or 2 operations.
	 * qp slot is the total number of operations available in qp */
	uint32_t num_ops = (task->num_reqs - task->num_completed_reqs) * 2;
	uint32_t qp_slot = task->dev->max_reqs - task->dev->reqs_submitted;
	uint32_t num_mkeys;
	int rc;

	assert(task->num_reqs >= task->num_completed_reqs);
	assert(task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO || task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C ||
	       task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C);
	num_ops = spdk_min(num_ops, qp_slot);
	num_ops = spdk_min(num_ops, ACCEL_MLX5_MAX_MKEYS_IN_TASK * 2);
	if (num_ops < 2) {
		/* We must do at least 1 UMR and 1 RDMA operation */
		task->num_ops = 0;
		return -ENOMEM;
	}
	num_mkeys = num_ops / 2;
	/* It does not matter if we use crypto_mkeys or sig_mkeys here because both are in the union and
	 * have identical addresses */
	rc = spdk_mempool_get_bulk(mkey_pool, (void **)task->crypto_mkeys, num_mkeys);
	if (spdk_unlikely(rc)) {
		task->num_ops = 0;
		return -ENOMEM;
	}
	task->num_ops = num_mkeys;

	return 0;
}

static inline uint8_t
bs_to_bs_selector(uint32_t bs)
{
	switch (bs) {
	case 512:
		return 1;
	case 520:
		return 2;
	case 4048:
		return 6;
	case 4096:
		return 3;
	case 4160:
		return 4;
	default:
		return 0;
	}
}

static inline int
accel_mlx5_copy_task_process_one(struct accel_mlx5_task *mlx5_task, struct accel_mlx5_dev *dev, uint64_t wrid, uint32_t fence)
{
	struct spdk_accel_task *task = &mlx5_task->base;
	struct accel_mlx5_klm klm;
	uint32_t remaining;
	uint32_t dst_len;
	int rc;

	/* Limit one RDMA_WRITE by length of dst buffer. Not all src buffers may fit into one dst buffer due to
	 * limitation on ACCEL_MLX5_MAX_SGE. If this is the case then remaining is not zero */
	assert(mlx5_task->dst.iov->iov_len > mlx5_task->dst.iov_offset);
	dst_len = mlx5_task->dst.iov->iov_len - mlx5_task->dst.iov_offset;
	rc = accel_mlx5_fill_block_sge(dev, klm.src_klm, &mlx5_task->src, task->src_domain,
				       task->src_domain_ctx, 0, dst_len, &remaining);
	if (spdk_unlikely(rc <= 0)) {
		if (rc == 0) {
			rc = -EINVAL;
		}
		SPDK_ERRLOG("failed set src sge, rc %d\n", rc);
		return rc;
	}
	klm.src_klm_count = rc;
	assert(dst_len > remaining);
	dst_len -= remaining;

	rc = accel_mlx5_fill_block_sge(dev, klm.dst_klm, &mlx5_task->dst, task->dst_domain,
				       task->dst_domain_ctx, 0, dst_len,  &remaining);
	if (spdk_unlikely(rc <= 0)) {
		if (rc == 0) {
			rc = -EINVAL;
		}
		SPDK_ERRLOG("failed set dst sge, rc %d\n", rc);
		return rc;
	}
	if (spdk_unlikely(remaining)) {
		SPDK_ERRLOG("something wrong\n");
		abort();
	}
	klm.dst_klm_count = rc;

	rc = spdk_mlx5_dma_qp_rdma_write(dev->dma_qp, klm.src_klm, klm.src_klm_count,
					 klm.dst_klm[0].addr, klm.dst_klm[0].lkey, wrid, fence);
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("new RDMA WRITE failed with %d\n", rc);
		return rc;
	}

	return 0;
}

static inline int
accel_mlx5_copy_task_process(struct accel_mlx5_task *mlx5_task)
{

	struct accel_mlx5_dev *dev = mlx5_task->dev;
	uint16_t i;
	int rc;

	dev->stats.tasks++;
	assert(mlx5_task->num_reqs > 0);
	assert(mlx5_task->num_ops > 0);

	/* Handle n-1 reqs in order to simplify wrid and fence handling */
	for (i = 0; i < mlx5_task->num_ops - 1; i++) {
		rc = accel_mlx5_copy_task_process_one(mlx5_task, dev, 0, 0);
		if (spdk_unlikely(rc)) {
			return rc;
		}
		dev->stats.rdma_writes++;
		assert(dev->reqs_submitted < dev->max_reqs);
		dev->reqs_submitted++;
		mlx5_task->num_submitted_reqs++;
	}

	rc = accel_mlx5_copy_task_process_one(mlx5_task, dev, (uint64_t)&mlx5_task->write_wrid,
					      SPDK_MLX5_WQE_CTRL_CQ_UPDATE);
	if (spdk_unlikely(rc)) {
		return rc;
	}
	dev->stats.rdma_writes++;
	assert(dev->reqs_submitted < dev->max_reqs);
	dev->reqs_submitted++;
	mlx5_task->num_submitted_reqs++;
	STAILQ_INSERT_TAIL(&dev->in_hw, mlx5_task, link);

	SPDK_DEBUGLOG(accel_mlx5, "end, copy task, %p\n", mlx5_task);

	return 0;
}

static inline int
accel_mlx5_configure_crypto_umr(struct accel_mlx5_task *mlx5_task, struct accel_mlx5_dev *dev,
				struct accel_mlx5_klm *klm, uint32_t dv_mkey, uint32_t src_lkey,
				uint32_t dst_lkey, uint64_t iv, uint32_t req_len)
{
	struct spdk_accel_task *task = &mlx5_task->base;
	struct spdk_mlx5_umr_crypto_attr cattr;
	struct spdk_mlx5_umr_attr umr_attr;
	struct spdk_mlx5_crypto_dek_data dek_data;
	uint32_t remaining;
	int rc;

	rc = accel_mlx5_fill_block_sge(dev, klm->src_klm, &mlx5_task->src, task->src_domain,
				       task->src_domain_ctx, src_lkey, req_len, &remaining);
	if (spdk_unlikely(rc <= 0)) {
		if (rc == 0) {
			rc = -EINVAL;
		}
		SPDK_ERRLOG("failed set src sge, rc %d\n", rc);
		return rc;
	}
	if (spdk_unlikely(remaining)) {
		SPDK_ERRLOG("Incorrect src iovs, handling not supported for crypto yet\n");
		abort();
	}
	klm->src_klm_count = rc;

	SPDK_DEBUGLOG(accel_mlx5, "task %p crypto_attr: bs %u, iv %"PRIu64", enc_on_tx %d\n",
		      mlx5_task, task->block_size, iv, mlx5_task->enc_order);
	rc = spdk_mlx5_crypto_get_dek_data(task->crypto_key->priv, dev->pd_ref, &dek_data);
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("failed to set crypto attr, rc %d\n", rc);
		return rc;
	}
	cattr.enc_order = mlx5_task->enc_order;
	cattr.bs_selector = bs_to_bs_selector(task->block_size);
	if (spdk_unlikely(!cattr.bs_selector)) {
		SPDK_ERRLOG("unsupported block size %u\n", task->block_size);
		return -EINVAL;
	}
	cattr.xts_iv = iv;
	cattr.keytag = 0;
	cattr.dek_obj_id = dek_data.dek_obj_id;
	cattr.tweak_mode = dek_data.tweak_mode;

	umr_attr.dv_mkey = dv_mkey;
	umr_attr.umr_len = req_len;
	umr_attr.klm_count = klm->src_klm_count;
	umr_attr.klm = klm->src_klm;

	if (!mlx5_task->flags.bits.inplace) {
		rc = accel_mlx5_fill_block_sge(dev, klm->dst_klm, &mlx5_task->dst, task->dst_domain,
					       task->dst_domain_ctx, dst_lkey, req_len, &remaining);
		if (spdk_unlikely(rc <= 0)) {
			if (rc == 0) {
				rc = -EINVAL;
			}
			SPDK_ERRLOG("failed set dst sge, rc %d\n", rc);
			return rc;
		}
		if (spdk_unlikely(remaining)) {
			SPDK_ERRLOG("Incorrect dst iovs, handling not supported for crypto yet\n");
			abort();
		}
		klm->dst_klm_count = rc;
	}
	rc = spdk_mlx5_umr_configure_crypto(dev->dma_qp, &umr_attr, &cattr, 0, 0);

	return rc;
}


static inline int
accel_mlx5_crypto_task_process(struct accel_mlx5_task *mlx5_task)
{
	struct accel_mlx5_klm klms[ACCEL_MLX5_MAX_MKEYS_IN_TASK];
	struct spdk_accel_task *task = &mlx5_task->base;
	struct accel_mlx5_dev *dev = mlx5_task->dev;
	uint32_t src_lkey = 0, dst_lkey = 0;
	uint64_t iv;
	uint16_t i;
	uint32_t num_ops = spdk_min(mlx5_task->num_reqs - mlx5_task->num_completed_reqs, mlx5_task->num_ops);
	uint32_t req_len;
	/* First RDMA after UMR must have a SMALL_FENCE */
	uint32_t first_rdma_fence = SPDK_MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
	uint32_t blocks_processed;
	size_t ops_len = mlx5_task->blocks_per_req * num_ops;
	int rc;

	if (spdk_unlikely(!num_ops)) {
		return -EINVAL;
	}

	dev->stats.tasks++;

	if (ops_len <= mlx5_task->src.iov->iov_len - mlx5_task->src.iov_offset || task->s.iovcnt == 1) {
		if (task->cached_lkey == NULL || *task->cached_lkey == 0 || !task->src_domain) {
			rc = accel_mlx5_translate_addr(task->s.iovs[0].iov_base, task->s.iovs[0].iov_len, task->src_domain,
						       task->src_domain_ctx, dev, klms[0].src_klm);
			if (spdk_unlikely(rc)) {
				return rc;
			}
			src_lkey = klms[0].src_klm->lkey;
			if (task->cached_lkey && task->src_domain) {
				//SPDK_ERRLOG("src updated task->cached_lkey=%lu -> src_lkey=%lu\n", *task->cached_lkey, src_lkey);
				*task->cached_lkey = src_lkey;
			}
		} else {
			src_lkey = *task->cached_lkey;
			//SPDK_ERRLOG("src using cached task->cached_lkey %lu\n", src_lkey);
		}
	}
	if (!mlx5_task->flags.bits.inplace &&
	    (ops_len <= mlx5_task->dst.iov->iov_len - mlx5_task->dst.iov_offset || task->d.iovcnt == 1)) {
		if (task->cached_lkey == NULL || *task->cached_lkey == 0 || !task->dst_domain) {
			rc = accel_mlx5_translate_addr(task->d.iovs[0].iov_base, task->d.iovs[0].iov_len, task->dst_domain,
						       task->dst_domain_ctx, dev, klms[0].dst_klm);
			if (spdk_unlikely(rc)) {
				return rc;
			}
			dst_lkey = klms[0].dst_klm->lkey;
			if (task->cached_lkey && task->dst_domain) {
				//SPDK_ERRLOG("dst updated task->cached_lkey=%lu -> dst_lkey=%lu\n", *task->cached_lkey, dst_lkey);
				*task->cached_lkey = dst_lkey;
			}
		} else {
			dst_lkey = *task->cached_lkey;
			//SPDK_ERRLOG("dst using cached task->cached_lkey %lu\n", dst_lkey);
		}
	}
	blocks_processed = mlx5_task->num_submitted_reqs * mlx5_task->blocks_per_req;
	iv = task->iv + blocks_processed;

	SPDK_DEBUGLOG(accel_mlx5, "begin, task, %p, reqs: total %u, submitted %u, completed %u\n",
		      mlx5_task, mlx5_task->num_reqs, mlx5_task->num_submitted_reqs, mlx5_task->num_completed_reqs);
	/* At this moment we have as many requests as can be submitted to a qp */
	for (i = 0; i < num_ops; i++) {
		if (mlx5_task->num_submitted_reqs + i + 1 == mlx5_task->num_reqs) {
			/* Last request may consume less than calculated */
			assert(mlx5_task->num_blocks > blocks_processed);
			req_len = (mlx5_task->num_blocks - blocks_processed) * task->block_size;
		} else {
			req_len = mlx5_task->blocks_per_req * task->block_size;
		}
		rc = accel_mlx5_configure_crypto_umr(mlx5_task, dev, &klms[i], mlx5_task->crypto_mkeys[i]->mkey,
						     src_lkey, dst_lkey, iv, req_len);
		if (spdk_unlikely(rc)) {
			SPDK_ERRLOG("UMR configure failed with %d\n", rc);
			return rc;
		}
		blocks_processed += mlx5_task->blocks_per_req;
		iv += mlx5_task->blocks_per_req;
		dev->stats.umrs++;
		assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
		assert(dev->reqs_submitted < dev->max_reqs);
		dev->reqs_submitted++;
	}

	for (i = 0; i < num_ops - 1; i++) {
		/* UMR is used as a destination for RDMA_READ - from UMR to klms
		 * XTS is applied on DPS */
		if (mlx5_task->flags.bits.inplace) {
			rc = spdk_mlx5_dma_qp_rdma_read(dev->dma_qp, klms[i].src_klm,
							klms[i].src_klm_count,
							0, mlx5_task->crypto_mkeys[i]->mkey, 0,
							first_rdma_fence);
		} else {
			rc = spdk_mlx5_dma_qp_rdma_read(dev->dma_qp, klms[i].dst_klm,
							klms[i].dst_klm_count,
							0, mlx5_task->crypto_mkeys[i]->mkey, 0,
							first_rdma_fence);
		}
		if (spdk_unlikely(rc)) {
			SPDK_ERRLOG("RDMA READ/WRITE failed with %d\n", rc);
			return rc;
		}
		first_rdma_fence = 0;
		dev->stats.rdma_writes++;
		mlx5_task->num_submitted_reqs++;
		assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
		assert(dev->reqs_submitted < dev->max_reqs);
		dev->reqs_submitted++;
	}

	if (mlx5_task->flags.bits.inplace) {
		rc = spdk_mlx5_dma_qp_rdma_read(dev->dma_qp, klms[i].src_klm, klms[i].src_klm_count,
						0, mlx5_task->crypto_mkeys[i]->mkey,
						(uint64_t) &mlx5_task->write_wrid,
						first_rdma_fence | SPDK_MLX5_WQE_CTRL_CQ_UPDATE);
	} else {
		rc = spdk_mlx5_dma_qp_rdma_read(dev->dma_qp, klms[i].dst_klm, klms[i].dst_klm_count,
						0, mlx5_task->crypto_mkeys[i]->mkey,
						(uint64_t) &mlx5_task->write_wrid,
						first_rdma_fence | SPDK_MLX5_WQE_CTRL_CQ_UPDATE);
	}

	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("RDMA WRITE failed with %d\n", rc);
		return rc;
	}
	dev->stats.rdma_writes++;
	mlx5_task->num_submitted_reqs++;
	assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
	assert(dev->reqs_submitted < dev->max_reqs);
	dev->reqs_submitted++;
	STAILQ_INSERT_TAIL(&dev->in_hw, mlx5_task, link);

	SPDK_DEBUGLOG(accel_mlx5, "end, task, %p, reqs: total %u, submitted %u, completed %u\n", mlx5_task,
		      mlx5_task->num_reqs, mlx5_task->num_submitted_reqs, mlx5_task->num_completed_reqs);

	return 0;
}

static inline int
accel_mlx5_configure_crypto_and_sig_umr(struct accel_mlx5_task *mlx5_task, struct spdk_accel_task *task,
					struct accel_mlx5_dev *dev, struct accel_mlx5_klm *klm,
					struct accel_mlx5_sig_key_wrapper *mkey, uint32_t src_lkey, uint32_t dst_lkey,
					enum spdk_mlx5_umr_sig_domain sig_domain, uint32_t psv_index,
					uint32_t *crc, uint32_t crc_seed, uint64_t iv, uint32_t req_len,
					bool init_signature, bool gen_signature, bool encrypt)
{
	struct spdk_mlx5_umr_crypto_attr cattr;
	struct spdk_mlx5_umr_sig_attr sattr;
	struct spdk_mlx5_umr_attr umr_attr;
	struct spdk_mlx5_crypto_dek_data dek_data;
	uint32_t remaining;
	uint32_t umr_klm_count;
	int rc;

	assert(mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C);

	rc = accel_mlx5_fill_block_sge(dev, klm->src_klm, &mlx5_task->src, task->src_domain,
				       task->src_domain_ctx, src_lkey, req_len, &remaining);
	if (spdk_unlikely(rc <= 0)) {
		if (rc == 0) {
			rc = -EINVAL;
		}
		SPDK_ERRLOG("failed set src sge, rc %d\n", rc);
		return rc;
	}
	if (spdk_unlikely(remaining)) {
		SPDK_ERRLOG("Incorrect src iovs, handling not supported for crypto yet\n");
		abort();
	}
	umr_klm_count = klm->src_klm_count = rc;

	if (!mlx5_task->flags.bits.inplace) {
		rc = accel_mlx5_fill_block_sge(dev, klm->dst_klm, &mlx5_task->dst, task->dst_domain,
					       task->dst_domain_ctx, dst_lkey, req_len, &remaining);
		if (spdk_unlikely(rc <= 0)) {
			if (rc == 0) {
				rc = -EINVAL;
			}
			SPDK_ERRLOG("failed set dst sge, rc %d\n", rc);
			return rc;
		}
		if (spdk_unlikely(remaining)) {
			SPDK_ERRLOG("Incorrect dst iovs, handling not supported for signature yet\n");
			abort();
		}
		klm->dst_klm_count = rc;
	}

	if (gen_signature && !encrypt) {
		/* Ensure that there is a free KLM */
		if (umr_klm_count >= ACCEL_MLX5_MAX_SGE) {
			SPDK_ERRLOG("No space left for crc_dst in klm\n");
			return -EINVAL;
		}

		rc = accel_mlx5_translate_addr(crc, sizeof(*crc), NULL, NULL, dev, &klm->src_klm[umr_klm_count++]);
		if (spdk_unlikely(rc)) {
			/*
			 * TODO: Add a pool of 4-byte memory chunks. Each chunk is DMAable. Allocate a staging
			 * buffer for crc_dst here instead of returning the error.
			 */
			SPDK_ERRLOG("Failed to translate address of crc_dst\n");
			return rc;
		}
	}

	SPDK_DEBUGLOG(accel_mlx5, "task %p crypto_attr: bs %u, iv %"PRIu64", enc_on_tx %d\n",
		      mlx5_task, task->block_size, iv, mlx5_task->enc_order);
	rc = spdk_mlx5_crypto_get_dek_data(task->crypto_key->priv, dev->pd_ref, &dek_data);
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("failed to set crypto attr, rc %d\n", rc);
		return rc;
	}
	cattr.enc_order = mlx5_task->enc_order;
	cattr.bs_selector = bs_to_bs_selector(task->block_size);
	if (spdk_unlikely(!cattr.bs_selector)) {
		SPDK_ERRLOG("unsupported block size %u\n", task->block_size);
		return -EINVAL;
	}
	cattr.xts_iv = iv;
	cattr.keytag = 0;
	cattr.dek_obj_id = dek_data.dek_obj_id;
	cattr.tweak_mode = dek_data.tweak_mode;

	sattr.seed = crc_seed;
	sattr.psv_index = psv_index;
	sattr.domain = sig_domain;
	sattr.sigerr_count = mkey->sigerr_count;
	/* raw_data_size is a size of data without signature. */
	sattr.raw_data_size = req_len;
	sattr.init = init_signature;
	sattr.check_gen = gen_signature;

	umr_attr.dv_mkey = mkey->mkey;
	/*
	 * umr_len is the size of data addressed by MKey in memory and includes
	 * the size of the signature if it exists in memory.
	 */
	umr_attr.umr_len = encrypt ? req_len : req_len + sizeof(*crc);
	umr_attr.klm_count = umr_klm_count;
	umr_attr.klm = klm->src_klm;

	return spdk_mlx5_umr_configure_sig_crypto(dev->dma_qp, &umr_attr, &sattr, &cattr, 0, 0);
}

static inline int
accel_mlx5_crypto_and_crc_task_process(struct accel_mlx5_task *mlx5_task)
{
	struct accel_mlx5_klm klms[ACCEL_MLX5_MAX_MKEYS_IN_TASK];
	struct accel_mlx5_task *mlx5_task_crypto;
	struct spdk_accel_task *task_crypto;
	struct spdk_accel_task *task_crc;
	struct accel_mlx5_dev *dev = mlx5_task->dev;
	uint32_t src_lkey = 0, dst_lkey = 0;
	uint64_t iv;
	uint16_t i;
	uint32_t num_ops = spdk_min(mlx5_task->num_reqs - mlx5_task->num_completed_reqs, mlx5_task->num_ops);
	uint32_t rdma_fence = SPDK_MLX5_WQE_CTRL_INITIATOR_SMALL_FENCE;
	uint32_t req_len;
	uint32_t blocks_processed;
	struct mlx5_wqe_data_seg *klm;
	uint32_t klm_count;
	size_t ops_len = mlx5_task->blocks_per_req * num_ops;
	bool init_signature = false;
	bool gen_signature = false;
	bool encrypt;
	enum spdk_mlx5_umr_sig_domain sig_domain;
	int rc;

	if (mlx5_task->base.op_code == ACCEL_OPC_ENCRYPT) {
		mlx5_task_crypto = mlx5_task;
		task_crypto = &mlx5_task_crypto->base;
		task_crc = TAILQ_NEXT(task_crypto, seq_link);
		encrypt = true;
		sig_domain = SPDK_MLX5_UMR_SIG_DOMAIN_WIRE;
	} else {
		assert(mlx5_task->base.op_code == ACCEL_OPC_CHECK_CRC32C);

		task_crc = &mlx5_task->base;
		task_crypto = TAILQ_NEXT(task_crc, seq_link);
		mlx5_task_crypto = SPDK_CONTAINEROF(task_crypto, struct accel_mlx5_task, base);
		encrypt = false;
		sig_domain = SPDK_MLX5_UMR_SIG_DOMAIN_MEMORY;
	}

	assert(mlx5_task_crypto);
	assert(task_crypto);
	assert(task_crc);

	if (spdk_unlikely(!num_ops)) {
		return -EINVAL;
	}

	dev->stats.tasks++;

	if (ops_len <= mlx5_task->src.iov->iov_len - mlx5_task->src.iov_offset || task_crypto->s.iovcnt == 1) {
		if (task_crypto->cached_lkey == NULL || *task_crypto->cached_lkey == 0 || !task_crypto->src_domain) {
			rc = accel_mlx5_translate_addr(task_crypto->s.iovs[0].iov_base, task_crypto->s.iovs[0].iov_len,
						       task_crypto->src_domain, task_crypto->src_domain_ctx, dev,
						       klms[0].src_klm);
			if (spdk_unlikely(rc)) {
				return rc;
			}
			src_lkey = klms[0].src_klm->lkey;
			if (task_crypto->cached_lkey && task_crypto->src_domain) {
				*task_crypto->cached_lkey = src_lkey;
			}
		} else {
			src_lkey = *task_crypto->cached_lkey;
		}
	}

	if (!mlx5_task->flags.bits.inplace &&
	    (ops_len <= mlx5_task->dst.iov->iov_len - mlx5_task->dst.iov_offset || task_crypto->d.iovcnt == 1)) {
		if (task_crypto->cached_lkey == NULL || *task_crypto->cached_lkey == 0 || !task_crypto->dst_domain) {
			rc = accel_mlx5_translate_addr(task_crypto->d.iovs[0].iov_base, task_crypto->d.iovs[0].iov_len,
						       task_crypto->dst_domain, task_crypto->dst_domain_ctx, dev,
						       klms[0].dst_klm);
			if (spdk_unlikely(rc)) {
				return rc;
			}
			dst_lkey = klms[0].dst_klm->lkey;
			if (task_crypto->cached_lkey && task_crypto->dst_domain) {
				*task_crypto->cached_lkey = dst_lkey;
			}
		} else {
			dst_lkey = *task_crypto->cached_lkey;
		}
	}

	blocks_processed = mlx5_task->num_submitted_reqs * mlx5_task->blocks_per_req;
	iv = task_crypto->iv + blocks_processed;

	SPDK_DEBUGLOG(accel_mlx5, "begin, crypto and crc task, %p, reqs: total %u, submitted %u, completed %u\n",
		      mlx5_task, mlx5_task->num_reqs, mlx5_task->num_submitted_reqs, mlx5_task->num_completed_reqs);

	/* At this moment we have as many requests as can be submitted to a qp */
	for (i = 0; i < num_ops; i++) {
		init_signature = false;
		gen_signature = false;
		if (mlx5_task->num_submitted_reqs + i == 0) {
			/* First req, init transactional signature */
			init_signature = true;
		}
		if (mlx5_task->num_submitted_reqs + i + 1 == mlx5_task->num_reqs) {
			/* Last request may consume less than calculated */
			assert(mlx5_task->num_blocks > blocks_processed);
			req_len = (mlx5_task->num_blocks - blocks_processed) * task_crypto->block_size;
			gen_signature = true;
		} else {
			req_len = mlx5_task->blocks_per_req * task_crypto->block_size;
		}

		/*
		 * There is an HW limitation for the case when crypto and transactional signature are mixed in the same
		 * mkey. The HW only supports two following configurations in this case:
		 *
		 *   *  SX - encrypt-append (XTS first + transaction signature):
		 *      Mem (data) -> Wire sig(xts(data)). BSF.enc_order is encrypted_raw_wire.
		 *
		 *   *  SX - strip-decrypt (Sinature first + transaction signature):
		 *      Mem sig(xts(data)) -> Wire (data). Configuring signature on Wire is not allowed in this case.
		 *      BSF.enc_order is encrypted_raw_memory.
		 */
		rc = accel_mlx5_configure_crypto_and_sig_umr(mlx5_task, task_crypto, dev, &klms[i],
							     mlx5_task->sig_mkeys[i],
							     src_lkey, dst_lkey,
							     sig_domain,
							     mlx5_task->psv->psv_index,
							     task_crc->crc,
							     task_crc->seed, iv, req_len,
							     init_signature, gen_signature,
							     encrypt);
		if (spdk_unlikely(rc)) {
			SPDK_ERRLOG("UMR configure failed with %d\n", rc);
			return rc;
		}
		blocks_processed += mlx5_task->blocks_per_req;
		iv += mlx5_task->blocks_per_req;
		dev->stats.umrs++;
		assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
		dev->reqs_submitted++;
	}

	if (spdk_unlikely(mlx5_task->psv->bits.error)) {
		rc = spdk_mlx5_set_psv(dev->dma_qp, mlx5_task->psv->psv_index, task_crc->seed, 0, 0);
		if (spdk_unlikely(rc)) {
			SPDK_ERRLOG("SET_PSV failed with %d\n", rc);
			return rc;
		}
		dev->reqs_submitted++;
	}

	for (i = 0; i < num_ops - 1; i++) {
		/* UMR is used as a destination for RDMA_READ - from UMR to klms
		 * XTS is applied on DPS */
		if (mlx5_task->flags.bits.inplace) {
			klm = klms[i].src_klm;
			klm_count = klms[i].src_klm_count;
		} else {
			klm = klms[i].dst_klm;
			klm_count = klms[i].dst_klm_count;
		}
		rc = spdk_mlx5_dma_qp_rdma_read(dev->dma_qp, klm, klm_count, 0, mlx5_task->sig_mkeys[i]->mkey,
						0, rdma_fence);
		if (spdk_unlikely(rc)) {
			SPDK_ERRLOG("RDMA WRITE failed with %d\n", rc);
			return rc;
		}
		rdma_fence = SPDK_MLX5_WQE_CTRL_STRONG_ORDERING;
		dev->stats.rdma_writes++;
		mlx5_task->num_submitted_reqs++;
		assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
		dev->reqs_submitted++;
	}

	if (mlx5_task->flags.bits.inplace) {
		klm = klms[i].src_klm;
		klm_count = klms[i].src_klm_count;
	} else {
		klm = klms[i].dst_klm;
		klm_count = klms[i].dst_klm_count;
	}

	/*
	 * TODO: Find a better solution and do not fail the task if klm_count == ACCEL_MLX5_MAX_SGE
	 *
	 * For now, the CRC offload feature is only used to calculate the data digest for write
	 * operations in the NVMe TCP initiator. Since one continues buffer is allocted for each IO
	 * in this case, klm_count is 1, and the below check does not fail.
	 */
	/* Last request, add crc_dst to the KLMs */
	if (encrypt && mlx5_task->num_submitted_reqs + 1 == mlx5_task->num_reqs) {
		/* Ensure that there is a free KLM */
		if (klm_count >= ACCEL_MLX5_MAX_SGE) {
			SPDK_ERRLOG("No space left for crc_dst in klm\n");
			return -EINVAL;
		}

		rc = accel_mlx5_translate_addr(task_crc->crc_dst, sizeof(uint32_t), NULL, NULL, dev,
					       &klm[klm_count++]);
		if (spdk_unlikely(rc)) {
			/*
			 * TODO: Add a pool of 4-byte memory chunks. Each chunk is DMAable. Allocate a staging
			 * buffer for crc_dst here instead of returning the error.
			 */
			SPDK_ERRLOG("Failed to translate address of crc_dst\n");
			return rc;
		}
	}

	rc = spdk_mlx5_dma_qp_rdma_read(dev->dma_qp, klm, klm_count, 0, mlx5_task->sig_mkeys[i]->mkey,
					(uint64_t)&mlx5_task->write_wrid, rdma_fence | SPDK_MLX5_WQE_CTRL_CQ_UPDATE);
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("RDMA WRITE failed with %d\n", rc);
		return rc;
	}
	dev->stats.rdma_writes++;
	mlx5_task->num_submitted_reqs++;
	assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
	dev->reqs_submitted++;
	STAILQ_INSERT_TAIL(&dev->in_hw, mlx5_task, link);

	SPDK_DEBUGLOG(accel_mlx5, "end, crypto and crc task, %p, reqs: total %u, submitted %u, completed %u\n",
		      mlx5_task, mlx5_task->num_reqs, mlx5_task->num_submitted_reqs, mlx5_task->num_completed_reqs);

	return 0;
}

static inline int
accel_mlx5_configure_sig_umr(struct accel_mlx5_task *mlx5_task, struct accel_mlx5_dev *dev, struct accel_mlx5_klm *klm,
			     struct accel_mlx5_sig_key_wrapper *mkey, enum spdk_mlx5_umr_sig_domain sig_domain,
			     uint32_t psv_index, uint32_t req_len)
{
	struct spdk_accel_task *task = &mlx5_task->base;
	struct spdk_mlx5_umr_sig_attr sattr;
	struct spdk_mlx5_umr_attr umr_attr;
	uint32_t remaining;
	int rc;

	assert(mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C);

	rc = accel_mlx5_fill_block_sge(dev, klm->src_klm, &mlx5_task->src, task->src_domain,
				       task->src_domain_ctx, 0, req_len, &remaining);
	if (spdk_unlikely(rc <= 0)) {
		if (rc == 0) {
			rc = -EINVAL;
		}
		SPDK_ERRLOG("failed set src sge, rc %d\n", rc);
		return rc;
	}
	if (spdk_unlikely(remaining)) {
		SPDK_ERRLOG("Incorrect src iovs, handling not supported for crc yet\n");
		abort();
	}
	klm->src_klm_count = rc;

	if (!mlx5_task->flags.bits.inplace) {
		rc = accel_mlx5_fill_block_sge(dev, klm->dst_klm, &mlx5_task->dst, task->dst_domain,
					       task->dst_domain_ctx, 0, req_len, &remaining);
		if (spdk_unlikely(rc <= 0)) {
			if (rc == 0) {
				rc = -EINVAL;
			}
			SPDK_ERRLOG("failed set dst sge, rc %d\n", rc);
			return rc;
		}
		if (spdk_unlikely(remaining)) {
			SPDK_ERRLOG("Incorrect dst iovs, handling not supported for crc yet\n");
			abort();
		}
		klm->dst_klm_count = rc;
	}

	sattr.seed = task->seed;
	sattr.psv_index = psv_index;
	sattr.domain = sig_domain;
	sattr.sigerr_count = mkey->sigerr_count;
	sattr.raw_data_size = req_len;
	sattr.init = true;
	sattr.check_gen = true;

	umr_attr.dv_mkey = mkey->mkey;
	umr_attr.umr_len = req_len;
	umr_attr.klm_count = klm->src_klm_count;
	umr_attr.klm = klm->src_klm;

	return spdk_mlx5_umr_configure_sig(dev->dma_qp, &umr_attr, &sattr, 0, 0);
}


static inline int
accel_mlx5_crc_task_process(struct accel_mlx5_task *mlx5_task)
{
	struct accel_mlx5_klm klms;
	struct accel_mlx5_dev *dev = mlx5_task->dev;
	uint32_t num_ops = spdk_min(mlx5_task->num_reqs - mlx5_task->num_completed_reqs, mlx5_task->num_ops);
	uint32_t rdma_fence = SPDK_MLX5_WQE_CTRL_STRONG_ORDERING;
	bool check_op = mlx5_task->base.op_code == ACCEL_OPC_CHECK_CRC32C;
	struct mlx5_wqe_data_seg *klm;
	uint16_t klm_count;
	int rc;

	assert(mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C);

	if (spdk_unlikely(!num_ops)) {
		return -EINVAL;
	}

	dev->stats.tasks++;

	SPDK_DEBUGLOG(accel_mlx5, "begin, crc task, %p, reqs: total %u, submitted %u, completed %u\n",
		      mlx5_task, mlx5_task->num_reqs, mlx5_task->num_submitted_reqs, mlx5_task->num_completed_reqs);
	/* At this moment we have as many requests as can be submitted to a qp */
	rc = accel_mlx5_configure_sig_umr(mlx5_task, dev, &klms, mlx5_task->sig_mkeys[0],
					  SPDK_MLX5_UMR_SIG_DOMAIN_WIRE, mlx5_task->psv->psv_index,
					  mlx5_task->nbytes);
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("UMR configure failed with %d\n", rc);
		return rc;
	}
	dev->stats.umrs++;
	assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
	dev->reqs_submitted++;

	if (mlx5_task->flags.bits.inplace) {
		klm = klms.src_klm;
		klm_count = klms.src_klm_count;
	} else {
		klm = klms.dst_klm;
		klm_count = klms.dst_klm_count;
	}

	/*
	 * TODO: Find a better solution and do not fail the task if klm_count == ACCEL_MLX5_MAX_SGE
	 *
	 * For now, the CRC offload feature is only used to calculate the data digest for write
	 * operations in the NVMe TCP initiator. Since one continues buffer is allocted for each IO
	 * in this case, klm_count is 1, and the below check does not fail.
	 */
	/* Ensure that there is a free KLM for the CRC destination. */
	if (klm_count >= ACCEL_MLX5_MAX_SGE) {
		SPDK_ERRLOG("No space left for crc klm\n");
		return -EINVAL;
	}

	/* Add the crc destination to the end of KLMs. */
	rc = accel_mlx5_translate_addr(check_op ? mlx5_task->base.crc : mlx5_task->base.crc_dst,
				       sizeof(uint32_t), NULL, NULL, dev, &klm[klm_count++]);
	if (spdk_unlikely(rc)) {
		/*
		 * TODO: Add a pool of 4-byte memory chunks. Each chunk is DMAable. Allocate a staging buffer
		 * for crc_dst here instead of returning the error.
		 */
		SPDK_ERRLOG("Failed to translate address of crc_dst\n");
		return rc;
	}

	if (spdk_unlikely(mlx5_task->psv->bits.error)) {
		rc = spdk_mlx5_set_psv(dev->dma_qp, mlx5_task->psv->psv_index, *mlx5_task->base.crc, 0, 0);
		if (spdk_unlikely(rc)) {
			SPDK_ERRLOG("SET_PSV failed with %d\n", rc);
			return rc;
		}
		dev->reqs_submitted++;
	}

	if (check_op) {
		/* Check with copy is not implemeted in this function */
		assert(mlx5_task->flags.bits.inplace);
		rc = spdk_mlx5_dma_qp_rdma_write(dev->dma_qp, klm, klm_count, 0, mlx5_task->sig_mkeys[0]->mkey,
						 (uint64_t)&mlx5_task->write_wrid,
						 rdma_fence | SPDK_MLX5_WQE_CTRL_CQ_UPDATE);
	} else {
		rc = spdk_mlx5_dma_qp_rdma_read(dev->dma_qp, klm, klm_count, 0, mlx5_task->sig_mkeys[0]->mkey,
						(uint64_t)&mlx5_task->write_wrid,
						rdma_fence | SPDK_MLX5_WQE_CTRL_CQ_UPDATE);
	}
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("RDMA READ/WRITE failed with %d\n", rc);
		return rc;
	}
	dev->stats.rdma_writes++;
	mlx5_task->num_submitted_reqs++;
	assert(mlx5_task->num_submitted_reqs <= mlx5_task->num_reqs);
	dev->reqs_submitted++;
	STAILQ_INSERT_TAIL(&dev->in_hw, mlx5_task, link);

	SPDK_DEBUGLOG(accel_mlx5, "end, crc task, %p, reqs: total %u, submitted %u, completed %u\n", mlx5_task,
		      mlx5_task->num_reqs, mlx5_task->num_submitted_reqs, mlx5_task->num_completed_reqs);

	return 0;
}

static inline int
accel_mlx5_task_alloc_crc_ctx(struct accel_mlx5_task *task)
{
	if (spdk_unlikely(accel_mlx5_task_alloc_mkeys(task, task->dev->sig_mkey_pool_ref))) {
		SPDK_DEBUGLOG(accel_mlx5, "no reqs in signature mkey pool, dev %s\n",
			      task->dev->pd_ref->context->device->name);
		return -ENOMEM;
	}
	task->psv = spdk_mempool_get(task->dev->psv_pool_ref);
	if (spdk_unlikely(!task->psv)) {
		SPDK_DEBUGLOG(accel_mlx5, "no reqs in psv pool, dev %s\n", task->dev->pd_ref->context->device->name);
		spdk_mempool_put_bulk(task->dev->sig_mkey_pool_ref, (void **)task->sig_mkeys, task->num_ops);
		task->num_ops = 0;
		return -ENOMEM;
	}
	/* One extra slot is needed for SET_PSV WQE to reset the error state in PSV. */
	if (spdk_unlikely(task->psv->bits.error)) {
		uint32_t qp_slot = task->dev->max_reqs - task->dev->reqs_submitted;
		uint32_t n_slots = task->num_ops * 2 + 1;

		if (qp_slot < n_slots) {
			spdk_mempool_put(task->dev->psv_pool_ref, task->psv);
			spdk_mempool_put_bulk(task->dev->sig_mkey_pool_ref, (void **)task->sig_mkeys, task->num_ops);
			task->num_ops = 0;
			return -ENOMEM;
		}
	}
	return 0;
}

static inline int
accel_mlx5_task_continue(struct accel_mlx5_task *task)
{
	int rc;

	if (spdk_unlikely(task->dev->recovering)) {
		STAILQ_INSERT_TAIL(&task->dev->nomem, task, link);
		return 0;
	}

	if (task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO) {
		if (task->num_ops == 0) {
			rc = accel_mlx5_task_alloc_mkeys(task, task->dev->mkey_pool_ref);
			if (spdk_unlikely(rc != 0)) {
				/* Pool is empty, queue this task */
				STAILQ_INSERT_TAIL(&task->dev->nomem, task, link);
				return -ENOMEM;
			}
		} else {
			/* Check that we have enough slots in QP */
			uint32_t qp_slot = task->dev->max_reqs - task->dev->reqs_submitted;
			uint32_t num_ops = (task->num_reqs - task->num_completed_reqs) * 2;

			num_ops = spdk_min(num_ops, 2 * task->num_ops);
			if (num_ops > qp_slot) {
				/* Pool is empty, queue this task */
				STAILQ_INSERT_TAIL(&task->dev->nomem, task, link);
				return -ENOMEM;
			}
		}
		return accel_mlx5_crypto_task_process(task);
	} else if (task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C ||
		   task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C) {
		if (task->num_ops == 0) {
			rc = accel_mlx5_task_alloc_crc_ctx(task);
			if (spdk_unlikely(rc != 0)) {
				/* Pool is empty, queue this task */
				STAILQ_INSERT_TAIL(&task->dev->nomem, task, link);
				return -ENOMEM;
			}
		} else {
			/* Check that we have enough slots in QP */
			uint32_t qp_slot = task->dev->max_reqs - task->dev->reqs_submitted;
			uint32_t num_ops = (task->num_reqs - task->num_completed_reqs) * 2;

			num_ops = spdk_min(num_ops, 2 * task->num_ops);
			if (num_ops > qp_slot) {
				/* Pool is empty, queue this task */
				STAILQ_INSERT_TAIL(&task->dev->nomem, task, link);
				return -ENOMEM;
			}
		}

		if (task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C)
			return accel_mlx5_crc_task_process(task);

		return accel_mlx5_crypto_and_crc_task_process(task);
	} else {
		uint16_t qp_slot = task->dev->max_reqs - task->dev->reqs_submitted;
		task->num_ops = spdk_min(qp_slot, task->num_reqs - task->num_completed_reqs);
		if (task->num_ops == 0) {
			/* Pool is empty, queue this task */
			STAILQ_INSERT_TAIL(&task->dev->nomem, task, link);
			return -ENOMEM;
		}
		return accel_mlx5_copy_task_process(task);
	}
}

static inline uint32_t
accel_mlx5_get_copy_task_count(struct iovec *src_iov, uint32_t src_iovcnt, struct iovec *dst_iov, uint32_t dst_iovcnt)
{
	uint64_t src_len = 0;
	uint32_t src_counter = 0;
	uint32_t i, j;
	uint32_t num_ops = 0;
	uint32_t split_by_src_iov_counter = 0;

	for (i = 0; i < dst_iovcnt; i++) {
		for (;src_counter < src_iovcnt; src_counter++) {
			split_by_src_iov_counter++;
			if (split_by_src_iov_counter > ACCEL_MLX5_MAX_SGE) {
				num_ops++;
				split_by_src_iov_counter = 0;
			}

			src_len += src_iov[src_counter].iov_len;
			if (src_len >= dst_iov[i].iov_len) {
				/* We accumulated src iovs bigger than dst iovs */
				if (src_len > dst_iov[i].iov_len) {
					/* src iov might be bigger than several dst iovs, find how many dst iovs
					 * we should rewind starting from the current dst iov counter */
					src_len -= dst_iov[i].iov_len;
					/* check how many dst iovs in 1 src iov */
					for (j = i + 1; j < dst_iovcnt; j++) {
						if (dst_iov[j].iov_len > src_len) {
							break;
						}
						src_len -= dst_iov[j].iov_len;
						/* for each rewound dst iov element, increase the number of ops */
						num_ops++;
						i++;
					}
					/* Since src_len is bigger than last dst iov, remaining part of src iov will
					 * become first sge element in next op */
					split_by_src_iov_counter = 1;
				} else {
					src_len = 0;
				    	split_by_src_iov_counter = 0;
				}
				src_counter++;
				break;
			}
		}
		num_ops++;
	}

	return num_ops;
}

static inline int
accel_mlx5_task_init(struct accel_mlx5_task *mlx5_task, struct accel_mlx5_dev *dev)
{
	struct spdk_accel_task *task = &mlx5_task->base;
	size_t src_nbytes = 0;
	uint32_t num_blocks;
	uint32_t i;

	for (i = 0; i < task->s.iovcnt; i++) {
		src_nbytes += task->s.iovs[i].iov_len;
	}

	if (spdk_unlikely(mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO &&
			  (src_nbytes % mlx5_task->base.block_size != 0))) {
		return -EINVAL;
	}

	mlx5_task->dev = dev;
	mlx5_task->num_completed_reqs = 0;
	mlx5_task->num_submitted_reqs = 0;
	mlx5_task->write_wrid.wrid = ACCEL_MLX5_WRID_WRITE;
	if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO) {
		accel_mlx5_iov_sgl_init(&mlx5_task->src, task->s.iovs, task->s.iovcnt);
		num_blocks = src_nbytes / mlx5_task->base.block_size;
		mlx5_task->num_blocks = num_blocks;
		if (task->d.iovcnt == 0 || (task->d.iovcnt == task->s.iovcnt &&
					    accel_mlx5_compare_iovs(task->d.iovs, task->s.iovs, task->s.iovcnt))) {
			mlx5_task->flags.bits.inplace = 1;
		} else {
			mlx5_task->flags.bits.inplace = 0;
			accel_mlx5_iov_sgl_init(&mlx5_task->dst, task->d.iovs, task->d.iovcnt);
		}
		if (mlx5_task->dev->crypto_multi_block) {
			if (g_accel_mlx5.split_mb_blocks) {
				mlx5_task->num_reqs = SPDK_CEIL_DIV(num_blocks, g_accel_mlx5.split_mb_blocks);
				/* Last req may consume less blocks */
				mlx5_task->blocks_per_req = spdk_min(num_blocks, g_accel_mlx5.split_mb_blocks);
			} else {
				mlx5_task->num_reqs = 1;
				mlx5_task->blocks_per_req = num_blocks;
			}
		} else {
			mlx5_task->num_reqs = num_blocks;
			mlx5_task->blocks_per_req = 1;
		}

		if (spdk_unlikely(accel_mlx5_task_alloc_mkeys(mlx5_task, mlx5_task->dev->mkey_pool_ref))) {
			/* Pool is empty, queue this task */
			SPDK_DEBUGLOG(accel_mlx5, "no reqs in pool, dev %s\n",
				      dev->dma_qp->qp.verbs_qp->context->device->name);
			return -ENOMEM;
		}
		SPDK_DEBUGLOG(accel_mlx5, "crypto task num_reqs %u, num_ops %u, num_blocks %u\n",
			      mlx5_task->num_reqs, mlx5_task->num_ops, mlx5_task->num_blocks);
	} else if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C) {
		struct spdk_accel_task *task_crypto;

		if (task->op_code == ACCEL_OPC_ENCRYPT) {
			task_crypto = task;
		} else {
			task_crypto = TAILQ_NEXT(task, seq_link);
		}
		assert(task_crypto);

		accel_mlx5_iov_sgl_init(&mlx5_task->src, task_crypto->s.iovs, task_crypto->s.iovcnt);
		if (!mlx5_task->flags.bits.inplace) {
			accel_mlx5_iov_sgl_init(&mlx5_task->dst, task_crypto->d.iovs, task_crypto->d.iovcnt);
		}
		num_blocks = src_nbytes / task_crypto->block_size;
		mlx5_task->num_blocks = num_blocks;
		if (mlx5_task->dev->crypto_multi_block) {
			if (g_accel_mlx5.split_mb_blocks) {
				mlx5_task->num_reqs = SPDK_CEIL_DIV(num_blocks, g_accel_mlx5.split_mb_blocks);
				/* Last req may consume less blocks */
				mlx5_task->blocks_per_req = spdk_min(num_blocks, g_accel_mlx5.split_mb_blocks);
			} else {
				mlx5_task->num_reqs = 1;
				mlx5_task->blocks_per_req = num_blocks;
			}
		} else {
			mlx5_task->num_reqs = num_blocks;
			mlx5_task->blocks_per_req = 1;
		}

		if (spdk_unlikely(accel_mlx5_task_alloc_crc_ctx(mlx5_task))) {
			return -ENOMEM;
		}
		SPDK_DEBUGLOG(accel_mlx5, "crypto and crc task num_reqs %u, num_ops %u, num_blocks %u\n", mlx5_task->num_reqs, mlx5_task->num_ops, mlx5_task->num_blocks);
	} else if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C) {
		mlx5_task->nbytes = src_nbytes;
		mlx5_task->num_reqs = 1;

		accel_mlx5_iov_sgl_init(&mlx5_task->src, task->s.iovs, task->s.iovcnt);
		if (!mlx5_task->flags.bits.inplace) {
			accel_mlx5_iov_sgl_init(&mlx5_task->dst, task->d.iovs, task->d.iovcnt);
		}

		if (spdk_unlikely(accel_mlx5_task_alloc_crc_ctx(mlx5_task))) {
			return -ENOMEM;
		}
	} else {
		uint32_t qp_slot = dev->max_reqs - dev->reqs_submitted;

		if (spdk_unlikely(task->s.iovcnt > ACCEL_MLX5_MAX_SGE)) {
			if (task->d.iovcnt == 1) {
				mlx5_task->num_reqs = SPDK_CEIL_DIV(task->s.iovcnt, ACCEL_MLX5_MAX_SGE);
			} else {
				mlx5_task->num_reqs = accel_mlx5_get_copy_task_count(task->s.iovs, task->s.iovcnt,
										     task->d.iovs, task->d.iovcnt);
			}
		} else {
			mlx5_task->num_reqs = task->d.iovcnt;
		}
		mlx5_task->flags.bits.inplace = 0;
		accel_mlx5_iov_sgl_init(&mlx5_task->src, task->s.iovs, task->s.iovcnt);
		accel_mlx5_iov_sgl_init(&mlx5_task->dst, task->d.iovs, task->d.iovcnt);
		mlx5_task->num_ops = spdk_min(qp_slot, mlx5_task->num_reqs);
		if (!mlx5_task->num_ops) {
			return -ENOMEM;
		}
		SPDK_DEBUGLOG(accel_mlx5, "copy task num_reqs %u, num_ops %u\n", mlx5_task->num_reqs, mlx5_task->num_ops);
	}

	SPDK_DEBUGLOG(accel_mlx5, "task %p, inplace %u, num_reqs %d\n", mlx5_task, mlx5_task->flags.bits.inplace,
		      mlx5_task->num_reqs);

	return 0;
}

static inline void
accel_mlx5_task_merge_encrypt_and_crc(struct accel_mlx5_task *mlx5_task)
{
	struct spdk_accel_task *task = &mlx5_task->base;
	struct spdk_accel_task *task_next = TAILQ_NEXT(task, seq_link);
	struct iovec *crypto_dst_iovs;
	uint32_t crypto_dst_iovcnt;
	struct accel_mlx5_task *mlx5_task_next;

	assert(task->op_code == ACCEL_OPC_ENCRYPT);

	if (!task_next || task_next->op_code != ACCEL_OPC_CRC32C) {
		return;
	}

	if (task->d.iovcnt == 0 || (task->d.iovcnt == task->s.iovcnt &&
				    accel_mlx5_compare_iovs(task->d.iovs, task->s.iovs, task->s.iovcnt))) {
		mlx5_task->flags.bits.inplace = 1;
		crypto_dst_iovs = task->s.iovs;
		crypto_dst_iovcnt = task->s.iovcnt;
	} else {
		mlx5_task->flags.bits.inplace = 0;
		crypto_dst_iovs = task->d.iovs;
		crypto_dst_iovcnt = task->d.iovcnt;
	}

	if ((crypto_dst_iovcnt != task_next->s.iovcnt) ||
	    !accel_mlx5_compare_iovs(crypto_dst_iovs, task_next->s.iovs,
				     crypto_dst_iovcnt)) {
		return;
	}

	mlx5_task->mlx5_opcode = ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C;
	mlx5_task_next = SPDK_CONTAINEROF(task_next, struct accel_mlx5_task, base);
	mlx5_task_next->flags.bits.merged = 1;
}

static inline void
accel_mlx5_task_merge_crc_and_decrypt(struct accel_mlx5_task *mlx5_task_crc)
{
	struct spdk_accel_task *task_crc = &mlx5_task_crc->base;
	struct spdk_accel_task *task_crypto = TAILQ_NEXT(task_crc, seq_link);
	struct accel_mlx5_task *mlx5_task_crypto;

	assert(task_crc->op_code == ACCEL_OPC_CHECK_CRC32C);

	if (!task_crypto || task_crypto->op_code != ACCEL_OPC_DECRYPT) {
		return;
	}
	mlx5_task_crypto = SPDK_CONTAINEROF(task_crypto, struct accel_mlx5_task, base);

	if (task_crypto->d.iovcnt == 0 ||
	    (task_crypto->d.iovcnt == task_crypto->s.iovcnt &&
	     accel_mlx5_compare_iovs(task_crypto->d.iovs, task_crypto->s.iovs, task_crypto->s.iovcnt))) {
		mlx5_task_crc->flags.bits.inplace = 1;
	} else {
		mlx5_task_crc->flags.bits.inplace = 0;
	}

	if ((task_crypto->s.iovcnt != task_crc->s.iovcnt) ||
	    !accel_mlx5_compare_iovs(task_crypto->s.iovs, task_crc->s.iovs,
				     task_crypto->s.iovcnt)) {
		return;
	}

	mlx5_task_crypto->flags.bits.merged = true;
	mlx5_task_crc->mlx5_opcode = ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C;
	mlx5_task_crc->enc_order = MLX5_ENCRYPTION_ORDER_ENCRYPTED_RAW_MEMORY;
}

static inline int
accel_mlx5_task_process(struct accel_mlx5_task *mlx5_task)
{
	int rc;

	if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO) {
		rc = accel_mlx5_crypto_task_process(mlx5_task);
	} else if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C) {
		rc = accel_mlx5_crypto_and_crc_task_process(mlx5_task);
	} else if (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C) {
		rc = accel_mlx5_crc_task_process(mlx5_task);
	} else {
		assert(mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_COPY);
		rc = accel_mlx5_copy_task_process(mlx5_task);
	}

	return rc;
}

static int
accel_mlx5_submit_tasks(struct spdk_io_channel *_ch, struct spdk_accel_task *task)
{
	struct accel_mlx5_io_channel *ch = spdk_io_channel_get_ctx(_ch);
	struct accel_mlx5_task *mlx5_task = SPDK_CONTAINEROF(task, struct accel_mlx5_task, base);
	struct accel_mlx5_dev *dev;
	bool crypto_key_ok;
	int rc;

	if (mlx5_task->flags.bits.merged) {
		dev = &ch->devs[ch->dev_idx];
		ch->dev_idx++;
		if (ch->dev_idx == ch->num_devs) {
			ch->dev_idx = 0;
		}
		mlx5_task->dev = dev;
		STAILQ_INSERT_TAIL(&dev->merged, mlx5_task, link);

		return 0;
	}

	switch (task->op_code) {
	case ACCEL_OPC_COPY:
		mlx5_task->mlx5_opcode = ACCEL_MLX5_OPC_COPY;
		break;
	case ACCEL_OPC_ENCRYPT:
		assert(g_accel_mlx5.crypto_supported);
		mlx5_task->enc_order = MLX5_ENCRYPTION_ORDER_ENCRYPTED_RAW_WIRE;
		mlx5_task->mlx5_opcode = ACCEL_MLX5_OPC_CRYPTO;
		crypto_key_ok = (task->crypto_key && task->crypto_key->module_if == &g_accel_mlx5.module &&
						    task->crypto_key->priv);
		if (g_accel_mlx5.merge) {
			accel_mlx5_task_merge_encrypt_and_crc(mlx5_task);
		}
		break;
	case ACCEL_OPC_DECRYPT:
		assert(g_accel_mlx5.crypto_supported);
		mlx5_task->enc_order = MLX5_ENCRYPTION_ORDER_ENCRYPTED_RAW_MEMORY;
		mlx5_task->mlx5_opcode = ACCEL_MLX5_OPC_CRYPTO;
		crypto_key_ok = (task->crypto_key && task->crypto_key->module_if == &g_accel_mlx5.module &&
						    task->crypto_key->priv);
		break;
	case ACCEL_OPC_CRC32C:
		mlx5_task->flags.bits.inplace = 1;
		mlx5_task->mlx5_opcode = ACCEL_MLX5_OPC_CRC32C;
		break;
	case ACCEL_OPC_CHECK_CRC32C:
		mlx5_task->flags.bits.inplace = 1;
		mlx5_task->mlx5_opcode = ACCEL_MLX5_OPC_CRC32C;
		if (g_accel_mlx5.merge) {
			accel_mlx5_task_merge_crc_and_decrypt(mlx5_task);
		}
		break;
	case ACCEL_OPC_COPY_CRC32C:
		mlx5_task->flags.bits.inplace = 0;
		mlx5_task->mlx5_opcode = ACCEL_MLX5_OPC_CRC32C;
		break;
	default:
		SPDK_ERRLOG("Unsupported accel opcode %d\n", task->op_code);
		return -ENOTSUP;
	}

	if (spdk_unlikely(!g_accel_mlx5.enabled ||
			  (mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO && !crypto_key_ok))) {
		return -EINVAL;
	}

	dev = &ch->devs[ch->dev_idx];
	ch->dev_idx++;
	if (ch->dev_idx == ch->num_devs) {
		ch->dev_idx = 0;
	}

	/*
	 * TODO: Fix crc_op when the merge crypto and CRC is enabled.
	 *
	 * Signature MKeys are created with crypto support when the merge is enabled
	 * in the configuration. Since UMR cannot disable crypto for the MKey, we
	 * cannot handle CRC tasks in this case if they are not merged with crypto
	 * tasks. This limitation is not a problem for the NVMe TCP initiator use
	 * cases and will be removed later.
	 */
	assert((g_accel_mlx5.merge && !(mlx5_task->mlx5_opcode == ACCEL_MLX5_OPC_CRC32C)) || !g_accel_mlx5.merge);

	rc = accel_mlx5_task_init(mlx5_task, dev);
	if (spdk_unlikely(rc)) {
		if (rc == -ENOMEM) {
			SPDK_DEBUGLOG(accel_mlx5, "no reqs to handle new task %p (requred %u), put to queue\n", mlx5_task,
				      mlx5_task->num_reqs);
			STAILQ_INSERT_TAIL(&dev->nomem, mlx5_task, link);
			return 0;
		}
		return rc;
	}

	if (spdk_unlikely(dev->recovering)) {
		STAILQ_INSERT_TAIL(&dev->nomem, mlx5_task, link);
		return 0;
	}

	return accel_mlx5_task_process(mlx5_task);
}

static inline void
accel_mlx5_task_clear_mkey_cache(struct accel_mlx5_task *task)
{
	struct spdk_accel_task *next_task;

	if (task->base.cached_lkey) {
		*task->base.cached_lkey = 0;
	}
	/* Clear the mkey cache when the decrypt task is merged into check CRC. */
	if (task->mlx5_opcode == ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C) {
		next_task = TAILQ_NEXT(&task->base, seq_link);
		if (next_task->cached_lkey) {
			*next_task->cached_lkey = 0;
		}
	}
}


static inline void
accel_mlx5_resubmit_recover_tasks(struct accel_mlx5_dev *dev)
{
	struct accel_mlx5_task *task, *tmp;
	int rc;

	assert(dev->recovering == false);
	/* There is a good chance that WR failure was caused by invalidated cached mkey.
	 * Clear the cache to avoid new failures. We clear cache for all tasks here,
	 * including ones queued in nomem queue. This may clear mkeys that are still
	 * valid, but it is better than triggering another QP recovery. Caches will be
	 * refilled quickly.
	 */
	STAILQ_FOREACH(task, &dev->nomem, link) {
		accel_mlx5_task_clear_mkey_cache(task);
	}

	STAILQ_FOREACH_SAFE(task, &dev->recover, link, tmp) {
		STAILQ_REMOVE_HEAD(&dev->recover, link);
		SPDK_DEBUGLOG(accel_mlx5,
			      "Resubmit task %p: num_ops %u, num_reqs %u, submitted_reqs %u, completed_reqs %u\n",
			      task, task->num_ops, task->num_reqs, task->num_submitted_reqs, task->num_completed_reqs);

		/* It is safe to restart an inplace CRC32C task because it does not modify data */
		if (task->flags.bits.inplace && task->mlx5_opcode != ACCEL_MLX5_OPC_CRC32C) {
			/* @todo: We can't restart inplace task from the beggining without data corruption.
			 * For now we fail such tasks. Better solution should be implemented later.
			 */
			SPDK_ERRLOG("Recovery of inplace tasks is not supported\n");
			accel_mlx5_task_complete(task, -EIO);
		}

		/* Restart the task from the beginning */
		accel_mlx5_task_release_mkeys(task);

		/* Clear mkey cache */
		accel_mlx5_task_clear_mkey_cache(task);

		rc = accel_mlx5_task_init(task, dev);
		if (spdk_likely(!rc)) {
			rc = accel_mlx5_task_process(task);
		}

		if (spdk_unlikely(rc)) {
			if (rc == -ENOMEM) {
				SPDK_DEBUGLOG(accel_mlx5, "no reqs to handle new task %p (required %u), put to queue\n",
					      task, task->num_reqs);
				STAILQ_INSERT_TAIL(&dev->nomem, task, link);
				continue;
			}

			accel_mlx5_task_complete(task, rc);
		}
	}
}

static void accel_mlx5_recover_dev(struct accel_mlx5_dev *dev);

static int
accel_mlx5_recover_dev_poller(void *arg) {
	struct accel_mlx5_dev *dev = arg;

	spdk_poller_unregister(&dev->recover_poller);
	accel_mlx5_recover_dev(dev);
	return SPDK_POLLER_BUSY;
}

static void
accel_mlx5_recover_dev(struct accel_mlx5_dev *dev)
{
	struct spdk_mlx5_cq_attr mlx5_cq_attr = {};
	struct spdk_mlx5_qp_attr mlx5_qp_attr = {};
	int rc;

	SPDK_NOTICELOG("Recovering device %p, qp %p, core %u\n",
		       dev, dev->dma_qp, spdk_env_get_current_core());
	if (dev->dma_qp) {
		spdk_mlx5_dma_qp_destroy(dev->dma_qp);
		dev->dma_qp = NULL;
	}

	mlx5_cq_attr.cqe_cnt = g_accel_mlx5.qp_size;
	mlx5_cq_attr.cqe_size = 64;
	mlx5_cq_attr.cq_context = dev;

	mlx5_qp_attr.cap.max_send_wr = g_accel_mlx5.qp_size;
	mlx5_qp_attr.cap.max_recv_wr = 0;
	mlx5_qp_attr.cap.max_send_sge = ACCEL_MLX5_MAX_SGE;
	mlx5_qp_attr.cap.max_inline_data = sizeof(struct ibv_sge) * ACCEL_MLX5_MAX_SGE;
	mlx5_qp_attr.siglast = g_accel_mlx5.siglast;

	rc = spdk_mlx5_dma_qp_create(dev->pd_ref, &mlx5_cq_attr, &mlx5_qp_attr, dev, &dev->dma_qp);
	if (rc) {
		SPDK_ERRLOG("Failed to create mlx5 dma QP, rc %d. Retry in %d usec\n",
			    rc, ACCEL_MLX5_RECOVER_POLLER_PERIOD_US);
		dev->recover_poller = SPDK_POLLER_REGISTER(accel_mlx5_recover_dev_poller, dev,
							   ACCEL_MLX5_RECOVER_POLLER_PERIOD_US);
		/* @todo: It may be worth resubmitting tasks to another device if we have one */
		return;
	}

	dev->recovering = false;
	accel_mlx5_resubmit_recover_tasks(dev);
	return;
}

static struct accel_mlx5_sig_key_wrapper *
get_mkey_from_sigerr_wc(struct accel_mlx5_dev *dev, struct spdk_mlx5_cq_completion *wc)
{
	struct accel_mlx5_sig_key_wrapper find;

	assert(wc->status == MLX5_CQE_SYNDROME_SIGERR);
	find.mkey = wc->mkey;

	return RB_FIND(mkeys_tree, dev->sig_mkey_tree_ref, &find);
}

static inline void
accel_mlx5_process_cpls_siglast(struct accel_mlx5_dev *dev, struct spdk_mlx5_cq_completion *wc, int reaped)
{
	struct accel_mlx5_task *task, *signaled_task, *task_tmp;
	struct accel_mlx5_wrid *wr;
	uint32_t completed;
	uint32_t num_completed_ops;
	int i, rc;

	for (i = 0; i < reaped; i++) {
		if (spdk_unlikely(wc[i].status == MLX5_CQE_SYNDROME_SIGERR)) {
			struct accel_mlx5_sig_key_wrapper *mkey;

			mkey = get_mkey_from_sigerr_wc(dev, &wc[i]);

			mkey->sigerr_count++;
			mkey->sigerr = true;
			continue;
		}

		wr = (struct accel_mlx5_wrid *)wc[i].wr_id;

		if (spdk_unlikely(!wr)) {
			/* That is unsignaled completion with error, just ignore it */
			continue;
		}

		switch (wr->wrid) {
		case ACCEL_MLX5_WRID_WRITE:
			signaled_task = SPDK_CONTAINEROF(wr, struct accel_mlx5_task, write_wrid);
			STAILQ_FOREACH_SAFE(task, &dev->in_hw, link, task_tmp) {
				STAILQ_REMOVE_HEAD(&dev->in_hw, link);
				assert(task->num_submitted_reqs > task->num_completed_reqs);
				completed = task->num_submitted_reqs - task->num_completed_reqs;
				num_completed_ops = 0;
				switch (task->mlx5_opcode) {
				case ACCEL_MLX5_OPC_COPY:
					num_completed_ops = completed;
					break;
				case ACCEL_MLX5_OPC_CRYPTO:
					num_completed_ops = completed * 2;
					break;
				case ACCEL_MLX5_OPC_CRC32C:
				case ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C:
					num_completed_ops = completed * 2;
					if (spdk_unlikely(task->psv->bits.error)) {
						num_completed_ops++;
						if (wc[i].status == IBV_WC_SUCCESS) {
							task->psv->bits.error = 0;
						}
					}
					break;
				}
				assert(num_completed_ops != 0);
				assert(dev->reqs_submitted >= num_completed_ops);
				dev->reqs_submitted -= num_completed_ops;
				if (spdk_unlikely(wc[i].status) && (signaled_task == task)) {
					/* We may have X unsignaled tasks queued in in_hw, if an error happens,
					 * then HW generates completions for every unsignaled WQE.
					 * If cpl with error generated for task X+1 then we still can process
					 * previous tasks as usual */
					if (wc[i].status != IBV_WC_WR_FLUSH_ERR) {
						SPDK_WARNLOG("RDMA: qp %p, task %p, WC status %d, core %u\n",
							     dev->dma_qp, task, wc[i].status,
							     spdk_env_get_current_core());
					} else {
						SPDK_DEBUGLOG(accel_mlx5,
							      "RDMA: qp %p, task %p, WC status %d, core %u\n",
							      dev->dma_qp, task, wc[i].status,
							      spdk_env_get_current_core());
					}

					dev->recovering = true;
					STAILQ_INSERT_TAIL(&dev->recover, task, link);
					if (dev->reqs_submitted == 0) {
						assert(STAILQ_EMPTY(&dev->in_hw));
						accel_mlx5_recover_dev(dev);
					}

					break;
				}

				task->num_completed_reqs += completed;
				SPDK_DEBUGLOG(accel_mlx5, "task %p, remaining %u\n", task,
					      task->num_reqs - task->num_completed_reqs);
				if (task->num_completed_reqs == task->num_reqs) {
					accel_mlx5_task_complete(task, 0);
				} else if (task->num_completed_reqs == task->num_submitted_reqs) {
					assert(task->num_submitted_reqs < task->num_reqs);
					rc = accel_mlx5_task_continue(task);
					if (spdk_unlikely(rc)) {
						if (rc != -ENOMEM) {
							accel_mlx5_task_complete(task, rc);
						}
					}
				}
				if (task == signaled_task) {
					break;
				}
			}
			break;
		}
	}

}

static inline void
accel_mlx5_process_cpls(struct accel_mlx5_dev *dev, struct spdk_mlx5_cq_completion *wc, int reaped)
{
	struct accel_mlx5_task *task;
	struct accel_mlx5_wrid *wr;
	uint32_t completed;
	uint32_t num_completed_ops;
	int i, rc;

	for (i = 0; i < reaped; i++) {
		if (spdk_unlikely(wc[i].status == MLX5_CQE_SYNDROME_SIGERR)) {
			struct accel_mlx5_sig_key_wrapper *mkey;

			mkey = get_mkey_from_sigerr_wc(dev, &wc[i]);

			mkey->sigerr_count++;
			mkey->sigerr = true;
			continue;
		}

		wr = (struct accel_mlx5_wrid *)wc[i].wr_id;

		if (spdk_unlikely(!wr)) {
			/* That is unsignaled completion with error, just ignore it */
			continue;
		}

		switch (wr->wrid) {
		case ACCEL_MLX5_WRID_WRITE:
			task = SPDK_CONTAINEROF(wr, struct accel_mlx5_task, write_wrid);
			assert(task == STAILQ_FIRST(&dev->in_hw) && "submission mismatch");
			STAILQ_REMOVE_HEAD(&dev->in_hw, link);
			assert(task->num_submitted_reqs > task->num_completed_reqs);
			completed = task->num_submitted_reqs - task->num_completed_reqs;
			num_completed_ops = 0;
			switch (task->mlx5_opcode) {
			case ACCEL_MLX5_OPC_COPY:
				num_completed_ops = completed;
				break;
			case ACCEL_MLX5_OPC_CRYPTO:
				num_completed_ops = completed * 2;
				break;
			case ACCEL_MLX5_OPC_CRC32C:
			case ACCEL_MLX5_OPC_CRYPTO_AND_CRC32C:
				num_completed_ops = completed * 2;
				if (spdk_unlikely(task->psv->bits.error)) {
					num_completed_ops++;
					if (wc[i].status == IBV_WC_SUCCESS) {
						task->psv->bits.error = 0;
					}
				}
				break;
			}
			assert(num_completed_ops != 0);
			assert(dev->reqs_submitted >= num_completed_ops);
			dev->reqs_submitted -= num_completed_ops;

			if (spdk_unlikely(wc[i].status)) {
				if (wc[i].status != IBV_WC_WR_FLUSH_ERR) {
					SPDK_WARNLOG("RDMA: qp %p, task %p, WC status %d, core %u\n",
						     dev->dma_qp, task, wc[i].status, spdk_env_get_current_core());
				} else {
					SPDK_DEBUGLOG(accel_mlx5, "RDMA: qp %p, task %p, WC status %d, core %u\n",
						      dev->dma_qp, task, wc[i].status, spdk_env_get_current_core());
				}

				/*
				 * Check if SIGERR CQE happened before the WQE error or flush.
				 * It is needed to recover the affected MKey and PSV properly.
				 */
				accel_mlx5_task_check_sigerr(task);

				dev->recovering = true;
				STAILQ_INSERT_TAIL(&dev->recover, task, link);
				if (dev->reqs_submitted == 0) {
					assert(STAILQ_EMPTY(&dev->in_hw));
					accel_mlx5_recover_dev(dev);
				}

				continue;
			}

			task->num_completed_reqs += completed;
			SPDK_DEBUGLOG(accel_mlx5, "task %p, remaining %u\n", task,
				      task->num_reqs - task->num_completed_reqs);
			if (task->num_completed_reqs == task->num_reqs) {
				accel_mlx5_task_complete(task, 0);
			} else if (task->num_completed_reqs == task->num_submitted_reqs) {
				assert(task->num_submitted_reqs < task->num_reqs);
				rc = accel_mlx5_task_continue(task);
				if (spdk_unlikely(rc)) {
					if (rc != -ENOMEM) {
						accel_mlx5_task_complete(task, rc);
					}
				}
			}
			break;
		}
	}
}

static inline int64_t
accel_mlx5_poll_cq(struct accel_mlx5_dev *dev)
{
	struct spdk_mlx5_cq_completion wc[ACCEL_MLX5_MAX_WC];
	int reaped;

	dev->stats.polls++;
	reaped = spdk_mlx5_dma_qp_poll_completions(dev->dma_qp, wc, ACCEL_MLX5_MAX_WC);
	if (spdk_unlikely(reaped < 0)) {
		SPDK_ERRLOG("Error polling CQ! (%d): %s\n", errno, spdk_strerror(errno));
		return reaped;
	} else if (reaped == 0) {
		dev->stats.idle_polls++;
		return 0;
	}

	dev->stats.completions += reaped;
	SPDK_DEBUGLOG(accel_mlx5, "Reaped %d cpls on dev %s\n", reaped,
		      dev->dma_qp->qp.verbs_qp->context->device->name);

	g_accel_mlx5_process_cpl_fn(dev, wc, reaped);

	return reaped;
}

static inline void
accel_mlx5_complete_merged_tasks(struct accel_mlx5_dev *dev)
{
	struct accel_mlx5_task *task, *tmp;

	STAILQ_FOREACH_SAFE(task, &dev->merged, link, tmp) {
		STAILQ_REMOVE_HEAD(&dev->merged, link);
		accel_mlx5_task_complete(task, 0);
	}
}

static inline void
accel_mlx5_resubmit_nomem_tasks(struct accel_mlx5_dev *dev)
{
	struct accel_mlx5_task *task, *tmp;
	int rc;

	if (spdk_unlikely(dev->recovering)) {
		return;
	}

	STAILQ_FOREACH_SAFE(task, &dev->nomem, link, tmp) {
		STAILQ_REMOVE_HEAD(&dev->nomem, link);
		rc = accel_mlx5_task_continue(task);
		if (rc) {
			if (rc == -ENOMEM) {
				break;
			} else {
				accel_mlx5_task_complete(task, rc);
			}
		}
	}
}

static int
accel_mlx5_poller(void *ctx)
{
	struct accel_mlx5_io_channel *ch = ctx;
	struct accel_mlx5_dev *dev;

	int64_t completions = 0, rc;
	uint32_t i;

	for (i = 0; i < ch->num_devs; i++) {
		dev = &ch->devs[i];
		if (dev->reqs_submitted) {
			rc = accel_mlx5_poll_cq(dev);
			if (spdk_unlikely(rc < 0)) {
				SPDK_ERRLOG("Error %"PRId64" on CQ, dev %s\n", rc,
					    dev->dma_qp->qp.verbs_qp->context->device->name);
			}
			completions += rc;
		}
		if (!STAILQ_EMPTY(&dev->merged)) {
			accel_mlx5_complete_merged_tasks(dev);
		}
		if (!STAILQ_EMPTY(&dev->nomem)) {
			accel_mlx5_resubmit_nomem_tasks(dev);
		}
	}

	return !!completions;
}

static bool
accel_mlx5_supports_opcode(enum accel_opcode opc)
{
	assert(g_accel_mlx5.enabled);

	switch (opc) {
	case ACCEL_OPC_COPY:
		return true;
	case ACCEL_OPC_ENCRYPT:
	case ACCEL_OPC_DECRYPT:
		return g_accel_mlx5.crypto_supported;
	case ACCEL_OPC_CRC32C:
	case ACCEL_OPC_COPY_CRC32C:
	case ACCEL_OPC_CHECK_CRC32C:
		return g_accel_mlx5.enable_crc;
	default:
		return false;
	}
}

static struct spdk_io_channel *
accel_mlx5_get_io_channel(void)
{
	assert(g_accel_mlx5.enabled);
	return spdk_get_io_channel(&g_accel_mlx5);
}

static void
accel_mlx5_destroy_cb(void *io_device, void *ctx_buf)
{
	struct accel_mlx5_io_channel *ch = ctx_buf;
	struct accel_mlx5_dev *dev;
	uint32_t i;

	spdk_poller_unregister(&ch->poller);
	for (i = 0; i < ch->num_devs; i++) {
		dev = &ch->devs[i];
		if (dev->dma_qp) {
			spdk_mlx5_dma_qp_destroy(dev->dma_qp);
		}
		spdk_poller_unregister(&dev->recover_poller);
		spdk_rdma_utils_free_mem_map(&dev->mmap);
		SPDK_NOTICELOG("Accel mlx5 device %p channel %p stats: tasks %lu, umrs %lu, "
			       "rdma_writes %lu, polls %lu, idle_polls %lu, completions %lu\n",
			       dev, ch, dev->stats.tasks, dev->stats.umrs,
			       dev->stats.rdma_writes, dev->stats.polls,
			       dev->stats.idle_polls, dev->stats.completions);
	}
	free(ch->devs);
}

static int
accel_mlx5_create_cb(void *io_device, void *ctx_buf)
{
	struct accel_mlx5_io_channel *ch = ctx_buf;
	struct accel_mlx5_crypto_dev_ctx *dev_ctx;
	struct accel_mlx5_dev *dev;
	uint32_t i;
	int rc;

	ch->devs = calloc(g_accel_mlx5.num_crypto_ctxs, sizeof(*ch->devs));
	if (!ch->devs) {
		SPDK_ERRLOG("Memory allocation failed\n");
		return -ENOMEM;
	}

	for (i = 0; i < g_accel_mlx5.num_crypto_ctxs; i++) {
		dev_ctx = &g_accel_mlx5.crypto_ctxs[i];
		dev = &ch->devs[i];
		dev->mkey_pool_ref = dev_ctx->mkey_pool;
		dev->sig_mkey_pool_ref = dev_ctx->sig_mkey_pool;
		dev->psv_pool_ref = dev_ctx->psv_pool;
		dev->pd_ref = dev_ctx->pd;
		dev->domain_ref = dev_ctx->domain.domain;
		dev->crypto_multi_block = dev_ctx->crypto_multi_block;
		dev->sig_mkey_tree_ref = &dev_ctx->sig_mkey_tree;
		ch->num_devs++;

		struct spdk_mlx5_cq_attr mlx5_cq_attr = {};
		mlx5_cq_attr.cqe_cnt = g_accel_mlx5.qp_size;
		mlx5_cq_attr.cqe_size = 64;
		mlx5_cq_attr.cq_context = dev;

		struct spdk_mlx5_qp_attr mlx5_qp_attr = {};
		mlx5_qp_attr.cap.max_send_wr = g_accel_mlx5.qp_size;
		mlx5_qp_attr.cap.max_recv_wr = 0;
		mlx5_qp_attr.cap.max_send_sge = ACCEL_MLX5_MAX_SGE;
		mlx5_qp_attr.cap.max_inline_data = sizeof(struct ibv_sge) * ACCEL_MLX5_MAX_SGE;
		mlx5_qp_attr.siglast = g_accel_mlx5.siglast;

		rc = spdk_mlx5_dma_qp_create(dev->pd_ref, &mlx5_cq_attr, &mlx5_qp_attr, dev, &dev->dma_qp);
		if (rc) {
			SPDK_ERRLOG("Failed to create mlx5 dma QP, rc %d\n", rc);
			goto err_out;
		}

		STAILQ_INIT(&dev->nomem);
		STAILQ_INIT(&dev->in_hw);
		STAILQ_INIT(&dev->recover);
		STAILQ_INIT(&dev->merged);
		dev->max_reqs = g_accel_mlx5.qp_size;
		dev->mmap = spdk_rdma_utils_create_mem_map(dev->pd_ref, NULL,
			    IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
		if (!dev->mmap) {
			SPDK_ERRLOG("Failed to create memory map\n");
			goto err_out;
		}
	}

	ch->poller = SPDK_POLLER_REGISTER(accel_mlx5_poller, ch, 0);

	return 0;

err_out:
	accel_mlx5_destroy_cb(&g_accel_mlx5, ctx_buf);
	return rc;
}

void
accel_mlx5_get_default_attr(struct accel_mlx5_attr *attr)
{
	assert(attr);

	memset(attr, 0, sizeof(*attr));

	attr->qp_size = ACCEL_MLX5_QP_SIZE;
	attr->num_requests = ACCEL_MLX5_NUM_MKEYS;
	attr->split_mb_blocks = 0;
	attr->siglast = false;
	attr->enable_crc = false;
	attr->merge = false;
}

static void
accel_mlx5_allowed_crypto_devs_free(void)
{
	size_t i;

	if (!g_accel_mlx5.allowed_crypto_devs || !g_accel_mlx5.allowed_crypto_devs_count) {
		return;
	}

	for (i = 0; i < g_accel_mlx5.allowed_crypto_devs_count; i++) {
		free(g_accel_mlx5.allowed_crypto_devs[i]);
	}
	free(g_accel_mlx5.allowed_crypto_devs);
	g_accel_mlx5.allowed_crypto_devs = NULL;
	g_accel_mlx5.allowed_crypto_devs_count = 0;
}

static int
accel_mlx5_allowed_crypto_devs_parse(const char *allowed_crypto_devs)
{
	char *str, *tmp, *tok;
	size_t devs_count = 0;

	str = strdup(allowed_crypto_devs);
	if (!str) {
		return -ENOMEM;
	}

	accel_mlx5_allowed_crypto_devs_free();

	tmp = str;
	while ((tmp = strchr(tmp, ',')) != NULL) {
		tmp++;
		devs_count++;
	}
	devs_count++;

	g_accel_mlx5.allowed_crypto_devs = calloc(devs_count, sizeof(char *));
	if (!g_accel_mlx5.allowed_crypto_devs) {
		free(str);
		return -ENOMEM;
	}

	devs_count = 0;
	tok = strtok(str, ",");
	while (tok) {
		g_accel_mlx5.allowed_crypto_devs[devs_count] = strdup(tok);
		if (!g_accel_mlx5.allowed_crypto_devs[devs_count]) {
			free(str);
			accel_mlx5_allowed_crypto_devs_free();
			return -ENOMEM;
		}
		tok = strtok(NULL, ",");
		devs_count++;
		g_accel_mlx5.allowed_crypto_devs_count++;
	}

	free(str);

	return 0;
}

int
accel_mlx5_enable(struct accel_mlx5_attr *attr)
{
	if (attr) {
		/* Copy attributes */
		g_accel_mlx5.qp_size = attr->qp_size;
		g_accel_mlx5.num_requests = attr->num_requests;
		g_accel_mlx5.split_mb_blocks = attr->split_mb_blocks;
		g_accel_mlx5.siglast= attr->siglast;
		g_accel_mlx5.enable_crc = attr->enable_crc;
		g_accel_mlx5.merge = attr->merge;

		if (attr->allowed_crypto_devs) {
			int rc;

			rc = accel_mlx5_allowed_crypto_devs_parse(attr->allowed_crypto_devs);
			if (rc) {
				return rc;
			}
			rc = spdk_mlx5_crypto_devs_allow((const char * const *)g_accel_mlx5.allowed_crypto_devs,
							 g_accel_mlx5.allowed_crypto_devs_count);
			if (rc) {
				accel_mlx5_allowed_crypto_devs_free();
				return rc;
			}
		}
	}

	g_accel_mlx5.enabled = true;

	return 0;
}

static void
accel_mlx5_mkeys_release(struct spdk_mempool *mkey_pool, struct spdk_mlx5_indirect_mkey **mkeys, uint32_t num_mkeys)
{
	uint32_t i, num_mkeys_in_pool;

	for (i = 0; i < num_mkeys; i++) {
		if (mkeys[i]) {
			spdk_mlx5_destroy_indirect_mkey(mkeys[i]);
			mkeys[i] = NULL;
		}
	}

	free(mkeys);

	if (!mkey_pool) {
		return;
	}

	num_mkeys_in_pool = spdk_mempool_count(mkey_pool);
	if (num_mkeys_in_pool != num_mkeys) {
		SPDK_ERRLOG("Expected %u reqs in the pool, but got only %u\n", num_mkeys, num_mkeys_in_pool);
	}
	spdk_mempool_free(mkey_pool);
}

static void
accel_mlx5_crypto_mkeys_release(struct accel_mlx5_crypto_dev_ctx *dev_ctx)
{
	if (dev_ctx->mkeys) {
		accel_mlx5_mkeys_release(dev_ctx->mkey_pool, dev_ctx->mkeys, dev_ctx->num_mkeys);
	}
}

static void
accel_mlx5_sig_mkey_remove_from_tree(struct spdk_mempool *mp, void *cb_arg, void *obj, unsigned obj_idx)
{
	struct accel_mlx5_crypto_dev_ctx *dev_ctx = cb_arg;
	struct accel_mlx5_sig_key_wrapper *wrapper = obj;

	RB_REMOVE(mkeys_tree, &dev_ctx->sig_mkey_tree, wrapper);
}

static void
accel_mlx5_sig_mkeys_release(struct accel_mlx5_crypto_dev_ctx *dev_ctx)
{
	if (dev_ctx->sig_mkeys) {
		spdk_mempool_obj_iter(dev_ctx->sig_mkey_pool, accel_mlx5_sig_mkey_remove_from_tree, dev_ctx);
		accel_mlx5_mkeys_release(dev_ctx->sig_mkey_pool, dev_ctx->sig_mkeys, dev_ctx->num_mkeys);
	}
}

static void
accel_mlx5_psvs_release(struct accel_mlx5_crypto_dev_ctx *dev_ctx)
{
	uint32_t i, num_psvs, num_psvs_in_pool;

	if (!dev_ctx->psvs) {
		return;
	}

	num_psvs = dev_ctx->num_mkeys;

	for (i = 0; i < num_psvs; i++) {
		if (dev_ctx->psvs[i]) {
			spdk_mlx5_destroy_psv(dev_ctx->psvs[i]);
			dev_ctx->psvs[i] = NULL;
		}
	}

	if (!dev_ctx->psv_pool) {
		return;
	}

	num_psvs_in_pool = spdk_mempool_count(dev_ctx->psv_pool);
	if (num_psvs_in_pool != num_psvs) {
		SPDK_ERRLOG("Expected %u reqs in the pool, but got only %u\n", num_psvs, num_psvs_in_pool);
	}
	spdk_mempool_free(dev_ctx->psv_pool);
}

static void
accel_mlx5_free_resources(void)
{
	uint32_t i;

	for (i = 0; i < g_accel_mlx5.num_crypto_ctxs; i++) {
		accel_mlx5_crypto_mkeys_release(&g_accel_mlx5.crypto_ctxs[i]);
		accel_mlx5_sig_mkeys_release(&g_accel_mlx5.crypto_ctxs[i]);
		accel_mlx5_psvs_release(&g_accel_mlx5.crypto_ctxs[i]);
		spdk_memory_domain_destroy(g_accel_mlx5.crypto_ctxs[i].domain.domain);
		spdk_rdma_utils_put_pd(g_accel_mlx5.crypto_ctxs[i].pd);
	}

	free(g_accel_mlx5.crypto_ctxs);
	g_accel_mlx5.crypto_ctxs = NULL;
}

static void
accel_mlx5_deinit_cb(void *ctx)
{
	accel_mlx5_free_resources();
	spdk_accel_module_finish();
}

static void
accel_mlx5_deinit(void *ctx)
{
	if (g_accel_mlx5.allowed_crypto_devs) {
		accel_mlx5_allowed_crypto_devs_free();
		spdk_mlx5_crypto_devs_allow(NULL, 0);
	}
	if (g_accel_mlx5.crypto_ctxs) {
		spdk_io_device_unregister(&g_accel_mlx5, accel_mlx5_deinit_cb);
	} else {
		spdk_accel_module_finish();
	}
}

static void
accel_mlx5_set_crypto_mkey_in_pool(struct spdk_mempool *mp, void *cb_arg, void *_mkey, unsigned obj_idx)
{
	struct accel_mlx5_crypto_key_wrapper *wrapper = _mkey;
	struct accel_mlx5_crypto_dev_ctx *dev_ctx = cb_arg;

	assert(obj_idx < dev_ctx->num_mkeys);
	assert(dev_ctx->mkeys[obj_idx] != NULL);
	wrapper->mkey = dev_ctx->mkeys[obj_idx]->mkey;
}

static int
accel_mlx5_configure_mkey(struct spdk_mlx5_indirect_mkey **_mkey, struct ibv_pd *pd, bool crypto, bool signature)
{
	struct spdk_mlx5_indirect_mkey *mkey;
	struct mlx5_devx_mkey_attr mkey_attr = {};
	struct spdk_mlx5_relaxed_ordering_caps caps = {};
	uint32_t bsf_size = 0;
	int rc;

	rc = spdk_mlx5_query_relaxed_ordering_caps(pd->context, &caps);
	if (rc) {
		SPDK_ERRLOG("Failed to get PCI relaxed ordering caps, rc %d\n", rc);
		return rc;
	}

	mkey_attr.addr = 0;
	mkey_attr.size = 0;
	mkey_attr.log_entity_size = 0;
	mkey_attr.relaxed_ordering_write = caps.relaxed_ordering_write;
	mkey_attr.relaxed_ordering_read = caps.relaxed_ordering_read;
	mkey_attr.sg_count = 0;
	mkey_attr.sg = NULL;
	if (crypto) {
		mkey_attr.crypto_en = true;
		bsf_size += 64;
	}
	if (signature) {
		bsf_size += 64;
	}
	mkey_attr.bsf_octowords = bsf_size / 16;

	mkey = spdk_mlx5_create_indirect_mkey(pd, &mkey_attr);
	if (!mkey) {
		SPDK_ERRLOG("Failed to create mkey on dev %s\n", pd->context->device->name);
		return -EINVAL;
	}
	*_mkey = mkey;

	return 0;
}

static int
accel_mlx5_fill_pool_name(struct accel_mlx5_crypto_dev_ctx *dev_ctx, char *suffix, char *pool_name,
			  size_t pool_name_size)
{
	/* Compiler may produce a warning like
	 * warning: ‘%s’ directive output may be truncated writing up to 63 bytes into a region of size 21
	 * [-Wformat-truncation=]
	 * That is expected and that is due to ibv device name is 64 bytes while DPDK mempool API allows
	 * name to be max 32 bytes.
	 * To suppress this warning check the value returned by snprintf */
	return snprintf(pool_name, pool_name_size, "accel_mlx5_%s_%s", suffix, dev_ctx->context->device->name);
}

static int
accel_mlx5_crypto_ctx_mkeys_create(struct accel_mlx5_crypto_dev_ctx *dev_ctx)
{
	char pool_name[32];
	uint32_t i;
	bool enable_signature = false;
	int rc;

	dev_ctx->mkeys = calloc(dev_ctx->num_mkeys, (sizeof(struct spdk_mlx5_indirect_mkey *)));
	if (!dev_ctx->mkeys) {
		SPDK_ERRLOG("Failed to alloc mkeys array\n");
		return -ENOMEM;
	}
	for (i = 0; i < dev_ctx->num_mkeys; i++) {
		rc = accel_mlx5_configure_mkey(&dev_ctx->mkeys[i], dev_ctx->pd, g_accel_mlx5.crypto_supported,
					       enable_signature);
		if (rc) {
			return rc;
		}
	}

	rc = accel_mlx5_fill_pool_name(dev_ctx, "crypto", pool_name, sizeof(pool_name));
	if (rc < 0) {
		assert(0);
		return -EINVAL;
	}
	uint32_t cache_size = dev_ctx->num_mkeys / 4 * 3 / spdk_env_get_core_count();
	SPDK_NOTICELOG("Total pool size %u, cache size %u\n", dev_ctx->num_mkeys, cache_size);
	dev_ctx->mkey_pool = spdk_mempool_create_ctor(pool_name, dev_ctx->num_mkeys,
						      sizeof(struct accel_mlx5_crypto_key_wrapper),
						      cache_size, SPDK_ENV_SOCKET_ID_ANY,
						      accel_mlx5_set_crypto_mkey_in_pool, dev_ctx);
	if (!dev_ctx->mkey_pool) {
		SPDK_ERRLOG("Failed to create memory pool\n");
		return -ENOMEM;
	}

	return 0;
}

static void
accel_mlx5_set_sig_mkey_in_pool(struct spdk_mempool *mp, void *cb_arg, void *_mkey, unsigned obj_idx)
{
	struct accel_mlx5_sig_key_wrapper *wrapper = _mkey;
	struct accel_mlx5_crypto_dev_ctx *dev_ctx = cb_arg;

	assert(obj_idx < dev_ctx->num_mkeys);
	assert(dev_ctx->sig_mkeys[obj_idx] != NULL);

	wrapper->mkey = dev_ctx->sig_mkeys[obj_idx]->mkey;
	wrapper->sigerr_count = 1;
	wrapper->sigerr = false;

	RB_INSERT(mkeys_tree, &dev_ctx->sig_mkey_tree, wrapper);
}

static int
accel_mlx5_sig_ctx_mkeys_create(struct accel_mlx5_crypto_dev_ctx *dev_ctx)
{
	char pool_name[32];
	uint32_t i;
	bool enable_crypto = g_accel_mlx5.merge && g_accel_mlx5.crypto_supported;
	bool enable_signature = true;
	int rc;

	dev_ctx->sig_mkeys = calloc(dev_ctx->num_mkeys, (sizeof(struct spdk_mlx5_indirect_mkey *)));
	if (!dev_ctx->sig_mkeys) {
		SPDK_ERRLOG("Failed to alloc mkeys array\n");
		return -ENOMEM;
	}
	for (i = 0; i < dev_ctx->num_mkeys; i++) {
		rc = accel_mlx5_configure_mkey(&dev_ctx->sig_mkeys[i], dev_ctx->pd, enable_crypto, enable_signature);
		if (rc) {
			return rc;
		}
	}

	rc = accel_mlx5_fill_pool_name(dev_ctx, "sig", pool_name, sizeof(pool_name));
	if (rc < 0) {
		assert(0);
		return -EINVAL;
	}
	uint32_t cache_size = dev_ctx->num_mkeys / 4 * 3 / spdk_env_get_core_count();
	SPDK_NOTICELOG("Total sig MKey pool size %u, cache size %u\n", dev_ctx->num_mkeys, cache_size);
	dev_ctx->sig_mkey_pool = spdk_mempool_create_ctor(pool_name, dev_ctx->num_mkeys,
							  sizeof(struct accel_mlx5_sig_key_wrapper),
							  cache_size, SPDK_ENV_SOCKET_ID_ANY,
							  accel_mlx5_set_sig_mkey_in_pool, dev_ctx);
	if (!dev_ctx->sig_mkey_pool) {
		SPDK_ERRLOG("Failed to create memory pool\n");
		return -ENOMEM;
	}

	return 0;
}

static void
accel_mlx5_set_psv_in_pool(struct spdk_mempool *mp, void *cb_arg, void *_psv, unsigned obj_idx)
{
	struct accel_mlx5_psv_wrapper *wrapper = _psv;
	struct accel_mlx5_crypto_dev_ctx *dev_ctx = cb_arg;

	assert(obj_idx < dev_ctx->num_mkeys);
	assert(dev_ctx->psvs[obj_idx] != NULL);
	memset(wrapper, 0, sizeof(*wrapper));
	wrapper->psv_index = dev_ctx->psvs[obj_idx]->index;
}

static int
accel_mlx5_psvs_create(struct accel_mlx5_crypto_dev_ctx *dev_ctx)
{
	char pool_name[32];
	uint32_t i;
	uint32_t num_psvs = dev_ctx->num_mkeys;
	int rc;

	dev_ctx->psvs = calloc(num_psvs, (sizeof(struct spdk_mlx5_psv *)));
	if (!dev_ctx->psvs) {
		SPDK_ERRLOG("Failed to alloc PSVs array\n");
		return -ENOMEM;
	}
	for (i = 0; i < num_psvs; i++) {
		dev_ctx->psvs[i] = spdk_mlx5_create_psv(dev_ctx->pd);
		if (!dev_ctx->psvs[i]) {
			SPDK_ERRLOG("Failed to create PSV on dev %s\n", dev_ctx->context->device->name);
			return -EINVAL;
		}
	}

	rc = accel_mlx5_fill_pool_name(dev_ctx, "psv", pool_name, sizeof(pool_name));
	if (rc < 0) {
		assert(0);
		return -EINVAL;
	}
	uint32_t cache_size = dev_ctx->num_mkeys / 4 * 3 / spdk_env_get_core_count();
	SPDK_NOTICELOG("Total PSV pool size %u, cache size %u\n", num_psvs, cache_size);
	dev_ctx->psv_pool = spdk_mempool_create_ctor(pool_name, num_psvs,
						     sizeof(struct accel_mlx5_psv_wrapper),
						     cache_size, SPDK_ENV_SOCKET_ID_ANY,
						     accel_mlx5_set_psv_in_pool, dev_ctx);
	if (!dev_ctx->psv_pool) {
		SPDK_ERRLOG("Failed to create memory pool\n");
		return -ENOMEM;
	}

	return 0;
}

static struct ibv_context *
accel_mlx5_rdma_get_mlx5_dev(struct ibv_context **devices, int num_devs)
{
	struct ibv_device_attr dev_attr = {};
	int rc, i;

	for (i = 0; i < num_devs; i++) {
		rc = ibv_query_device(devices[i], &dev_attr);
		if (rc) {
			continue;
		}
		if (dev_attr.vendor_id == SPDK_MLX5_VENDOR_ID_MELLANOX) {
			return devices[i];
		}
	}
	return NULL;
}

static int
accel_mlx5_init_mem_op(void)
{
	struct accel_mlx5_crypto_dev_ctx *crypto_dev_ctx;
	struct accel_mlx5_cryptodev_memory_domain *domain;
	struct ibv_context **rdma_devs, *dev;
	struct spdk_memory_domain_ctx ctx;
	struct ibv_pd *pd;
	int num_devs = 0, rc;

	rdma_devs = rdma_get_devices(&num_devs);
	if (!rdma_devs || !num_devs) {
		return -ENODEV;
	}

	dev = accel_mlx5_rdma_get_mlx5_dev(rdma_devs, num_devs);
	if (!dev) {
		SPDK_ERRLOG("No mlx devices found\n");
		rc = -ENODEV;
		goto cleanup;
	}

	g_accel_mlx5.crypto_ctxs = calloc(1, sizeof(*g_accel_mlx5.crypto_ctxs));
	if (!g_accel_mlx5.crypto_ctxs) {
		SPDK_ERRLOG("Memory allocation failed\n");
		rc = -ENOMEM;
		goto cleanup;
	}

	crypto_dev_ctx = &g_accel_mlx5.crypto_ctxs[0];

	pd = spdk_rdma_utils_get_pd(dev);
	if (!pd) {
		SPDK_ERRLOG("Failed to get PD for context %p, dev %s\n", dev, dev->device->name);
		rc = -EINVAL;
		goto cleanup;
	}
	crypto_dev_ctx->context = dev;
	crypto_dev_ctx->pd = pd;

	domain = &g_accel_mlx5.crypto_ctxs[0].domain;
	domain->rdma_ctx.size = sizeof(domain->rdma_ctx);
	domain->rdma_ctx.ibv_pd = (void *) pd;
	ctx.size = sizeof(ctx);
	ctx.user_ctx = &domain->rdma_ctx;

	rc = spdk_memory_domain_create(&domain->domain, SPDK_DMA_DEVICE_TYPE_RDMA, &ctx,
				       SPDK_RDMA_DMA_DEVICE);
	if (rc) {
		goto cleanup;
	}

	g_accel_mlx5.num_crypto_ctxs = 1;

	SPDK_NOTICELOG("Accel framework mlx5 initialized\n");
	spdk_io_device_register(&g_accel_mlx5, accel_mlx5_create_cb, accel_mlx5_destroy_cb,
				sizeof(struct accel_mlx5_io_channel), "accel_mlx5");

	return 0;

cleanup:
	rdma_free_devices(rdma_devs);
	accel_mlx5_free_resources();

	return rc;
}

static int
accel_mlx5_init(void)
{
	struct accel_mlx5_crypto_dev_ctx *crypto_dev_ctx;
	struct accel_mlx5_cryptodev_memory_domain *domain;
	struct ibv_context **rdma_devs, *dev;
	struct spdk_memory_domain_ctx ctx;
	struct ibv_pd *pd;
	struct spdk_mlx5_crypto_caps crypto_caps;
	int num_devs = 0, rc = 0, i;

	if (!g_accel_mlx5.enabled) {
		return -EINVAL;
	}

	if (g_accel_mlx5.siglast) {
		g_accel_mlx5_process_cpl_fn = accel_mlx5_process_cpls_siglast;
	} else {
		g_accel_mlx5_process_cpl_fn = accel_mlx5_process_cpls;
	}

	rdma_devs = spdk_mlx5_crypto_devs_get(&num_devs);
	if (!rdma_devs || !num_devs) {
		if (g_accel_mlx5.allowed_crypto_devs) {
			SPDK_WARNLOG("No crypto devs found, only memory operations will be supported\n");
		} else {
			SPDK_NOTICELOG("No crypto devs found, only memory operations will be supported\n");
		}
		g_accel_mlx5.crypto_supported = false;
		return accel_mlx5_init_mem_op();
	} else {
		g_accel_mlx5.crypto_supported = true;
	}

	g_accel_mlx5.crypto_ctxs = calloc(num_devs, sizeof(*g_accel_mlx5.crypto_ctxs));
	if (!g_accel_mlx5.crypto_ctxs) {
		SPDK_ERRLOG("Memory allocation failed\n");
		rc = -ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < num_devs; i++) {
		crypto_dev_ctx = &g_accel_mlx5.crypto_ctxs[i];
		dev = rdma_devs[i];
		memset(&crypto_caps, 0, sizeof(crypto_caps));
		rc = spdk_mlx5_query_crypto_caps(dev, &crypto_caps);
		if (rc) {
			SPDK_ERRLOG("Failed to get aes_xts caps, dev %s\n", dev->device->name);
			goto cleanup;
		}
		SPDK_NOTICELOG("Crypto dev %s, aes_xts: single block %d, mb_be %d, mb_le %d, inc_64 %d\n",
			       dev->device->name,
			       crypto_caps.single_block_le_tweak,
			       crypto_caps.multi_block_be_tweak,
			       crypto_caps.multi_block_le_tweak,
			       crypto_caps.tweak_inc_64);

		pd = spdk_rdma_utils_get_pd(dev);
		if (!pd) {
			SPDK_ERRLOG("Failed to get PD for context %p, dev %s\n", dev, dev->device->name);
			rc = -EINVAL;
			goto cleanup;
		}
		crypto_dev_ctx->context = dev;
		crypto_dev_ctx->pd = pd;
		RB_INIT(&crypto_dev_ctx->sig_mkey_tree);
		crypto_dev_ctx->num_mkeys = g_accel_mlx5.num_requests;
		rc = accel_mlx5_crypto_ctx_mkeys_create(crypto_dev_ctx);
		if (rc) {
			goto cleanup;
		}

		if (g_accel_mlx5.enable_crc) {
			rc = accel_mlx5_sig_ctx_mkeys_create(crypto_dev_ctx);
			if (rc) {
				goto cleanup;
			}
			rc = accel_mlx5_psvs_create(crypto_dev_ctx);
			if (rc) {
				goto cleanup;
			}
		}

		domain = &g_accel_mlx5.crypto_ctxs[i].domain;
		domain->rdma_ctx.size = sizeof(domain->rdma_ctx);
		domain->rdma_ctx.ibv_pd = (void *) pd;
		ctx.size = sizeof(ctx);
		ctx.user_ctx = &domain->rdma_ctx;

		rc = spdk_memory_domain_create(&domain->domain, SPDK_DMA_DEVICE_TYPE_RDMA, &ctx,
					       SPDK_RDMA_DMA_DEVICE);
		if (rc) {
			goto cleanup;
		}

		/* Explicitly disabled by default */
		crypto_dev_ctx->crypto_multi_block = false;
		if (crypto_caps.multi_block_be_tweak) {
			/* TODO: multi_block LE tweak will be checked later once LE BSF is fixed */
			crypto_dev_ctx->crypto_multi_block = true;
		} else if (g_accel_mlx5.split_mb_blocks) {
			SPDK_WARNLOG("\"split_mb_block\" is set but dev %s doesn't support multi block crypto\n",
				     dev->device->name);
		}

		g_accel_mlx5.num_crypto_ctxs++;
	}

	SPDK_NOTICELOG("Accel framework mlx5 initialized, found %d devices.\n", num_devs);
	spdk_io_device_register(&g_accel_mlx5, accel_mlx5_create_cb, accel_mlx5_destroy_cb,
				sizeof(struct accel_mlx5_io_channel), "accel_mlx5");

	spdk_mlx5_crypto_devs_release(rdma_devs);

	return rc;

cleanup:
	spdk_mlx5_crypto_devs_release(rdma_devs);
	accel_mlx5_free_resources();

	return rc;
}

static void
accel_mlx5_write_config_json(struct spdk_json_write_ctx *w)
{
	if (g_accel_mlx5.enabled) {
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "method", "mlx5_scan_accel_module");
		spdk_json_write_named_object_begin(w, "params");
		spdk_json_write_named_uint16(w, "qp_size", g_accel_mlx5.qp_size);
		spdk_json_write_named_uint32(w, "num_requests", g_accel_mlx5.num_requests);
		spdk_json_write_named_bool(w, "enable_crc", g_accel_mlx5.enable_crc);
		spdk_json_write_named_bool(w, "merge", g_accel_mlx5.merge);
		spdk_json_write_object_end(w);
		spdk_json_write_object_end(w);
	}
}

static size_t
accel_mlx5_get_ctx_size(void)
{
	return sizeof(struct accel_mlx5_task);
}

static int
accel_mlx5_crypto_key_init(struct spdk_accel_crypto_key *key)
{
	struct spdk_mlx5_crypto_dek_create_attr attr = {};
	struct spdk_mlx5_crypto_keytag *keytag;
	int rc;

	if (!key || !key->key || !key->key2 || !key->key_size || !key->key2_size) {
		return -EINVAL;
	}

	attr.dek = calloc(1, key->key_size + key->key2_size);
	if (!attr.dek) {
		return -ENOMEM;
	}

	memcpy(attr.dek, key->key, key->key_size);
	memcpy(attr.dek + key->key_size, key->key2, key->key2_size);
	attr.dek_len = key->key_size + key->key2_size;
	attr.tweak_upper_lba = key->tweak_mode == SPDK_ACCEL_CRYPTO_TWEAK_MODE_INCR_512_UPPER_LBA;

	rc = spdk_mlx5_crypto_keytag_create(&attr, &keytag);
	spdk_memset_s(attr.dek, attr.dek_len, 0, attr.dek_len);
	free(attr.dek);
	if (rc) {
		SPDK_ERRLOG("Failed to create a keytag, rc %d\n", rc);
		return rc;
	}

	key->priv = keytag;

	return 0;
}

static void
accel_mlx5_crypto_key_deinit(struct spdk_accel_crypto_key *key)
{
	if (!key || key->module_if != &g_accel_mlx5.module || !key->priv) {
		return;
	}

	spdk_mlx5_crypto_keytag_destroy(key->priv);
}
static int
accel_mlx5_get_memory_domains(struct spdk_memory_domain **domains, int array_size)
{
	int i, size;

	if (!domains || !array_size) {
		return (int)g_accel_mlx5.num_crypto_ctxs;
	}

	size = spdk_min(array_size, (int)g_accel_mlx5.num_crypto_ctxs);

	for (i = 0; i < size; i++) {
		domains[i] = g_accel_mlx5.crypto_ctxs[i].domain.domain;
	}

	return (int)g_accel_mlx5.num_crypto_ctxs;
}

static bool accel_mlx5_crypto_supports_tweak_mode(enum spdk_accel_crypto_tweak_mode tweak_mode)
{
	struct ibv_context **devs;
	struct spdk_mlx5_crypto_caps dev_caps;
	int devs_count, i, rc;
	bool upper_lba_supported;

	if (!g_accel_mlx5.crypto_supported) {
		return false;
	}

	if (tweak_mode == SPDK_ACCEL_CRYPTO_TWEAK_MODE_SIMPLE_LBA) {
		return true;
	}
	if (tweak_mode == SPDK_ACCEL_CRYPTO_TWEAK_MODE_INCR_512_UPPER_LBA) {
		upper_lba_supported = true;
		devs = spdk_mlx5_crypto_devs_get(&devs_count);
		assert(devs);
		for (i = 0; i < devs_count; i++) {
			rc = spdk_mlx5_query_crypto_caps(devs[i], &dev_caps);
			if (rc || !dev_caps.tweak_inc_64) {
				upper_lba_supported = false;
				break;
			}
		}
		spdk_mlx5_crypto_devs_release(devs);
		return upper_lba_supported;
	}

	return false;
}

static struct accel_mlx5_module g_accel_mlx5 = {
	.module = {
		.module_init		= accel_mlx5_init,
		.module_fini		= accel_mlx5_deinit,
		.write_config_json	= accel_mlx5_write_config_json,
		.get_ctx_size		= accel_mlx5_get_ctx_size,
		.name			= "mlx5",
		.supports_opcode	= accel_mlx5_supports_opcode,
		.get_io_channel		= accel_mlx5_get_io_channel,
		.submit_tasks		= accel_mlx5_submit_tasks,
		.crypto_key_init	= accel_mlx5_crypto_key_init,
		.crypto_key_deinit	= accel_mlx5_crypto_key_deinit,
		.get_memory_domains	= accel_mlx5_get_memory_domains,
		.crypto_supports_tweak_mode	= accel_mlx5_crypto_supports_tweak_mode,
	},
	.enabled = true,
	.qp_size = ACCEL_MLX5_QP_SIZE,
	.num_requests = ACCEL_MLX5_NUM_MKEYS,
	.split_mb_blocks = 0
};

SPDK_ACCEL_MODULE_REGISTER(mlx5, &g_accel_mlx5.module)
SPDK_LOG_REGISTER_COMPONENT(accel_mlx5)
