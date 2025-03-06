/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2021 Intel Corporation.
 *   Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk_internal/cunit.h"
#include "spdk_internal/mock.h"
#include "common/lib/ut_multithread.c"
#include "accel/mlx5/accel_mlx5.c"

DEFINE_STUB_V(spdk_memory_domain_destroy, (struct spdk_memory_domain *domain));
DEFINE_STUB(spdk_memory_domain_get_dma_device_id, const char *, (struct spdk_memory_domain *domain),
	    "UT_DMA");
DEFINE_STUB(spdk_memory_domain_get_dma_device_type, enum spdk_dma_device_type,
	    (struct spdk_memory_domain *domain), SPDK_DMA_DEVICE_TYPE_RDMA);
DEFINE_STUB(spdk_memory_domain_update_notification_subscribe, int, (void *user_ctx,
		spdk_memory_domain_update_notification_cb user_cb), 0);
DEFINE_STUB(spdk_mlx5_crypto_keytag_create, int, (struct spdk_mlx5_crypto_dek_create_attr *attr,
		struct spdk_mlx5_crypto_keytag **out), 0);
DEFINE_STUB_V(spdk_mlx5_crypto_keytag_destroy, (struct spdk_mlx5_crypto_keytag *keytag));
DEFINE_STUB(spdk_mlx5_cq_poll_completions, int, (struct spdk_mlx5_cq *cq,
		struct spdk_mlx5_cq_completion *comp, union spdk_mlx5_cq_error *err, int max_completions), 0);
DEFINE_STUB(spdk_mlx5_qp_create, int, (struct ibv_pd *pd, struct spdk_mlx5_cq *cq,
				       struct spdk_mlx5_qp_attr *qp_attr, struct spdk_mlx5_qp **qp_out), 0);
DEFINE_STUB(spdk_mlx5_qp_get_verbs_qp, struct ibv_qp *, (struct spdk_mlx5_qp *qp), 0);
DEFINE_STUB(spdk_mlx5_qp_connect_loopback, int, (struct spdk_mlx5_qp *qp), 0);
DEFINE_STUB_V(spdk_mlx5_qp_destroy, (struct spdk_mlx5_qp *qp));
DEFINE_STUB_V(spdk_mlx5_qp_complete_send, (struct spdk_mlx5_qp *qp));
DEFINE_STUB(spdk_mlx5_cq_create, int, (struct ibv_pd *pd, struct spdk_mlx5_cq_attr *cq_attr,
				       struct spdk_mlx5_cq **cq_out), 0);
DEFINE_STUB(spdk_mlx5_cq_destroy, int, (struct spdk_mlx5_cq *cq), 0);
DEFINE_STUB(spdk_mlx5_qp_set_error_state, int, (struct spdk_mlx5_qp *qp), 0);
DEFINE_STUB(spdk_memory_domain_update_notification_unsubscribe, int, (void *user_ctx), 0);
DEFINE_STUB(spdk_mlx5_crypto_devs_allow, int, (const char *const dev_names[], size_t devs_count),
	    0);
DEFINE_STUB_V(spdk_accel_module_finish, (void));
DEFINE_STUB(spdk_mlx5_crypto_devs_get, struct ibv_context **, (int *dev_num), NULL);
DEFINE_STUB(spdk_mlx5_device_query_caps, int, (struct ibv_context *context,
		struct spdk_mlx5_device_caps *caps), 0);
DEFINE_STUB_V(spdk_mlx5_crypto_devs_release, (struct ibv_context **rdma_devs));
DEFINE_STUB(spdk_memory_domain_translate_data, int, (struct spdk_memory_domain *src_domain,
		void *src_domain_ctx,
		struct spdk_memory_domain *dst_domain, struct spdk_memory_domain_translation_ctx *dst_domain_ctx,
		void *addr, size_t len, struct spdk_memory_domain_translation_result *result), 0);
DEFINE_STUB(spdk_memory_domain_transfer_data, int, (struct spdk_memory_domain *dst_domain,
		void *dst_domain_ctx,
		struct iovec *dst_iov, uint32_t dst_iovcnt,
		struct spdk_memory_domain *src_domain, void *src_domain_ctx,
		struct iovec *src_iov, uint32_t src_iovcnt,
		struct spdk_memory_domain_translation_result *src_translation,
		spdk_memory_domain_data_cpl_cb cpl_cb, void *cpl_cb_arg), 0);
DEFINE_STUB(spdk_rdma_utils_get_translation, int, (struct spdk_rdma_utils_mem_map *map,
		void *address,
		size_t length, struct spdk_rdma_utils_memory_translation *translation), 0);
DEFINE_STUB(spdk_mlx5_crypto_get_dek_data, int, (struct spdk_mlx5_crypto_keytag *keytag,
		struct ibv_pd *pd, struct spdk_mlx5_crypto_dek_data *data), 0);
DEFINE_STUB(spdk_mlx5_umr_configure_crypto, int, (struct spdk_mlx5_qp *qp,
		struct spdk_mlx5_umr_attr *umr_attr,
		struct spdk_mlx5_umr_crypto_attr *crypto_attr, uint64_t wr_id, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_umr_configure, int, (struct spdk_mlx5_qp *qp,
		struct spdk_mlx5_umr_attr *umr_attr, uint64_t wr_id, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_qp_rdma_read, int, (struct spdk_mlx5_qp *qp, struct ibv_sge *sge,
		uint32_t sge_count,
		uint64_t dstaddr, uint32_t rkey, uint64_t wrid, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_qp_rdma_write, int, (struct spdk_mlx5_qp *qp, struct ibv_sge *sge,
		uint32_t sge_count,
		uint64_t dstaddr, uint32_t rkey, uint64_t wrid, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_umr_configure_trans_sig_crypto, int, (struct spdk_mlx5_qp *qp,
		struct spdk_mlx5_umr_attr *umr_attr,
		struct spdk_mlx5_umr_trans_sig_attr *sig_attr,
		struct spdk_mlx5_umr_crypto_attr *crypto_attr,
		uint64_t wr_id, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_qp_set_psv, int, (struct spdk_mlx5_qp *dv_qp, uint32_t psv_index,
					uint64_t transient_signature, uint64_t wr_id, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_umr_configure_trans_sig, int, (struct spdk_mlx5_qp *qp,
		struct spdk_mlx5_umr_attr *umr_attr, struct spdk_mlx5_umr_trans_sig_attr *sig_attr,
		uint64_t wr_id, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_umr_configure_block_sig, int, (struct spdk_mlx5_qp *qp,
		struct spdk_mlx5_umr_attr *umr_attr, struct spdk_mlx5_umr_block_sig_attr *sig_attr,
		uint64_t wr_id, uint32_t flags), 0);
DEFINE_STUB(spdk_mlx5_mkey_pool_init, int, (struct spdk_mlx5_mkey_pool_param *params,
		struct ibv_pd *pd), 0);
DEFINE_STUB(spdk_mlx5_mkey_pool_destroy, int, (uint32_t flags, struct ibv_pd *pd), 0);
DEFINE_STUB(spdk_mlx5_mkey_pool_get_ref, struct spdk_mlx5_mkey_pool *, (struct ibv_pd *pd,
		uint32_t flags), NULL);
DEFINE_STUB_V(spdk_mlx5_mkey_pool_put_ref, (struct spdk_mlx5_mkey_pool *pool));
DEFINE_STUB(spdk_mlx5_mkey_pool_get_bulk, int, (struct spdk_mlx5_mkey_pool *pool,
		struct spdk_mlx5_mkey_pool_obj **mkeys,
		uint32_t mkeys_count), 0);
DEFINE_STUB_V(spdk_mlx5_mkey_pool_put_bulk, (struct spdk_mlx5_mkey_pool *pool,
		struct spdk_mlx5_mkey_pool_obj **mkeys,
		uint32_t mkeys_count));
DEFINE_STUB(spdk_mlx5_mkey_pool_get, struct spdk_mlx5_mkey_pool_obj *,
	    (struct spdk_mlx5_mkey_pool *pool), 0);
DEFINE_STUB_V(spdk_mlx5_mkey_pool_put, (struct spdk_mlx5_mkey_pool *pool,
					struct spdk_mlx5_mkey_pool_obj *mkey));
DEFINE_STUB_V(spdk_mlx5_mkey_pool_obj_get_ref, (struct spdk_mlx5_mkey_pool_obj *mkey));
DEFINE_STUB_V(spdk_mlx5_mkey_pool_obj_put_ref, (struct spdk_mlx5_mkey_pool_obj *mkey));
DEFINE_STUB(spdk_mlx5_mkey_pool_find_mkey_by_id, struct spdk_mlx5_mkey_pool_obj *, (void *ch,
		uint32_t mkey_id), NULL);
DEFINE_STUB(spdk_mlx5_psv_pool_create, struct spdk_mlx5_psv_pool *,
	    (struct spdk_mlx5_psv_pool_param *params, struct ibv_pd *pd), NULL);
DEFINE_STUB_V(spdk_mlx5_psv_pool_destroy, (struct spdk_mlx5_psv_pool *pool));
DEFINE_STUB(spdk_mlx5_psv_pool_get, struct spdk_mlx5_psv_pool_obj *,
	    (struct spdk_mlx5_psv_pool *pool), NULL);
DEFINE_STUB_V(spdk_mlx5_psv_pool_put, (struct spdk_mlx5_psv_pool_obj **ppsv));

DEFINE_STUB_V(spdk_mlx5_umr_implementer_register, (bool registered));
DEFINE_STUB_V(spdk_accel_module_list_add, (struct spdk_accel_module_if *accel_module));
DEFINE_STUB_V(spdk_accel_sequence_continue, (struct spdk_accel_sequence *seq));
DEFINE_STUB(spdk_accel_get_memory_domain, struct spdk_memory_domain *, (void), NULL);
DEFINE_STUB(spdk_accel_get_opcode_name, const char *, (enum spdk_accel_opcode opcode), "pewpew");
DEFINE_STUB_V(spdk_accel_driver_register, (struct spdk_accel_driver *driver));
DEFINE_STUB(spdk_accel_set_driver, int, (const char *name), 0);
DEFINE_STUB(spdk_rdma_utils_get_memory_domain, struct spdk_memory_domain *,
	    (struct ibv_pd *pd, enum spdk_dma_device_type type), NULL);
DEFINE_STUB(spdk_rdma_utils_put_memory_domain, int, (struct spdk_memory_domain *domain), 0);
DEFINE_STUB(spdk_rdma_utils_create_mem_map, struct spdk_rdma_utils_mem_map *, (struct ibv_pd *pd,
		struct spdk_nvme_rdma_hooks *hooks, uint32_t accel_flags), 0);
DEFINE_STUB_V(spdk_rdma_utils_free_mem_map, (struct spdk_rdma_utils_mem_map **_map));
DEFINE_STUB(spdk_rdma_utils_get_pd, struct ibv_pd *, (struct ibv_context *context), NULL);
DEFINE_STUB_V(spdk_rdma_utils_put_pd, (struct ibv_pd *pd));

struct spdk_memory_domain {
	size_t user_ctx_size;
	void *user_ctx;
};

void *
spdk_memory_domain_get_user_context(struct spdk_memory_domain *domain, size_t *ctx_size)
{
	SPDK_CU_ASSERT_FATAL(domain != NULL);

	if (!domain->user_ctx_size) {
		return NULL;
	}

	*ctx_size = domain->user_ctx_size;
	return domain->user_ctx;
}

struct accel_io_channel {
	STAILQ_HEAD(, spdk_accel_task)	task_pool;
};

struct spdk_accel_sequence {
	TAILQ_HEAD(, spdk_accel_task)	tasks;
};

struct spdk_accel_task *
spdk_accel_sequence_first_task(struct spdk_accel_sequence *seq)
{
	return TAILQ_FIRST(&seq->tasks);
}

struct spdk_accel_task *
spdk_accel_sequence_next_task(struct spdk_accel_task *task)
{
	return TAILQ_NEXT(task, seq_link);
}

void
spdk_accel_task_complete(struct spdk_accel_task *accel_task, int status)
{
	SPDK_CU_ASSERT_FATAL(accel_task->cb_fn != NULL);
	SPDK_CU_ASSERT_FATAL(accel_task->cb_arg != NULL);

	accel_task->cb_fn(accel_task->cb_arg, status);
}

static int
test_setup(void)
{
	return 0;
}

static int
test_cleanup(void)
{
	return 0;
}

static void
test_accel_mlx5_get_copy_task_count(void)
{
	uint32_t num_ops;

	struct iovec src1[1] = { { .iov_len = 4096 } };
	struct iovec dst1[1] = { { .iov_len = 4096 } };
	num_ops = accel_mlx5_get_copy_task_count(src1, SPDK_COUNTOF(src1), dst1, SPDK_COUNTOF(dst1));
	CU_ASSERT(num_ops == 1);

	struct iovec src2[1] = { { .iov_len = 8192 } };
	struct iovec dst2[2] = { { .iov_len = 4096 }, { .iov_len = 4096 } };
	num_ops = accel_mlx5_get_copy_task_count(src2, SPDK_COUNTOF(src2), dst2, SPDK_COUNTOF(dst2));
	CU_ASSERT(num_ops == 2);

	struct iovec src3[2] = { { .iov_len = 4096 }, { .iov_len = 4096 } };
	struct iovec dst3[1] = { { .iov_len = 8192 } };
	num_ops = accel_mlx5_get_copy_task_count(src3, SPDK_COUNTOF(src3), dst3, SPDK_COUNTOF(dst3));
	CU_ASSERT(num_ops == 1);

	struct iovec src4[16] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }
	};
	struct iovec dst4[1] = { { .iov_len = 4096 } };
	num_ops = accel_mlx5_get_copy_task_count(src4, SPDK_COUNTOF(src4), dst4, SPDK_COUNTOF(dst4));
	CU_ASSERT(num_ops == 1);

	struct iovec src5[17] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 128 },
		{ .iov_len = 128 }
	};
	struct iovec dst5[1] = { { .iov_len = 4096 } };
	num_ops = accel_mlx5_get_copy_task_count(src5, SPDK_COUNTOF(src5), dst5, SPDK_COUNTOF(dst5));
	CU_ASSERT(num_ops == 2);

	struct iovec src6[18] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 128 },
		{ .iov_len = 128 }, { .iov_len = 4096 }
	};
	struct iovec dst6[2] = { { .iov_len = 4096 }, { .iov_len = 4096 } };
	num_ops = accel_mlx5_get_copy_task_count(src6, SPDK_COUNTOF(src6), dst6, SPDK_COUNTOF(dst6));
	CU_ASSERT(num_ops == 3);

	struct iovec src7[32] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }
	};
	struct iovec dst7[2] = { { .iov_len = 4096 }, { .iov_len = 4096 } };
	num_ops = accel_mlx5_get_copy_task_count(src7, SPDK_COUNTOF(src7), dst7, SPDK_COUNTOF(dst7));
	CU_ASSERT(num_ops == 2);

	struct iovec src8[17] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 4096 }
	};
	struct iovec dst8[3] = { { .iov_len = 4096 }, { .iov_len = 2048 }, { .iov_len = 2048 } };
	num_ops = accel_mlx5_get_copy_task_count(src8, SPDK_COUNTOF(src8), dst8, SPDK_COUNTOF(dst8));
	CU_ASSERT(num_ops == 3);

	struct iovec src9[16] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 4352 }
	};
	struct iovec dst9[3] = { { .iov_len = 4096 }, { .iov_len = 2048 }, { .iov_len = 2048 } };
	num_ops = accel_mlx5_get_copy_task_count(src9, SPDK_COUNTOF(src9), dst9, SPDK_COUNTOF(dst9));
	CU_ASSERT(num_ops == 3);

	struct iovec src10[16] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 4352 }
	};
	struct iovec dst10[4] = { { .iov_len = 4096 }, { .iov_len = 2048 }, { .iov_len = 1792 }, { .iov_len = 256 } };
	num_ops = accel_mlx5_get_copy_task_count(src10, SPDK_COUNTOF(src10), dst10, SPDK_COUNTOF(dst10));
	CU_ASSERT(num_ops == 4);

	struct iovec src11[18] = { { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 4096 }, { .iov_len = 4096 }
	};
	struct iovec dst11[4] = { { .iov_len = 4096 }, { .iov_len = 2048 }, { .iov_len = 1792 }, { .iov_len = 4352 } };
	num_ops = accel_mlx5_get_copy_task_count(src11, SPDK_COUNTOF(src11), dst11, SPDK_COUNTOF(dst11));
	CU_ASSERT(num_ops == 4);

	struct iovec src12[24] = { { .iov_len = 512 }, { .iov_len = 512 }, { .iov_len = 512 }, { .iov_len = 512 },
		{ .iov_len = 512 }, { .iov_len = 512 }, { .iov_len = 512 }, { .iov_len = 512 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 },
		{ .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }, { .iov_len = 256 }
	};
	struct iovec dst12[2] = { { .iov_len = 4096 }, { .iov_len = 4096 } };
	num_ops = accel_mlx5_get_copy_task_count(src12, SPDK_COUNTOF(src12), dst12, SPDK_COUNTOF(dst12));
	CU_ASSERT(num_ops == 2);
}

static void
ut_accel_copy_task_done(void *cb_arg, int status)
{
	bool *copy_done = cb_arg;

	CU_ASSERT(status == 0);
	*copy_done = true;
}

static void
test_accel_mlx5_driver_examine_sequence(void)
{
	struct ibv_pd pd;
	struct spdk_memory_domain_rdma_ctx domain_rdma_ctx = {
		.ibv_pd = &pd,
		.size = sizeof(struct spdk_memory_domain_rdma_ctx),
	};
	struct spdk_memory_domain domain = {
		.user_ctx = &domain_rdma_ctx,
		.user_ctx_size = sizeof(struct spdk_memory_domain_rdma_ctx),
	};
	struct accel_mlx5_dev_ctx mlx5_dev_ctx = { .pd = &pd, .domain = &domain, };
	struct accel_mlx5_io_channel mlx5_ch;
	struct spdk_accel_sequence seq = { .tasks = TAILQ_HEAD_INITIALIZER(seq.tasks), };
	struct accel_mlx5_task copy_mlx5_task, dif_mlx5_task;
	struct spdk_accel_task *copy_task = &copy_mlx5_task.base, *dif_task = &dif_mlx5_task.base;
	bool g_qp_per_domain;
	bool copy_done;
	int rc;

	g_qp_per_domain = g_accel_mlx5.attr.qp_per_domain;
	g_accel_mlx5.attr.qp_per_domain = true;

	mlx5_ch.devs = calloc(1, sizeof(struct accel_mlx5_dev));
	SPDK_CU_ASSERT_FATAL(mlx5_ch.devs != NULL);

	mlx5_ch.num_devs = 1;
	mlx5_ch.devs[0].dev_ctx = &mlx5_dev_ctx;

	copy_task->dst_domain = copy_task->src_domain = &domain;
	copy_task->cb_fn = ut_accel_copy_task_done;
	copy_task->cb_arg = &copy_done;
	copy_task->op_code = SPDK_ACCEL_OPC_COPY;

	dif_mlx5_task.mlx5_opcode = ACCEL_MLX5_OPC_DIF_GENERATE_COPY;
	dif_task->src_domain = (struct spdk_memory_domain *)0xABADBABE;
	dif_task->dst_domain = (struct spdk_memory_domain *)0xCAFEBABE;
	dif_task->op_code = SPDK_ACCEL_OPC_DIF_GENERATE_COPY;

	TAILQ_INSERT_TAIL(&seq.tasks, dif_task, seq_link);
	TAILQ_INSERT_TAIL(&seq.tasks, copy_task, seq_link);
	copy_done = false;

	rc = accel_mlx5_driver_examine_sequence(&seq, &mlx5_ch);
	CU_ASSERT(rc == 0);
	CU_ASSERT(dif_mlx5_task.mlx5_opcode == ACCEL_MLX5_OPC_DIF_GENERATE_COPY_MKEY);
	CU_ASSERT(dif_task->src_domain == (struct spdk_memory_domain *)0xABADBABE);
	CU_ASSERT(dif_task->dst_domain == &domain);
	CU_ASSERT(dif_mlx5_task.md_in_umr == false);
	CU_ASSERT(copy_done == true);

	dif_mlx5_task.mlx5_opcode = ACCEL_MLX5_OPC_DIF_GENERATE_COPY;
	dif_task->src_domain = (struct spdk_memory_domain *)0xABADBABE;
	dif_task->dst_domain = (struct spdk_memory_domain *)0xCAFEBABE;

	TAILQ_REMOVE(&seq.tasks, copy_task, seq_link);
	TAILQ_INSERT_HEAD(&seq.tasks, copy_task, seq_link);
	copy_done = false;

	rc = accel_mlx5_driver_examine_sequence(&seq, &mlx5_ch);
	CU_ASSERT(rc == 0);
	CU_ASSERT(dif_mlx5_task.mlx5_opcode == ACCEL_MLX5_OPC_DIF_GENERATE_COPY_MKEY);
	CU_ASSERT(dif_task->src_domain == (struct spdk_memory_domain *)0xABADBABE);
	CU_ASSERT(dif_task->dst_domain == &domain);
	CU_ASSERT(dif_mlx5_task.md_in_umr == true);
	CU_ASSERT(copy_done == true);

	dif_mlx5_task.mlx5_opcode = ACCEL_MLX5_OPC_DIF_VERIFY_COPY;
	dif_task->src_domain = (struct spdk_memory_domain *)0xABADBABE;
	dif_task->dst_domain = (struct spdk_memory_domain *)0xCAFEBABE;
	dif_task->op_code = SPDK_ACCEL_OPC_DIF_VERIFY_COPY;

	copy_done = false;

	rc = accel_mlx5_driver_examine_sequence(&seq, &mlx5_ch);
	CU_ASSERT(rc == 0);
	CU_ASSERT(dif_mlx5_task.mlx5_opcode == ACCEL_MLX5_OPC_DIF_VERIFY_COPY_MKEY);
	CU_ASSERT(dif_task->src_domain == (struct spdk_memory_domain *)0xCAFEBABE);
	CU_ASSERT(dif_task->dst_domain == &domain);
	CU_ASSERT(dif_mlx5_task.md_in_umr == false);
	CU_ASSERT(copy_done == true);

	dif_mlx5_task.mlx5_opcode = ACCEL_MLX5_OPC_DIF_VERIFY_COPY;
	dif_task->src_domain = (struct spdk_memory_domain *)0xABADBABE;
	dif_task->dst_domain = (struct spdk_memory_domain *)0xCAFEBABE;

	TAILQ_REMOVE(&seq.tasks, copy_task, seq_link);
	TAILQ_INSERT_TAIL(&seq.tasks, copy_task, seq_link);
	copy_done = false;

	rc = accel_mlx5_driver_examine_sequence(&seq, &mlx5_ch);
	CU_ASSERT(rc == 0);
	CU_ASSERT(dif_mlx5_task.mlx5_opcode == ACCEL_MLX5_OPC_DIF_VERIFY_COPY_MKEY);
	CU_ASSERT(dif_task->src_domain == (struct spdk_memory_domain *)0xABADBABE);
	CU_ASSERT(dif_task->dst_domain == &domain);
	CU_ASSERT(dif_mlx5_task.md_in_umr == true);
	CU_ASSERT(copy_done == true);

	free(mlx5_ch.devs);

	g_accel_mlx5.attr.qp_per_domain = g_qp_per_domain;
}

int
main(int argc, char **argv)
{
	CU_pSuite	suite = NULL;
	unsigned int	num_failures;

	CU_set_error_action(CUEA_ABORT);
	CU_initialize_registry();

	suite = CU_add_suite("accel_mlx5", test_setup, test_cleanup);
	CU_ADD_TEST(suite, test_accel_mlx5_get_copy_task_count);
	CU_ADD_TEST(suite, test_accel_mlx5_driver_examine_sequence);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	num_failures = CU_get_number_of_failures();
	CU_cleanup_registry();

	return num_failures;
}
