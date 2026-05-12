/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk_internal/cunit.h"
#include "common/lib/test_env.c"
#include "unit/lib/json_mock.c"
#include "dma/dma.c"

static bool g_memory_domain_pull_called;
static bool g_memory_domain_push_called;
static bool g_memory_domain_translate_called;
static bool g_memory_domain_memzero_called;
static int g_memory_domain_cb_rc = 123;

static void
test_memory_domain_data_cpl_cb(void *ctx, int rc)
{
}

static int
test_memory_domain_pull_data_cb(struct spdk_memory_domain *src_device,
				void *src_device_ctx, struct iovec *src_iov, uint32_t src_iovcnt, struct iovec *dst_iov,
				uint32_t dst_iovcnt, spdk_memory_domain_data_cpl_cb cpl_cb, void *cpl_cb_arg)
{
	g_memory_domain_pull_called = true;

	return g_memory_domain_cb_rc;
}

static int
test_memory_domain_push_data_cb(struct spdk_memory_domain *dst_domain,
				void *dst_domain_ctx,
				struct iovec *dst_iov, uint32_t dst_iovcnt, struct iovec *src_iov, uint32_t src_iovcnt,
				spdk_memory_domain_data_cpl_cb cpl_cb, void *cpl_cb_arg)
{
	g_memory_domain_push_called = true;

	return g_memory_domain_cb_rc;
}

static int
test_memory_domain_translate_memory_cb(struct spdk_memory_domain *src_device, void *src_device_ctx,
				       struct spdk_memory_domain *dst_device, struct spdk_memory_domain_translation_ctx *dst_device_ctx,
				       void *addr, size_t len, struct spdk_memory_domain_translation_result *result)
{
	g_memory_domain_translate_called = true;

	return g_memory_domain_cb_rc;
}

static int
test_memory_domain_memzero_cb(struct spdk_memory_domain *src_domain, void *src_domain_ctx,
			      struct iovec *iov, uint32_t iovcnt, spdk_memory_domain_data_cpl_cb cpl_cb, void *cpl_cb_arg)
{
	g_memory_domain_memzero_called = true;

	return g_memory_domain_cb_rc;
}

static void
test_dma(void)
{
	void *test_ibv_pd = (void *)0xdeadbeaf;
	struct iovec src_iov = {}, dst_iov = {};
	struct spdk_memory_domain *domain = NULL, *domain_2 = NULL, *domain_3 = NULL;
	struct spdk_memory_domain *system_domain;
	struct spdk_memory_domain_rdma_ctx rdma_ctx = { .ibv_pd = test_ibv_pd };
	struct spdk_memory_domain_ctx memory_domain_ctx = { .user_ctx = &rdma_ctx };
	struct spdk_memory_domain_ctx *stored_memory_domain_ctx;
	struct spdk_memory_domain_translation_result translation_result;
	const char *id;
	int rc;

	system_domain = spdk_memory_domain_get_system_domain();
	CU_ASSERT(system_domain != NULL);

	/* Create memory domain. No device ptr, expect fail */
	rc = spdk_memory_domain_create(NULL, SPDK_DMA_DEVICE_TYPE_RDMA, &memory_domain_ctx, "test");
	CU_ASSERT(rc != 0);

	/* Create memory domain. ctx with zero size, expect fail */
	memory_domain_ctx.size = 0;
	rc = spdk_memory_domain_create(&domain, SPDK_DMA_DEVICE_TYPE_RDMA, &memory_domain_ctx, "test");
	CU_ASSERT(rc != 0);

	/* Create memory domain. expect pass */
	memory_domain_ctx.size = sizeof(memory_domain_ctx);
	rc = spdk_memory_domain_create(&domain, SPDK_DMA_DEVICE_TYPE_RDMA, &memory_domain_ctx, "test");
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(domain != NULL);

	/* Get context. Expect pass */
	stored_memory_domain_ctx = spdk_memory_domain_get_context(domain);
	SPDK_CU_ASSERT_FATAL(stored_memory_domain_ctx != NULL);
	CU_ASSERT(stored_memory_domain_ctx->user_ctx == &rdma_ctx);
	CU_ASSERT(((struct spdk_memory_domain_rdma_ctx *)stored_memory_domain_ctx->user_ctx)->ibv_pd ==
		  rdma_ctx.ibv_pd);

	/* Get DMA device type. Expect pass */
	CU_ASSERT(spdk_memory_domain_get_dma_device_type(domain) == SPDK_DMA_DEVICE_TYPE_RDMA);

	/* Get DMA id. Expect pass */
	id = spdk_memory_domain_get_dma_device_id(domain);
	CU_ASSERT((!strcmp(id, domain->id)));

	/* pull data, callback is NULL. Expect fail */
	g_memory_domain_pull_called = false;
	rc = spdk_memory_domain_pull_data(domain, NULL, &src_iov, 1, &dst_iov, 1,
					  test_memory_domain_data_cpl_cb, NULL);
	CU_ASSERT(rc == -ENOTSUP);
	CU_ASSERT(g_memory_domain_pull_called == false);

	/* Set pull callback */
	spdk_memory_domain_set_pull(domain, test_memory_domain_pull_data_cb);

	/* pull data. Expect pass */
	rc = spdk_memory_domain_pull_data(domain, NULL, &src_iov, 1, &dst_iov, 1,
					  test_memory_domain_data_cpl_cb, NULL);
	CU_ASSERT(rc == g_memory_domain_cb_rc);
	CU_ASSERT(g_memory_domain_pull_called == true);

	/* push data, callback is NULL. Expect fail */
	g_memory_domain_push_called = false;
	rc = spdk_memory_domain_push_data(domain, NULL, &dst_iov, 1, &src_iov, 1,
					  test_memory_domain_data_cpl_cb, NULL);
	CU_ASSERT(rc == -ENOTSUP);
	CU_ASSERT(g_memory_domain_push_called == false);

	/* Set push callback */
	spdk_memory_domain_set_push(domain, test_memory_domain_push_data_cb);

	/* push data. Expect pass */
	rc = spdk_memory_domain_push_data(domain, NULL, &dst_iov, 1, &src_iov, 1,
					  test_memory_domain_data_cpl_cb, NULL);
	CU_ASSERT(rc == g_memory_domain_cb_rc);
	CU_ASSERT(g_memory_domain_push_called == true);

	/* Translate data, callback is NULL. Expect fail */
	g_memory_domain_translate_called = false;
	rc = spdk_memory_domain_translate_data(domain, NULL, domain, NULL, (void *)0xfeeddbeef, 0x1000,
					       &translation_result);
	CU_ASSERT(rc == -ENOTSUP);
	CU_ASSERT(g_memory_domain_translate_called == false);

	/* Set translate callback */
	spdk_memory_domain_set_translation(domain, test_memory_domain_translate_memory_cb);

	/* Translate data. Expect pass */
	g_memory_domain_translate_called = false;
	rc = spdk_memory_domain_translate_data(domain, NULL, domain, NULL, (void *)0xfeeddbeef, 0x1000,
					       &translation_result);
	CU_ASSERT(rc == g_memory_domain_cb_rc);
	CU_ASSERT(g_memory_domain_translate_called == true);

	/* memzero, callback is NULL. Expect fail */
	g_memory_domain_memzero_called = false;
	rc = spdk_memory_domain_memzero(domain, NULL, &src_iov, 1, test_memory_domain_data_cpl_cb, NULL);
	CU_ASSERT(rc == -ENOTSUP);
	CU_ASSERT(g_memory_domain_memzero_called == false);

	/* Set memzero callback */
	spdk_memory_domain_set_memzero(domain, test_memory_domain_memzero_cb);

	/* memzero. Expect pass */
	rc = spdk_memory_domain_memzero(domain, NULL, &src_iov, 1, test_memory_domain_data_cpl_cb, NULL);
	CU_ASSERT(rc == g_memory_domain_cb_rc);
	CU_ASSERT(g_memory_domain_memzero_called == true);

	/* Set translation callback to NULL. Expect pass */
	spdk_memory_domain_set_translation(domain, NULL);
	CU_ASSERT(domain->translate_cb == NULL);

	/* Set translation callback. Expect pass */
	spdk_memory_domain_set_translation(domain, test_memory_domain_translate_memory_cb);
	CU_ASSERT(domain->translate_cb == test_memory_domain_translate_memory_cb);

	/* Set pull callback to NULL. Expect pass */
	spdk_memory_domain_set_pull(domain, NULL);
	CU_ASSERT(domain->pull_cb == NULL);

	/* Set pull callback. Expect pass */
	spdk_memory_domain_set_pull(domain, test_memory_domain_pull_data_cb);
	CU_ASSERT(domain->pull_cb == test_memory_domain_pull_data_cb);

	/* Set memzero to NULL. Expect pass */
	spdk_memory_domain_set_memzero(domain, NULL);
	CU_ASSERT(domain->memzero_cb == NULL);

	/* Set memzero callback. Expect pass */
	spdk_memory_domain_set_memzero(domain, test_memory_domain_memzero_cb);
	CU_ASSERT(domain->memzero_cb == test_memory_domain_memzero_cb);

	/* Create 2nd and 3rd memory domains with equal id to test enumeration */
	rc = spdk_memory_domain_create(&domain_2, SPDK_DMA_DEVICE_TYPE_RDMA, &memory_domain_ctx, "test_2");
	CU_ASSERT(rc == 0);

	rc = spdk_memory_domain_create(&domain_3, SPDK_DMA_DEVICE_TYPE_RDMA, &memory_domain_ctx, "test_2");
	CU_ASSERT(rc == 0);

	CU_ASSERT(spdk_memory_domain_get_first("test") == domain);
	CU_ASSERT(spdk_memory_domain_get_next(domain, "test") == NULL);
	CU_ASSERT(spdk_memory_domain_get_first("test_2") == domain_2);
	CU_ASSERT(spdk_memory_domain_get_next(domain_2, "test_2") == domain_3);
	CU_ASSERT(spdk_memory_domain_get_next(domain_3, "test_2") == NULL);

	CU_ASSERT(spdk_memory_domain_get_first(NULL) == system_domain);
	CU_ASSERT(spdk_memory_domain_get_next(system_domain, NULL) == domain);
	CU_ASSERT(spdk_memory_domain_get_next(domain, NULL) == domain_2);
	CU_ASSERT(spdk_memory_domain_get_next(domain_2, NULL) == domain_3);
	CU_ASSERT(spdk_memory_domain_get_next(domain_3, NULL) == NULL);

	/* Remove 2nd device, repeat iteration */
	spdk_memory_domain_destroy(domain_2);
	CU_ASSERT(spdk_memory_domain_get_first(NULL) == system_domain);
	CU_ASSERT(spdk_memory_domain_get_next(system_domain, NULL) == domain);
	CU_ASSERT(spdk_memory_domain_get_next(domain, NULL) == domain_3);
	CU_ASSERT(spdk_memory_domain_get_next(domain_3, NULL) == NULL);

	/* Remove 3rd device, repeat iteration */
	spdk_memory_domain_destroy(domain_3);
	CU_ASSERT(spdk_memory_domain_get_first(NULL) == system_domain);
	CU_ASSERT(spdk_memory_domain_get_next(system_domain, NULL) == domain);
	CU_ASSERT(spdk_memory_domain_get_next(domain, NULL) == NULL);
	CU_ASSERT(spdk_memory_domain_get_first("test_2") == NULL);

	/* Destroy memory domain, domain == NULL */
	spdk_memory_domain_destroy(NULL);
	CU_ASSERT(spdk_memory_domain_get_first(NULL) == system_domain);

	/* Destroy memory domain */
	spdk_memory_domain_destroy(domain);
	CU_ASSERT(spdk_memory_domain_get_first(NULL) == system_domain);
}

static void
test_dma_path(void)
{
	struct spdk_dma_path_opts opts;
	struct spdk_dma_path *dp1, *dp2, *dp3, *dp_reuse_name, *dp_reuse_id;
	bool saved_used[SPDK_COUNTOF(g_path_id_used)];
	uint8_t freed_id;

	/* NULL opts -> NULL */
	CU_ASSERT(spdk_dma_register_path(NULL) == NULL);

	/* opts->size too small (cannot fully contain 'name') -> NULL */
	memset(&opts, 0, sizeof(opts));
	opts.size = offsetof(struct spdk_dma_path_opts, name);
	memcpy(opts.name, "small", sizeof("small"));
	CU_ASSERT(spdk_dma_register_path(&opts) == NULL);

	/* Empty name -> NULL */
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	CU_ASSERT(spdk_dma_register_path(&opts) == NULL);

	/* Not null-terminated -> NULL */
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	memset(opts.name, 'A', sizeof(opts.name));
	CU_ASSERT(spdk_dma_register_path(&opts) == NULL);

	/* Successful registration: id is 1 (first registration in the test suite). */
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	memcpy(opts.name, "gpci0", sizeof("gpci0"));
	dp1 = spdk_dma_register_path(&opts);
	SPDK_CU_ASSERT_FATAL(dp1 != NULL);
	CU_ASSERT(spdk_dma_path_get_id(dp1) == 1);
	CU_ASSERT(strcmp(spdk_dma_path_get_name(dp1), "gpci0") == 0);
	CU_ASSERT(strcmp(spdk_dma_path_get_name_by_id(1), "gpci0") == 0);
	CU_ASSERT(g_path_id_used[1] == true);

	/* Second registration: id increments to 2, name round-trips. */
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	memcpy(opts.name, "gpci1", sizeof("gpci1"));
	dp2 = spdk_dma_register_path(&opts);
	SPDK_CU_ASSERT_FATAL(dp2 != NULL);
	CU_ASSERT(spdk_dma_path_get_id(dp2) == 2);
	CU_ASSERT(spdk_dma_path_get_id(dp2) >= 1);
	CU_ASSERT(strcmp(spdk_dma_path_get_name(dp2), "gpci1") == 0);
	CU_ASSERT(strcmp(spdk_dma_path_get_name_by_id(2), "gpci1") == 0);

	/* Verify that trying to get name by an invalid ID returns NULL. */
	CU_ASSERT(spdk_dma_path_get_name_by_id(3) == NULL);

	/* Duplicate name -> NULL, no id is allocated for the failed call. */
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	memcpy(opts.name, "gpci0", sizeof("gpci0"));
	CU_ASSERT(spdk_dma_register_path(&opts) == NULL);
	CU_ASSERT(g_path_id_used[3] == false);

	/* opts->size larger than current struct (forward-compat) is accepted. */
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts) + 16;
	memcpy(opts.name, "gpci2", sizeof("gpci2"));
	dp3 = spdk_dma_register_path(&opts);
	SPDK_CU_ASSERT_FATAL(dp3 != NULL);
	CU_ASSERT(spdk_dma_path_get_id(dp3) == 3);

	/* Unregister releases the id back to the allocator. */
	freed_id = spdk_dma_path_get_id(dp1);
	spdk_dma_unregister_path(dp1);
	CU_ASSERT(g_path_id_used[freed_id] == false);

	/* The just-freed name can be reused by a subsequent registration; the
	 * lowest free id is handed out, which is the id that was just freed. */
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	memcpy(opts.name, "gpci0", sizeof("gpci0"));
	dp_reuse_name = spdk_dma_register_path(&opts);
	SPDK_CU_ASSERT_FATAL(dp_reuse_name != NULL);
	CU_ASSERT(spdk_dma_path_get_id(dp_reuse_name) == freed_id);
	CU_ASSERT(strcmp(spdk_dma_path_get_name(dp_reuse_name), "gpci0") == 0);

	/* Unregister + register a brand-new name picks the lowest free id again. */
	freed_id = spdk_dma_path_get_id(dp_reuse_name);
	spdk_dma_unregister_path(dp_reuse_name);
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	memcpy(opts.name, "gpci-new", sizeof("gpci-new"));
	dp_reuse_id = spdk_dma_register_path(&opts);
	SPDK_CU_ASSERT_FATAL(dp_reuse_id != NULL);
	CU_ASSERT(spdk_dma_path_get_id(dp_reuse_id) == freed_id);

	/* Unregister(NULL) is a no-op. */
	spdk_dma_unregister_path(NULL);

	/* Id space exhaustion: snapshot the bitmap, mark every slot used, and
	 * confirm the next register call fails. Restore afterward so we don't
	 * leak state into other tests. */
	memcpy(saved_used, g_path_id_used, sizeof(saved_used));
	memset(g_path_id_used, true, sizeof(g_path_id_used));
	memset(&opts, 0, sizeof(opts));
	opts.size = sizeof(opts);
	memcpy(opts.name, "exhausted", sizeof("exhausted"));
	CU_ASSERT(spdk_dma_register_path(&opts) == NULL);
	memcpy(g_path_id_used, saved_used, sizeof(saved_used));

	/* Clean up everything the test allocated so global state is left
	 * exactly as we found it. */
	spdk_dma_unregister_path(dp2);
	spdk_dma_unregister_path(dp3);
	spdk_dma_unregister_path(dp_reuse_id);
}

int
main(int argc, char **argv)
{
	CU_pSuite suite = NULL;
	unsigned int num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("dma_suite", NULL, NULL);
	CU_ADD_TEST(suite, test_dma);
	CU_ADD_TEST(suite, test_dma_path);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();

	return num_failures;
}
