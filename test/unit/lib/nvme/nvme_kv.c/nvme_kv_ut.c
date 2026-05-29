/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk_internal/cunit.h"

#include "nvme/nvme_kv.c"
#include "nvme/nvme_ns_cmd.c"
#include "nvme/nvme.c"

#include "common/lib/test_env.c"

static struct nvme_driver _g_nvme_driver = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static struct nvme_request *g_request = NULL;

DEFINE_STUB_V(nvme_io_msg_ctrlr_detach, (struct spdk_nvme_ctrlr *ctrlr));

DEFINE_STUB_V(nvme_ctrlr_destruct_async,
	      (struct spdk_nvme_ctrlr *ctrlr, struct nvme_ctrlr_detach_ctx *ctx));

DEFINE_STUB(nvme_ctrlr_destruct_poll_async,
	    int,
	    (struct spdk_nvme_ctrlr *ctrlr, struct nvme_ctrlr_detach_ctx *ctx),
	    0);

DEFINE_STUB(spdk_nvme_poll_group_process_completions,
	    int64_t,
	    (struct spdk_nvme_poll_group *group, uint32_t completions_per_qpair,
	     spdk_nvme_disconnected_qpair_cb disconnected_qpair_cb),
	    0);

DEFINE_STUB(spdk_nvme_qpair_process_completions,
	    int32_t,
	    (struct spdk_nvme_qpair *qpair, uint32_t max_completions),
	    0);

DEFINE_STUB(spdk_nvme_ctrlr_get_regs_csts,
	    union spdk_nvme_csts_register,
	    (struct spdk_nvme_ctrlr *ctrlr),
	    {});

DEFINE_STUB(spdk_pci_event_listen, int, (void), 1);

DEFINE_STUB_V(nvme_ctrlr_fail,
	      (struct spdk_nvme_ctrlr *ctrlr, bool hotremove));

DEFINE_STUB(nvme_transport_ctrlr_destruct,
	    int,
	    (struct spdk_nvme_ctrlr *ctrlr),
	    0);

DEFINE_STUB(nvme_ctrlr_get_current_process,
	    struct spdk_nvme_ctrlr_process *,
	    (struct spdk_nvme_ctrlr *ctrlr),
	    (struct spdk_nvme_ctrlr_process *)(uintptr_t)0x1);

DEFINE_STUB(nvme_transport_ctrlr_scan_attached,
	    int,
	    (struct spdk_nvme_probe_ctx *probe_ctx),
	    0);

int
nvme_qpair_submit_request(struct spdk_nvme_qpair *qpair, struct nvme_request *req)
{
	g_request = req;

	return 0;
}

void
nvme_ctrlr_destruct(struct spdk_nvme_ctrlr *ctrlr)
{
}

void
nvme_ctrlr_proc_get_ref(struct spdk_nvme_ctrlr *ctrlr)
{
	return;
}

int
nvme_ctrlr_process_init(struct spdk_nvme_ctrlr *ctrlr)
{
	return 0;
}

void
nvme_ctrlr_proc_put_ref(struct spdk_nvme_ctrlr *ctrlr)
{
	return;
}

void
spdk_nvme_ctrlr_get_default_ctrlr_opts(struct spdk_nvme_ctrlr_opts *opts, size_t opts_size)
{
	memset(opts, 0, sizeof(*opts));
}

bool
spdk_nvme_transport_available_by_name(const char *transport_name)
{
	return true;
}

struct spdk_nvme_ctrlr *nvme_transport_ctrlr_construct(const struct spdk_nvme_transport_id *trid,
		const struct spdk_nvme_ctrlr_opts *opts,
		void *devhandle)
{
	return NULL;
}

int
nvme_ctrlr_get_ref_count(struct spdk_nvme_ctrlr *ctrlr)
{
	return 0;
}

int
nvme_transport_ctrlr_scan(struct spdk_nvme_probe_ctx *probe_ctx,
			  bool direct_connect)
{
	return 0;
}

static void
prepare_for_test(struct spdk_nvme_ns *ns, struct spdk_nvme_ctrlr *ctrlr,
		 struct spdk_nvme_qpair *qpair)
{
	uint32_t num_requests = 32;
	uint32_t i;

	memset(ctrlr, 0, sizeof(*ctrlr));
	ctrlr->max_xfer_size = 0x100000;
	ctrlr->flags = 0;
	ctrlr->min_page_size = 4096;
	ctrlr->page_size = 4096;
	memset(&ctrlr->opts, 0, sizeof(ctrlr->opts));
	memset(ns, 0, sizeof(*ns));
	ns->ctrlr = ctrlr;
	ns->id = 1;

	memset(qpair, 0, sizeof(*qpair));
	qpair->ctrlr = ctrlr;
	qpair->req_buf = calloc(num_requests, sizeof(struct nvme_request));
	SPDK_CU_ASSERT_FATAL(qpair->req_buf != NULL);

	for (i = 0; i < num_requests; i++) {
		struct nvme_request *req = qpair->req_buf + i * sizeof(struct nvme_request);

		req->qpair = qpair;
		STAILQ_INSERT_HEAD(&qpair->free_req, req, stailq);
	}

	g_request = NULL;
}

static void
cleanup_after_test(struct spdk_nvme_qpair *qpair)
{
	free(qpair->req_buf);
}

/* Helper function to verify key encoding in command */
static void
verify_key_encoding(const struct spdk_nvme_cmd *cmd, const void *key, uint8_t key_len)
{
	const uint8_t *key_bytes = (const uint8_t *)key;
	uint8_t *rsvd2_bytes = (uint8_t *)&cmd->rsvd2;
	uint8_t *cdw14_bytes = (uint8_t *)&cmd->cdw14;
	uint32_t i;

	/* Verify key length in CDW11 */
	CU_ASSERT(cmd->cdw11_bits.kv.kl == key_len);

	if (key_len == 0) {
		/* Empty key: all fields should be zero */
		CU_ASSERT(cmd->rsvd2 == 0);
		CU_ASSERT(cmd->rsvd3 == 0);
		CU_ASSERT(cmd->cdw14 == 0);
		CU_ASSERT(cmd->cdw15 == 0);
		return;
	}

	/* Verify first 8 bytes in CDW2-3 (rsvd2, rsvd3) */
	for (i = 0; i < spdk_min(key_len, 8); i++) {
		CU_ASSERT(rsvd2_bytes[i] == key_bytes[i]);
	}
	/* Verify remaining bytes in rsvd2/rsvd3 are zero if key is shorter than 8 bytes */
	for (i = key_len; i < 8; i++) {
		CU_ASSERT(rsvd2_bytes[i] == 0);
	}

	/* If key is longer than 8 bytes, verify remaining bytes in CDW14-15 */
	if (key_len > 8) {
		uint32_t remaining_len = key_len - 8;
		for (i = 0; i < remaining_len; i++) {
			CU_ASSERT(cdw14_bytes[i] == key_bytes[8 + i]);
		}
		/* Verify remaining bytes in cdw14/cdw15 are zero if key is shorter than 16 bytes */
		for (i = remaining_len; i < 8; i++) {
			CU_ASSERT(cdw14_bytes[i] == 0);
		}
	} else {
		/* If key is 8 bytes or less, CDW14-15 should be zero */
		CU_ASSERT(cmd->cdw14 == 0);
		CU_ASSERT(cmd->cdw15 == 0);
	}
}

/* Test KV Store command with various key lengths */
static void
test_nvme_kv_store_key_lengths(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key1[1] = {0xAA};
	uint8_t key8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t key9[9] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t key16[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
			     0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF
			    };
	uint8_t value[256] = {0};
	uint32_t value_len = 256;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with 1-byte key */
	rc = spdk_nvme_kv_store(&ns, &qpair, key1, 1, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_STORE);
	CU_ASSERT(g_request->cmd.nsid == ns.id);
	CU_ASSERT(g_request->cmd.cdw10_bits.kv.vsize == value_len);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.ro == 0);
	verify_key_encoding(&g_request->cmd, key1, 1);
	CU_ASSERT(g_request->payload.size == value_len);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with 8-byte key */
	rc = spdk_nvme_kv_store(&ns, &qpair, key8, 8, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_STORE);
	verify_key_encoding(&g_request->cmd, key8, 8);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with 9-byte key (spans CDW2-3 and CDW14-15) */
	rc = spdk_nvme_kv_store(&ns, &qpair, key9, 9, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_STORE);
	verify_key_encoding(&g_request->cmd, key9, 9);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with 16-byte key (maximum) */
	rc = spdk_nvme_kv_store(&ns, &qpair, key16, 16, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_STORE);
	verify_key_encoding(&g_request->cmd, key16, 16);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test KV Store command with different store options */
static void
test_nvme_kv_store_options(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t value[128] = {0};
	uint32_t value_len = 128;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with DONT_STORE_IF_KEY_NOT_EXISTS option */
	rc = spdk_nvme_kv_store(&ns, &qpair, key, 4, value, value_len, NULL, NULL,
				SPDK_NVME_KV_STORE_OPT_DONT_STORE_IF_KEY_NOT_EXISTS);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_STORE);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.ro == SPDK_NVME_KV_STORE_OPT_DONT_STORE_IF_KEY_NOT_EXISTS);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with DONT_STORE_IF_KEY_EXISTS option */
	rc = spdk_nvme_kv_store(&ns, &qpair, key, 4, value, value_len, NULL, NULL,
				SPDK_NVME_KV_STORE_OPT_DONT_STORE_IF_KEY_EXISTS);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.ro == SPDK_NVME_KV_STORE_OPT_DONT_STORE_IF_KEY_EXISTS);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with DONT_COMPRESS option */
	rc = spdk_nvme_kv_store(&ns, &qpair, key, 4, value, value_len, NULL, NULL,
				SPDK_NVME_KV_STORE_OPT_DONT_COMPRESS);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.ro == SPDK_NVME_KV_STORE_OPT_DONT_COMPRESS);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with multiple options combined */
	rc = spdk_nvme_kv_store(&ns, &qpair, key, 4, value, value_len, NULL, NULL,
				SPDK_NVME_KV_STORE_OPT_DONT_STORE_IF_KEY_NOT_EXISTS |
				SPDK_NVME_KV_STORE_OPT_DONT_COMPRESS);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.ro ==
		  (SPDK_NVME_KV_STORE_OPT_DONT_STORE_IF_KEY_NOT_EXISTS | SPDK_NVME_KV_STORE_OPT_DONT_COMPRESS));
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test KV Store command error cases */
static void
test_nvme_kv_store_errors(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t value[128] = {0};
	uint32_t value_len = 128;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with NULL key */
	rc = spdk_nvme_kv_store(&ns, &qpair, NULL, 4, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with zero key length */
	rc = spdk_nvme_kv_store(&ns, &qpair, key, 0, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with key length > 16 */
	rc = spdk_nvme_kv_store(&ns, &qpair, key, 17, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with zero value length */
	rc = spdk_nvme_kv_store(&ns, &qpair, key, 4, value, 0, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	cleanup_after_test(&qpair);
}

/* Test KV Retrieve command */
static void
test_nvme_kv_retrieve(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t value[512] = {0};
	uint32_t value_len = 512;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test basic retrieve */
	rc = spdk_nvme_kv_retrieve(&ns, &qpair, key, 8, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_RETRIEVE);
	CU_ASSERT(g_request->cmd.nsid == ns.id);
	CU_ASSERT(g_request->cmd.cdw10_bits.kv.vsize == value_len);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.ro == 0);
	verify_key_encoding(&g_request->cmd, key, 8);
	CU_ASSERT(g_request->payload.size == value_len);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with RETRIEVE_RAW option */
	rc = spdk_nvme_kv_retrieve(&ns, &qpair, key, 8, value, value_len, NULL, NULL,
				   SPDK_NVME_KV_RETRIEVE_OPT_RETRIEVE_RAW);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.ro == SPDK_NVME_KV_RETRIEVE_OPT_RETRIEVE_RAW);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test KV Retrieve command error cases */
static void
test_nvme_kv_retrieve_errors(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t value[128] = {0};
	uint32_t value_len = 128;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with NULL key */
	rc = spdk_nvme_kv_retrieve(&ns, &qpair, NULL, 4, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with zero key length */
	rc = spdk_nvme_kv_retrieve(&ns, &qpair, key, 0, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with key length > 16 */
	rc = spdk_nvme_kv_retrieve(&ns, &qpair, key, 17, value, value_len, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with zero value length */
	rc = spdk_nvme_kv_retrieve(&ns, &qpair, key, 4, value, 0, NULL, NULL, 0);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	cleanup_after_test(&qpair);
}

/* Test KV Delete command */
static void
test_nvme_kv_delete(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key1[1] = {0xAA};
	uint8_t key8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t key16[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
			     0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF
			    };

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with 1-byte key */
	rc = spdk_nvme_kv_delete(&ns, &qpair, key1, 1, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_DELETE);
	CU_ASSERT(g_request->cmd.nsid == ns.id);
	verify_key_encoding(&g_request->cmd, key1, 1);
	CU_ASSERT(g_request->payload.size == 0);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with 8-byte key */
	rc = spdk_nvme_kv_delete(&ns, &qpair, key8, 8, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_DELETE);
	verify_key_encoding(&g_request->cmd, key8, 8);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with 16-byte key */
	rc = spdk_nvme_kv_delete(&ns, &qpair, key16, 16, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_DELETE);
	verify_key_encoding(&g_request->cmd, key16, 16);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test KV Delete command error cases */
static void
test_nvme_kv_delete_errors(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key[4] = {0xAA, 0xBB, 0xCC, 0xDD};

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with NULL key */
	rc = spdk_nvme_kv_delete(&ns, &qpair, NULL, 4, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with zero key length */
	rc = spdk_nvme_kv_delete(&ns, &qpair, key, 0, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with key length > 16 */
	rc = spdk_nvme_kv_delete(&ns, &qpair, key, 17, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	cleanup_after_test(&qpair);
}

/* Test KV Exist command */
static void
test_nvme_kv_exist(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

	prepare_for_test(&ns, &ctrlr, &qpair);

	rc = spdk_nvme_kv_exist(&ns, &qpair, key, 8, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_EXIST);
	CU_ASSERT(g_request->cmd.nsid == ns.id);
	verify_key_encoding(&g_request->cmd, key, 8);
	CU_ASSERT(g_request->payload.size == 0);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test KV Exist command error cases */
static void
test_nvme_kv_exist_errors(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key[4] = {0xAA, 0xBB, 0xCC, 0xDD};

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with NULL key */
	rc = spdk_nvme_kv_exist(&ns, &qpair, NULL, 4, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with zero key length */
	rc = spdk_nvme_kv_exist(&ns, &qpair, key, 0, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with key length > 16 */
	rc = spdk_nvme_kv_exist(&ns, &qpair, key, 17, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	cleanup_after_test(&qpair);
}

/* Test KV List command with start key */
static void
test_nvme_kv_list_with_start_key(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t start_key[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t buffer[1024] = {0};
	uint32_t buffer_len = 1024;

	prepare_for_test(&ns, &ctrlr, &qpair);

	rc = spdk_nvme_kv_list(&ns, &qpair, start_key, 4, buffer, buffer_len, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_LIST);
	CU_ASSERT(g_request->cmd.nsid == ns.id);
	CU_ASSERT(g_request->cmd.cdw10_bits.kv.vsize == buffer_len);
	verify_key_encoding(&g_request->cmd, start_key, 4);
	CU_ASSERT(g_request->payload.size == buffer_len);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test KV List command without start key (list all keys) */
static void
test_nvme_kv_list_all_keys(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t buffer[1024] = {0};
	uint32_t buffer_len = 1024;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with NULL start_key (list all keys) */
	rc = spdk_nvme_kv_list(&ns, &qpair, NULL, 0, buffer, buffer_len, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	CU_ASSERT(g_request->cmd.opc == SPDK_NVME_OPC_KV_LIST);
	CU_ASSERT(g_request->cmd.nsid == ns.id);
	CU_ASSERT(g_request->cmd.cdw10_bits.kv.vsize == buffer_len);
	CU_ASSERT(g_request->cmd.cdw11_bits.kv.kl == 0);
	CU_ASSERT(g_request->cmd.rsvd2 == 0);
	CU_ASSERT(g_request->cmd.rsvd3 == 0);
	CU_ASSERT(g_request->cmd.cdw14 == 0);
	CU_ASSERT(g_request->cmd.cdw15 == 0);
	CU_ASSERT(g_request->payload.size == buffer_len);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test KV List command error cases */
static void
test_nvme_kv_list_errors(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t start_key[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t buffer[1024] = {0};
	uint32_t buffer_len = 1024;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with NULL buffer */
	rc = spdk_nvme_kv_list(&ns, &qpair, start_key, 4, NULL, buffer_len, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with zero buffer length */
	rc = spdk_nvme_kv_list(&ns, &qpair, start_key, 4, buffer, 0, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	/* Test with start_key_len > 16 */
	rc = spdk_nvme_kv_list(&ns, &qpair, start_key, 17, buffer, buffer_len, NULL, NULL);
	CU_ASSERT(rc == -EINVAL);
	CU_ASSERT(g_request == NULL);

	cleanup_after_test(&qpair);
}

/* Test KV List command with various start key lengths */
static void
test_nvme_kv_list_key_lengths(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_qpair qpair;
	int rc;
	uint8_t key1[1] = {0xAA};
	uint8_t key8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t key16[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
			     0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF
			    };
	uint8_t buffer[1024] = {0};
	uint32_t buffer_len = 1024;

	prepare_for_test(&ns, &ctrlr, &qpair);

	/* Test with 1-byte start key */
	rc = spdk_nvme_kv_list(&ns, &qpair, key1, 1, buffer, buffer_len, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	verify_key_encoding(&g_request->cmd, key1, 1);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with 8-byte start key */
	rc = spdk_nvme_kv_list(&ns, &qpair, key8, 8, buffer, buffer_len, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	verify_key_encoding(&g_request->cmd, key8, 8);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	/* Test with 16-byte start key */
	rc = spdk_nvme_kv_list(&ns, &qpair, key16, 16, buffer, buffer_len, NULL, NULL);
	CU_ASSERT(rc == 0);
	SPDK_CU_ASSERT_FATAL(g_request != NULL);
	verify_key_encoding(&g_request->cmd, key16, 16);
	nvme_cleanup_user_req(g_request);
	nvme_free_request(g_request);
	g_request = NULL;

	cleanup_after_test(&qpair);
}

/* Test helper functions for KV namespace data */
static void
test_nvme_kv_ns_helpers(void)
{
	struct spdk_nvme_ns ns;
	struct spdk_nvme_kv_ns_data nsdata_kv = {};
	const struct spdk_nvme_kv_ns_data *ret_nsdata;

	memset(&ns, 0, sizeof(ns));

	/* Test with NULL nsdata_kv */
	ret_nsdata = spdk_nvme_kv_ns_get_data(&ns);
	CU_ASSERT(ret_nsdata == NULL);

	/* Test with valid nsdata_kv */
	nsdata_kv.kvfc.kvfi = 0;
	nsdata_kv.kvf[0].kvkml = 16;
	nsdata_kv.kvf[0].kvvml = 4096;
	nsdata_kv.novg = 1024;
	ns.nsdata_kv = &nsdata_kv;

	ret_nsdata = spdk_nvme_kv_ns_get_data(&ns);
	CU_ASSERT(ret_nsdata == &nsdata_kv);
	CU_ASSERT(ret_nsdata->kvf[0].kvkml == 16);
	CU_ASSERT(ret_nsdata->kvf[0].kvvml == 4096);
	CU_ASSERT(ret_nsdata->novg == 1024);
}

/* Test helper functions for KV controller data */
static void
test_nvme_kv_ctrlr_helpers(void)
{
	struct spdk_nvme_ctrlr ctrlr;
	struct spdk_nvme_kv_ctrlr_data cdata_kv = {};
	const struct spdk_nvme_kv_ctrlr_data *ret_cdata;

	memset(&ctrlr, 0, sizeof(ctrlr));

	/* Test with NULL cdata_kv */
	ret_cdata = spdk_nvme_kv_ctrlr_get_data(&ctrlr);
	CU_ASSERT(ret_cdata == NULL);

	/* Test with valid cdata_kv */
	ctrlr.cdata_kv = &cdata_kv;
	ret_cdata = spdk_nvme_kv_ctrlr_get_data(&ctrlr);
	CU_ASSERT(ret_cdata == &cdata_kv);
}

int
main(int argc, char **argv)
{
	CU_pSuite	suite = NULL;
	unsigned int	num_failures;

	CU_initialize_registry();

	suite = CU_add_suite("nvme_kv", NULL, NULL);

	/* Key encoding and command structure tests */
	CU_ADD_TEST(suite, test_nvme_kv_store_key_lengths);
	CU_ADD_TEST(suite, test_nvme_kv_store_options);
	CU_ADD_TEST(suite, test_nvme_kv_store_errors);

	/* Retrieve command tests */
	CU_ADD_TEST(suite, test_nvme_kv_retrieve);
	CU_ADD_TEST(suite, test_nvme_kv_retrieve_errors);

	/* Delete command tests */
	CU_ADD_TEST(suite, test_nvme_kv_delete);
	CU_ADD_TEST(suite, test_nvme_kv_delete_errors);

	/* Exist command tests */
	CU_ADD_TEST(suite, test_nvme_kv_exist);
	CU_ADD_TEST(suite, test_nvme_kv_exist_errors);

	/* List command tests */
	CU_ADD_TEST(suite, test_nvme_kv_list_with_start_key);
	CU_ADD_TEST(suite, test_nvme_kv_list_all_keys);
	CU_ADD_TEST(suite, test_nvme_kv_list_errors);
	CU_ADD_TEST(suite, test_nvme_kv_list_key_lengths);

	/* Helper function tests */
	CU_ADD_TEST(suite, test_nvme_kv_ns_helpers);
	CU_ADD_TEST(suite, test_nvme_kv_ctrlr_helpers);

	g_spdk_nvme_driver = &_g_nvme_driver;

	num_failures = spdk_ut_run_tests(argc, argv, NULL);
	CU_cleanup_registry();
	return num_failures;
}
