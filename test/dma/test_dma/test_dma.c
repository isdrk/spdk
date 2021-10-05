/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Nvidia Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/event.h"
#include "spdk/env.h"
#include "spdk/dma.h"
#include <infiniband/verbs.h>

#define DMA_TEST_IO_BUFFER_SIZE 4096

struct dma_test_task;

struct dma_test_req {
	void *buffer;
	struct ibv_mr *mr;
	struct dma_test_task *task;
};

struct dma_test_task {
	struct spdk_bdev_desc *desc;
	struct spdk_io_channel *channel;
	bool is_draining;
	struct dma_test_req *reqs;
	uint32_t reqs_inflight;

	struct spdk_thread *thread;
	struct spdk_poller *stop_poller;

	TAILQ_ENTRY(dma_test_task) link;

};

TAILQ_HEAD(, dma_test_task) g_tasks = TAILQ_HEAD_INITIALIZER(g_tasks);

/* User's input */
static char *g_bdev_name;
static const char *g_rw_mode_str;
struct spdk_thread *g_main_thread;
static int g_rw_percentage = -1;
static uint32_t g_queue_depth;
static uint32_t g_io_size;
static uint32_t g_run_time_sec;
static bool g_is_random;

static struct spdk_memory_domain *g_domain;
static uint64_t g_num_blocks_per_io;
static uint64_t g_local_barrier;
static bool g_shutdown;

static void
dma_test_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *event_ctx)
{
}

struct dma_test_ctx {
	const char *bdev_name;
	struct spdk_bdev_desc *desc;
	struct spdk_io_channel *ch;
	struct spdk_memory_domain *memory_domain;
	void *write_io_buffer;
	void *read_io_buffer;
	struct spdk_bdev_ext_io_opts ext_io_opts;
	struct ibv_mr *mr;
	struct iovec iov;
	uint64_t num_blocks;
};

static int
dma_test_translate_memory_cb(struct spdk_memory_domain *src_domain, void *src_domain_ctx,
			     struct spdk_memory_domain *dst_domain, struct spdk_memory_domain_translation_ctx *dst_domain_ctx,
			     void *addr, size_t len, struct spdk_memory_domain_translation_result *result)
{
	struct dma_test_ctx *ctx = src_domain_ctx;
	struct ibv_qp *dst_domain_qp = (struct ibv_qp *)dst_domain_ctx->rdma.ibv_qp;

	fprintf(stdout, "Translating memory\n");

	ctx->mr = ibv_reg_mr(dst_domain_qp->pd, addr, len, IBV_ACCESS_LOCAL_WRITE |
			     IBV_ACCESS_REMOTE_READ |
			     IBV_ACCESS_REMOTE_WRITE);
	if (!ctx->mr) {
		fprintf(stderr, "Failed to register memory region, errno %d\n", errno);
		return -1;
	}

	ctx->iov.iov_base = addr;
	ctx->iov.iov_len = len;
	result->iov = &ctx->iov;
	result->iov_count = 1;
	result->rdma.lkey = ctx->mr->lkey;
	result->rdma.rkey = ctx->mr->rkey;
	result->dst_domain = dst_domain;

	return 0;
}

static void
dma_test_cleanup(struct dma_test_ctx *ctx)
{
	if (ctx->ch) {
		spdk_put_io_channel(ctx->ch);
		ctx->ch = NULL;
	}
	if (ctx->desc) {
		spdk_bdev_close(ctx->desc);
		ctx->desc = NULL;
	}
	spdk_memory_domain_destroy(ctx->memory_domain);
	ctx->memory_domain = NULL;
	if (ctx->mr) {
		ibv_dereg_mr(ctx->mr);
		ctx->mr = NULL;
	}
	free(ctx->write_io_buffer);
	ctx->write_io_buffer = NULL;
	free(ctx->read_io_buffer);
	ctx->read_io_buffer = NULL;
}

static void
dma_test_read_completed(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct dma_test_ctx *ctx = cb_arg;
	int sct, sc;
	uint32_t cdw0;

	if (success) {
		spdk_bdev_free_io(bdev_io);
	} else {
		spdk_bdev_io_get_nvme_status(bdev_io, &cdw0, &sct, &sc);
		fprintf(stderr, "bdev read IO failed, cdw0 %x, sct %d, sc %d\n", cdw0, sct, sc);
		spdk_app_stop(-1);
		return;
	}

	if (memcmp(ctx->write_io_buffer, ctx->read_io_buffer, DMA_TEST_IO_BUFFER_SIZE)) {
		fprintf(stderr, "Read buffer doesn't match written data!\n");
		spdk_app_stop(-1);
		return;
	}

	fprintf(stdout, "DMA test completed successfully\n");

	dma_test_cleanup(ctx);

	spdk_app_stop(0);
}

static void
dma_test_write_completed(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct dma_test_ctx *ctx = cb_arg;
	struct iovec iov;
	int sct, sc, rc;
	uint32_t cdw0;

	if (success) {
		spdk_bdev_free_io(bdev_io);
	} else {
		spdk_bdev_io_get_nvme_status(bdev_io, &cdw0, &sct, &sc);
		fprintf(stderr, "bdev write IO failed, cdw0 %x, sct %d, sc %d\n", cdw0, sct, sc);
		spdk_app_stop(-1);
		return;
	}

	fprintf(stdout, "Write IO completed, submitting read IO\n");

	ibv_dereg_mr(ctx->mr);

	iov.iov_base = ctx->read_io_buffer;
	iov.iov_len = DMA_TEST_IO_BUFFER_SIZE;

	rc = spdk_bdev_readv_blocks_ext(ctx->desc, ctx->ch, &iov, 1, 0, ctx->num_blocks,
					dma_test_read_completed, ctx, &ctx->ext_io_opts);
	if (rc) {
		fprintf(stderr, "Falied to submit read operation");
		spdk_app_stop(-1);
	}
}

static void
dma_test_drain_task(void *ctx)
{
	struct dma_test_task *task = ctx;

	spdk_poller_unregister(&task->stop_poller);
	task->is_draining = true;
}

static void
dma_test_shutdown_cb(void)
{
	struct dma_test_task *task;

	g_shutdown = true;

	TAILQ_FOREACH(task, &g_tasks, link) {
		spdk_thread_send_msg(task->thread, dma_test_drain_task, task);
	}

}

static bool
dma_test_check_bdev_supports_rdma_memory_domain(struct spdk_bdev *bdev)
{
	struct spdk_memory_domain **bdev_domains;
	int bdev_domains_count, bdev_domains_count_tmp, i;
	bool rdma_domain_supported = false;

	bdev_domains_count = spdk_bdev_get_memory_domains(bdev, NULL, 0);

	if (bdev_domains_count < 0) {
		fprintf(stderr, "Failed to get bdev memory domains count, rc %d\n", bdev_domains_count);
		return false;
	} else if (bdev_domains_count == 0) {
		fprintf(stderr, "bdev %s doesn't support any memory domains\n", spdk_bdev_get_name(bdev));
		return false;
	}

	fprintf(stdout, "bdev %s reports %d memory domains\n", spdk_bdev_get_name(bdev),
		bdev_domains_count);

	bdev_domains = calloc((size_t)bdev_domains_count, sizeof(*bdev_domains));
	if (!bdev_domains) {
		fprintf(stderr, "Failed to allocate memory domains\n");
		return false;
	}

	bdev_domains_count_tmp = spdk_bdev_get_memory_domains(bdev, bdev_domains, bdev_domains_count);
	if (bdev_domains_count_tmp != bdev_domains_count) {
		fprintf(stderr, "Unexpected bdev domains return value %d\n", bdev_domains_count_tmp);
		return false;
	}

	for (i = 0; i < bdev_domains_count; i++) {
		if (spdk_memory_domain_get_dma_device_type(bdev_domains[i]) == SPDK_DMA_DEVICE_TYPE_RDMA) {
			/* Bdev supports memory domain of RDMA type, we can try to submit IO request to it using
			 * bdev ext API */
			rdma_domain_supported = true;
			break;
		}
	}

	fprintf(stdout, "bdev %s %s RDMA memory domain\n", spdk_bdev_get_name(bdev),
		rdma_domain_supported ? "supports" : "doesn't support");
	free(bdev_domains);

	return rdma_domain_supported;
}

static int
allocate_task(uint32_t core)
{
	char thread_name[32];
	struct spdk_cpuset cpu_set;
	uint32_t i;
	struct dma_test_task *task;

	task = calloc(1, sizeof(*task));
	if (!task) {
		fprintf(stderr, "Failed to allocate per thread task\n");
		return -ENOMEM;
	}

	TAILQ_INSERT_TAIL(&g_tasks, task, link);

	task->reqs = calloc(g_queue_depth, sizeof(task->reqs));
	if (!task->reqs) {
		fprintf(stderr, "Failed to allocate requests\n");
		return -ENOMEM;
	}

	for (i = 0; i < g_queue_depth; i++) {
		task->reqs[i].task = task;
		task->reqs[i].buffer = malloc(g_io_size);
		if (!task->reqs[i].buffer) {
			fprintf(stderr, "Failed to allocate request data buffer\n");
			return -ENOMEM;
		}
		memset(task->reqs[i].buffer, 0xc, g_io_size);
	}

	snprintf(thread_name, 32, "task_%u", core);
	spdk_cpuset_zero(&cpu_set);
	spdk_cpuset_set_cpu(&cpu_set, core, true);
	task->thread = spdk_thread_create(thread_name, &cpu_set);
	if (!task->thread) {
		fprintf(stderr, "Failed to create SPDK thread\n");
		return -ENOMEM;
	}

	return 0;
}

static void
destroy_tasks(void)
{
	struct dma_test_task *task, *tmp_task;

	TAILQ_FOREACH_SAFE(task, &g_tasks, link, tmp_task) {
		TAILQ_REMOVE(&g_tasks, task, link);
		free(task);
	}
}

static void
dma_test_start(void *arg)
{
	uint32_t i;
	int rc;
	struct spdk_bdev *bdev;

	bdev = spdk_bdev_get_by_name(g_bdev_name);
	if (!bdev) {
		fprintf(stderr, "Can't find bdev %s\n", g_bdev_name);
		spdk_app_stop(-ENODEV);
		return;
	}
	if (!dma_test_check_bdev_supports_rdma_memory_domain(bdev)) {
		spdk_app_stop(-ENODEV);
		return;
	}

	g_main_thread = spdk_get_thread();
	g_num_blocks_per_io = g_io_size / spdk_bdev_get_block_size(bdev);
	assert(g_num_blocks_per_io);

	/* Create a memory domain to represent the source memory domain.
	 * Since we don't actually have a remote memory domain in this test, this will describe memory
	 * on the local system and the translation to the destination memory domain will be trivial.
	 * But this at least allows us to demonstrate the flow and test the functionality. */
	rc = spdk_memory_domain_create(&g_domain, SPDK_DMA_DEVICE_TYPE_RDMA, NULL, "test_dma");
	if (rc != 0) {
		spdk_app_stop(rc);
		return;
	}
	spdk_memory_domain_set_translation(g_domain, dma_test_translate_memory_cb);

	SPDK_ENV_FOREACH_CORE(i) {
		rc = allocate_task(i);
		if (rc) {
			destroy_tasks();
			spdk_app_stop(rc);
			return;
		}
	}
	SPDK_ENV_FOREACH_CORE(i) {

	}
}

static void
print_usage(void)
{
	printf(" -b <bdev>         bdev name for test\n");
	printf(" -q <val>          io depth\n");
	printf(" -o <val>          io size in bytes\n");
	printf(" -t <val>          run time in seconds\n");
	printf(" -w <str>          io pattern (read, write, randread, randwrite, randrw)\n");
	printf(" -M <0-100>        rw percentage (100 for reads, 0 for writes)\n");
}

static int
parse_arg(int ch, char *arg)
{
	long tmp;

	switch (ch) {
	case 'q':
	case 'o':
	case 't':
	case 'M':
		tmp = spdk_strtol(arg, 10);
		if (tmp < 0) {
			fprintf(stderr, "Invalid option %c value %s\n", ch, arg);
			return 1;
		}

		switch (ch) {
		case 'q':
			g_queue_depth = (uint32_t) tmp;
			break;
		case 'o':
			g_io_size = (uint32_t) tmp;
			break;
		case 't':
			g_run_time_sec = (uint32_t) tmp;
			break;
		case 'M':
			g_rw_percentage = (uint32_t) tmp;
			break;
		}
		break;
	case 'w':
		g_rw_mode_str = arg;
		break;
	case 'b':
		g_bdev_name = arg;
		break;

	default:
		fprintf(stderr, "Unknown option %c\n", ch);
		return 1;
	}

	return 0;
}

static int
verify_args(void)
{
	if (g_queue_depth == 0) {
		fprintf(stderr, "queue depth (-q) is not set\n");
		return 1;
	}
	if (g_io_size == 0) {
		fprintf(stderr, "io size (-o) is not set\n");
		return 1;
	}
	if (g_run_time_sec == 0) {
		fprintf(stderr, "test run time (-t) is not set\n");
		return 1;
	}
	if (!g_rw_mode_str) {
		fprintf(stderr, "io pattern (-w) is not set\n");
		return 1;
	}
	if (strncmp(g_rw_mode_str, "rand", 4) == 0) {
		g_is_random = true;
		g_rw_mode_str = &g_rw_mode_str[4];
	}
	if (strcmp(g_rw_mode_str, "read") == 0 || strcmp(g_rw_mode_str, "write") == 0) {
		g_rw_percentage = strcmp(g_rw_mode_str, "read") == 0 ? 100 : 0;
		if (g_rw_percentage > 0) {
			fprintf(stderr, "Ignoring -M option\n");
		}
	} else if (strcmp(g_rw_mode_str, "rw") == 0) {
		if (g_rw_percentage < 0 || g_rw_percentage > 100) {
			fprintf(stderr, "Invalid -M value (%d) must be 0..100\n", g_rw_percentage);
			return 1;
		}
	} else {
		fprintf(stderr, "io pattern (-w) one of [read, write, randread, randwrite, rw, randrw]\n");
		return 1;
	}
	if (!g_bdev_name) {
		fprintf(stderr, "bdev name (-b) is not set\n");
		return 1;
	}
}

int
main(int argc, char **argv)
{
	struct dma_test_ctx ctx = {};
	struct spdk_app_opts opts = {};
	int rc;

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "test_dma";
	opts.shutdown_cb =

		if ((rc = spdk_app_parse_args(argc, argv, &opts, "b:q:o:t:w:M:", NULL, parse_arg, print_usage)) !=
	SPDK_APP_PARSE_ARGS_SUCCESS) {
		exit(rc);
	}

	if (!verify_args()) {
		return -1;
	}

	ctx.bdev_name = g_bdev_name;

	rc = spdk_app_start(&opts, dma_test_start, &ctx);

	dma_test_cleanup(&ctx);

	spdk_app_fini();

	return rc;
}
