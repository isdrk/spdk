/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
 *     * Neither the name of Intel Corporation nor the names of its
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

#include "spdk/log.h"
#include "spdk_internal/assert.h"
#include "spdk_internal/rdma.h"

static TAILQ_HEAD(, spdk_rdma_memory_domain) g_memory_domains = TAILQ_HEAD_INITIALIZER(
			g_memory_domains);
static pthread_mutex_t g_memory_domains_lock = PTHREAD_MUTEX_INITIALIZER;

struct spdk_rdma_memory_domain *
spdk_rdma_get_memory_domain(struct ibv_pd *pd)
{
	struct spdk_rdma_memory_domain *domain = NULL;
	struct spdk_memory_domain_ctx ctx;
	int rc;

	pthread_mutex_lock(&g_memory_domains_lock);

	TAILQ_FOREACH(domain, &g_memory_domains, link) {
		if (domain->pd == pd) {
			domain->ref++;
			pthread_mutex_unlock(&g_memory_domains_lock);
			return domain;
		}
	}

	domain = calloc(1, sizeof(*domain));
	if (!domain) {
		SPDK_ERRLOG("Memory allocation failed\n");
		pthread_mutex_unlock(&g_memory_domains_lock);
		return NULL;
	}

	domain->rdma_ctx.size = sizeof(domain->rdma_ctx);
	domain->rdma_ctx.ibv_pd = pd;
	ctx.size = sizeof(ctx);
	ctx.user_ctx = &domain->rdma_ctx;

	rc = spdk_memory_domain_create(&domain->domain, SPDK_DMA_DEVICE_TYPE_RDMA, &ctx,
				       SPDK_RDMA_DMA_DEVICE);
	if (rc) {
		SPDK_ERRLOG("Failed to create memory domain\n");
		free(domain);
		pthread_mutex_unlock(&g_memory_domains_lock);
		return NULL;
	}

	domain->pd = pd;
	domain->ref = 1;
	TAILQ_INSERT_TAIL(&g_memory_domains, domain, link);

	pthread_mutex_unlock(&g_memory_domains_lock);

	return domain;
}

struct spdk_rdma_memory_domain *
spdk_rdma_get_tcp_memory_domain(struct ibv_pd *pd)
{
	struct spdk_rdma_memory_domain *domain = NULL;
	struct spdk_memory_domain_ctx ctx;
	int rc;

	pthread_mutex_lock(&g_memory_domains_lock);

	TAILQ_FOREACH(domain, &g_memory_domains, link) {
		/* @todo: check type as well */
		if (domain->pd == pd) {
			domain->ref++;
			pthread_mutex_unlock(&g_memory_domains_lock);
			return domain;
		}
	}

	domain = calloc(1, sizeof(*domain));
	if (!domain) {
		SPDK_ERRLOG("Memory allocation failed\n");
		pthread_mutex_unlock(&g_memory_domains_lock);
		return NULL;
	}

	domain->rdma_ctx.size = sizeof(domain->rdma_ctx);
	domain->rdma_ctx.ibv_pd = pd;
	ctx.size = sizeof(ctx);
	ctx.user_ctx = &domain->rdma_ctx;

	rc = spdk_memory_domain_create(&domain->domain, SPDK_DMA_DEVICE_TYPE_RDMA_TCP, &ctx,
				       SPDK_RDMA_DMA_DEVICE);
	if (rc) {
		SPDK_ERRLOG("Failed to create memory domain\n");
		free(domain);
		pthread_mutex_unlock(&g_memory_domains_lock);
		return NULL;
	}

	domain->pd = pd;
	domain->ref = 1;
	TAILQ_INSERT_TAIL(&g_memory_domains, domain, link);

	pthread_mutex_unlock(&g_memory_domains_lock);

	return domain;
}

void
spdk_rdma_put_memory_domain(struct spdk_rdma_memory_domain *domain)
{
	if (!domain) {
		return;
	}

	pthread_mutex_lock(&g_memory_domains_lock);

	assert(domain->ref > 0);

	domain->ref--;

	if (domain->ref == 0) {
		spdk_memory_domain_destroy(domain->domain);
		TAILQ_REMOVE(&g_memory_domains, domain, link);
		free(domain);
	}

	pthread_mutex_unlock(&g_memory_domains_lock);
}
