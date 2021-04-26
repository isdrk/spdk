/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation. All rights reserved.
 *   Copyright (c) Mellanox Technologies LTD. All rights reserved.
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

#include "spdk/dma.h"
#include "spdk/log.h"

int
spdk_dma_device_create(struct spdk_dma_device **_device, enum spdk_dma_device_type type,
		       struct spdk_dma_device_ctx *ctx)
{
	struct spdk_dma_device *device;

	assert(_device);

	device = calloc(1, sizeof(*device));
	if (!device) {
		SPDK_ERRLOG("Failed to allocate memory");
		return -ENOMEM;
	}
	TAILQ_INIT(&device->domains);
	if (ctx) {
		device->ctx = calloc(1, sizeof(*device->ctx));
		if (!device->ctx) {
			SPDK_ERRLOG("Failed to allocate memory");
			free(device);
			return -ENOMEM;
		}
		memcpy(device->ctx, ctx, sizeof(*device->ctx));
	}

	device->type = type;

	*_device = device;

	return 0;
}

int
spdk_dma_device_add_memory_domain(struct spdk_dma_memory_domain **_domain,
				  enum spdk_memory_domain_type type, struct spdk_dma_device *device, spdk_dma_fetch_data_cb fetch_cb)
{
	struct spdk_dma_memory_domain *domain;

	assert(domain);
	assert(device);

	domain = calloc(1, sizeof(*domain));
	if (!domain) {
		SPDK_ERRLOG("Failed to allocate memory");
		return -ENOMEM;
	}

	domain->type = type;
	domain->device = device;
	domain->fetch_cb = fetch_cb;
	domain->translate_cb_count = SPDK_MEMORY_DOMAIN_TYPE_MAX;
	domain->translate_cb = calloc((size_t)domain->translate_cb_count,
				      sizeof(spdk_dma_translate_data_cb));
	if (!domain->translate_cb) {
		SPDK_ERRLOG("Failed to allocate memory");
		free(domain);
		return -ENOMEM;
	}

	TAILQ_INSERT_TAIL(&device->domains, domain, link);

	return 0;
}

int spdk_dma_memory_domain_add_translation(struct spdk_dma_memory_domain *domain,
		enum spdk_memory_domain_type dst_type, spdk_dma_translate_data_cb translate_cb)
{
	assert(domain);
	if (dst_type >= domain->translate_cb_count) {
		SPDK_ERRLOG("Invalid domain type %d, max supported %d\n", dst_type, domain->translate_cb_count - 1);
		return -EINVAL;
	}

	/* TODO: warn if existing translation is overwritten? */
	domain->translate_cb[dst_type] = translate_cb;

	return 0;
}

void
spdk_dma_device_remove_memory_domain(struct spdk_dma_device *device,
				     struct spdk_dma_memory_domain *domain)
{
	assert(device);
	assert(domain);

	TAILQ_REMOVE(&device->domains, domain, link);
	free(domain->translate_cb);
	free(domain);
}

void
spdk_dma_device_destroy(struct spdk_dma_device *device)
{
	struct spdk_dma_memory_domain *domain, *domain_tmp;
	assert(device);
	TAILQ_FOREACH_SAFE(domain, &device->domains, link, domain_tmp) {
		spdk_dma_device_remove_memory_domain(device, domain);
	}

	free(device->ctx);
	free(device);
}

int
spdk_dma_fetch_data(struct spdk_dma_memory_domain *src_domain, void *src_domain_ctx,
		    struct spdk_dma_memory_domain *dst_domain, struct iovec *src_iov,
		    uint32_t src_iov_cnt, struct iovec *dst_iov, uint32_t dst_iov_cnt,
		    spdk_dma_fetch_data_cpl_cb cpl_cb, void *cpl_cb_arg)
{
	assert(src_domain);
	assert(dst_domain);
	assert(src_iov);
	assert(dst_iov);

	if (!src_domain->fetch_cb) {
		return -ENOTSUP;
	}

	return src_domain->fetch_cb(src_domain, src_domain_ctx, dst_domain, src_iov, src_iov_cnt, dst_iov,
				    dst_iov_cnt, cpl_cb, cpl_cb_arg);
}

int
spdk_dma_translate_data(struct spdk_dma_memory_domain *src_domain, void *src_domain_ctx,
			struct spdk_dma_memory_domain *dst_domain,
			struct spdk_dma_translation_context *dst_domain_ctx, void *addr,
			size_t len, struct spdk_dma_translation_result *result)
{
	assert(src_domain);
	assert(dst_domain);

	if (dst_domain->type >= src_domain->translate_cb_count) {
		SPDK_ERRLOG("Destination domain type %d is out of range of source domain type %d\n",
			    dst_domain->type, src_domain->translate_cb_count - 1);
		return -EINVAL;
	}
	if (!src_domain->translate_cb[dst_domain->type]) {
		SPDK_ERRLOG("Destination domain type %d is not supported\n", dst_domain->type);
		return -ENOTSUP;
	}

	return src_domain->translate_cb[dst_domain->type](src_domain, src_domain_ctx, dst_domain,
			dst_domain_ctx, addr, len, result);
}
