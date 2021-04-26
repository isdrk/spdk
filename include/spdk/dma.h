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


#ifndef SPDK_DMA_H
#define SPDK_DMA_H

#include "spdk/assert.h"
#include "spdk/queue.h"
#include "spdk/stdinc.h"

#ifdef __cplusplus
extern "C" {
#endif

enum spdk_dma_device_type {
	SPDK_DMA_DEVICE_TYPE_RDMA,
	SPDK_DMA_DEVICE_TYPE_DMA
};

enum spdk_memory_domain_type {
	SPDK_MEMORY_DOMAIN_TYPE_LOCAL = 0,
	SPDK_MEMORY_DOMAIN_TYPE_REMOTE,
	SPDK_MEMORY_DOMAIN_TYPE_RDMA,
	SPDK_MEMORY_DOMAIN_TYPE_MAX
};

SPDK_STATIC_ASSERT(SPDK_MEMORY_DOMAIN_TYPE_MAX > 0, "invalid domain type");

struct spdk_dma_memory_domain;

typedef void (*spdk_dma_fetch_data_cpl_cb)(void *ctx, void *iov, uint32_t iovcnt, int rc);

/**
 * Definition of function to fetch data from src_domain to dst_domain. Implementation of this function
 * must call \b cpl_cb only when it returns 0. All other return codes means failure.
 */
typedef int (*spdk_dma_fetch_data_cb)(struct spdk_dma_memory_domain *src_domain,
				      void *src_domain_ctx, struct spdk_dma_memory_domain *dst_domain, struct iovec *src_iov,
				      uint32_t src_iovcnt, struct iovec *dst_iov, uint32_t dst_iovcnt, spdk_dma_fetch_data_cpl_cb cpl_cb,
				      void *cpl_cb_arg);

enum spdk_dma_translation_result_type {
	/** Translation result is a pointer in the caller's memory domain */
	SPDK_DMA_TRANSLATION_RESULT_ADDR,
	/** Translation result is pair or local and remote memory keys which can be used
	 * by RDMA device */
	SPDK_DMA_TRANSLATION_RESULT_MKEY
};

struct spdk_dma_translation_result {
	/** size of this structure in bytes */
	size_t size;
	/* TODO: do we need to support iov ? */
	void *translation_addr;
	size_t translation_size;
	/* TODO: translation result type can be determined by dst_domain, type can be removed */
	enum spdk_dma_translation_result_type type;
	union {
		struct {
			uint32_t lkey;
			uint32_t rkey;
		} rdma;
	};
};

/* TODO: probably this structure can be part of memory domain */
struct spdk_dma_translation_context {
	/** size of this structure in bytes */
	size_t size;
	union {
		struct {
			/* Opaque handle for ibv_qp */
			void *ibv_qp;
		} rdma;
	};
};

typedef int (*spdk_dma_translate_data_cb)(struct spdk_dma_memory_domain *src_domain,
		void *src_domain_ctx, struct spdk_dma_memory_domain *dst_domain,
		struct spdk_dma_translation_context *dst_domain_ctx, void *addr, size_t len,
		struct spdk_dma_translation_result *result);

struct spdk_dma_memory_domain {
	enum spdk_memory_domain_type type;
	struct spdk_dma_device *device;
	spdk_dma_fetch_data_cb fetch_cb;
	uint32_t translate_cb_count;
	spdk_dma_translate_data_cb *translate_cb;
	TAILQ_ENTRY(spdk_dma_memory_domain) link;
};

struct spdk_dma_device_ctx {
	/** size of this structure in bytes */
	size_t size;
	union {
		struct {
			/* Opaque handle for ibv_pd */
			void *ibv_pd;
		} rdma;
	};
};

struct spdk_dma_device {
	enum spdk_dma_device_type type;
	TAILQ_HEAD(, spdk_dma_memory_domain) domains;
	struct spdk_dma_device_ctx *ctx;
};

/**
 * Creates DMA device of specified type. After creation, memory domains of different types
 * can be added to DMA device, they are used to translate data between.
 * \param device Double pointer to DMA device to be allocated by this function
 * \param type Type of the DMA device
 * \param ctx Optional DMA device context
 * \return 0 on succes, negated errno on failure
 */
int spdk_dma_device_create(struct spdk_dma_device **device, enum spdk_dma_device_type type,
			   struct spdk_dma_device_ctx *ctx);

/**
 * Create DMA memory domain and attach it to the specified DMA device.
 * \param domain Double pointer to memory domain to be allocated by this function
 * \param type type of the memory domain
 * \param device DMA device which memory domain is attached to
 * \param fetch_cb Optional callback to fetch data from the current memory domain to another memory domain,
 * used when the user calls \ref spdk_dma_fetch_data
 * \return 0 on succes, negated errno on failure
 */
int spdk_dma_device_add_memory_domain(struct spdk_dma_memory_domain **domain,
				      enum spdk_memory_domain_type type, struct spdk_dma_device *device, spdk_dma_fetch_data_cb fetch_cb);

/**
 * Add a callback to translate data from the memory domain to another memory domain of type \b dst_type.
 * \param domain Pointer to a memory domain which the callback will be attached to
 * \param dst_type Type of the destination memory domain
 * \param translate_cb Translation callback to be called when the user calls \ref spdk_dma_translate_data
 * \return 0 on succes, negated errno on failure
 */
int spdk_dma_memory_domain_add_translation(struct spdk_dma_memory_domain *domain,
		enum spdk_memory_domain_type dst_type, spdk_dma_translate_data_cb translate_cb);

/**
 * Remove specified memory domain from the device.
 * \param device DMA device
 * \param domain Memory domain
 */
void spdk_dma_device_remove_memory_domain(struct spdk_dma_device *device,
		struct spdk_dma_memory_domain *domain);

/**
 * Destroy DMA device and release all attached memory domains
 * \param device DMA device
 */
void spdk_dma_device_destroy(struct spdk_dma_device *device);

/**
 * Asynchronously fetch data which is described by \b src_domain and located in \b src_iov to a location
 * \b dst_iov in \b dst_domain memory domain.
 * \param src_domain Memory domain where data is located
 * \param src_domain_ctx User defined context
 * \param dst_domain Memory domain in which data should be fetched
 * \param src_iov Source data iov
 * \param src_iov_cnt The number of elements in \b src_iov
 * \param dst_iov Destination iov
 * \param dst_iov_cnt The number of elements in \b dst_iov
 * \param cpl_cb Completion callback
 * \param cpl_cb_arg Completion callback argument
 * \return 0 on success, negated errno on failure. fetch_cb implementation must only call the callback when 0
 * is returned
 */
int spdk_dma_fetch_data(struct spdk_dma_memory_domain *src_domain, void *src_domain_ctx,
			struct spdk_dma_memory_domain *dst_domain, struct iovec *src_iov, uint32_t src_iov_cnt,
			struct iovec *dst_iov, uint32_t dst_iov_cnt, spdk_dma_fetch_data_cpl_cb cpl_cb, void *cpl_cb_arg);

/**
 * Translate data which is described by \b src_domain and located in \b addr to form accessible by \b
 * dst_domain. Result of translation is stored in \b result, its content depends on the type of \b
 * dst_domain.
 * \param src_domain Memory domain where data is located
 * \param src_domain_ctx User defined context
 * \param dst_domain Memory domain in which data should be translated
 * \param dst_domain_ctx Ancillary data for dst_domain
 * \param addr Addres in \b src_domain
 * \param len Length of the data
 * \param result Translation result. Translation result is only valid if this function returns 0.
 * \return 0 on succes, negated errno on failure.
 */
int spdk_dma_translate_data(struct spdk_dma_memory_domain *src_domain, void *src_domain_ctx,
			    struct spdk_dma_memory_domain *dst_domain, struct spdk_dma_translation_context *dst_domain_ctx,
			    void *addr, size_t len, struct spdk_dma_translation_result *result);

#ifdef __cplusplus
}
#endif

#endif /* SPDK_DMA_H */
