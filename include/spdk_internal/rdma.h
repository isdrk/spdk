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

#ifndef SPDK_RDMA_H
#define SPDK_RDMA_H

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

/* Contains hooks definition */
#include "spdk/nvme.h"

struct spdk_rdma_qp_init_attr {
	void		       *qp_context;
	struct ibv_cq	       *send_cq;
	struct ibv_cq	       *recv_cq;
	struct ibv_srq	       *srq;
	struct ibv_qp_cap	cap;
	struct ibv_pd	       *pd;
};

struct spdk_rdma_send_wr_list {
	struct ibv_send_wr	*first;
	struct ibv_send_wr	*last;
};

struct spdk_rdma_qp {
	struct ibv_qp *qp;
	struct rdma_cm_id *cm_id;
	struct spdk_rdma_send_wr_list send_wrs;
};

struct spdk_rdma_mem_map;

union spdk_rdma_mr {
	struct ibv_mr	*mr;
	uint64_t	key;
};

enum SPDK_RDMA_TRANSLATION_TYPE {
	SPDK_RDMA_TRANSLATION_MR = 0,
	SPDK_RDMA_TRANSLATION_KEY
};

struct spdk_rdma_memory_translation {
	union spdk_rdma_mr mr_or_key;
	void *addr;
	uint8_t translation_type;
};

/**
 * Create RDMA provider specific qpair
 * \param cm_id Pointer to RDMACM cm_id
 * \param qp_attr Pointer to qpair init attributes
 * \return Pointer to a newly created qpair on success or NULL on failure
 */
struct spdk_rdma_qp *spdk_rdma_qp_create(struct rdma_cm_id *cm_id,
		struct spdk_rdma_qp_init_attr *qp_attr);

/**
 * Accept a connection request. Called by the passive side (NVMEoF target)
 * \param spdk_rdma_qp Pointer to a qpair
 * \param conn_param Optional information needed to establish the connection
 * \return 0 on success, errno on failure
 */
int spdk_rdma_qp_accept(struct spdk_rdma_qp *spdk_rdma_qp, struct rdma_conn_param *conn_param);

/**
 * Complete the connection process, must be called by the active
 * side (NVMEoF initiator) upon receipt RDMA_CM_EVENT_CONNECT_RESPONSE
 * \param spdk_rdma_qp Pointer to a qpair
 * \return 0 on success, errno on failure
 */
int spdk_rdma_qp_complete_connect(struct spdk_rdma_qp *spdk_rdma_qp);

/**
 * Destroy RDMA provider specific qpair
 * \param spdk_rdma_qp Pointer to qpair to be destroyed
 */
void spdk_rdma_qp_destroy(struct spdk_rdma_qp *spdk_rdma_qp);

/**
 * Disconnect a connection and transition assoiciated qpair to error state.
 * Generates RDMA_CM_EVENT_DISCONNECTED on both connection sides
 * \param spdk_rdma_qp Pointer to qpair to be destroyed
 */
int spdk_rdma_qp_disconnect(struct spdk_rdma_qp *spdk_rdma_qp);

/**
 * Append the given send wr structure to the qpair's outstanding sends list.
 * This function accepts either a single Work Request or the first WR in a linked list.
 *
 * \param spdk_rdma_qp Pointer to SPDK RDMA qpair
 * \param first Pointer to the first Work Request
 * \return true if there were no outstanding WRs before, false otherwise
 */
bool spdk_rdma_qp_queue_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr *first);

/**
 * Submit all queued Work Request
 * \param spdk_rdma_qp Pointer to SPDK RDMA qpair
 * \param bad_wr Stores a pointer to the first failed WR if this function return nonzero value
 * \return 0 on succes, errno on failure
 */
int spdk_rdma_qp_flush_send_wrs(struct spdk_rdma_qp *spdk_rdma_qp, struct ibv_send_wr **bad_wr);

/**
 * Create a memory map which is used to register Memory Regions and perform address -> memory
 * key translations
 *
 * \param pd Protection Domain which will be used to create Memory Regions
 * \param hooks Structure with hooks which is used to create Protection Domain or ger RKey
 * \return Pointer to memory map or NULL on failure
 */
struct spdk_rdma_mem_map *spdk_rdma_create_mem_map(struct ibv_pd *pd,
		struct spdk_nvme_rdma_hooks *hooks);

/**
 * Free previously allocated memory map
 *
 * \param map Pointer to memory map to free
 */
void spdk_rdma_free_mem_map(struct spdk_rdma_mem_map **map);

/**
 * Get a translation for the given address and length.
 *
 * Note: the user of this function should use address returned in \b translation structure
 *
 * \param qp Pointer to RDMA qpair
 * \param map Pointer to translation map
 * \param address Memory address for translation
 * \param length Length of the memory address
 * \param[in,out] translation Pointer to translation result to be filled by this function
 * \retval -EINVAL if translation is not found
 * \retval -ERANGE if requested address + length crosses Memory Region boundary
 * \retval 0 translation succeed
 */
int spdk_rdma_get_translation(struct spdk_rdma_qp *qp, struct spdk_rdma_mem_map *map, void *address,
			      size_t length, struct spdk_rdma_memory_translation *translation);

/**
 * Prototype of the function to be used for custom memory translation.
 *
 * \param qp Pointer to RDMA qpair
 * \param address Memory address for translation
 * \param length Length of the memory address
 * \param[in,out] translation Pointer to translation result to be filled by this function
 * \retval -EINVAL if translation is not found
 * \retval 0 translation succeed
 */
typedef int (*spdk_rdma_addr_translation_cb)(struct spdk_rdma_qp *qp, void *address, size_t length,
		struct spdk_rdma_memory_translation *translation);

/**
 * Register a custom translation method which will be used for every memory translation in runtime.
 *
 * This approach differs from callbacks defined in spdk_nvme_rdma_hooks structure, the callbacks
 * are only used to create Memory Regions, typically at initialization time.
 *
 * \param translation_cb Pointer to the translation function
 */
void spdk_rdma_register_translation_method(spdk_rdma_addr_translation_cb translation_cb);

#endif /* SPDK_RDMA_H */
