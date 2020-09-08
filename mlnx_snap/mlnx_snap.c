/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation. All rights reserved.
 *   Copyright (c) 2020 Mellanox Technologies LTD. All rights reserved.
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

#include "spdk/stdinc.h"

#include "spdk/likely.h"
#include "spdk/nvmf_transport.h"
#include "spdk/string.h"
#include "spdk/log.h"
#include "spdk/util.h"

#include "spdk_internal/assert.h"

//TODO: somehow get rid of this include - it contains _nvmf_subsystem_get_ns
#include "nvmf_internal.h"

#include <snap.h>
#include <snap_nvme.h>
#include <snap_dma.h>
#include <spdk/nvme_spec.h>
#include <spdk/nvmf_spec.h>


#include "devx_verbs.h"
#include "nvme_regs.h"
#include "mlnx_snap_utils.h"

struct nvmf_mlnx_snap_nvme_query_attr {
	/* Device Capabilites */
	uint32_t    max_namespaces;         /**< max number of namespaces support per SQ */
	uint16_t    max_reg_size;       /**< max size of the bar register area */
	uint32_t    max_emulated_cq_num;    /**< max number of CQs that can be emulated */
	uint32_t    max_emulated_sq_num;    /**< max number of SQs that can be emulated */
	uint32_t    max_emulated_pfs;    /**< max number of NVMe function that can be emulated */
};

struct nvmf_mlnx_snap_req;
struct nvmf_mlnx_snap_transport;
struct nvmf_mlnx_snap_emu;
struct nvmf_mlnx_snap_ctrlr;
struct nvmf_mlnx_snap_nvme_req;
struct nvmf_mlnx_snap_listener;
struct nvmf_mlnx_snap_qpair;
struct nvmf_mlnx_snap_poll_group;
struct nvmf_mlnx_snap_nvme_sq;

struct nvmf_mlnx_snap_nvme_cq {
	struct snap_nvme_cq *snap_cq;
	struct nvmf_mlnx_snap_ctrlr *ctrlr;

	uint8_t     phase;
	uint16_t    cqid;
	uint16_t    head;
	uint16_t    tail;
	uint16_t    size;
	uint16_t    irq_vector;
	uint64_t    dma_addr;

	TAILQ_HEAD(, nvmf_mlnx_snap_nvme_req) req_list;
	TAILQ_ENTRY(nvmf_mlnx_snap_nvme_cq) link;

	/* TODO: probably it can be replaced with counter */
	TAILQ_HEAD(,  nvmf_mlnx_snap_nvme_sq) sqs;

	TAILQ_ENTRY(nvmf_mlnx_snap_nvme_cq) pg_link;
	struct nvmf_mlnx_snap_poller *poller;
};

struct nvmf_mlnx_snap_req_resources {
	/* TODO: move cpl to nvmf_mlnx_snap_nvme_req if mr is not needed*/
	union nvmf_c2h_msg			*cpls;

	uint64_t *prp_list_base;
	struct iovec *iovs_base;
	/* Since each request uses preallocated memory for PRP list, we can store it's MR to avoid
	 * unnecessary translations */
	uint32_t       list_lkey;
	/* Memory allocated by requests */
	struct nvmf_mlnx_snap_nvme_req   *reqs;

	TAILQ_HEAD(, nvmf_mlnx_snap_nvme_req) free_req_list;
	TAILQ_HEAD(, nvmf_mlnx_snap_nvme_req) out_req_list;
};

struct nvmf_mlnx_snap_nvme_sq {
	struct snap_nvme_sq *snap_sq;
	struct snap_dma_q *dma_q;

	struct nvmf_mlnx_snap_ctrlr *ctrlr;
	/* sq is bound to qpair */
	struct nvmf_mlnx_snap_qpair *mqpair;
	struct nvmf_mlnx_snap_req_resources *resources;

	uint16_t    sqid;
	uint16_t    cqid;
	uint16_t    head;
	uint16_t    tail;
	uint16_t    size;
	uint32_t	dma_rkey;
	uint32_t	db_addr;
	uint64_t    dma_addr;

	TAILQ_ENTRY(nvmf_mlnx_snap_nvme_sq) link;

	struct nvmf_mlnx_snap_poll_group *pg;
};

struct nvmf_mlnx_snap_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct nvmf_mlnx_snap_ctrlr *ctrlr;
	TAILQ_ENTRY(nvmf_mlnx_snap_qpair) link;
	struct nvmf_mlnx_snap_nvme_cq *cq;
	struct nvmf_mlnx_snap_nvme_sq *sq;
	struct nvmf_mlnx_snap_poller *poller;
	//TODO: find a better way to save a pointer to this request
	//we have to go thour spdk_nvmf_tgt_new_qpair -> poll_group_add and
	//I don't see easy way to save it
	struct nvmf_mlnx_snap_nvme_req *create_sq_req;
	TAILQ_ENTRY(nvmf_mlnx_snap_qpair) poller_link;
	uint16_t qid;
};

typedef void (*nvmf_mlnx_snap_nvmf_cb_fn)(struct nvmf_mlnx_snap_nvme_req *mreq);


/** @prp: prp state which is used by the nvme_prp_rw() */
struct nvmf_mlnx_snap_prp_req {
	/**
	 * @prp.prp1: as defined by the NVMe spec
	 */
	uint64_t  prp1;
	/**
	 * @prp.prp2: as defined by the NVMe spec
	 */
	uint64_t  prp2;
	/**
	 * @prp.len: size of data to be read/written from/to prp list
	 */
	size_t    len;
	/**
	 * @prp.list_base: memory that holds list addreses
	 */
	uint64_t *list_base;
	/**
	 * @prp.list_idx: current address in the list that is being processed
	 */
	uint16_t       list_idx;
	uint16_t       list_size;
};

/**
 * @dma_cmd: describe dma operation that will be done by nvme_request_submit()
 *
 * DMA_TO_HOST: (data_buf + offset, len) write to (raddr, rkey)
 * DMA_FROM_HOST: (data_buf + offset, len)  read from (raddr, rkey)
 */
struct nvmf_mlnx_snap_dma_cmd {
	/**
	 * @dma_cmd.op: operation type
	 */
	enum spdk_nvme_data_transfer op;
	/**
	 * @dma_cmd.rkey: host rkey
	 */
	uint32_t rkey;
	/**
	 * @dma_cmd.raddr: address in the host memory
	 */
	uint64_t raddr;
	/**
	 * @dma_cmd.srcadd: address in the ARM memory
	 */
	void *srcaddr;

	/**
	 * @dma_cmd.offset: offset into data_buf
	 */
	uint64_t offset;
	/**
	 * @dma_cmd.len: how many bytes should be transferred
	 */
	size_t   len;

	/* lkey describing srcaddr */
	uint32_t lkey;
	/* Number of elements in iovs */
	uint16_t       iov_cnt;
	struct iovec *iovs;
	struct snap_dma_completion  dma_comp;
};

/**
 * struct nvme_async_req - NVMe async DMA request
 *
 * The request is used to copy data to or from the host memory
 * in a non-blocking, asynchronous way.
 *
 * The request is a low level building block which is used by
 * a higher level APIs such as nvme_prp_rw(), nvme_sgl_rw() and
 * by the following io driver functions:
 *  nvme_driver_write_prp_nb()
 *  nvme_driver_read_prp_nb()
 *  nvme_driver_write_sgl_nb()
 *  nvme_driver_read_sgl_nb()
 * to transfer data from or to the host memory.
 *
 * Request lifecycle:
 *
 *  - The request must be allocated. Because request may have private data
 *    use nvme_emu_request_size() to get true reqeust size.
 *  - Use nvme_emu_request_init() to initialize request.
 *  - Set &nvme_async_req.comp_cb and call nvme_prp_rw() or nvme_sgl_rw()
 *  - Or setup &nvme_async_req.dma_cmd and call nvme_emu_request_submit()
 *  - Use nvme_emu_request_reset() and free request's memory.
 */
struct nvmf_mlnx_snap_req {
	struct nvmf_mlnx_snap_prp_req prp;
	struct nvmf_mlnx_snap_dma_cmd dma_cmd;
};

/****** qpairs end *******/

enum nvmf_mlnx_snap_req_state {
	MLNX_SNAP_REQ_STATE_FREE = 0,
	MLNX_SNAP_REQ_STATE_NEW,
	MLNX_SNAP_REQ_STATE_NEED_BUFFER,
	MLNX_SNAP_REQ_STATE_TRANSFER_IN,
	MLNX_SNAP_REQ_STATE_TRANSFERRING_IN,
	MLNX_SNAP_REQ_STATE_READY_TO_EXEC,
	MLNX_SNAP_REQ_STATE_EXECUTING,
	MLNX_SNAP_REQ_STATE_EXECUTED,
	MLNX_SNAP_REQ_STATE_TRANSFER_OUT,
	MLNX_SNAP_REQ_STATE_TRANSFERRING_OUT,
	MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE,
	MLNX_SNAP_REQ_STATE_COMPLETED
};

struct nvmf_mlnx_snap_nvme_req {
	struct spdk_nvmf_request nvmf_req;
	struct nvmf_mlnx_snap_req snap_req;
	union nvmf_h2c_msg cmd;
	struct nvmf_mlnx_snap_nvme_sq	*sq;
	/* to be called when handling req_complete transport API */
	nvmf_mlnx_snap_nvmf_cb_fn     nvmf_comp_cb;

	enum nvmf_mlnx_snap_req_state state;
	TAILQ_ENTRY(nvmf_mlnx_snap_nvme_req) link;
	uint8_t nvmf_req_iovpos;
};

struct nvmf_mlnx_snap_ctrlr {
	struct nvmf_mlnx_snap_emu    *snap_emu;
	struct nvmf_mlnx_snap_qpair *admin_qpair;
	TAILQ_HEAD(, nvmf_mlnx_snap_qpair)	io_qpairs;

	/* arrays of pointers of num_queues size */
	struct nvmf_mlnx_snap_nvme_sq **sqs;
	struct nvmf_mlnx_snap_nvme_cq **cqs;

	struct spdk_nvmf_ctrlr *ctrlr;

	uint32_t	page_bits;
	uint32_t	page_size;
	uint16_t	cq_period;
	uint16_t	cq_max_count;
	uint32_t	num_queues;
	bool	destroying;
};

struct nvmf_mlnx_snap_sf {
	devx_ctx_t              sf;
	struct ibv_pd           *pd;

	uint32_t                dma_rkey;
};

struct nvmf_mlnx_snap_emu {
	uint32_t pci_func_num;
	struct snap_context *snap_ctx;
	struct snap_device *snap_dev;
	struct nvmf_mlnx_snap_sf *sf;
	struct nvmf_mlnx_snap_nvme_query_attr dev_caps;
	struct nvmf_mlnx_snap_listener	*listener;
	struct nvmf_mlnx_snap_ctrlr *mctrlr;
	struct spdk_mem_map			*map;
	pthread_mutex_t			lock;
	/* Vendor ID */
	uint16_t                     vid;
	/* Subsystem vendor ID*/
	uint16_t                     ssvid;
	struct nvmf_mlnx_snap_nvme_bar_instance          bar;
	struct {
		uint32_t curr_enabled : 1;
		uint32_t prev_enabled : 1;
		uint32_t flr_active : 1;
		uint32_t is_started : 1;
		uint32_t reserved : 28;
	} flags;
	char                         if_name[IFACE_MAX_LEN];
	char                         name[16];
};

struct nvmf_mlnx_snap_listener {
	const struct spdk_nvme_transport_id	*trid;
	struct nvmf_mlnx_snap_transport *mtransport;
	struct nvmf_mlnx_snap_emu *snap_emu;
	const struct spdk_nvmf_subsystem *subsystem;
	TAILQ_ENTRY(nvmf_mlnx_snap_listener)	link;
};

struct nvmf_mlnx_snap_ctx {
	struct snap_context *ctx;
	TAILQ_ENTRY(nvmf_mlnx_snap_ctx) link;
};

struct nvmf_mlnx_snap_conn_sched {
	struct nvmf_mlnx_snap_poll_group *next_admin_pg;
	struct nvmf_mlnx_snap_poll_group *next_io_pg;
};

struct nvmf_mlnx_snap_transport {
	struct spdk_nvmf_transport	transport;
	struct nvmf_mlnx_snap_conn_sched conn_sched;
	TAILQ_HEAD(, nvmf_mlnx_snap_ctx) snap_ctxs;
	TAILQ_HEAD(, nvmf_mlnx_snap_listener)	listeners;
	TAILQ_HEAD(, nvmf_mlnx_snap_poll_group)	poll_groups;

	pthread_mutex_t			lock;
};

struct nvmf_mlnx_snap_poller {
	struct nvmf_mlnx_snap_ctx		*context;
	struct nvmf_mlnx_snap_poll_group	*group;

	/* list of cqs attached to this poller */
	TAILQ_HEAD(,  nvmf_mlnx_snap_nvme_cq) cqs;
	/* list of qpair attached to this poller*/
	TAILQ_HEAD(, nvmf_mlnx_snap_qpair) qpairs;

	TAILQ_ENTRY(nvmf_mlnx_snap_poller)	link;
};

struct nvmf_mlnx_snap_poll_group {
	struct spdk_nvmf_transport_poll_group		group;
	/* list of pollers for each snap context */
	TAILQ_HEAD(, nvmf_mlnx_snap_poller)		pollers;
	TAILQ_ENTRY(nvmf_mlnx_snap_poll_group)		link;
};

static void nvmf_mlnx_snap_emu_destroy(struct nvmf_mlnx_snap_emu *snap_emu);
static int snap_emu_stop(struct nvmf_mlnx_snap_emu *snap_emu);
static int snap_emu_start(struct nvmf_mlnx_snap_emu *snap_emu);
static struct nvmf_mlnx_snap_emu *nvmf_mlnx_snap_emu_create(struct nvmf_mlnx_snap_listener
		*mlistener, const char *dev_name, uint32_t pf);
static void nvmf_mlnx_snap_resources_destroy(struct nvmf_mlnx_snap_req_resources *resources);
static int nvmf_mlnx_snap_dma_start_rw(struct nvmf_mlnx_snap_nvme_req *mreq);
static int nvmf_mlnx_snap_request_exec(struct nvmf_mlnx_snap_nvme_req *mreq);
static void nvmf_mlnx_snap_destroy_cq(struct nvmf_mlnx_snap_nvme_cq *cq);
static int nvmf_mlnx_snap_create_sq(struct nvmf_mlnx_snap_ctrlr *mctrlr, uint16_t sqid,
				    uint16_t cqid, uint16_t sqsize, uint64_t dma_addr);
static struct nvmf_mlnx_snap_qpair *nvmf_mlnx_snap_create_qpair_and_sq(
	struct nvmf_mlnx_snap_ctrlr *mctrlr, uint16_t sqid, uint16_t cqid, uint16_t sqsize,
	uint64_t dma_addr);
static int nvmf_mlnx_snap_create_cq(struct nvmf_mlnx_snap_ctrlr *mctrlr, uint16_t cqid,
				    uint16_t cqsize,
				    uint64_t dma_addr, uint16_t irq_vector);
static struct nvmf_mlnx_snap_qpair *nvmf_mlnx_snap_qpair_create(struct nvmf_mlnx_snap_ctrlr *mctrlr,
		uint16_t qid, uint16_t cqid, uint16_t sqid);
static void nvmf_mlnx_snap_close_qpair(struct spdk_nvmf_qpair *qpair,
				       spdk_nvmf_transport_qpair_fini_cb cb_fn, void *cb_args);
static void nvmf_mlnx_snap_destroy_qpair(struct nvmf_mlnx_snap_qpair *mqpair);
static void nvmf_mlnx_snap_destroy_sq(struct nvmf_mlnx_snap_nvme_sq *sq);
static void nvmf_mlnx_snap_ctrlr_destroy(struct nvmf_mlnx_snap_emu *snap_emu);

static void nvme_reg_cap_dump(uint64_t cap, char *dump);
static void nvme_reg_vs_dump(uint64_t vs, char *dump);
static void nvme_reg_cc_dump(uint64_t cc, char *dump);
static void nvme_reg_csts_dump(uint64_t csts, char *dump);
static void nvme_reg_aqa_dump(uint64_t aqa, char *dump);

static struct nvmf_mlnx_snap_nvme_register nvme_regs[] = {
	{ SNAP_NVME_REG_CAP,    8, SNAP_NVME_REG_RO, "CAP", "Controller Capabilities", nvme_reg_cap_dump },
	{ SNAP_NVME_REG_VS,     4, SNAP_NVME_REG_RO, "VS",  "Controller Version", nvme_reg_vs_dump },
	{ SNAP_NVME_REG_INTMS,  4, SNAP_NVME_REG_RW1S, "INTMS", "Interrupt Mask Set" },
	{ SNAP_NVME_REG_INTMC,  4, SNAP_NVME_REG_RW1C, "INTMC", "Interrupt Mask Clear" },
	{ SNAP_NVME_REG_CC,     4, SNAP_NVME_REG_RW,   "CC",    "Controller Configuration", nvme_reg_cc_dump },
	{ SNAP_NVME_REG_CSTS,   4, SNAP_NVME_REG_RO | SNAP_NVME_REG_RW1C, "CSTS", "Controller Status", nvme_reg_csts_dump },
	{ SNAP_NVME_REG_NSSR,   4, SNAP_NVME_REG_RW,   "NSSR", "NVM Subsystem Reset" },

	/* Adming Queue */
	{ SNAP_NVME_REG_AQA,    4, SNAP_NVME_REG_RW,   "AQA",  "Admin Queue Attributes", nvme_reg_aqa_dump },
	{ SNAP_NVME_REG_ASQ,    8, SNAP_NVME_REG_RW,   "ASQ",  "Admin Submission Queue Base Address" },
	{ SNAP_NVME_REG_ACQ,    8, SNAP_NVME_REG_RW,   "ACQ",  "Admin Completion Queue Base Address" },

	/* Opttional registers */
	{ SNAP_NVME_REG_CMBLOC, 4, SNAP_NVME_REG_RO,   "CMBLOC", "Controller Memory Buffer Location" },
	{ SNAP_NVME_REG_CMBSZ,  4, SNAP_NVME_REG_RO,   "CMBSZ",  "Controller Memory Buffer Size" },
	{ SNAP_NVME_REG_BPINFO, 4, SNAP_NVME_REG_RO,   "BPINFO", "Boot Partition Information" },
	{ SNAP_NVME_REG_BPRSEL, 4, SNAP_NVME_REG_RW,   "BPRSEL", "Boot Partition Select" },
	{ SNAP_NVME_REG_BPMBL,  4, SNAP_NVME_REG_RW,   "BPMBL",  "Boot Partition Memory Buffer Location" },
	{ SNAP_NVME_REG_LAST,   0, 0, 0, 0 }
};

uint64_t nvme_reg_get(struct nvmf_mlnx_snap_nvme_register *r, void *bar)
{
	char *p;

	p = (char *)bar + r->reg_base;
	return r->reg_size == 4 ? *(uint32_t *)p : *(uint64_t *)p;
}

void nvme_reg_set(struct nvmf_mlnx_snap_nvme_register *r, void *bar, uint64_t v)
{
	char *p;

	p = (char *)bar + r->reg_base;

	if (r->reg_size == 4) {
		*(uint32_t *)p = v;
	} else {
		*(uint64_t *)p = v;
	}
}

void nvme_reg_dump(struct nvmf_mlnx_snap_nvme_register *r, void *bar, bool user_mode)
{
	uint64_t val;
	char dump_priv[SNAP_NVME_REG_MAX_DUMP_FUNC_LEN] = {0};

	val = nvme_reg_get(r, bar);

	if (r->reg_dump_func) {
		r->reg_dump_func(val, dump_priv);
	}

	if (user_mode)
		printf("%-6s [%s, 0x%02x..0x%02x]: 0x%llx {%s}\n",
		       r->name, r->desc,
		       r->reg_base, r->reg_base + r->reg_size,
		       (unsigned long long)val,
		       dump_priv);
	else
		SPDK_NOTICELOG("%-6s [%s, 0x%02x..0x%02x]: 0x%llx {%s}\n",
			       r->name, r->desc,
			       r->reg_base, r->reg_base + r->reg_size,
			       (unsigned long long)val,
			       dump_priv);
}

void nvme_bar_dump(void *bar, unsigned len)
{
	int i;

	for (i = 0;
	     nvme_regs[i].reg_base != SNAP_NVME_REG_LAST && nvme_regs[i].reg_base < len;
	     i++) {
		nvme_reg_dump(&nvme_regs[i], bar, true);
	}
}

static void nvme_reg_cap_dump(uint64_t _cap, char *dump)
{
	union spdk_nvme_cap_register cap;

	cap.raw = _cap;
	snprintf(dump, SNAP_NVME_REG_MAX_DUMP_FUNC_LEN,
		 "MQES:%d CQR:%d AMS:%d TO:%d DSTRD:%d NSSRS:%d CSS:%d BPS:%d MPSMIN:%d MPSMAX:%d",
		 cap.bits.mqes, cap.bits.cqr, cap.bits.ams, cap.bits.to, cap.bits.dstrd, cap.bits.nssrs,
		 cap.bits.css, cap.bits.bps, cap.bits.mpsmin, cap.bits.mpsmax);
}

static void nvme_reg_vs_dump(uint64_t _vs, char *dump)
{
	union spdk_nvme_vs_register vs;

	vs.raw = (uint32_t)_vs;
	snprintf(dump, SNAP_NVME_REG_MAX_DUMP_FUNC_LEN,
		 "%d.%d.%d",
		 vs.bits.mjr, vs.bits.mnr, vs.bits.ter);
}

static void nvme_reg_cc_dump(uint64_t _cc, char *dump)
{
	union spdk_nvme_cc_register cc;

	cc.raw = (uint32_t)_cc;
	snprintf(dump, SNAP_NVME_REG_MAX_DUMP_FUNC_LEN,
		 "EN:%d CSS:%d MPS:%d AMS:%d SHN:%d IOSQES:%d IOCQES:%d",
		 cc.bits.en, cc.bits.css, cc.bits.css, cc.bits.mps, cc.bits.ams,
		 cc.bits.iosqes, cc.bits.iocqes);
}

static void nvme_reg_csts_dump(uint64_t _csts, char *dump)
{
	union spdk_nvme_csts_register csts;

	csts.raw = (uint32_t)_csts;
	snprintf(dump, SNAP_NVME_REG_MAX_DUMP_FUNC_LEN,
		 "RDY:%d CFS:%d SHST:%d NSSRO:%d PP:%d",
		 csts.bits.rdy, csts.bits.cfs, csts.bits.shst, csts.bits.nssro, csts.bits.pp);
}

static void nvme_reg_aqa_dump(uint64_t _aqa, char *dump)
{
	union spdk_nvme_aqa_register aqa;

	aqa.raw = (uint32_t)_aqa;
	snprintf(dump, SNAP_NVME_REG_MAX_DUMP_FUNC_LEN,
		 "ASQS:%d ACQS:%d",
		 aqa.bits.asqs, aqa.bits.acqs);
}

int nvme_bar_init_modify(nvme_bar_write_func_t bar_writer,
			 struct nvmf_mlnx_snap_nvme_bar_instance *bar, void *ucontext)
{
	struct nvmf_mlnx_snap_nvme_register *csts_reg = &nvme_regs[SNAP_NVME_REG_CSTS_IDX];
	int err;

	MLNX_SNAP_FATALV_COND(!memcmp(&bar->prev, &bar->curr, sizeof(bar->prev)),
			      "bar was already modified");

	if (!bar->curr.cc.bits.en) {
		/*
		 * Controller is not enabled, so we can safely unset the CFS bit
		 * and all other CSTS bits.
		 */
		bar->prev.csts.raw = bar->curr.csts.raw = 0;
		err = bar_writer(ucontext, &bar->curr.csts,
				 csts_reg->reg_base, csts_reg->reg_size);
		if (err) {
			SPDK_ERRLOG("Failed to reset CSTS bar register\n");
			return -1;
		}
		return 0;
	}

	if (!bar->curr.csts.bits.rdy) {
		/* Driver is already running and enabled controller. So pretend that
		 * we just got EN=1
		 */
		SPDK_NOTICELOG("CC.EN=1 and controller is not ready, scheduling enable controller\n");
		bar->prev.cc.bits.en = 0;
	} else {
		/* Controller is already up and running. But since we are (re)starting all
		 * state will be lost. It means that driver is going to reset controller
		 * when admin or io command timeouts. Raising CFS will help the driver
		 * to do the right thing.
		 */
		bar->curr.csts.bits.cfs = 1;
		bar->prev.csts = bar->curr.csts;
		/* since raising CFS is optional, don't check error code */
		bar_writer(ucontext, &bar->curr.csts, csts_reg->reg_base, csts_reg->reg_size);
		SPDK_NOTICELOG("CC.EN=1 and controller was running, raising CFS\n");
	}

	/* There was a shutdown request which did not complete. Make sure we complete it */
	if (bar->curr.cc.bits.shn && !bar->curr.csts.bits.shst) {
		SPDK_NOTICELOG("CC.SHN=1 and shutdown is not completed, scheduling shutdown\n");
		bar->prev.cc.bits.shn = 0;
	}

	return 0;
}

int nvme_bar_init(nvme_bar_read_func_t bar_reader, struct nvmf_mlnx_snap_nvme_bar_instance *bar,
		  void *ucontext)
{
	int err;
	int i;
	struct nvmf_mlnx_snap_nvme_register *reg;
	const int init_bar_regs[4] = {
		SNAP_NVME_REG_CAP_IDX,
		SNAP_NVME_REG_VS_IDX,
		SNAP_NVME_REG_CC_IDX,
		SNAP_NVME_REG_CSTS_IDX
	};
	const int init_bar_regs_sz = sizeof(init_bar_regs) /
				     sizeof(init_bar_regs[0]);

	memset(bar, 0, sizeof(*bar));

	bar->ucontext = ucontext;
	for (i = 0; i < init_bar_regs_sz; i++) {
		reg = &nvme_regs[init_bar_regs[i]];
		err = bar_reader(ucontext, (char *)&bar->curr + reg->reg_base,
				 reg->reg_base, reg->reg_size);
		if (err) {
			SPDK_ERRLOG("Failed to read initial value of %s\n", reg->name);
			return -1;
		}
		/* Dump initial state, it makes log analysis much easier */
		nvme_reg_dump(&nvme_regs[init_bar_regs[i]], &bar->curr, false);
	}

	MLNX_SNAP_FATALV_COND(err == 0, "bar_reader failed");
	MLNX_SNAP_FATALV_COND(bar->curr.cap.raw, "cap");
	MLNX_SNAP_FATALV_COND(bar->curr.cap.bits.mqes > 0, "cap_mqes");
	MLNX_SNAP_FATALV_COND(bar->curr.cap.bits.cqr == 1, "cap_cqr");
	MLNX_SNAP_FATALV_COND(bar->curr.cap.bits.nssrs == 0, "cap_nssrs");
	MLNX_SNAP_FATALV_COND(bar->curr.cap.bits.css == 1, "cap_css");
	MLNX_SNAP_FATALV_COND(bar->curr.cap.bits.bps == 0, "cap_bps");

	MLNX_SNAP_FATALV_COND(bar->curr.vs.raw, "vs");
	MLNX_SNAP_FATALV_COND(bar->curr.vs.bits.mjr == 1, "vs_mjr");

	memcpy(&bar->prev, &bar->curr, sizeof(bar->prev));
	return 0;
}

int nvme_bar_update(struct nvmf_mlnx_snap_nvme_bar_instance *bar, nvme_bar_read_func_t bar_reader,
		    nvme_reg_mod_cb_func_t cb)
{
	uint64_t cur_val, prev_val;
	int i;

	/* we do not suport cmb and boot */
	bar_reader(bar->ucontext, &bar->curr, 0, SNAP_NVME_REG_CMBLOC);
	/* do sanity check */
	/* TODO: write back fatal status */
	MLNX_SNAP_FATALV_COND(bar->curr.cap.raw == bar->prev.cap.raw, "ro cap");
	MLNX_SNAP_FATALV_COND(bar->curr.vs.raw == bar->prev.vs.raw, "ro vs");
	//do not check until we handle bar
	//nvmx_assertv_always(cur_bar.csts == prev_bar.csts, "ro csts");

	/* nothing is written to regs that we do not support */
	MLNX_SNAP_FATALV_COND(bar->curr.intms == 0, "intms not supported");
	MLNX_SNAP_FATALV_COND(bar->curr.intmc == 0, "intmc not supported");
	MLNX_SNAP_FATALV_COND(bar->curr.nssr == 0, "nssr is not supported");

	/* Controller Config changes should be handled last */
	for (i = SNAP_NVME_REG_ACQ_IDX; i >= SNAP_NVME_REG_CC_IDX; i--) {
		cur_val  = nvme_reg_get(&nvme_regs[i], &bar->curr);
		prev_val = nvme_reg_get(&nvme_regs[i], &bar->prev);
		if (cur_val != prev_val) {
			SPDK_NOTICELOG("reg %s changed, dumping\n", nvme_regs[i].name);
			nvme_reg_dump(&nvme_regs[i], &bar->curr, false);
			cb(&bar->curr, &nvme_regs[i], cur_val, prev_val);
			nvme_reg_set(&nvme_regs[i], &bar->prev, cur_val);
		}
	}

	/* just memcopy 80 bytes */
	memcpy(&bar->prev, &bar->curr, sizeof(bar->prev));
	return 0;
}


static int
nvmf_mlnx_snap_mem_notify(void *cb_ctx, struct spdk_mem_map *map,
			  enum spdk_mem_map_notify_action action,
			  void *vaddr, size_t size)
{
	struct ibv_pd *pd = cb_ctx;
	struct ibv_mr *mr;
	int rc;

	switch (action) {
	case SPDK_MEM_MAP_NOTIFY_REGISTER:
		mr = ibv_reg_mr(pd, vaddr, size,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
		if (mr == NULL) {
			SPDK_ERRLOG("ibv_reg_mr() failed\n");
			return -1;
		} else {
			rc = spdk_mem_map_set_translation(map, (uint64_t)vaddr, size, (uint64_t)mr);
		}
		break;
	case SPDK_MEM_MAP_NOTIFY_UNREGISTER:
		mr = (struct ibv_mr *)spdk_mem_map_translate(map, (uint64_t)vaddr, NULL);
		if (mr) {
			ibv_dereg_mr(mr);
		}
		rc = spdk_mem_map_clear_translation(map, (uint64_t)vaddr, size);
		break;
	default:
		SPDK_UNREACHABLE();
	}

	return rc;
}

static int
nvmf_mlnx_snap_check_contiguous_entries(uint64_t addr_1, uint64_t addr_2)
{
	/* Two contiguous mappings will point to the same address which is the start of the RDMA MR. */
	return addr_1 == addr_2;
}

const struct spdk_mem_map_ops g_nvmf_mlnx_snap_map_ops = {
	.notify_cb = nvmf_mlnx_snap_mem_notify,
	.are_contiguous = nvmf_mlnx_snap_check_contiguous_entries
};


const struct spdk_nvmf_transport_ops spdk_nvmf_transport_mlnx_snap;

static inline struct nvmf_mlnx_snap_transport *
nvmf_mlnx_snap_transport_get(struct spdk_nvmf_transport *transport)
{
	return SPDK_CONTAINEROF(transport, struct nvmf_mlnx_snap_transport, transport);
}

static inline struct nvmf_mlnx_snap_poll_group *
nvmf_mlnx_snap_poll_group_get(struct spdk_nvmf_transport_poll_group *poll_group)
{
	return SPDK_CONTAINEROF(poll_group, struct nvmf_mlnx_snap_poll_group, group);
}

static inline struct nvmf_mlnx_snap_qpair *
nvmf_mlnx_snap_qpair_get(struct spdk_nvmf_qpair *qpair)
{
	return SPDK_CONTAINEROF(qpair, struct nvmf_mlnx_snap_qpair, qpair);
}

static inline struct nvmf_mlnx_snap_nvme_req *
nvmf_mlnx_snap_req_get(struct spdk_nvmf_request *req)
{
	return SPDK_CONTAINEROF(req, struct nvmf_mlnx_snap_nvme_req, nvmf_req);
}

static inline void
nvmf_mlnx_snap_fail_req_by_dma_transfer(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct spdk_nvme_cpl *rsp = &mreq->nvmf_req.rsp->nvme_cpl;
	rsp->status.sc = SPDK_NVME_SC_DATA_TRANSFER_ERROR;
	rsp->status.dnr = 1;
	mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
}

static inline struct nvmf_mlnx_snap_nvme_req *
nvmf_mlnx_snap_qpair_sq_get_req(struct nvmf_mlnx_snap_nvme_sq *sq)
{
	struct nvmf_mlnx_snap_nvme_req *mreq;

	mreq = TAILQ_FIRST(&sq->resources->free_req_list);
	if (!mreq) {
		return NULL;
	}
	TAILQ_REMOVE(&sq->resources->free_req_list, mreq, link);
	TAILQ_INSERT_TAIL(&sq->resources->out_req_list, mreq, link);

	assert(mreq->state == MLNX_SNAP_REQ_STATE_FREE);

	memset(mreq->nvmf_req.cmd, 0, sizeof(*mreq->nvmf_req.cmd));
	memset(mreq->nvmf_req.rsp, 0, sizeof(*mreq->nvmf_req.rsp));
	mreq->nvmf_req_iovpos = 0;
	mreq->state = MLNX_SNAP_REQ_STATE_NEW;
	mreq->nvmf_comp_cb = NULL;

	return mreq;
}

static inline bool
nvmf_mlnx_snap_check_sqid_valid(struct nvmf_mlnx_snap_ctrlr *ctrl, uint16_t sqid)
{
	return sqid < ctrl->num_queues && ctrl->sqs[sqid] != NULL;
}

/* read from host bar space */
static int
snap_emu_mmio_read(struct nvmf_mlnx_snap_emu *snap_emu, void *buf,
		   uint32_t bar_addr, unsigned len)
{
	struct snap_nvme_device_attr attr = {};
	struct nvmf_mlnx_snap_nvme_bar *bar;
	int rc;

	rc = snap_nvme_query_device(snap_emu->snap_dev, &attr);
	if (rc) {
		return -1;
	}

	snap_emu->flags.curr_enabled = attr.enabled;
	if (snap_emu->flags.curr_enabled != snap_emu->flags.prev_enabled) {
		SPDK_DEBUGLOG(mlnx_snap, "enable change: %d -> %d\n", snap_emu->flags.prev_enabled,
			      snap_emu->flags.curr_enabled);
		if (!snap_emu->flags.curr_enabled && snap_emu->flags.prev_enabled) {
			bar = (struct nvmf_mlnx_snap_nvme_bar *)snap_emu->snap_dev->pci->bar.data;
			SPDK_NOTICELOG("FLR detected!!! cc = 0x%0x\n", bar->cc.raw);
			SPDK_DEBUGLOG(mlnx_snap, "FLR detected!!! cc = 0x%0x\n", bar->cc.raw);
			/*
			 * We must clear the cc.en bit in case the HW device state changed
			 * to disabled. In this case, probably caused by FLR, the host
			 * will eventually set the cc.en to 1 and SW controller might miss
			 * this reset/FLR case. This is not good since all the HW resources
			 * that where created on the NVMe function where destroyed but the
			 * parallel SW resources are still alive. SW must destroy (and
			 * later re-create) those resources to avoid having stale resources
			 * and to configure the HW correctly. For that we clear the cc.en
			 * bit so the NVMe SW controller will be notified and perform the
			 * needed destruction.
			 */
			bar->cc.bits.en = 0;
			snap_emu->flags.flr_active = 1;
		}
		snap_emu->flags.prev_enabled = snap_emu->flags.curr_enabled;
	}

	memcpy(buf, snap_emu->snap_dev->pci->bar.data + bar_addr, len);
	return 0;
}

/* write to host bar space */
static int
snap_emu_mmio_write(struct nvmf_mlnx_snap_emu *snap_emu, void *buf, uint32_t bar_addr, unsigned len)
{
	struct snap_device *sdev = snap_emu->snap_dev;
	struct snap_nvme_device_attr attr = {};
	int rc;

	/* copy old value to attributes */
	memcpy(attr.bar.regs, sdev->pci->bar.data, sdev->pci->bar.size);
	/* modify needed register values */
	memcpy(attr.bar.regs + bar_addr, buf, len);

	rc = snap_nvme_modify_device(sdev, SNAP_NVME_DEV_MOD_BAR, &attr);
	if (rc) {
		SPDK_ERRLOG("dev 0x%p modify SNAP BAR. ret=%d\n", snap_emu, rc);
		return -1;
	}

	return 0;
}

/*
 * Make sure that there is at least one send wqe in the QP.
 * This is a temporary solution until 'pending queue' mechanism
 * is implemented.
 * There are several problems here:
 * - blocking calling thread
 * - additional progress calls from inside progress. With a possibility
 *   of a deep recursion
 * - fairness both with respect to other ops on the same queue and with
 *   respect to other queues on the same thread context
 */
static inline void nvmf_mlnx_snap_dma_wait4tx(struct snap_dma_q *dma_q)
{
	while (dma_q->tx_available == 0) {
		snap_dma_q_progress(dma_q);
	}
}

/* send to host memory */
static void nvmf_mlnx_snap_nvme_emu_send(struct nvmf_mlnx_snap_nvme_sq *sq, void *src_buf,
		size_t len)
{
	struct snap_dma_q *dma_q = sq->dma_q;
	int ret;

	nvmf_mlnx_snap_dma_wait4tx(dma_q);
	ret = snap_dma_q_send_completion(dma_q, src_buf, len);
	assert(ret >= 0);
}


static inline void
nvmf_mlnx_snap_nvme_cq_inc_tail(struct nvmf_mlnx_snap_nvme_cq *cq)
{
	cq->tail++;
	if (cq->tail >= cq->size) {
		cq->tail = 0;
		cq->phase = !cq->phase;
	}
}

static void
nvmf_mlnx_snap_nvme_post_cqes(struct nvmf_mlnx_snap_nvme_cq *cq)
{
	struct nvmf_mlnx_snap_nvme_req *mreq, *tmp;
	struct nvmf_mlnx_snap_nvme_sq *sq;
	struct spdk_nvme_cpl *rsp;

	TAILQ_FOREACH_SAFE(mreq, &cq->req_list, link, tmp) {

		TAILQ_REMOVE(&cq->req_list, mreq, link);
		SPDK_DEBUGLOG(mlnx_snap, "Complete req %p, opc %x cid %hu\n", mreq,
			      mreq->nvmf_req.cmd->nvme_cmd.opc, mreq->nvmf_req.cmd->nvme_cmd.cid);
		sq = mreq->sq;
		rsp = &mreq->nvmf_req.rsp->nvme_cpl;

		rsp->status.p = cq->phase;
		rsp->sqid = cpu_to_le16(sq->sqid);
		rsp->sqhd = cpu_to_le16(sq->head);
		SPDK_DEBUGLOG(mlnx_snap,
			      "rsp: cdw0 %x, sqid %hu, sqhd %hu, cid %hu, status.raw %x, cmd->cdw10 %x\n",
			      rsp->cdw0, rsp->sqid, rsp->sqhd, rsp->cid, rsp->status_raw, mreq->nvmf_req.cmd->nvme_cmd.cdw10);
		nvmf_mlnx_snap_nvme_cq_inc_tail(cq);
		nvmf_mlnx_snap_nvme_emu_send(sq, (void *)rsp, sizeof(*rsp));

		SPDK_DEBUGLOG(mlnx_snap,
			      "CQ %u posted completion: tag %d status 0x%x phase %d sq_id %d sq_head 0x%x\n",
			      cq->cqid, rsp->cid, rsp->status_raw, le16_to_cpu(rsp->status.p), rsp->sqid, rsp->sqhd);
	}
}

static inline void
nvmf_mlnx_snap_nvme_req_push_to_cq(struct nvmf_mlnx_snap_nvme_cq *cq,
				   struct nvmf_mlnx_snap_nvme_req *mreq)
{
	assert(cq->cqid == mreq->sq->cqid);
	TAILQ_INSERT_TAIL(&cq->req_list, mreq, link);
	//TODO: implement batching - add ceq_entries in a list and post them in a batch ?
	nvmf_mlnx_snap_nvme_post_cqes(cq);
}

static void
nvmf_mlnx_snap_dma_done(struct snap_dma_completion *comp, int status)
{
	struct nvmf_mlnx_snap_nvme_req *mreq = SPDK_CONTAINEROF(comp, struct nvmf_mlnx_snap_nvme_req,
					       snap_req.dma_cmd.dma_comp);

	if (spdk_unlikely(status)) {
		SPDK_ERRLOG("Req %p, state %d, DMA failed, status %d\n", mreq, mreq->state, status);
		nvmf_mlnx_snap_fail_req_by_dma_transfer(mreq);
		nvmf_mlnx_snap_request_exec(mreq);
		return;
	}

	SPDK_DEBUGLOG(mlnx_snap, "mreq %p cid %u, DMA transfer completed\n", mreq,
		      mreq->nvmf_req.cmd->nvme_cmd.cid);

	if (mreq->nvmf_req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
		assert(mreq->state == MLNX_SNAP_REQ_STATE_TRANSFERRING_IN);
		mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_EXEC;
	} else {
		assert(mreq->state == MLNX_SNAP_REQ_STATE_TRANSFERRING_OUT);
		mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
	}
	nvmf_mlnx_snap_request_exec(mreq);
}

static int
nvmf_mlnx_snap_submit_dma_singe_req(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	int rc;
	struct ibv_mr *mr;
	struct nvmf_mlnx_snap_dma_cmd *dma_cmd = &mreq->snap_req.dma_cmd;
	void *src_addr = dma_cmd->srcaddr;
	uint64_t translation_len = mreq->snap_req.dma_cmd.len;

	assert(src_addr);

	nvmf_mlnx_snap_dma_wait4tx(mreq->sq->dma_q);

	/* TODO: optimize memory translation, in most cases there is not need to do it per each dma op */

	/* Considering lkey 0 is invalid */
	if (dma_cmd->lkey == 0) {
		mr = (struct ibv_mr *)spdk_mem_map_translate(mreq->sq->ctrlr->snap_emu->map,
				(uint64_t)src_addr, &translation_len);
		if (spdk_unlikely(!mr)) {
			SPDK_ERRLOG("Failed to get MR for address %p\n", src_addr);
			return -1;
		}

		dma_cmd->lkey = mr->lkey;
	}

	if (translation_len < mreq->snap_req.dma_cmd.len) {
		SPDK_ERRLOG("Memory translation failed\n");
		return -1;
	}

	switch (mreq->snap_req.dma_cmd.op) {
	case SPDK_NVME_DATA_CONTROLLER_TO_HOST:
		rc = snap_dma_q_write(mreq->sq->dma_q, src_addr + dma_cmd->offset,
				      dma_cmd->len, mr->lkey, dma_cmd->raddr,
				      dma_cmd->rkey, &dma_cmd->dma_comp);
		break;
	case SPDK_NVME_DATA_HOST_TO_CONTROLLER:
		rc = snap_dma_q_read(mreq->sq->dma_q, src_addr + mreq->snap_req.dma_cmd.offset,
				     dma_cmd->len, mr->lkey, dma_cmd->raddr,
				     dma_cmd->rkey, &dma_cmd->dma_comp);
		break;
	default:
		SPDK_ERRLOG("Unknown DMA cmd %d\n", dma_cmd->op);
		SPDK_UNREACHABLE();
	}

	return rc;
}

static inline int
nvmf_mlnx_snap_submit_dma_iov(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_dma_cmd *dma_cmd = &mreq->snap_req.dma_cmd;
	struct iovec *iov = dma_cmd->iovs;
	uint16_t i;
	int rc;

	assert(dma_cmd->iov_cnt > 0);

	for (i = 0; i < dma_cmd->iov_cnt; i++) {
		dma_cmd->raddr = (uint64_t)iov[i].iov_base;
		dma_cmd->len = iov[i].iov_len;

		rc = nvmf_mlnx_snap_submit_dma_singe_req(mreq);
		if (spdk_unlikely(rc)) {
			return rc;
		}

		dma_cmd->offset += dma_cmd->len;
	}

	return 0;
}

/* Used to r/w both PRP1 and PRP list */
static inline void
nvmf_mlnx_snap_prp_to_iov(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_dma_cmd *dma_cmd = &mreq->snap_req.dma_cmd;
	struct nvmf_mlnx_snap_ctrlr *mctrlr;
	size_t prp1_len, total_len, processed_len, prp_len;
	uint16_t iov_idx = 0, prp_idx = 0;
	uint64_t *prp_list;

	mctrlr = mreq->sq->ctrlr;
	prp1_len = mctrlr->page_size - (mreq->snap_req.prp.prp1 & (mctrlr->page_size - 1));
	processed_len = prp1_len;
	total_len = mreq->snap_req.prp.len;
	dma_cmd->iovs[0].iov_base = (void *)mreq->snap_req.prp.prp1;
	dma_cmd->iovs[0].iov_len = prp1_len;
	prp_list = mreq->snap_req.prp.list_base;

	while (prp_idx < mreq->snap_req.prp.list_size) {
		if (prp_idx + 1 == mreq->snap_req.prp.list_size) {
			/* last PRP entry, length is remaining length */
			prp_len = total_len - processed_len;
		} else {
			/* not last prp entry should have page_size length */
			prp_len = mctrlr->page_size;
		}

		if ((char *)dma_cmd->iovs[iov_idx].iov_base + dma_cmd->iovs[iov_idx].iov_len ==
		    (char *)prp_list[prp_idx]) {
			/* The current PRP entry is contig with the previous one, just increase iov len */
			dma_cmd->iovs[iov_idx].iov_len += prp_len;
			SPDK_DEBUGLOG(mlnx_snap, "mreq %p: merge prp_idx %hu with iov %hu, len %zu\n", mreq, prp_idx,
				      iov_idx, dma_cmd->iovs[iov_idx].iov_len);
		} else {
			/* Consume new iov */
			iov_idx++;
			dma_cmd->iovs[iov_idx].iov_base = (void *)prp_list[prp_idx];
			dma_cmd->iovs[iov_idx].iov_len = prp_len;
			SPDK_DEBUGLOG(mlnx_snap, "req %p: consume new iov %hu, 0x%x len %zu\n", mreq, iov_idx,
				      dma_cmd->iovs[iov_idx].iov_base, dma_cmd->iovs[iov_idx].iov_len);
		}
		prp_idx++;
		processed_len += prp_len;
	}

	dma_cmd->iov_cnt = iov_idx + 1;
	SPDK_DEBUGLOG(mlnx_snap, "mreq %p: filled %hu iovs\n", mreq, dma_cmd->iov_cnt);
	assert(processed_len == total_len);
}

static void
nvmf_mlnx_snap_dma_prp_list_read_done(struct snap_dma_completion *comp, int rc)
{
	struct nvmf_mlnx_snap_nvme_req *mreq = SPDK_CONTAINEROF(comp, struct nvmf_mlnx_snap_nvme_req,
					       snap_req.dma_cmd.dma_comp);
	struct nvmf_mlnx_snap_dma_cmd *dma_cmd;

	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("mreq %p cid %u: Error reading prp list, rc %d\n", mreq, mreq->cmd.nvme_cmd.cid,
			    rc);
		nvmf_mlnx_snap_fail_req_by_dma_transfer(mreq);
		nvmf_mlnx_snap_request_exec(mreq);
		return;
	}

	dma_cmd = &mreq->snap_req.dma_cmd;
	SPDK_DEBUGLOG(mlnx_snap, "mreq %p: prp list read done\n", mreq);
	nvmf_mlnx_snap_prp_to_iov(mreq);
	dma_cmd->dma_comp.count = mreq->snap_req.dma_cmd.iov_cnt;
	dma_cmd->dma_comp.func = nvmf_mlnx_snap_dma_done;
	dma_cmd->op = mreq->nvmf_req.xfer;
	dma_cmd->lkey = 0;
	dma_cmd->srcaddr = mreq->nvmf_req.iov[mreq->nvmf_req_iovpos].iov_base;
	rc = nvmf_mlnx_snap_submit_dma_iov(mreq);
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("mreq %p cid %u: Error writing iov, rc %d\n", mreq, mreq->cmd.nvme_cmd.cid,
			    rc);
		nvmf_mlnx_snap_fail_req_by_dma_transfer(mreq);
		nvmf_mlnx_snap_request_exec(mreq);
	}
}

static int
nvmf_mlnx_snap_dma_start_rw(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	size_t prp1_len, prp2_len;
	struct nvmf_mlnx_snap_ctrlr *mctrlr = mreq->sq->ctrlr;
	struct nvmf_mlnx_snap_dma_cmd *dma_cmd = &mreq->snap_req.dma_cmd;

	prp1_len = mctrlr->page_size - (mreq->snap_req.prp.prp1 & (mctrlr->page_size - 1));
	dma_cmd->raddr = mreq->snap_req.prp.prp1;
	dma_cmd->offset = 0;
	dma_cmd->srcaddr = mreq->nvmf_req.iov[mreq->nvmf_req_iovpos].iov_base;
	dma_cmd->op = mreq->nvmf_req.xfer;
	dma_cmd->len = prp1_len;
	dma_cmd->lkey = 0;
	dma_cmd->dma_comp.count = 1;
	dma_cmd->dma_comp.func = nvmf_mlnx_snap_dma_done;

	SPDK_DEBUGLOG(mlnx_snap, "mreq %p cid %u: xfer %d, prp1 %x, prp1 len %u, totlen %u \n", mreq,
		      mreq->cmd.nvme_cmd.cid,
		      mreq->snap_req.dma_cmd.op, mreq->snap_req.prp.prp1, prp1_len, mreq->snap_req.prp.len);
	// TODO: assume that transport buffer is contig for now
	// later we will need to add more complex logic to read parts of PRP
	if (mreq->snap_req.prp.len <= prp1_len) {
		/* Only 1 PRP */
		dma_cmd->len = prp1_len;
		SPDK_DEBUGLOG(mlnx_snap, "mreq %p: rw prp1\n", mreq);
		return nvmf_mlnx_snap_submit_dma_singe_req(mreq);
	}

	prp2_len = mreq->snap_req.prp.len - prp1_len;

	if (mreq->snap_req.prp.prp1 + prp1_len == mreq->snap_req.prp.prp2 &&
	    prp2_len <= mctrlr->page_size) {
		/* PRP2 is data, PRP1 and PRP2 are contig, handle them in 1 operation */
		dma_cmd->len = mreq->snap_req.prp.len;
		SPDK_DEBUGLOG(mlnx_snap, "mreq %p: prp1+prp2 contig\n", mreq);
		return nvmf_mlnx_snap_submit_dma_singe_req(mreq);
	}

	/* Fill iov[0] with PRP1. It will be used in the case of PRP list and not contig PRP2 */
	dma_cmd->iovs[0].iov_base = (void *)mreq->snap_req.prp.prp1;
	dma_cmd->iovs[0].iov_len = prp1_len;

	if (prp2_len <= mctrlr->page_size) {
		/* PRP1 and PRP2 are not contig. We should do at least 2 DMA operations */
		dma_cmd->iovs[1].iov_base = (void *)mreq->snap_req.prp.prp2;
		dma_cmd->iovs[1].iov_len = prp2_len;
		dma_cmd->iov_cnt = 2;
		dma_cmd->dma_comp.count = 2;
		SPDK_DEBUGLOG(mlnx_snap, "mreq %p: prp1+prp2 not contig\n", mreq);
		return nvmf_mlnx_snap_submit_dma_iov(mreq);
	}

	/* PRP2 is PRP list. First read PRP list, later PRP1 and PRP list entries will be
	 * handled together with possible operations merge */
	mreq->snap_req.prp.list_size = SPDK_CEIL_DIV((uint32_t)prp2_len, mctrlr->page_size);
	mreq->snap_req.prp.list_idx = 0;
	dma_cmd->len = sizeof(uint64_t) * mreq->snap_req.prp.list_size;
	dma_cmd->srcaddr = mreq->snap_req.prp.list_base;
	dma_cmd->raddr  = mreq->snap_req.prp.prp2;
	/* Will be changed to actual value when we get PRP List */
	dma_cmd->op = SPDK_NVME_DATA_HOST_TO_CONTROLLER;
	dma_cmd->lkey = mreq->sq->resources->list_lkey;
	dma_cmd->dma_comp.count = 1;
	dma_cmd->dma_comp.func = nvmf_mlnx_snap_dma_prp_list_read_done;

	SPDK_DEBUGLOG(mlnx_snap, "mreq %p cid %u: reading PRP list, entries %u, size %zu\n", mreq,
		      mreq->cmd.nvme_cmd.cid, mreq->snap_req.prp.list_size,
		      mreq->snap_req.dma_cmd.len);

	return nvmf_mlnx_snap_submit_dma_singe_req(mreq);
}

static inline void
nvmf_mlnx_snap_prepare_dma_param(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	mreq->snap_req.prp.prp1 = le64_to_cpu(mreq->cmd.nvme_cmd.dptr.prp.prp1);
	mreq->snap_req.prp.prp2 = le64_to_cpu(mreq->cmd.nvme_cmd.dptr.prp.prp2);
	mreq->snap_req.prp.len = mreq->nvmf_req.length;
}

static inline int
nvmf_mlnx_snap_io_cmd_length(struct nvmf_mlnx_snap_nvme_req *mreq)
{
//	uint64_t start_lba;
	uint16_t lba_count;
	uint32_t nsid;
	struct spdk_nvmf_ns *ns;
	struct spdk_nvme_cmd *cmd = &mreq->nvmf_req.cmd->nvme_cmd;
	struct nvmf_mlnx_snap_ctrlr *mctrlr = mreq->sq->ctrlr;
	struct spdk_nvme_cpl *rsp = &mreq->nvmf_req.rsp->nvme_cpl;

//	/* SLBA: CDW10 and CDW11 */
//	start_lba = from_le64(&cmd->cdw10);

	/* NLB: CDW12 bits 15:00, 0's based */
	lba_count = (uint16_t)((le32_to_cpu(cmd->cdw12) & 0xFFFFu) + 1);

	nsid = cmd->nsid;
	ns = _nvmf_subsystem_get_ns(mctrlr->ctrlr->subsys, nsid);

	if (spdk_unlikely(ns == NULL || ns->bdev == NULL)) {
		SPDK_ERRLOG("Unsuccessful query for nsid %u\n", cmd->nsid);
		rsp->status.sc = SPDK_NVME_SC_INVALID_NAMESPACE_OR_FORMAT;
		rsp->status.dnr = 1;
		return -1;
	}

	mreq->nvmf_req.length = lba_count * spdk_bdev_get_block_size(ns->bdev);
	if (spdk_unlikely(mreq->nvmf_req.length == 0 && mreq->nvmf_req.xfer != SPDK_NVME_DATA_NONE)) {
		SPDK_ERRLOG("Got 0 length with invalid xfer type %d\n", mreq->nvmf_req.xfer);
		rsp->status.sc = SPDK_NVME_SC_INVALID_NAMESPACE_OR_FORMAT;
		rsp->status.dnr = 1;
		return -1;
	}

	return 0;
}

static inline void
nvmf_mlnx_snap_admin_cmd_length(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	mreq->nvmf_req.length = 0;
	uint8_t feature;

	switch (mreq->cmd.nvme_cmd.opc) {
	case SPDK_NVME_OPC_IDENTIFY:
		mreq->nvmf_req.length = 4096;
		break;
	case SPDK_NVME_OPC_GET_LOG_PAGE:
		mreq->nvmf_req.length = (mreq->cmd.nvme_cmd.cdw10_bits.get_log_page.numdl + 1) * 4;
		break;
	case SPDK_NVME_OPC_GET_FEATURES:
		feature = mreq->nvmf_req.cmd->nvme_cmd.cdw10_bits.get_features.fid;
		switch (feature) {
		case SPDK_NVME_FEAT_HOST_IDENTIFIER:
			mreq->nvmf_req.length = sizeof(struct spdk_uuid);
		default:
			break;
		}
	default:
		break;
	}
}

static void
nvmf_mlnx_snap_sq_destroyed(void *ctx)
{
	struct nvmf_mlnx_snap_nvme_req *mreq = ctx;
	struct spdk_thread *thread;
	uint16_t sqid = le16_to_cpu(mreq->nvmf_req.cmd->nvme_cmd.cdw10_bits.delete_io_q.qid);

	if (mreq->sq->mqpair->qpair.group && mreq->sq->mqpair->qpair.group->thread) {
		thread = mreq->sq->mqpair->qpair.group->thread;
	} else {
		thread = spdk_get_thread();
	}

	assert(thread != NULL);

	if (spdk_get_thread() != thread) {
		/* We should complete this request in the context of admin qpair thread */
		spdk_thread_send_msg(thread, nvmf_mlnx_snap_sq_destroyed, mreq);
		return;
	}

	SPDK_DEBUGLOG(mlnx_snap, "sq %u deleted\n", sqid);

	/* Complete this request without involving NVMF layer */
	mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
	nvmf_mlnx_snap_request_exec(mreq);
}

static void
nvmf_mlnx_snap_delete_sq_cmd(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_ctrlr *mctrlr = mreq->sq->ctrlr;
	struct spdk_nvme_cpl *rsp = &mreq->nvmf_req.rsp->nvme_cpl;
	struct spdk_nvme_cmd *cmd = &mreq->nvmf_req.cmd->nvme_cmd;
	struct nvmf_mlnx_snap_nvme_sq *sq;
	struct nvmf_mlnx_snap_nvme_cq *cq;
	struct nvmf_mlnx_snap_qpair *mqpair;
	uint16_t sqid = le16_to_cpu(cmd->cdw10_bits.delete_io_q.qid);

	SPDK_DEBUGLOG(mlnx_snap, "deleting sqid %u\n", sqid);

	if (!sqid || !(sqid < mctrlr->num_queues && mctrlr->sqs[sqid] != NULL)) {
		SPDK_ERRLOG("Invalid sqid %u\n", sqid);
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.sct = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		rsp->status.dnr = 1;
		mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
		nvmf_mlnx_snap_request_exec(mreq);
		return;
	}

	sq = mctrlr->sqs[sqid];
	mqpair = sq->mqpair;

	/* SQ will be deleted when all requests are completed */
	spdk_nvmf_qpair_disconnect(&mqpair->qpair, nvmf_mlnx_snap_sq_destroyed, mreq);
}

static void
nvmf_mlnx_snap_create_sq_cmd(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_ctrlr *mctrlr = mreq->sq->ctrlr;
	struct spdk_nvme_cpl *rsp = &mreq->nvmf_req.rsp->nvme_cpl;
	struct spdk_nvme_cmd *cmd = &mreq->nvmf_req.cmd->nvme_cmd;
	struct spdk_nvmf_transport_opts *topts = &mctrlr->snap_emu->listener->mtransport->transport.opts;
	struct spdk_nvmf_transport *transport = &mctrlr->snap_emu->listener->mtransport->transport;
	struct nvmf_mlnx_snap_qpair *mqpair;
	uint16_t sqid = le16_to_cpu(cmd->cdw10_bits.create_io_q.qid);
	uint16_t sqsize = le16_to_cpu(cmd->cdw10_bits.create_io_q.qsize);
	uint16_t cqid = le16_to_cpu(cmd->cdw11_bits.create_io_sq.cqid);
	uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);

	assert(mreq->sq->sqid == 0);

	if (!cqid || !(cqid < mctrlr->num_queues && mctrlr->cqs[cqid] != NULL)) {
		SPDK_ERRLOG("Invalid cqid %u: max id %u, used? %s\n", cqid, mctrlr->num_queues,
			    mctrlr->cqs[cqid] == NULL ? "no" : "yes");
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.sct = SPDK_NVME_SC_COMPLETION_QUEUE_INVALID;
		rsp->status.dnr = 1;
		goto out;
	}

	if (!sqid || !(sqid < mctrlr->num_queues && mctrlr->sqs[sqid] == NULL)) {
		SPDK_ERRLOG("Invalid sqid %u: max id %u, used? %s\n", sqid, mctrlr->num_queues,
			    mctrlr->sqs[sqid] == NULL ? "no" : "yes");
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.sct = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		rsp->status.dnr = 1;
		goto out;
	}

	if (!sqsize || sqsize > topts->max_queue_depth) {
		SPDK_ERRLOG("Invalid sqsize %u, exceeds max value %u\n", sqsize, topts->max_queue_depth);
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.sct = SPDK_NVME_SC_INVALID_QUEUE_SIZE;
		rsp->status.dnr = 1;
		goto out;
	}

	if (!prp1 || (prp1 & (mctrlr->page_size - 1))) {
		SPDK_ERRLOG("Invalid prp1 alignment\n");
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.dnr = 1;
		goto out;
	}

	if (!cmd->cdw11_bits.create_io_sq.pc) {
		SPDK_ERRLOG("SQ DMA address must be physically contig\n");
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.dnr = 1;
		goto out;
	}

	//TODO: should we handle cmd->cdw11_bits.create_io_sq.qprio ?
	mqpair = nvmf_mlnx_snap_create_qpair_and_sq(mctrlr, sqid, cqid, sqsize + 1, prp1);
	if (!mqpair) {
		SPDK_ERRLOG("Failed to create SQ\n");
		rsp->status.sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
		rsp->status.dnr = 1;
		goto out;
	}

	mqpair->create_sq_req = mreq;
	spdk_nvmf_tgt_new_qpair(transport->tgt, &mqpair->qpair);

	return;

	/* Complete this request without involving NVMF layer */
out:
	mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
	nvmf_mlnx_snap_request_exec(mreq);
}

static void
nvmf_mlnx_snap_delete_cq_cmd(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_ctrlr *mctrlr = mreq->sq->ctrlr;
	struct spdk_nvme_cpl *rsp = &mreq->nvmf_req.rsp->nvme_cpl;
	struct spdk_nvme_cmd *cmd = &mreq->nvmf_req.cmd->nvme_cmd;
	struct nvmf_mlnx_snap_nvme_cq *cq;

	uint16_t cqid = cmd->cdw10_bits.delete_io_q.qid;

	SPDK_DEBUGLOG(mlnx_snap, "deleting cqid %u\n", cqid);

	if (!cqid || !(cqid < mctrlr->num_queues && mctrlr->cqs[cqid] != NULL)) {
		SPDK_ERRLOG("Invalid cqid %u\n", cqid);
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.sct = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		rsp->status.dnr = 1;
		goto out;
	}

	cq = mctrlr->cqs[cqid];
	if (!TAILQ_EMPTY(&cq->sqs)) {
		SPDK_ERRLOG("CQ %u contains active SQs\n", cqid);
		rsp->status.sc = SPDK_NVME_SC_INVALID_OPCODE;
		rsp->status.sct = SPDK_NVME_SC_INVALID_QUEUE_DELETION;
		rsp->status.dnr = 1;
		goto out;
	}

	nvmf_mlnx_snap_destroy_cq(cq);

out:
	mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
	nvmf_mlnx_snap_request_exec(mreq);
}

static void
nvmf_mlnx_snap_create_cq_cmd(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_ctrlr *mctrlr = mreq->sq->ctrlr;
	struct spdk_nvme_cpl *rsp = &mreq->nvmf_req.rsp->nvme_cpl;
	struct spdk_nvme_cmd *cmd = &mreq->nvmf_req.cmd->nvme_cmd;
	struct spdk_nvmf_transport_opts *topts = &mctrlr->snap_emu->listener->mtransport->transport.opts;
	uint16_t cqsize = le16_to_cpu(cmd->cdw10_bits.create_io_q.qsize);
	uint16_t cqid = le16_to_cpu(cmd->cdw10_bits.create_io_q.qid);
	bool irq_enabled = !!cmd->cdw11_bits.create_io_cq.ien;
	uint16_t irq_vector = irq_enabled ? cmd->cdw11_bits.create_io_cq.iv : 0;
	uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);
	int rc;

	if (!cqid || !(cqid < mctrlr->num_queues && mctrlr->cqs[cqid] == NULL)) {
		SPDK_ERRLOG("Invali cqid %u: max id %u, used? %s\n", cqid, mctrlr->num_queues,
			    mctrlr->cqs[cqid] == NULL ? "no" : "yes");
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.sct = SPDK_NVME_SC_COMPLETION_QUEUE_INVALID;
		rsp->status.dnr = 1;
		goto out;
	}

	if (!cqsize || cqsize > topts->max_queue_depth) {
		SPDK_ERRLOG("Invali cqsize %u, exceeds max value %u\n", cqsize, topts->max_queue_depth);
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.sct = SPDK_NVME_SC_INVALID_QUEUE_SIZE;
		rsp->status.dnr = 1;
		goto out;
	}

	if (!prp1 || (prp1 & (mctrlr->page_size - 1))) {
		SPDK_ERRLOG("Invali prp1 alignment\n");
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.dnr = 1;
		goto out;
	}

	if (!cmd->cdw11_bits.create_io_cq.pc) {
		SPDK_ERRLOG("CQ DMA address must be physically contig\n");
		rsp->status.sc = SPDK_NVME_SC_INVALID_FIELD;
		rsp->status.dnr = 1;
		goto out;
	}

	rc = nvmf_mlnx_snap_create_cq(mctrlr, cqid, cqsize + 1, prp1, irq_vector);
	if (rc) {
		SPDK_ERRLOG("Failed to create CQ\n");
		rsp->status.sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
		rsp->status.dnr = 1;
		goto out;
	}

	SPDK_DEBUGLOG(mlnx_snap, "CQ %u created\n", cqid);
	/* Complete this request without involving NVMF layer */
out:
	mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
	nvmf_mlnx_snap_request_exec(mreq);
}

static void
nvmf_mlnx_snap_identify_ctrlr_done(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct spdk_nvme_ctrlr_data *cdata;
	struct nvmf_mlnx_snap_qpair *mqpair;
	struct nvmf_mlnx_snap_emu *snap_emu;

	mqpair = nvmf_mlnx_snap_qpair_get(mreq->nvmf_req.qpair);
	assert(mqpair != NULL);
	snap_emu = mqpair->ctrlr->snap_emu;
	cdata = mreq->nvmf_req.data;
	memset(&cdata->sgls, 0, sizeof(cdata->sgls));
	cdata->vid = snap_emu->vid;
	cdata->ssvid = snap_emu->ssvid;


	nvmf_mlnx_snap_request_exec(mreq);
}

static void
nvmf_mlnx_snap_identify_cmd(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	uint8_t cns;
	struct spdk_nvme_cmd *cmd;

	cmd = &mreq->cmd.nvme_cmd;
	cns = cmd->cdw10_bits.identify.cns;

	if (cns == SPDK_NVME_IDENTIFY_CTRLR) {
		mreq->nvmf_comp_cb = nvmf_mlnx_snap_identify_ctrlr_done;
	}

	spdk_nvmf_request_exec(&mreq->nvmf_req);
}

static void
nvmf_mlnx_snap_json_rpc_req_cmd(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	assert(0);
}

static void
nvmf_mlnx_snap_json_rpc_resp_cmd(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	assert(0);
}

#if 0
void nvmf_mlnx_snap_cdata_init(struct spdk_nvmf_transport *transport,
			       struct spdk_nvmf_subsystem *subsystem,
			       struct spdk_nvmf_ctrlr_data *cdata)
{
	memset(&cdata->sgls, 0, sizeof(cdata->sgls));
}
#endif

static void
nvmf_mlnx_snap_admin_request_exec(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct spdk_nvme_cmd *cmd = &mreq->nvmf_req.cmd->nvme_cmd;

	SPDK_DEBUGLOG(mlnx_snap, "opc %x, mqpair %p, ctrlr %p\n", cmd->opc, mreq->sq->mqpair,
		      mreq->sq->mqpair->qpair.ctrlr);

	switch (cmd->opc) {
	case SPDK_NVME_OPC_DELETE_IO_SQ:
		nvmf_mlnx_snap_delete_sq_cmd(mreq);
		break;
	case SPDK_NVME_OPC_CREATE_IO_SQ:
		nvmf_mlnx_snap_create_sq_cmd(mreq);
		break;
	case SPDK_NVME_OPC_DELETE_IO_CQ:
		nvmf_mlnx_snap_delete_cq_cmd(mreq);
		break;
	case SPDK_NVME_OPC_CREATE_IO_CQ:
		nvmf_mlnx_snap_create_cq_cmd(mreq);
		break;
	case SPDK_NVME_OPC_IDENTIFY:
		nvmf_mlnx_snap_identify_cmd(mreq);
		break;
	case NVME_ADM_CMD_VS_JSON_RPC_2_0_REQ:
		nvmf_mlnx_snap_json_rpc_req_cmd(mreq);
		break;
	case NVME_ADM_CMD_VS_JSON_RPC_2_0_RSP:
		nvmf_mlnx_snap_json_rpc_resp_cmd(mreq);
		break;
	default:
		if (mreq->nvmf_req.qpair->ctrlr == NULL) {
			SPDK_ERRLOG("something wrong");
		}
		spdk_nvmf_request_exec(&mreq->nvmf_req);
	}
}

static int
nvmf_mlnx_snap_request_exec(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	enum nvmf_mlnx_snap_req_state prev_state;
	struct nvmf_mlnx_snap_nvme_sq *sq = mreq->sq;
	struct nvmf_mlnx_snap_ctrlr *mctrlr = sq->ctrlr;
	struct nvmf_mlnx_snap_transport *mtransport = mctrlr->snap_emu->listener->mtransport;
	struct nvmf_mlnx_snap_poll_group *mgroup = sq->pg;
	struct nvmf_mlnx_snap_qpair *mqpair = mreq->sq->mqpair;
	struct spdk_nvme_cmd *cmd = &mreq->nvmf_req.cmd->nvme_cmd;
	struct spdk_nvme_cpl *rsp = &mreq->nvmf_req.rsp->nvme_cpl;
	int rc;

	if (spdk_unlikely(mqpair->qpair.state != SPDK_NVMF_QPAIR_ACTIVE)) {
		TAILQ_REMOVE(&sq->resources->out_req_list, mreq, link);
		mreq->state = MLNX_SNAP_REQ_STATE_COMPLETED;
	}

	do {
		prev_state = mreq->state;

		SPDK_DEBUGLOG(mlnx_snap, "Req %p state %d\n", mreq, mreq->state);

		switch (mreq->state) {
		case MLNX_SNAP_REQ_STATE_FREE:
			break;
		case MLNX_SNAP_REQ_STATE_NEW:
			mreq->nvmf_req.xfer = cmd->opc & 0x3;
			rsp->cid = cmd->cid;

			/* Get request length */
			if (spdk_unlikely(sq->sqid == 0)) {
				nvmf_mlnx_snap_admin_cmd_length(mreq);
			} else {
				rc = nvmf_mlnx_snap_io_cmd_length(mreq);
				if (spdk_unlikely(rc)) {
					SPDK_ERRLOG("Req %p length error\n", mreq);
					rsp->status.sc = SPDK_NVME_SC_DATA_TRANSFER_ERROR;
					rsp->status.dnr = 1;
					mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
					break;
				}
			}

			SPDK_DEBUGLOG(mlnx_snap, "new req opc %x cid %hu length %u\n", cmd->opc, cmd->cid,
				      mreq->nvmf_req.length);
			if (spdk_unlikely(mreq->nvmf_req.length == 0)) {
				/* e.g. for OPC_FLUSH/async event */
				mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_EXEC;
				mreq->nvmf_req.xfer = SPDK_NVME_DATA_NONE;
				break;
			}
			if (spdk_unlikely(mreq->nvmf_req.xfer == SPDK_NVME_DATA_BIDIRECTIONAL)) {
				SPDK_ERRLOG("Req %p: invalid xfer type %d\n", mreq, mreq->nvmf_req.xfer);
				rsp->status.sc = SPDK_NVME_SC_INVALID_OPCODE;
				rsp->status.dnr = 1;
				mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
			}

			STAILQ_INSERT_TAIL(&mgroup->group.pending_buf_queue, &mreq->nvmf_req, buf_link);
			mreq->state = MLNX_SNAP_REQ_STATE_NEED_BUFFER;
			break;
		case MLNX_SNAP_REQ_STATE_NEED_BUFFER:
			if (&mreq->nvmf_req != STAILQ_FIRST(&mgroup->group.pending_buf_queue)) {
				/* This request needs to wait in line to obtain a buffer */
				break;
			}

			rc = spdk_nvmf_request_get_buffers(&mreq->nvmf_req, &mreq->sq->pg->group,
							   &mtransport->transport, mreq->nvmf_req.length);
			if (rc) {
				/* Keep this request in pending_buf_queue */
				// TODO: inc pending buf queue stats
				break;
			}
			mreq->nvmf_req.data = mreq->nvmf_req.iov[0].iov_base;

			STAILQ_REMOVE_HEAD(&mgroup->group.pending_buf_queue, buf_link);

			nvmf_mlnx_snap_prepare_dma_param(mreq);

			if (mreq->nvmf_req.xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
				mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_EXEC;
			} else {
				mreq->state = MLNX_SNAP_REQ_STATE_TRANSFER_IN;
			}
			break;
		case MLNX_SNAP_REQ_STATE_TRANSFER_IN:
			SPDK_DEBUGLOG(mlnx_snap, "start DMA in req opc %x cid %hu length %u\n", cmd->opc, cmd->cid,
				      mreq->nvmf_req.length);
			rc = nvmf_mlnx_snap_dma_start_rw(mreq);
			if (spdk_unlikely(rc)) {
				SPDK_ERRLOG("Req %p length error\n", mreq);
				nvmf_mlnx_snap_fail_req_by_dma_transfer(mreq);
				break;
			}
			mreq->state = MLNX_SNAP_REQ_STATE_TRANSFERRING_IN;
			break;
		case MLNX_SNAP_REQ_STATE_TRANSFERRING_IN:
			/* Waiting for DMA completion */
			break;
		case MLNX_SNAP_REQ_STATE_READY_TO_EXEC:
			mreq->state = MLNX_SNAP_REQ_STATE_EXECUTING;
			if (spdk_unlikely(mreq->sq->sqid == 0)) {
				/* we may want to catch some admin commands and process them in a different way */
				nvmf_mlnx_snap_admin_request_exec(mreq);
				break;
			}
			SPDK_DEBUGLOG(mlnx_snap, "start exec req opc %x cid %hu length %u\n", cmd->opc, cmd->cid,
				      mreq->nvmf_req.length);
			spdk_nvmf_request_exec(&mreq->nvmf_req);
			break;
		case MLNX_SNAP_REQ_STATE_EXECUTING:
			/* Waiting for NVMF completion */
			break;
		case MLNX_SNAP_REQ_STATE_EXECUTED:
			if (mreq->nvmf_req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER ||
			    mreq->nvmf_req.xfer == SPDK_NVME_DATA_NONE) {
				mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
			} else {
				mreq->state = MLNX_SNAP_REQ_STATE_TRANSFER_OUT;
			}
			break;
		case MLNX_SNAP_REQ_STATE_TRANSFER_OUT:
			SPDK_DEBUGLOG(mlnx_snap, "start DMA out req opc %x cid %hu length %u\n", cmd->opc, cmd->cid,
				      mreq->nvmf_req.length);
			rc = nvmf_mlnx_snap_dma_start_rw(mreq);
			if (spdk_unlikely(rc)) {
				SPDK_ERRLOG("Req %p length error\n", mreq);
				nvmf_mlnx_snap_fail_req_by_dma_transfer(mreq);
				break;
			}
			mreq->state = MLNX_SNAP_REQ_STATE_TRANSFERRING_OUT;
			break;
		case MLNX_SNAP_REQ_STATE_TRANSFERRING_OUT:
			/* Waiting for DMA completion */
			break;
		case MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE:
			/* Post completion to CQ */
			SPDK_DEBUGLOG(mlnx_snap, "Completing req opc %x cid %hu length %u\n", cmd->opc, cmd->cid,
				      mreq->nvmf_req.length);
			TAILQ_REMOVE(&sq->resources->out_req_list, mreq, link);
			nvmf_mlnx_snap_nvme_req_push_to_cq(mctrlr->cqs[mreq->sq->cqid], mreq);
			mreq->state = MLNX_SNAP_REQ_STATE_COMPLETED;
			break;
		case MLNX_SNAP_REQ_STATE_COMPLETED:
			TAILQ_INSERT_TAIL(&sq->resources->free_req_list, mreq, link);
			if (mreq->nvmf_req.xfer != SPDK_NVME_DATA_NONE) {
				spdk_nvmf_request_free_buffers(&mreq->nvmf_req, &mreq->sq->pg->group, &mtransport->transport);
			}
			mreq->state = MLNX_SNAP_REQ_STATE_FREE;
			break;
		}

	} while (prev_state != mreq->state);

	return 0;
}

static int
nvmf_mlnx_snap_process_sq(struct nvmf_mlnx_snap_nvme_sq *sq, struct spdk_nvme_cmd *cmd,
			  uint32_t len)
{
	struct nvmf_mlnx_snap_ctrlr *mctrlr = sq->ctrlr;
	uint32_t db_addr = sq->db_addr;
	uint16_t qid = (uint16_t)(db_addr - 0x1000) >> 3;
	struct nvmf_mlnx_snap_nvme_req *mreq;
	int rc;

	if (spdk_unlikely(!nvmf_mlnx_snap_check_sqid_valid(mctrlr, qid) || sq->sqid != qid)) {
		SPDK_ERRLOG("SQ DB write to non-existing queue. Expected sqid %hu, received %hu\n",
			    sq->sqid, qid);
		return -1;
	}

	sq->head = (sq->head + 1) % sq->size;

	mreq = nvmf_mlnx_snap_qpair_sq_get_req(sq);
	if (!mreq) {
		//TODO: handle this case, maybe queue this req?
		return -1;
	}
	//TODO: LE to host conversion?
	//TODO: I receive strange cid
	memcpy(&mreq->cmd.nvme_cmd, cmd, sizeof(*cmd));
	SPDK_DEBUGLOG(mlnx_snap,
		      "new cmd, sqid %u,  opc %x, cid %u, nsid %u prp1 %llx prp2 %llx, cdw10 %x\n", sq->sqid, cmd->opc,
		      cmd->cid, cmd->nsid,
		      cmd->dptr.prp.prp1, cmd->dptr.prp.prp2, cmd->cdw10);

	rc = nvmf_mlnx_snap_request_exec(mreq);

	return rc;
}

static void nvmf_mlnx_snap_nvme_dma_rx(struct snap_dma_q *dma_q, void *_cmd, uint32_t len,
				       uint32_t imm_data)
{
	struct nvmf_mlnx_snap_nvme_sq *sq = snap_dma_q_ctx(dma_q);
	// TODO: SQE mode is supported for now
	struct spdk_nvme_cmd *cmd = _cmd;

	nvmf_mlnx_snap_process_sq(sq, cmd, len);
}

static void
nvmf_mlnx_snap_destroy_cq(struct nvmf_mlnx_snap_nvme_cq *cq)
{
	uint16_t cqid = cq->cqid;
	struct nvmf_mlnx_snap_ctrlr *mctrlr = cq->ctrlr;

	SPDK_DEBUGLOG(mlnx_snap, "destroying CQ %u\n", cqid);

	if (cq->snap_cq) {
		SPDK_DEBUGLOG(mlnx_snap, "destroy NVME CQ %u\n", cqid);
		snap_nvme_destroy_cq(cq->snap_cq);
	}

	if (cq->poller) {
		TAILQ_REMOVE(&cq->poller->cqs, cq, pg_link);
		cq->poller = NULL;
	}

	free(mctrlr->cqs[cqid]);
	mctrlr->cqs[cqid] = NULL;

	SPDK_DEBUGLOG(mlnx_snap, "destroy CQ %u done\n", cqid);
}

static int
nvmf_mlnx_snap_schedule_cq(struct nvmf_mlnx_snap_transport *mtransport,
			   struct nvmf_mlnx_snap_nvme_cq *cq)
{
	struct nvmf_mlnx_snap_poll_group **mgroup, *result;
	struct nvmf_mlnx_snap_poller *mpoller, *tmp;

	if (cq->poller != NULL) {
		SPDK_ERRLOG("cqid %u already bound to poller\n", cq->cqid);
		return -1;
	}

	pthread_mutex_lock(&mtransport->lock);

	if (TAILQ_EMPTY(&mtransport->poll_groups)) {
		pthread_mutex_unlock(&mtransport->lock);
		return -1;
	}

	if (cq->cqid == 0) {
		mgroup = &mtransport->conn_sched.next_admin_pg;
	} else {
		mgroup = &mtransport->conn_sched.next_io_pg;
	}

	assert(*mgroup != NULL);
	result = *mgroup;

	TAILQ_FOREACH_SAFE(mpoller, &result->pollers, link, tmp) {
		if (mpoller->context->ctx == cq->ctrlr->snap_emu->snap_ctx) {
			cq->poller = mpoller;
			TAILQ_INSERT_HEAD(&mpoller->cqs, cq, pg_link);
			SPDK_DEBUGLOG(mlnx_snap, "cq %u set to pg %p, cpumask %s\n", cq->cqid, result,
				      spdk_cpuset_fmt(spdk_thread_get_cpumask(result->group.group->thread)));
			break;
		}
	}

	if (cq->poller == NULL) {
		SPDK_ERRLOG("Unable to find poll_group for cqid %u\n", cq->cqid);
		pthread_mutex_unlock(&mtransport->lock);
		return -1;
	}

	/* update conn sched to point to the next poll group */
	*mgroup = TAILQ_NEXT(*mgroup, link);
	if (*mgroup == NULL) {
		*mgroup = TAILQ_FIRST(&mtransport->poll_groups);
	}

	pthread_mutex_unlock(&mtransport->lock);

	return 0;
}

static int
nvmf_mlnx_snap_init_cq(struct nvmf_mlnx_snap_nvme_cq *cq)
{
	struct nvmf_mlnx_snap_emu *snap_emu;
	/* TODO: determine cq type */
	struct snap_nvme_cq_attr cq_attr = {
		.type = SNAP_NVME_RAW_MODE,
		.id = cq->cqid,
		.queue_depth = cq->size,
		.base_addr = cq->dma_addr,
		.msix = cq->irq_vector
	};

	snap_emu = cq->ctrlr->snap_emu;

	/* SPEC: 5.14.1.8 states that moderation only applies to the IO queues */
	if (cq->cqid) {
		cq_attr.cq_period = cq->ctrlr->cq_period;
		cq_attr.cq_max_count = cq->ctrlr->cq_max_count;
	}

	SPDK_NOTICELOG("Creating nvme CQ %hu, dev %p, dd_data %p\n", cq->cqid, snap_emu->snap_dev,
		       snap_emu->snap_dev->dd_data);
	cq->snap_cq = snap_nvme_create_cq(snap_emu->snap_dev, &cq_attr);
	if (!cq->snap_cq) {
		SPDK_ERRLOG("Failed to create snap_cq, qid %u, errno %d\n", cq->cqid, errno);
		return -1;
	}

	return 0;
}

static int
nvmf_mlnx_snap_create_cq(struct nvmf_mlnx_snap_ctrlr *mctrlr, uint16_t cqid, uint16_t cqsize,
			 uint64_t dma_addr, uint16_t irq_vector)
{
	struct nvmf_mlnx_snap_nvme_cq *cq;
	int rc;

	SPDK_DEBUGLOG(mlnx_snap, "Creating CQ %u, qsize %u\n", cqid, cqsize);

	if (cqid >= mctrlr->num_queues) {
		SPDK_ERRLOG("Invalid cqid %u, exceeds max num_queues %u\n", cqid, mctrlr->num_queues);
		return -1;
	}

	if (mctrlr->cqs[cqid] != NULL) {
		SPDK_ERRLOG("cqid %u already in use\n", cqid);
		return -1;
	}

	mctrlr->cqs[cqid] = calloc(1, sizeof(struct nvmf_mlnx_snap_nvme_cq));
	if (!mctrlr->cqs[cqid]) {
		SPDK_ERRLOG("Memory allocation failed\n");
		return -1;
	}

	cq = mctrlr->cqs[cqid];

	cq->size = cqsize;
	cq->dma_addr = dma_addr;
	cq->cqid = cqid;
	cq->ctrlr = mctrlr;
	cq->phase = 1;
	cq->irq_vector = irq_vector;
	TAILQ_INIT(&cq->sqs);
	TAILQ_INIT(&cq->req_list);

	rc = nvmf_mlnx_snap_init_cq(cq);
	if (rc) {
		SPDK_ERRLOG("Failed to init cqid %u\n", cqid);
		nvmf_mlnx_snap_destroy_cq(cq);
		return -1;
	}

	SPDK_DEBUGLOG(mlnx_snap, "scheduling cq %u\n", cqid);
	rc = nvmf_mlnx_snap_schedule_cq(mctrlr->snap_emu->listener->mtransport, cq);
	if (rc) {
		SPDK_ERRLOG("Failed to schedule cqid %u\n", cqid);
		nvmf_mlnx_snap_destroy_cq(cq);
		return -1;
	}

	return 0;
}

static void
nvmf_mlnx_snap_destroy_sq(struct nvmf_mlnx_snap_nvme_sq *sq)
{
	uint16_t sqid = sq->sqid;
	struct nvmf_mlnx_snap_ctrlr *mctrlr = sq->ctrlr;
	struct nvmf_mlnx_snap_nvme_req *mreq, *tmp_mreq;

	SPDK_DEBUGLOG(mlnx_snap, "destroying SQ %u\n", sqid);

	if (sq->dma_q) {
		SPDK_DEBUGLOG(mlnx_snap, "destroy DMA q, sq %u\n", sqid);
		snap_dma_q_destroy(sq->dma_q);
	}

	if (sq->snap_sq) {
		SPDK_DEBUGLOG(mlnx_snap, "destroy NVME q, sq %u\n", sqid);
		snap_nvme_destroy_sq(sq->snap_sq);
	}

	if (!TAILQ_EMPTY(&sq->resources->out_req_list)) {
		TAILQ_FOREACH_SAFE(mreq, &sq->resources->out_req_list, link, tmp_mreq) {
			/* qpair should be in inactive state and request will be freed */
			nvmf_mlnx_snap_request_exec(mreq);
		}
	}

	if (sq->resources) {
		SPDK_DEBUGLOG(mlnx_snap, "destroy resources, sq %u\n", sqid);
		nvmf_mlnx_snap_resources_destroy(sq->resources);
	}

	free(mctrlr->sqs[sqid]);
	mctrlr->sqs[sqid] = NULL;

	SPDK_DEBUGLOG(mlnx_snap, "destroy SQ %u done\n", sqid);
}

static int
nvmf_mlnx_snap_init_sq(struct nvmf_mlnx_snap_nvme_sq *sq)
{
	struct nvmf_mlnx_snap_emu *snap_emu = sq->ctrlr->snap_emu;
	/* TODO: determine sq type */
	struct snap_nvme_sq_attr sq_attr = {
		.type = SNAP_NVME_RAW_MODE,
		.id = sq->sqid,
		.queue_depth = sq->size,
		.base_addr = sq->dma_addr,
		.cq = sq->ctrlr->cqs[sq->cqid]->snap_cq,
	};
	struct snap_dma_q_create_attr dma_attr = {
		.tx_qsize = sq->size,
		.rx_qsize = sq->size,
		.tx_elem_size = 16,
		.rx_elem_size = 64,
		.uctx = sq,
		.rx_cb = nvmf_mlnx_snap_nvme_dma_rx
	};
	struct snap_nvme_device *nvme_dev = (struct snap_nvme_device *)snap_emu->snap_dev->dd_data;
	int rc;

	sq->tail = 0;
	sq->head = 0;

	SPDK_NOTICELOG("Creating nvme SQ %u, dev %p\n", sq->sqid, snap_emu->snap_dev);
	sq->snap_sq = snap_nvme_create_sq(snap_emu->snap_dev, &sq_attr);
	if (!sq->snap_sq) {
		SPDK_ERRLOG("Failed to create snap_sq, sqid %u, errno %d\n", sq->sqid, errno);
		return -1;
	}

	sq->dma_q = snap_dma_q_create(snap_emu->sf->pd, &dma_attr);
	if (!sq->dma_q) {
		SPDK_ERRLOG("Failed create snap dma queue, sqid %u, errno %d\n", sq->sqid, errno);
		return -1;
	}

	memset(&sq_attr, 0, sizeof(sq_attr));

	sq_attr.qp = snap_dma_q_get_fw_qp(sq->dma_q);
	if (!sq_attr.qp) {
		SPDK_ERRLOG("Failed to get fw qp, sqid %u\n", sq->sqid);
		return -1;
	}
	sq_attr.state = SNAP_NVME_SQ_STATE_RDY;

	rc = snap_nvme_modify_sq(sq->snap_sq, SNAP_NVME_SQ_MOD_QPN | SNAP_NVME_SQ_MOD_STATE, &sq_attr);
	if (rc) {
		SPDK_ERRLOG("Failed to modify SQ, sqid %u, rc=%d\n", sq->sqid, rc);
		return -1;
	}

	memset(&sq_attr, 0, sizeof(sq_attr));
	rc = snap_nvme_query_sq(sq->snap_sq, &sq_attr);
	if (rc) {
		SPDK_ERRLOG("Failed to query SQ, sqid %u, rc %d\n", sq->sqid, rc);
		return -1;
	}

	sq->db_addr = nvme_dev->db_base + sq->sqid * 8;
	if (sq_attr.emulated_device_dma_mkey) {
		sq->dma_rkey = sq_attr.emulated_device_dma_mkey;
	} else {
		sq->dma_rkey = snap_emu->snap_dev->dma_rkey;
	}

	return 0;
}

static void
nvmf_mlnx_snap_resources_destroy(struct nvmf_mlnx_snap_req_resources *resources)
{
	spdk_free(resources->prp_list_base);
	free(resources->iovs_base);
	free(resources->cpls);
	free(resources->reqs);
	free(resources);
}

static int
nvmf_mlnx_snap_resources_create(struct nvmf_mlnx_snap_ctrlr *mctrlr,
				struct nvmf_mlnx_snap_nvme_sq *sq, uint16_t num_reqs)
{
	struct nvmf_mlnx_snap_nvme_req *req;
	struct nvmf_mlnx_snap_req_resources *resources;
	struct spdk_nvmf_transport_opts *topts;
	struct ibv_mr *list_mr;
	uint16_t i;
	size_t prp_list_base_size, prp_list_total_size;

	topts = &mctrlr->snap_emu->listener->mtransport->transport.opts;

	resources = calloc(1, sizeof(*resources));
	if (!resources) {
		SPDK_ERRLOG("Failed to allocate resources\n");
		return -1;
	}
	resources->cpls = calloc(num_reqs, sizeof(union nvmf_c2h_msg));
	if (!resources->cpls) {
		SPDK_ERRLOG("Failed to allocate cpls\n");
		nvmf_mlnx_snap_resources_destroy(resources);
		return -1;
	}

	prp_list_base_size = sizeof(uint64_t) * topts->max_io_size / mctrlr->page_size;
	prp_list_total_size = num_reqs * prp_list_base_size;
	resources->prp_list_base = spdk_zmalloc(num_reqs * prp_list_base_size, 4096, 0,
						SPDK_ENV_SOCKET_ID_ANY,
						SPDK_MALLOC_DMA);
	if (!resources->prp_list_base) {
		SPDK_ERRLOG("Failed to allocate prp_list_base\n");
		nvmf_mlnx_snap_resources_destroy(resources);
		return -1;
	}

	list_mr = (struct ibv_mr *)spdk_mem_map_translate(mctrlr->snap_emu->map,
			(uint64_t)resources->prp_list_base, &prp_list_total_size);
	if (!list_mr) {
		SPDK_ERRLOG("Failed to get list_base MR\n");
		nvmf_mlnx_snap_resources_destroy(resources);
		return -1;
	}

	resources->list_lkey = list_mr->lkey;

	resources->iovs_base = calloc(num_reqs * (prp_list_base_size + 1), sizeof(struct iovec));
	if (!resources->iovs_base) {
		SPDK_ERRLOG("Failed to allocate iovs\n");
		nvmf_mlnx_snap_resources_destroy(resources);
		return -1;
	}

	resources->reqs = calloc(num_reqs, sizeof(struct nvmf_mlnx_snap_nvme_req));
	if (!resources->reqs) {
		SPDK_ERRLOG("Failed to allocate requests\n");
		nvmf_mlnx_snap_resources_destroy(resources);
		return -1;
	}

	TAILQ_INIT(&resources->free_req_list);
	TAILQ_INIT(&resources->out_req_list);

	for (i = 0; i < num_reqs; i++) {
		req = &resources->reqs[i];
		req->sq = sq;
		TAILQ_INSERT_TAIL(&(resources->free_req_list), req, link);

		req->snap_req.prp.list_base = (uint64_t *)(((uint8_t *)resources->prp_list_base) + i *
					      prp_list_base_size);
		req->snap_req.dma_cmd.iovs = &resources->iovs_base[i * (prp_list_base_size + 1)];
		req->snap_req.dma_cmd.rkey = sq->dma_rkey;
		req->state = MLNX_SNAP_REQ_STATE_FREE;

		req->nvmf_req.rsp = &resources->cpls[i];
		req->nvmf_req.cmd = &req->cmd;
		req->nvmf_req.qpair = &sq->mqpair->qpair;
	}

	sq->resources = resources;

	return 0;
}

static struct nvmf_mlnx_snap_qpair *
nvmf_mlnx_snap_create_qpair_and_sq(struct nvmf_mlnx_snap_ctrlr *mctrlr, uint16_t sqid,
				   uint16_t cqid,
				   uint16_t sqsize, uint64_t dma_addr)
{
	struct nvmf_mlnx_snap_qpair *mqpair;
	struct nvmf_mlnx_snap_nvme_sq *sq;
	int rc;

	rc = nvmf_mlnx_snap_create_sq(mctrlr, sqid, cqid, sqsize, dma_addr);
	if (rc) {
		return NULL;
	}

	sq = mctrlr->sqs[sqid];
	assert(sq);

	mqpair = nvmf_mlnx_snap_qpair_create(mctrlr, sqid, cqid, sqid);
	if (!mqpair) {
		nvmf_mlnx_snap_destroy_sq(sq);
		SPDK_ERRLOG("Failed to create %s qpair\n", sqid ? "IO" : "admin");
		return NULL;
	}

	/* For every CREATE SQ command we send additional FABRIC_CONNECT command which consumes
	 * 1 request. So increment sqsize by 1 */
	rc =  nvmf_mlnx_snap_resources_create(sq->ctrlr, sq, sq->size + 1);
	if (rc) {
		SPDK_ERRLOG("Failed to init create sq request, sqid %u\n", sqid);
		nvmf_mlnx_snap_destroy_qpair(mqpair);
		return NULL;
	}

	return mqpair;
}

static int
nvmf_mlnx_snap_create_sq(struct nvmf_mlnx_snap_ctrlr *mctrlr, uint16_t sqid, uint16_t cqid,
			 uint16_t sqsize, uint64_t dma_addr)
{
	struct nvmf_mlnx_snap_nvme_sq *sq;
	int rc;

	SPDK_DEBUGLOG(mlnx_snap, "Creating SQ %u with CQ %i, qsize %u\n", sqid, cqid, sqsize);

	if (sqid >= mctrlr->num_queues) {
		SPDK_ERRLOG("Invalid sqid %u, excced max num_queues %u\n", sqid, mctrlr->num_queues);
		return -1;
	}

	if (mctrlr->sqs[sqid] != NULL) {
		SPDK_ERRLOG("sqid %u already in use\n", sqid);
		return -1;
	}

	mctrlr->sqs[sqid] = calloc(1, sizeof(struct nvmf_mlnx_snap_nvme_sq));
	if (!mctrlr->sqs[sqid]) {
		SPDK_ERRLOG("Memory allocation failed\n");
		return -1;
	}

	sq = mctrlr->sqs[sqid];
	assert(sq);

	sq->size = sqsize;
	sq->dma_addr = dma_addr;
	sq->sqid = sqid;
	sq->cqid = cqid;
	sq->ctrlr = mctrlr;

	rc = nvmf_mlnx_snap_init_sq(sq);
	if (rc) {
		SPDK_ERRLOG("Failed to init sqid, %u\n", sqid);
		nvmf_mlnx_snap_destroy_sq(sq);
		return -1;
	}

	return 0;
}

static struct nvmf_mlnx_snap_qpair *
nvmf_mlnx_snap_qpair_create(struct nvmf_mlnx_snap_ctrlr *mctrlr, uint16_t qid, uint16_t cqid,
			    uint16_t sqid)
{
	struct nvmf_mlnx_snap_qpair *mqpair;

	mqpair = calloc(1, sizeof(*mqpair));
	if (!mqpair) {
		SPDK_ERRLOG("Memory allocation failed\n");
		return NULL;
	}

	mqpair->ctrlr = mctrlr;
	mqpair->qid = qid;
	mqpair->qpair.qid = qid;

	assert(mctrlr->sqs[sqid] != NULL);
	assert(mctrlr->cqs[cqid] != NULL);

	mqpair->sq = mctrlr->sqs[sqid];
	mqpair->sq->mqpair = mqpair;
	mqpair->cq = mctrlr->cqs[cqid];

	pthread_mutex_lock(&mctrlr->snap_emu->lock);
	if (qid) {
		TAILQ_INSERT_TAIL(&mctrlr->io_qpairs, mqpair, link);
	} else {
		assert(mctrlr->admin_qpair == NULL);
		mctrlr->admin_qpair = mqpair;
	}
	pthread_mutex_unlock(&mctrlr->snap_emu->lock);

	mqpair->qpair.transport = &mctrlr->snap_emu->listener->mtransport->transport;

	return mqpair;
}

static uint32_t
nvmf_mlnx_snap_ctrlr_num_queues(struct nvmf_mlnx_snap_ctrlr *mctrlr)
{
	uint32_t max_queues;

	max_queues = spdk_min(mctrlr->snap_emu->dev_caps.max_emulated_sq_num,
			      mctrlr->snap_emu->dev_caps.max_emulated_cq_num);
	max_queues = spdk_min(max_queues,
			      mctrlr->snap_emu->listener->mtransport->transport.opts.max_qpairs_per_ctrlr);

	return max_queues;
}

static void
nvmf_mlnx_snap_ctrlr_destroy(struct nvmf_mlnx_snap_emu *snap_emu)
{
	uint32_t i;
	int rc = 0;
	struct nvmf_mlnx_snap_ctrlr *mctrlr;
	struct nvmf_mlnx_snap_nvme_bar *bar = &snap_emu->bar.curr;
	struct nvmf_mlnx_snap_qpair *mqpair, *tmp_mqpair;

	pthread_mutex_lock(&snap_emu->lock);

	mctrlr = snap_emu->mctrlr;
	if (!mctrlr) {
		goto out;
	}
	mctrlr->destroying = true;

	TAILQ_FOREACH_SAFE(mqpair, &mctrlr->io_qpairs, link, tmp_mqpair) {
		spdk_nvmf_qpair_disconnect(&mqpair->qpair, NULL, NULL);
	}

	if (!TAILQ_EMPTY(&mctrlr->io_qpairs)) {
		SPDK_DEBUGLOG(mlnx_snap, "Waiting for IO qpairs destruction\n");
		pthread_mutex_unlock(&snap_emu->lock);
		return;
	}

	if (mctrlr->admin_qpair) {
		struct nvmf_mlnx_snap_qpair *adminq = mctrlr->admin_qpair;

		mctrlr->admin_qpair = NULL;
		SPDK_NOTICELOG("Destroying admin qpair\n");
		spdk_nvmf_qpair_disconnect(&adminq->qpair, NULL, NULL);
		pthread_mutex_unlock(&snap_emu->lock);
		return;
	}

	SPDK_NOTICELOG("Destroying controller %p\n", mctrlr);

	/* Admin qpair's sq is already destroyed, so start from 1 here */
	for (i = 1; i < mctrlr->num_queues; i++) {
		if (mctrlr->sqs[i]) {
			nvmf_mlnx_snap_destroy_sq(mctrlr->sqs[i]);
		}
	}

	for (i = 0; i < mctrlr->num_queues; i++) {
		if (mctrlr->cqs[i]) {
			nvmf_mlnx_snap_destroy_cq(mctrlr->cqs[i]);
		}
	}

	rc = snap_emu_stop(snap_emu);

	free(mctrlr->sqs);
	free(mctrlr->cqs);
	free(mctrlr);

out:

	SPDK_NOTICELOG("Controller %p destroyed\n", mctrlr);
	snap_emu->mctrlr = NULL;

	if (rc == 0) {
		bar->cc.raw = 0;
		snap_emu_mmio_write(snap_emu, &bar->cc, SNAP_NVME_REG_CC, 4);
	}
	bar->csts.raw = 0;
	snap_emu_mmio_write(snap_emu, &bar->csts, SNAP_NVME_REG_CSTS, 4);

	pthread_mutex_unlock(&snap_emu->lock);
}

static int
nvmf_mlnx_snap_ctrlr_create(struct nvmf_mlnx_snap_emu *snap_emu)
{
	int rc = 0;
	struct nvmf_mlnx_snap_nvme_bar *bar = &snap_emu->bar.curr;
	struct nvmf_mlnx_snap_transport *mtransport = snap_emu->listener->mtransport;
	struct spdk_nvmf_transport_opts *topts = &mtransport->transport.opts;
	uint16_t sqsize;
	uint16_t cqsize;

	SPDK_NOTICELOG("Creating NVME emu controller\n");

	struct nvmf_mlnx_snap_ctrlr *mctrlr = calloc(1, sizeof(*mctrlr));
	if (!mctrlr) {
		SPDK_ERRLOG("Memory allocation failed\n");
		return -ENOMEM;
	}

	mctrlr->snap_emu = snap_emu;
	assert(snap_emu->mctrlr == NULL);
	snap_emu->mctrlr = mctrlr;
	/* TODO: cq_period and cq_max_count must be configured */
	mctrlr->cq_period = 3;
	mctrlr->cq_max_count = 6;
	mctrlr->page_bits = bar->cc.bits.mps + 12;
	mctrlr->page_size = 1u << mctrlr->page_bits;
	mctrlr->num_queues = nvmf_mlnx_snap_ctrlr_num_queues(mctrlr);
	TAILQ_INIT(&mctrlr->io_qpairs);

	mctrlr->sqs = calloc(mctrlr->num_queues, sizeof(struct nvmf_mlnx_snap_nvme_sq *));
	if (!mctrlr->sqs) {
		SPDK_ERRLOG("Failed to allocate sqs\n");
		rc = -ENOMEM;
		goto err_out;
	}

	mctrlr->cqs = calloc(mctrlr->num_queues, sizeof(struct nvmf_mlnx_snap_nvme_cq *));
	if (!mctrlr->cqs) {
		SPDK_ERRLOG("Failed to allocate sqs\n");
		rc = -ENOMEM;
		goto err_out;
	}

	cqsize = bar->aqa.bits.acqs + 1;
	sqsize = bar->aqa.bits.asqs + 1;

	if (cqsize > topts->max_aq_depth || sqsize > topts->max_aq_depth) {
		SPDK_ERRLOG("cqsize (%u) or sqsize (%u) exceed max available value %u\n", cqsize, sqsize,
			    topts->max_aq_depth);
		rc = -EINVAL;
		goto err_out;
	}

	rc = snap_emu_start(snap_emu);
	if (rc) {
		SPDK_ERRLOG("Failed to start snap emulation\n");
		rc = -ENODEV;
		goto err_out;
	}

	/* create admin qpair, first init cq/sq */
	rc = nvmf_mlnx_snap_create_cq(mctrlr, 0, cqsize, bar->acq, 0);
	if (rc) {
		SPDK_ERRLOG("Failed to create cq\n");
		rc = -ENODEV;
		goto err_out;
	}

	if (!nvmf_mlnx_snap_create_qpair_and_sq(mctrlr, 0, 0, sqsize, bar->asq)) {
		SPDK_ERRLOG("Failed to create sq\n");
		rc = -ENODEV;
		goto err_out;
	}

	spdk_nvmf_tgt_new_qpair(mtransport->transport.tgt, &mctrlr->admin_qpair->qpair);

	return 0;

err_out:
	nvmf_mlnx_snap_ctrlr_destroy(snap_emu);

	return rc;
}

/* change controller configuration */
static void nvme_ctrl_modify_config(struct nvmf_mlnx_snap_emu *snap_emu, uint32_t cur_cfg,
				    uint32_t prev_cfg)
{
	struct nvmf_mlnx_snap_nvme_bar *bar = &snap_emu->bar.curr;
	union spdk_nvme_cc_register cur_cc;
	union spdk_nvme_cc_register prev_cc;
	int rc = 0;

	cur_cc.raw = cur_cfg;
	prev_cc.raw = prev_cfg;

	/* TODO: need to check this one more carefully */
	/* Windows first sends data, then sends enable bit */
	if (!cur_cc.bits.en && !prev_cc.bits.en &&
	    !cur_cc.bits.shn && prev_cc.bits.shn) {
		return;
	}

	/* enable command:
	 * NOTE that SPEC 3.1.5 allows modifying both CC.SHN and CC.EN
	 * however it does not clarify what is expected behaviour
	 *
	 * SPEC 3.1.5 CC.EN:
	 * Setting this field from a '0' to a '1' when CSTS.RDY is a '1' or
	 * setting this field from a '1' to a '0' when CSTS.RDY is a '0'
	 * has undefined results.
	 *
	 * We don't see 0 -> 0 or 1 -> 1 transitions because we only pickup
	 * bar changes.
	 *
	 * We must always set or clear RDY bit even if we failed to start or
	 * stop the conroller. If we don't following can happen:
	 * - snap is not running
	 * - modprobe nvme, modprobe timeouts, bus master disabled. EN=1, RDY=0
	 * - start snap. start fails because bus master disabled. EN=1, RDY=0
	 * - modprobe nvme fails because
	 *      - driver does EN=1 -> EN:0 and immediately sees RDY=0, writes EN=1
	 *        we miss EN=1 -> EN:0 because we are in the polling mode
	 *      - driver is spec compliant and just does EN=1, which we ignore
	 */
	if (cur_cc.bits.en && !prev_cc.bits.en) {
		/* controller start:
		 * If we fail assume it is because driver tried enable, got timeout
		 * and disabled bus master. Act as if we are ready but also raise CFS.
		 *
		 * Next time driver will try to reset either because EN == 1 && RDY == 1
		 * or because CFS == 1 or because there is an admin command timeout.
		 */
		if (snap_emu->mctrlr) {
			SPDK_NOTICELOG("Got CC.EN=1 while controller is created, activate\n");
			rc = snap_emu_start(snap_emu);
			bar->csts.bits.rdy = 1;
			snap_emu_mmio_write(snap_emu, &bar->csts, SNAP_NVME_REG_CSTS, 4);
		} else {
			SPDK_NOTICELOG("Creating snap controller\n");
			rc = nvmf_mlnx_snap_ctrlr_create(snap_emu);
			/* rdy = 1 will be set when we create and enable NVMF controller */
		}

		if (rc != 0) {
			bar->csts.bits.cfs = 1;
			snap_emu_mmio_write(snap_emu, &bar->csts, SNAP_NVME_REG_CSTS, 4);
		}

	} else if (!cur_cc.bits.en && prev_cc.bits.en) {
		/* controller stop:
		 * SPEC 7.3.2 "Controller Level Reset" says that
		 * All other controller registers defined in section 3 and internal
		 * controller state are reset.
		 * Reset CSTS and CC
		 *
		 * SPEC does not say that we can raise CFS if reset fails. So we don't
		 * raise it.
		 */
		SPDK_NOTICELOG("Destroying SNAP controller CC.EN=0. cur_cc = %x, prev_cc = %x\n", cur_cc.raw,
			       prev_cc.raw);
		nvmf_mlnx_snap_ctrlr_destroy(snap_emu);
	}

	/* shutdown command */
	if (cur_cc.bits.shn && !prev_cc.bits.shn) {
		bar->csts.bits.shst = SPDK_NVME_SHST_COMPLETE;
		snap_emu_mmio_write(snap_emu, &bar->csts, SNAP_NVME_REG_CSTS, 4);
	} else if (!cur_cc.bits.shn && prev_cc.bits.shn) {
		bar->csts.bits.shst &= ~SPDK_NVME_SHST_COMPLETE;
		snap_emu_mmio_write(snap_emu, &bar->csts, SNAP_NVME_REG_CSTS, 4);
	}
}

static inline const char *
nvme_ctrl_reg_str(unsigned reg_base)
{
	switch (reg_base) {
	case SNAP_NVME_REG_CAP:
		return "Controller Capabilities (CAP)";
	case SNAP_NVME_REG_VS:
		return "Controller Version (VS)";
	case SNAP_NVME_REG_INTMS:
		return "Interrupt Mask Set (INTMS)";
	case SNAP_NVME_REG_INTMC:
		return "Interrupt Mask Set (INTMC)";
	case SNAP_NVME_REG_CC:
		return "Controller Configuration (CC)";
	case SNAP_NVME_REG_CSTS:
		return "Controller Status (CSTS)";
	case SNAP_NVME_REG_NSSR:
		return "NVM Subsystem Reset (NSSR)";
	case SNAP_NVME_REG_AQA:
		return "Admin Queue Attributes (AQA)";
	case SNAP_NVME_REG_ASQ:
		return "Admin Submission Queue Base Address (ASQ)";
	case SNAP_NVME_REG_ACQ:
		return "Admin Completion Queue Base Address (ACQ)";
	case SNAP_NVME_REG_CMBLOC:
		return "Controller Memory Buffer Location (CMBLOC)";
	case SNAP_NVME_REG_CMBSZ:
		return "Controller Memory Buffer Size (CMBSZ)";
	case SNAP_NVME_REG_BPINFO:
		return "Boot Partition Information (BPINFO)";
	case SNAP_NVME_REG_BPRSEL:
		return "Boot Partition Select (BPRSEL)";
	case SNAP_NVME_REG_BPMBL:
		return "Boot Partition Memory Buffer Location (BPMBL)";
	default:
		return "unrecognized register";
	}
}


static void
nvme_bar_write_cb(void *bar, struct nvmf_mlnx_snap_nvme_register *reg, uint64_t val,
		  uint64_t prev_val)
{
	struct nvmf_mlnx_snap_nvme_bar_instance *dev_bar = bar;
	struct nvmf_mlnx_snap_emu *snap_emu = container_of(dev_bar, struct nvmf_mlnx_snap_emu, bar);

	SPDK_NOTICELOG("%s [0x%llx] -> 0x%llx bar write detected\n",
		       nvme_ctrl_reg_str(reg->reg_base),
		       (unsigned long long)prev_val,
		       (unsigned long long)val);

	switch (reg->reg_base) {
	case SNAP_NVME_REG_CC:
		nvme_ctrl_modify_config(snap_emu, (uint32_t)val, (uint32_t)prev_val);
		break;
	case SNAP_NVME_REG_AQA:
	case SNAP_NVME_REG_ASQ:
	case SNAP_NVME_REG_ACQ:
		break;
	case SNAP_NVME_REG_CSTS:
		/* ignore it until fully decoupled from qemu */
		SPDK_WARNLOG("CSTS change ignored\n");
		break;
	default:
		SPDK_ERRLOG("0x%X <- 0x%llx unsupported bar write detected\n", reg->reg_base,
			    (unsigned long long)val);
		SPDK_UNREACHABLE();
	}
}

static void
nvme_ctrl_bar_write_event(struct nvmf_mlnx_snap_emu *snap_emu)
{
	int err;

	err = nvme_bar_update(&snap_emu->bar, (nvme_bar_read_func_t)snap_emu_mmio_read,
			      nvme_bar_write_cb);
	if (err != 0) {
		SPDK_WARNLOG("failed to update bar\n");
	}
}

static int
nvmf_mlnx_snap_destroy(struct spdk_nvmf_transport *transport,
		       spdk_nvmf_transport_destroy_done_cb cb_fn, void *cb_arg)
{
	struct nvmf_mlnx_snap_transport *mtransport;
	struct nvmf_mlnx_snap_ctx *snap_ctx, *tmp;

	mtransport = nvmf_mlnx_snap_transport_get(transport);

	TAILQ_FOREACH_SAFE(snap_ctx, &mtransport->snap_ctxs, link, tmp) {
		if (snap_ctx->ctx) {
			snap_close(snap_ctx->ctx);
		}
		TAILQ_REMOVE(&mtransport->snap_ctxs, snap_ctx, link);
		free(snap_ctx);
	}

	pthread_mutex_destroy(&mtransport->lock);

	free(mtransport);

	if (cb_fn) {
		cb_fn(cb_arg);
	}

	return 0;
}

static int
nvmf_mlnx_snap_mutex_init_recursive(pthread_mutex_t *mtx)
{
	pthread_mutexattr_t attr;
	int rc = 0;

	if (pthread_mutexattr_init(&attr)) {
		return -1;
	}
	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) ||
	    pthread_mutex_init(mtx, &attr)) {
		rc = -1;
	}
	pthread_mutexattr_destroy(&attr);
	return rc;
}

#define NVMF_MLNX_SNAP_DEFAULT_MAX_QUEUE_DEPTH 64
#define NVMF_MLNX_SNAP_DEFAULT_AQ_DEPTH 128
#define NVMF_MLNX_SNAP_DEFAULT_MAX_QPAIRS_PER_CTRLR 128
#define NVMF_MLNX_SNAP_DEFAULT_IN_CAPSULE_DATA_SIZE 4096
#define NVMF_MLNX_SNAP_DEFAULT_MAX_IO_SIZE 131072
#define NVMF_MLNX_SNAP_DEFAULT_NUM_SHARED_BUFFERS 4095
#define NVMF_MLNX_SNAP_DEFAULT_BUFFER_CACHE_SIZE 32
#define NVMF_MLNX_SNAP_DIF_INSERT_OR_STRIP false
#define NVMF_MLNX_SNAP_DEFAULT_ABORT_TIMEOUT_SEC 1


static void
nvmf_mlnx_snap_opts_init(struct spdk_nvmf_transport_opts *opts)
{
	opts->max_queue_depth =		NVMF_MLNX_SNAP_DEFAULT_MAX_QUEUE_DEPTH;
	opts->max_qpairs_per_ctrlr =	NVMF_MLNX_SNAP_DEFAULT_MAX_QPAIRS_PER_CTRLR;
	opts->in_capsule_data_size =	0;
	opts->max_io_size =		NVMF_MLNX_SNAP_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size =		NVMF_MLNX_SNAP_DEFAULT_MAX_IO_SIZE;
	opts->max_aq_depth =		NVMF_MLNX_SNAP_DEFAULT_AQ_DEPTH;
	opts->num_shared_buffers =	NVMF_MLNX_SNAP_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size =		NVMF_MLNX_SNAP_DEFAULT_BUFFER_CACHE_SIZE;
	opts->dif_insert_or_strip =	NVMF_MLNX_SNAP_DIF_INSERT_OR_STRIP;
	opts->abort_timeout_sec =	NVMF_MLNX_SNAP_DEFAULT_ABORT_TIMEOUT_SEC;
}

static struct spdk_nvmf_transport *
nvmf_mlnx_snap_create(struct spdk_nvmf_transport_opts *opts)
{
	struct nvmf_mlnx_snap_transport *mtransport;
	struct ibv_device **list = NULL;
	int dev_count = 0;
	int i;
	int rc;

	mtransport = calloc(1, sizeof(*mtransport));
	if (!mtransport) {
		SPDK_ERRLOG("Memory allocation failed\n");
		return NULL;
	}

	mtransport->transport.ops = &spdk_nvmf_transport_mlnx_snap;

	list = ibv_get_device_list(&dev_count);
	if (!list || !dev_count) {
		SPDK_ERRLOG("Failed to get ibv devices list\n");
		goto err_out;
	}

	for (i = 0; i < dev_count; i++) {
		struct nvmf_mlnx_snap_ctx *snap_ctx = calloc(1, sizeof(*snap_ctx));
		SPDK_DEBUGLOG(mlnx_snap, "opening snap ctx on device %s\n", list[i]->name);
		snap_ctx->ctx = snap_open(list[i]);
		if (!snap_ctx->ctx) {
			ibv_free_device_list(list);
			SPDK_ERRLOG("Failed to open snap_ctx for device %s, , errno %d (%s)\n", list[i]->name,
				    errno, spdk_strerror(errno));
			goto err_out;
		}
		TAILQ_INSERT_HEAD(&mtransport->snap_ctxs, snap_ctx, link);
	}
	TAILQ_INIT(&mtransport->poll_groups);

	ibv_free_device_list(list);

	rc = nvmf_mlnx_snap_mutex_init_recursive(&mtransport->lock);
	if (rc) {
		SPDK_ERRLOG("Failed to create transport lock\n");
		goto err_out;
	}

	return &mtransport->transport;

err_out:
	nvmf_mlnx_snap_destroy(&mtransport->transport, NULL, NULL);

	return NULL;
}

/**
 *
 * @param transport
 * @param trid - traddr - hca name. trsvcid - PCI PF
 * @return
 */
static int
nvmf_mlnx_snap_listen(struct spdk_nvmf_transport *transport,
		      const struct spdk_nvme_transport_id *trid)
{
	long pci_func;
	int rc;
	struct nvmf_mlnx_snap_transport *mtransport;
	struct nvmf_mlnx_snap_listener *mlistener = NULL;
	struct nvmf_mlnx_snap_emu *snap_emu = NULL;

	mtransport = nvmf_mlnx_snap_transport_get(transport);
	mlistener = calloc(1, sizeof(*mlistener));
	if (!mlistener) {
		SPDK_ERRLOG("Memory allocation failed\n");
		rc = -ENOMEM;
		goto err_out;
	}
	mlistener->trid = trid;
	mlistener->mtransport = mtransport;

	pci_func = spdk_strtol(trid->trsvcid, 10);
	if (pci_func < 0) {
		SPDK_ERRLOG("Invalid trsvcid %s\n", trid->trsvcid);
		rc = -EINVAL;
		goto err_out;
	}

	snap_emu = nvmf_mlnx_snap_emu_create(mlistener, trid->traddr, (uint32_t)pci_func);
	if (!snap_emu) {
		SPDK_ERRLOG("Failed to create snap emulation %s\n", trid->trsvcid);
		rc = -ENODEV;
		goto err_out;
	}

	mlistener->snap_emu = snap_emu;

	TAILQ_INSERT_HEAD(&mtransport->listeners, mlistener, link);

	return 0;

err_out:
	free(mlistener);

	return rc;
}

static void
nvmf_mlnx_snap_stop_listen(struct spdk_nvmf_transport *transport,
			   const struct spdk_nvme_transport_id *trid)
{
	struct nvmf_mlnx_snap_transport *mtransport = nvmf_mlnx_snap_transport_get(transport);
	struct nvmf_mlnx_snap_listener *mlistener;

	pthread_mutex_lock(&mtransport->lock);

	TAILQ_FOREACH(mlistener, &mtransport->listeners, link) {
		if (spdk_nvme_transport_id_compare(trid, mlistener->trid) == 0) {
			break;
		}
	}

	if (!mlistener) {
		pthread_mutex_unlock(&mtransport->lock);
		SPDK_ERRLOG("Can't find listener for trid %s:%s\n", trid->traddr, trid->trsvcid);
		return;
	}

	TAILQ_REMOVE(&mtransport->listeners, mlistener, link);
	pthread_mutex_unlock(&mtransport->lock);

	SPDK_NOTICELOG("Destroying listener, trid %s:%s\n", trid->traddr, trid->trsvcid);
	nvmf_mlnx_snap_emu_destroy(mlistener->snap_emu);
	free(mlistener);
}

static int
nvmf_mlnx_snap_listen_associate(struct spdk_nvmf_transport *transport,
				const struct spdk_nvmf_subsystem *subsystem,
				const struct spdk_nvme_transport_id *trid)
{
	struct nvmf_mlnx_snap_transport *mtransport = nvmf_mlnx_snap_transport_get(transport);
	struct nvmf_mlnx_snap_listener *mlistener;

	assert(mtransport);

	pthread_mutex_lock(&mtransport->lock);

	TAILQ_FOREACH(mlistener, &mtransport->listeners, link) {
		if (strncmp(trid->traddr, mlistener->trid->traddr, sizeof(mlistener->trid->traddr)) == 0 &&
		    strncmp(trid->trsvcid, mlistener->trid->trsvcid, sizeof(mlistener->trid->trsvcid)) == 0) {
			break;
		}
	}

	if (!mlistener) {
		pthread_mutex_unlock(&mtransport->lock);
		SPDK_ERRLOG("Failed to find listener for trid %s:%s\n", trid->traddr, trid->trsvcid);
		return -1;
	}

	mlistener->subsystem = subsystem;
	pthread_mutex_unlock(&mtransport->lock);
	SPDK_DEBUGLOG(mlnx_snap, "Associate subsys NQN %s with listener %s:%s\n", subsystem->subnqn,
		      trid->traddr, trid->trsvcid);

	return 0;
}

static uint32_t
nvmf_mlnx_snap_accept(struct spdk_nvmf_transport *transport)
{
	struct nvmf_mlnx_snap_transport *mtransport;
	struct nvmf_mlnx_snap_listener *mlistener, *tmp;

	mtransport = nvmf_mlnx_snap_transport_get(transport);

	TAILQ_FOREACH_SAFE(mlistener, &mtransport->listeners, link, tmp) {
		nvme_ctrl_bar_write_event(mlistener->snap_emu);
	}

	/* no way to get the number of occurred events */
	return 0;
}

static struct nvmf_mlnx_snap_sf *
nvmf_mlnx_snap_sf_alloc(const char *dev_name)
{
	struct nvmf_mlnx_snap_sf *sf;
	int ret;

	sf = calloc(1, sizeof(*sf));
	if (!sf) {
		return NULL;
	}

	ret = devx_init_dev(dev_name, &sf->sf);
	if (ret) {
		free(sf);
		return NULL;
	}

	sf->pd = ibv_alloc_pd(sf->sf.ibv_ctx);
	if (!sf->pd) {
		devx_reset_dev(&sf->sf);
		return NULL;
	}

	SPDK_NOTICELOG("sf 0x%p created on %s\n", sf, dev_name);

	return sf;
}

static void
nvmf_mlnx_snap_sf_free(struct nvmf_mlnx_snap_sf *sf)
{
	ibv_dealloc_pd(sf->pd);
	devx_reset_dev(&sf->sf);
	free(sf);
}

static void
nvmf_mlnx_snap_emu_destroy(struct nvmf_mlnx_snap_emu *snap_emu)
{
	if (snap_emu->snap_dev) {
		snap_close_device(snap_emu->snap_dev);
	}
	if (snap_emu->sf) {
		nvmf_mlnx_snap_sf_free(snap_emu->sf);
	}

	pthread_mutex_destroy(&snap_emu->lock);

	free(snap_emu);
}

static void
nvmf_mlnx_snap_conn_sched_pg_removed(struct nvmf_mlnx_snap_transport *mtransport,
				     struct nvmf_mlnx_snap_poll_group *mgroup)
{
	struct nvmf_mlnx_snap_poll_group *next_mgroup;

	pthread_mutex_lock(&mtransport->lock);
	next_mgroup = TAILQ_NEXT(mgroup, link);
	if (next_mgroup == NULL) {
		next_mgroup = TAILQ_FIRST(&mtransport->poll_groups);
	}
	if (mtransport->conn_sched.next_admin_pg == mgroup) {
		mtransport->conn_sched.next_admin_pg = next_mgroup;
	}
	if (mtransport->conn_sched.next_io_pg == mgroup) {
		mtransport->conn_sched.next_io_pg = next_mgroup;
	}
	pthread_mutex_unlock(&mtransport->lock);
}


static void
nvmf_mlnx_snap_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
	struct nvmf_mlnx_snap_poll_group *mgroup = nvmf_mlnx_snap_poll_group_get(group);
	struct nvmf_mlnx_snap_transport *mtransport = nvmf_mlnx_snap_transport_get(group->transport);
	struct nvmf_mlnx_snap_poller *mpoller, *tmp_mpoller;
	struct nvmf_mlnx_snap_qpair *mqpair, *tmp_mqpair;

	nvmf_mlnx_snap_conn_sched_pg_removed(mtransport, mgroup);

	TAILQ_FOREACH_SAFE(mpoller, &mgroup->pollers, link, tmp_mpoller) {
		TAILQ_FOREACH_SAFE(mqpair, &mpoller->qpairs, poller_link, tmp_mqpair) {
			SPDK_NOTICELOG("Forcefully destroy qpair %p %u\n", mqpair, mqpair->qid);
			nvmf_mlnx_snap_destroy_qpair(mqpair);
		}

		assert(TAILQ_EMPTY(&mpoller->cqs));
		TAILQ_REMOVE(&mgroup->pollers, mpoller, link);
		free(mpoller);
	}
	pthread_mutex_lock(&mtransport->lock);
	TAILQ_REMOVE(&mtransport->poll_groups, mgroup, link);
	pthread_mutex_unlock(&mtransport->lock);

	free(mgroup);
}

static int
nvmf_mlnx_snap_poller_create(struct nvmf_mlnx_snap_poll_group *mgroup,
			     struct nvmf_mlnx_snap_ctx *snap_ctx)
{
	struct nvmf_mlnx_snap_poller *mpoller;

	mpoller = calloc(1, sizeof(*mpoller));
	if (!mpoller) {
		SPDK_ERRLOG("Failed to allocate memory for poller\n");
		return -1;
	}
	mpoller->context = snap_ctx;
	mpoller->group = mgroup;
	TAILQ_INIT(&mpoller->cqs);
	TAILQ_INSERT_HEAD(&mgroup->pollers, mpoller, link);

	return 0;
}

static void
nvmf_mlnx_snap_discover(struct spdk_nvmf_transport *transport, struct spdk_nvme_transport_id *trid,
			struct spdk_nvmf_discovery_log_page_entry *entry)
{

}

static struct spdk_nvmf_transport_poll_group *
nvmf_mlnx_snap_poll_group_create(struct spdk_nvmf_transport *transport)
{
	struct nvmf_mlnx_snap_transport *mtransport;
	struct nvmf_mlnx_snap_ctx *snap_ctx;
	struct nvmf_mlnx_snap_poll_group *mgroup;
	int rc;

	mtransport = nvmf_mlnx_snap_transport_get(transport);
	mgroup = calloc(1, sizeof(*mgroup));
	if (!mgroup) {
		SPDK_ERRLOG("Failed to allocate poll group\n");
		return NULL;
	}
	TAILQ_INIT(&mgroup->pollers);

	pthread_mutex_lock(&mtransport->lock);
	TAILQ_FOREACH(snap_ctx, &mtransport->snap_ctxs, link) {
		rc = nvmf_mlnx_snap_poller_create(mgroup, snap_ctx);
		if (rc) {
			pthread_mutex_unlock(&mtransport->lock);
			SPDK_ERRLOG("Failed to create transport poll group\n");
			nvmf_mlnx_snap_poll_group_destroy(&mgroup->group);
			return NULL;
		}
	}

	TAILQ_INSERT_HEAD(&mtransport->poll_groups, mgroup, link);
	if (mtransport->conn_sched.next_admin_pg == NULL) {
		mtransport->conn_sched.next_admin_pg = mgroup;
		mtransport->conn_sched.next_io_pg = mgroup;
	}
	pthread_mutex_unlock(&mtransport->lock);

	return &mgroup->group;
}

static struct spdk_nvmf_transport_poll_group *
nvmf_mlnx_snap_get_optimal_poll_group(struct spdk_nvmf_qpair *qpair)
{
	struct nvmf_mlnx_snap_qpair *mqpair = nvmf_mlnx_snap_qpair_get(qpair);

	if (mqpair->cq == NULL) {
		SPDK_ERRLOG("Unable to get pg for qpair %u, no cq\n", mqpair->qid);
		return NULL;
	}
	if (mqpair->cq->poller == NULL) {
		SPDK_ERRLOG("Unable to get pg for qpair %u, no pg on cq\n", mqpair->qid);
		return NULL;
	}

	return &mqpair->cq->poller->group->group;
}

static void
nvmf_mlnx_snap_set_cc_en_resp(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_qpair *mqpair = mreq->sq->mqpair;
	struct spdk_nvme_cpl *rsp;
	struct nvmf_mlnx_snap_emu *snap_emu;
	struct nvmf_mlnx_snap_nvme_bar *bar;
	bool destroy = false;

	rsp = &mreq->nvmf_req.rsp->nvme_cpl;
	if (rsp->status.sc != SPDK_NVME_SC_SUCCESS || rsp->status.sct != SPDK_NVME_SCT_GENERIC) {
		SPDK_ERRLOG("NVMF controller prop_set failed, sc %x, sct %x\n", rsp->status.sc, rsp->status.sct);
		destroy = true;
	}
	TAILQ_REMOVE(&mreq->sq->resources->out_req_list, mreq, link);
	mreq->state = MLNX_SNAP_REQ_STATE_COMPLETED;
	nvmf_mlnx_snap_request_exec(mreq);

	if (destroy) {
		nvmf_mlnx_snap_destroy_qpair(mqpair);
	} else {
		snap_emu = mqpair->ctrlr->snap_emu;
		bar = &snap_emu->bar.curr;
		bar->csts.bits.rdy = 1;
		snap_emu_mmio_write(snap_emu, &bar->csts, SNAP_NVME_REG_CSTS, 4);
	}
}

static void
nvmf_mlnx_snap_set_cc_en(struct nvmf_mlnx_snap_qpair *mqpair)
{
	struct nvmf_mlnx_snap_nvme_req *mreq;
	struct spdk_nvmf_fabric_prop_set_cmd *cmd;

	mreq = nvmf_mlnx_snap_qpair_sq_get_req(mqpair->sq);
	if (!mreq) {
		SPDK_ERRLOG("no free req\n");
		assert(0);
		return;
	}

	cmd = &mreq->nvmf_req.cmd->prop_set_cmd;
	cmd->opcode = SPDK_NVME_OPC_FABRIC;
	cmd->cid = 0;
	cmd->fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_SET;
	cmd->attrib.size = SPDK_NVMF_PROP_SIZE_4;
	cmd->ofst = offsetof(struct spdk_nvme_registers, cc.raw);
	cmd->value.u64 = mqpair->ctrlr->snap_emu->bar.curr.cc.raw;

	mreq->nvmf_req.xfer = SPDK_NVME_DATA_NONE;
	mreq->nvmf_req.length = 0;
	mreq->nvmf_comp_cb = nvmf_mlnx_snap_set_cc_en_resp;
	/* Special case for fabric connect */
	mreq->state = MLNX_SNAP_REQ_STATE_EXECUTING;
	spdk_nvmf_request_exec_fabrics(&mreq->nvmf_req);
}

static void
nvmf_mlnx_snap_complete_sq_creation(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	mreq->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;
	nvmf_mlnx_snap_request_exec(mreq);
}

static void
nvmf_mlnx_snap_fabric_conn_resp(struct nvmf_mlnx_snap_nvme_req *mreq)
{
	struct nvmf_mlnx_snap_qpair *mqpair = mreq->sq->mqpair;
	struct nvmf_mlnx_snap_ctrlr *mctrlr = mqpair->ctrlr;
	struct nvmf_mlnx_snap_nvme_req *create_sq_req;
	struct spdk_nvmf_fabric_connect_rsp *rsp;
	struct spdk_thread *admin_thread;
	bool destroy = false;

	rsp = &mreq->nvmf_req.rsp->connect_rsp;

	if (rsp->status.sc != SPDK_NVME_SC_SUCCESS || rsp->status.sct != SPDK_NVME_SCT_GENERIC) {
		SPDK_ERRLOG("NVMF controller creation failed, sc %x, sct %x\n", rsp->status.sc, rsp->status.sct);
		destroy = true;
	} else if (mqpair->qid == 0) {
		assert(mqpair->qpair.ctrlr);
		SPDK_DEBUGLOG(mlnx_snap, "Created NVMF cntrlr, id %hu\n", mqpair->qpair.ctrlr->cntlid);
		mctrlr->ctrlr = mqpair->qpair.ctrlr;
	}

	/* Complete request used to send FABRIC_CONNECT command */
	TAILQ_REMOVE(&mreq->sq->resources->out_req_list, mreq, link);
	mreq->state = MLNX_SNAP_REQ_STATE_COMPLETED;
	nvmf_mlnx_snap_request_exec(mreq);

	if (destroy) {
		nvmf_mlnx_snap_destroy_qpair(mqpair);
	} else if (mqpair->qid == 0) {
		/* issue property_set command to enable NVMF controller */
		SPDK_DEBUGLOG(mlnx_snap, "setting nvmf ctrlr cc.en = 1\n");
		nvmf_mlnx_snap_set_cc_en(mqpair);
	} else {
		assert(mqpair->create_sq_req != NULL);
		/* Should be completed in the context of admin qpair's thread */
		assert(mqpair->ctrlr->admin_qpair);
		assert(mqpair->ctrlr->admin_qpair->qpair.group);
		admin_thread = mqpair->ctrlr->admin_qpair->qpair.group->thread;
		assert(admin_thread);

		create_sq_req = mqpair->create_sq_req;
		mqpair->create_sq_req = NULL;

		if (admin_thread != spdk_get_thread()) {
			spdk_thread_send_msg(admin_thread, (spdk_msg_fn)nvmf_mlnx_snap_complete_sq_creation, create_sq_req);
		} else {
			nvmf_mlnx_snap_complete_sq_creation(create_sq_req);
		}
	}
}

static int
nvmf_mlnx_snap_send_fabric_connect(struct nvmf_mlnx_snap_qpair *mqpair)
{
	struct nvmf_mlnx_snap_nvme_req *mreq;
	struct spdk_nvmf_fabric_connect_cmd *connect_cmd;
	struct spdk_nvmf_fabric_connect_data *data;
	struct spdk_nvmf_transport_poll_group *group;
	int rc;

	group = &mqpair->sq->pg->group;
	mreq = nvmf_mlnx_snap_qpair_sq_get_req(mqpair->sq);
	if (!mreq) {
		SPDK_ERRLOG("no free req\n");
		assert(0);
		return -1;
	}

	connect_cmd = &mreq->nvmf_req.cmd->connect_cmd;

	connect_cmd->opcode = SPDK_NVME_OPC_FABRIC;
	connect_cmd->cid = 0;
	connect_cmd->fctype = SPDK_NVMF_FABRIC_COMMAND_CONNECT;
	connect_cmd->recfmt = 0;
	connect_cmd->sqsize = mqpair->sq->size - 1;
	connect_cmd->qid = mqpair->qid;
	/* Implicitly disable kato */
	connect_cmd->kato = 0;

	mreq->nvmf_req.length = sizeof(struct spdk_nvmf_fabric_connect_data);
	rc = spdk_nvmf_request_get_buffers(&mreq->nvmf_req, group, group->transport, mreq->nvmf_req.length);
	if (rc) {
		SPDK_ERRLOG("Failed to get transport buffer\n");
		return rc;
	}
	mreq->nvmf_req.data = mreq->nvmf_req.iov[0].iov_base;
	mreq->nvmf_req.xfer = SPDK_NVME_DATA_HOST_TO_CONTROLLER;
	memset(mreq->nvmf_req.data, 0, sizeof(*data));
	data = (struct spdk_nvmf_fabric_connect_data *)mreq->nvmf_req.data;
	data->cntlid = mqpair->qid == 0 ? 0xFFFF : mqpair->ctrlr->ctrlr->cntlid;
	snprintf((char *)data->subnqn, sizeof(data->subnqn), "%s",
		 spdk_nvmf_subsystem_get_nqn(mqpair->ctrlr->snap_emu->listener->subsystem));

	mreq->nvmf_comp_cb = nvmf_mlnx_snap_fabric_conn_resp;

	/* Special case for fabric connect */
	mreq->state = MLNX_SNAP_REQ_STATE_EXECUTING;
	spdk_nvmf_request_exec_fabrics(&mreq->nvmf_req);

	return 0;
}

static int
nvmf_mlnx_snap_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
			      struct spdk_nvmf_qpair *qpair)
{
	struct nvmf_mlnx_snap_poller *mpoller;
	struct nvmf_mlnx_snap_qpair *mqpair = nvmf_mlnx_snap_qpair_get(qpair);

	SPDK_NOTICELOG("Adding qpair %p qid %u to poll group %p\n", qpair, qpair->qid, group);

	if (mqpair->cq == NULL) {
		SPDK_ERRLOG("Failed to add qpair %u to pg, no cq\n", mqpair->qid);
		return -1;
	}
	if (mqpair->cq->poller == NULL) {
		SPDK_ERRLOG("Failed to add qpair %u to pg, no pg on cq\n", mqpair->qid);
		return -1;
	}
	if (mqpair->sq == NULL) {
		SPDK_ERRLOG("Failed to add qpair %u to pg, no sq\n", mqpair->qid);
		return -1;
	}

	TAILQ_INSERT_TAIL(&mqpair->cq->sqs, mqpair->sq, link);

	mpoller = mqpair->cq->poller;
	TAILQ_INSERT_HEAD(&mpoller->qpairs, mqpair, poller_link);
	mqpair->sq->pg = mqpair->cq->poller->group;
	mqpair->poller = mpoller;
	mqpair->qpair.trid = mqpair->ctrlr->snap_emu->listener->trid;

	return nvmf_mlnx_snap_send_fabric_connect(mqpair);
}

static int
nvmf_mlnx_snap_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
				 struct spdk_nvmf_qpair *qpair)
{
#if 0
	struct nvmf_mlnx_snap_qpair *mqpair = nvmf_mlnx_snap_qpair_get(qpair);
	struct nvmf_mlnx_snap_poller *mpoller;

	if (mqpair->poller) {
		mpoller = mqpair->poller;
		TAILQ_REMOVE(&mpoller->qpairs, mqpair, poller_link);
		mqpair->poller = NULL;
	}
#endif

	return 0;
}

static int
nvmf_mlnx_snap_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct nvmf_mlnx_snap_poll_group *mgroup = nvmf_mlnx_snap_poll_group_get(group);
	struct nvmf_mlnx_snap_poller *mpoller, *mpoller_tmp;
	struct nvmf_mlnx_snap_qpair *mqpair, *mqpair_tmp;
	int count = 0;

	TAILQ_FOREACH_SAFE(mpoller, &mgroup->pollers, link, mpoller_tmp) {
		TAILQ_FOREACH_SAFE(mqpair, &mpoller->qpairs, poller_link, mqpair_tmp) {
			snap_dma_q_progress(mqpair->sq->dma_q);
			if (spdk_unlikely(mqpair->qpair.state != SPDK_NVMF_QPAIR_ACTIVE)) {
				SPDK_DEBUGLOG(mlnx_snap, "Disconnecting qpair %p\n", mqpair);
				spdk_nvmf_qpair_disconnect(&mqpair->qpair, NULL, NULL);
			}
		}
	}

	return count;
}

static int
nvmf_mlnx_snap_request_free(struct spdk_nvmf_request *req)
{
	struct nvmf_mlnx_snap_nvme_req *mreq;

	mreq = nvmf_mlnx_snap_req_get(req);
	mreq->state = MLNX_SNAP_REQ_STATE_COMPLETED;
	TAILQ_REMOVE(&mreq->sq->resources->out_req_list, mreq, link);
	nvmf_mlnx_snap_request_exec(mreq);

	return 0;
}

static int
nvmf_mlnx_snap_request_complete(struct spdk_nvmf_request *req)
{
	struct nvmf_mlnx_snap_nvme_req *mreq;

	mreq = nvmf_mlnx_snap_req_get(req);
	assert(mreq->state == MLNX_SNAP_REQ_STATE_EXECUTING);
	mreq->state = MLNX_SNAP_REQ_STATE_EXECUTED;

	SPDK_DEBUGLOG(mlnx_snap, "Completing req %p, opc %x\n", mreq, req->cmd->nvme_cmd.opc);
	if (mreq->nvmf_comp_cb) {
		mreq->nvmf_comp_cb(mreq);
		return 0;
	}
	nvmf_mlnx_snap_request_exec(mreq);

	return 0;
}

static void
nvmf_mlnx_snap_destroy_qpair(struct nvmf_mlnx_snap_qpair *mqpair)
{
	struct nvmf_mlnx_snap_nvme_cq *cq;
	struct nvmf_mlnx_snap_ctrlr *mctrlr;

	SPDK_NOTICELOG("Destroy qpair %p %u\n", mqpair, mqpair->qid);

	if (mqpair->qpair.group && mqpair->qpair.group->thread != spdk_get_thread()) {
		SPDK_ERRLOG("Destroying qpair %p %u on wrong thread\n", mqpair, mqpair->qid);
		assert(0);
	}

	if (mqpair->poller) {
		TAILQ_REMOVE(&mqpair->poller->qpairs, mqpair, poller_link);
		mqpair->poller = NULL;
	}

	mctrlr = mqpair->ctrlr;

	if (mqpair->sq) {
		/* SQ is attached to CQ in _poll_group_add API
		 * Until it happens qpair remains in UNINITIALIZED state */
		if (mctrlr && mqpair->qpair.state != SPDK_NVMF_QPAIR_UNINITIALIZED) {
			cq = mctrlr->cqs[mqpair->sq->cqid];
			TAILQ_REMOVE(&cq->sqs, mqpair->sq, link);
		}
		nvmf_mlnx_snap_destroy_sq(mqpair->sq);
		mqpair->sq = NULL;
	}

	if (mctrlr) {
		pthread_mutex_lock(&mctrlr->snap_emu->lock);
		if (mqpair->qid != 0) {
			TAILQ_REMOVE(&mctrlr->io_qpairs, mqpair, link);
			mqpair->ctrlr = NULL;
		} else {
			mctrlr->admin_qpair = NULL;
		}
		pthread_mutex_unlock(&mctrlr->snap_emu->lock);
	}

	free(mqpair);

	if (mctrlr && (mctrlr->destroying || mctrlr->admin_qpair == NULL)) {
		nvmf_mlnx_snap_ctrlr_destroy(mctrlr->snap_emu);
	}
}

static void
nvmf_mlnx_snap_try_destroy_qpair(struct nvmf_mlnx_snap_qpair *mqpair)
{
	struct nvmf_mlnx_snap_nvme_sq *sq = mqpair->sq;

	SPDK_NOTICELOG("qpair %p %u sq %p\n", mqpair, mqpair->qpair.qid, sq);

	if (!TAILQ_EMPTY(&sq->resources->out_req_list)) {
		SPDK_NOTICELOG("qpair %p: has outstanding\n", mqpair);
		return;
	}

	nvmf_mlnx_snap_destroy_qpair(mqpair);
}

static void
nvmf_mlnx_snap_close_qpair(struct spdk_nvmf_qpair *qpair, spdk_nvmf_transport_qpair_fini_cb cb_fn,
			   void *cb_args)
{
	struct nvmf_mlnx_snap_qpair *mqpair = nvmf_mlnx_snap_qpair_get(qpair);

	SPDK_NOTICELOG("Destroying qpair %p %u\n", qpair, qpair->qid);

	if (qpair->state == SPDK_NVMF_QPAIR_UNINITIALIZED) {
		SPDK_NOTICELOG("qpair %p: nvmf qpair not initialized, destroy\n", mqpair);
		nvmf_mlnx_snap_destroy_qpair(mqpair);
		return;
	}

	nvmf_mlnx_snap_try_destroy_qpair(mqpair);

	if (cb_fn) {
		cb_fn(cb_args);
	}
}

static int
nvmf_mlnx_snap_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
				   struct spdk_nvme_transport_id *trid)
{
	return 0;
}

static int
nvmf_mlnx_snap_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
				    struct spdk_nvme_transport_id *trid)
{
	struct nvmf_mlnx_snap_qpair *mqpair = nvmf_mlnx_snap_qpair_get(qpair);

	memcpy(trid, mqpair->sq->ctrlr->snap_emu->listener->trid, sizeof(*trid));
	return 0;
}

static int
nvmf_mlnx_snap_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
				     struct spdk_nvme_transport_id *trid)
{
	struct nvmf_mlnx_snap_qpair *mqpair = nvmf_mlnx_snap_qpair_get(qpair);

	memcpy(trid, mqpair->sq->ctrlr->snap_emu->listener->trid, sizeof(*trid));
	return 0;
}

static void
nvmf_mlnx_snap_request_set_abort_status(struct spdk_nvmf_request *req,
					struct nvmf_mlnx_snap_nvme_req *mreq_to_abort)
{
	mreq_to_abort->nvmf_req.rsp->nvme_cpl.status.sct = SPDK_NVME_SCT_GENERIC;
	mreq_to_abort->nvmf_req.rsp->nvme_cpl.status.sc = SPDK_NVME_SC_ABORTED_BY_REQUEST;

	mreq_to_abort->state = MLNX_SNAP_REQ_STATE_READY_TO_COMPLETE;

	req->rsp->nvme_cpl.cdw0 &= ~1U;	/* Command was successfully aborted. */
}

static int
_nvmf_mlnx_snap_qpair_abort_request(void *ctx)
{
	struct spdk_nvmf_request *req = ctx;
	struct nvmf_mlnx_snap_nvme_req *mreq_to_abort = nvmf_mlnx_snap_req_get(req->req_to_abort);
	int rc;

	spdk_poller_unregister(&req->poller);

	switch (mreq_to_abort->state) {
	case MLNX_SNAP_REQ_STATE_EXECUTING:
		rc = nvmf_ctrlr_abort_request(req);
		if (rc == SPDK_NVMF_REQUEST_EXEC_STATUS_ASYNCHRONOUS) {
			return SPDK_POLLER_BUSY;
		}
		break;

	case MLNX_SNAP_REQ_STATE_NEW:
	case MLNX_SNAP_REQ_STATE_NEED_BUFFER:
	case MLNX_SNAP_REQ_STATE_TRANSFER_IN:
	case MLNX_SNAP_REQ_STATE_READY_TO_EXEC:
	case MLNX_SNAP_REQ_STATE_EXECUTED:
		nvmf_mlnx_snap_request_set_abort_status(req, mreq_to_abort);
		break;

	case MLNX_SNAP_REQ_STATE_TRANSFERRING_IN:
	case MLNX_SNAP_REQ_STATE_TRANSFERRING_OUT:
		if (spdk_get_ticks() < req->timeout_tsc) {
			req->poller = SPDK_POLLER_REGISTER(_nvmf_mlnx_snap_qpair_abort_request, req, 0);
			return SPDK_POLLER_BUSY;
		}
		break;

	default:
		break;
	}

	spdk_nvmf_request_complete(req);
	return SPDK_POLLER_BUSY;
}

static void
nvmf_mlnx_snap_qpair_abort_request(struct spdk_nvmf_qpair *qpair,
				   struct spdk_nvmf_request *req)
{
	struct nvmf_mlnx_snap_qpair *mqpair = nvmf_mlnx_snap_qpair_get(qpair);
	struct nvmf_mlnx_snap_nvme_req *mreq, *mreq_to_abort = NULL;
	uint16_t cid, i;

	cid = req->cmd->nvme_cmd.cdw10_bits.abort.cid;

	SPDK_NOTICELOG("searching for command cid %hu sqid %hu\n", cid,
		       req->cmd->nvme_cmd.cdw10_bits.abort.sqid);

	for (i = 0; i < mqpair->sq->size; i++) {
		mreq = &mqpair->sq->resources->reqs[i];
		if (mreq->state != MLNX_SNAP_REQ_STATE_FREE &&
		    mreq->nvmf_req.cmd->nvme_cmd.cid == cid) {
			mreq_to_abort = mreq;
			break;
		}
	}

	if (mreq_to_abort == NULL) {
		SPDK_NOTICELOG("no req found for cid %u\n", cid);
		spdk_nvmf_request_complete(req);
		return;
	}

	SPDK_NOTICELOG("aborting snap_req %p cid %hu\n", mreq_to_abort,
		       mreq_to_abort->nvmf_req.cmd->nvme_cmd.cid);
	req->req_to_abort = &mreq_to_abort->nvmf_req;
	req->timeout_tsc = spdk_get_ticks() +
			   qpair->transport->opts.abort_timeout_sec * spdk_get_ticks_hz();
	req->poller = NULL;

	_nvmf_mlnx_snap_qpair_abort_request(req);
}

static struct nvmf_mlnx_snap_emu *
nvmf_mlnx_snap_emu_create(struct nvmf_mlnx_snap_listener *mlistener, const char *dev_name,
			  uint32_t pf)
{
	int	rc = 0;
	struct nvmf_mlnx_snap_emu *snap_emu = NULL;
	struct nvmf_mlnx_snap_ctx *snap_ctx, *tmp;
	struct snap_device_attr attr = {.type = SNAP_NVME_PF};

	snap_emu = calloc(1, sizeof(*snap_emu));
	if (!snap_emu) {
		SPDK_ERRLOG("Failed to allocate memory\n");
		return NULL;
	}

	snap_emu->pci_func_num = pf;
	snap_emu->listener = mlistener;

	TAILQ_FOREACH_SAFE(snap_ctx, &mlistener->mtransport->snap_ctxs, link, tmp) {
		if (!strcmp(snap_ctx->ctx->context->device->name, mlistener->trid->traddr)) {
			snap_emu->snap_ctx = snap_ctx->ctx;
			break;
		}
	}

	if (!snap_emu->snap_ctx) {
		SPDK_ERRLOG("No snap_ctx created\n");
		rc = -ENODEV;
		goto err_out;
	}

	snap_emu->dev_caps.max_reg_size = snap_emu->snap_ctx->nvme_caps.reg_size;
	snap_emu->dev_caps.max_emulated_cq_num = snap_emu->snap_ctx->nvme_caps.max_emulated_nvme_cqs;
	snap_emu->dev_caps.max_emulated_sq_num = snap_emu->snap_ctx->nvme_caps.max_emulated_nvme_sqs;
	snap_emu->dev_caps.max_namespaces = snap_emu->snap_ctx->nvme_caps.max_nvme_namespaces;
	snap_emu->dev_caps.max_emulated_pfs = snap_emu->snap_ctx->nvme_pfs.max_pfs;

	SPDK_NOTICELOG("Opening SNAP emu on device %s, pf %u\n", snap_emu->snap_ctx->context->device->name,
		       snap_emu->pci_func_num);
	attr.pf_id = pf;
	snap_emu->snap_dev = snap_open_device(snap_emu->snap_ctx, &attr);
	if (!snap_emu->snap_dev) {
		SPDK_ERRLOG("Failed to open snap device %s\n", snap_emu->snap_ctx->context->device->name);
		rc = -ENODEV;
		goto err_out;
	}

	snap_emu->vid = snap_emu->snap_dev->pci->pci_attr.vendor_id;
	snap_emu->ssvid = snap_emu->snap_dev->pci->pci_attr.subsystem_vendor_id;

	snap_emu->sf = nvmf_mlnx_snap_sf_alloc(dev_name);
	if (!snap_emu->sf) {
		SPDK_ERRLOG("Failed to allocate SF\n");
		goto err_out;
	}

	snap_emu->map = spdk_mem_map_alloc(0, &g_nvmf_mlnx_snap_map_ops, snap_emu->sf->pd);
	if (!snap_emu->map) {
		SPDK_ERRLOG("Unable to allocate memory map for listen address\n");
		rc = -ENOMEM;
		goto err_out;
	}

	rc = nvme_bar_init((nvme_bar_read_func_t)snap_emu_mmio_read, &snap_emu->bar, snap_emu);
	if (rc != 0) {
		SPDK_ERRLOG("dev 0x%p failed to init BAR", mlistener);
		rc = -ENODEV;
		goto err_out;
	}

	rc = nvme_bar_init_modify((nvme_bar_write_func_t)snap_emu_mmio_write, &snap_emu->bar, snap_emu);
	if (rc != 0) {
		SPDK_ERRLOG("dev 0x%p failed to modify BAR", mlistener);
		rc = -ENODEV;
		goto err_out;
	}

	rc = nvmf_mlnx_snap_mutex_init_recursive(&snap_emu->lock);
	if (rc) {
		SPDK_ERRLOG("Failed to create mutex\n");
		goto err_out;
	}

	memcpy(snap_emu->if_name, snap_emu->sf->sf.if_name, sizeof(snap_emu->if_name));
	strncpy(snap_emu->name, SNAP_EMU_NAME, sizeof(snap_emu->name) - 1);

	snap_emu->flags.is_started = 0;

	return snap_emu;

err_out:
	nvmf_mlnx_snap_emu_destroy(snap_emu);

	return NULL;
}

static int
snap_emu_stop(struct nvmf_mlnx_snap_emu *snap_emu)
{
	int rc;

	if (snap_emu->flags.is_started == 0) {
		SPDK_NOTICELOG("Already stopped\n");
		return 0;
	}

	SPDK_NOTICELOG("Stopping SNAP emu\n");

	snap_emu->flags.is_started = 0;
	rc = snap_nvme_teardown_device(snap_emu->snap_dev);
	if (rc) {
		SPDK_ERRLOG("snap_dev teardown finished with %d\n", rc);
	}

	return rc;
}

static int
snap_emu_start(struct nvmf_mlnx_snap_emu *snap_emu)
{
	struct snap_device_attr attr = {};
	int rc;

	if (snap_emu->flags.is_started == 1) {
		SPDK_DEBUGLOG(mlnx_snap, "Already started\n");
		return 0;
	}

	SPDK_NOTICELOG("Starting SNAP emu\n");

	/*
	 * On BF2 we have to close and open emulation manager object
	 * in order to clear FLR status. Fortunately this approach
	 * is backward compatible with the BF1.
	 */
	if (snap_emu->flags.flr_active) {
		snap_emu->flags.prev_enabled = 0;
		snap_emu->flags.curr_enabled = 0;
		SPDK_NOTICELOG("FLR, reopening emulation object\n");
		snap_close_device(snap_emu->snap_dev);

		attr.type = SNAP_NVME_PF;
		attr.pf_id = snap_emu->pci_func_num;
		snap_emu->snap_dev = snap_open_device(snap_emu->snap_ctx, &attr);
		if (!snap_emu->snap_dev) {
			SPDK_ERRLOG("dev 0x%p can't create snap device with id 0x%x", snap_emu,
				    snap_emu->pci_func_num);
			return -1;
		}
		snap_emu->flags.flr_active = 0;
	}

	rc = snap_nvme_init_device(snap_emu->snap_dev);
	if (rc) {
		SPDK_ERRLOG("dev %p failed INIT snap nvme device ret=%d\n", snap_emu, rc);
		return -1;
	}

	SPDK_NOTICELOG("Created snap nvme device %p, dd_data %p\n", snap_emu->snap_dev,
		       snap_emu->snap_dev->dd_data);

	snap_emu->flags.prev_enabled = 1;
	snap_emu->flags.curr_enabled = 1;
	snap_emu->flags.is_started = 1;

	return 0;
}

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_mlnx_snap = {
	.name = "MLNX_SNAP",
	.type = SPDK_NVME_TRANSPORT_CUSTOM,
	.opts_init = nvmf_mlnx_snap_opts_init,
	.create = nvmf_mlnx_snap_create,
	.destroy = nvmf_mlnx_snap_destroy,

	.listen = nvmf_mlnx_snap_listen,
	.stop_listen = nvmf_mlnx_snap_stop_listen,
	.listen_associate = nvmf_mlnx_snap_listen_associate,
	.accept = nvmf_mlnx_snap_accept,
//	.cdata_init = nvmf_mlnx_snap_cdata_init,

	.listener_discover = nvmf_mlnx_snap_discover,

	.poll_group_create = nvmf_mlnx_snap_poll_group_create,
	.get_optimal_poll_group = nvmf_mlnx_snap_get_optimal_poll_group,
	.poll_group_destroy = nvmf_mlnx_snap_poll_group_destroy,
	.poll_group_add = nvmf_mlnx_snap_poll_group_add,
	.poll_group_remove = nvmf_mlnx_snap_poll_group_remove,
	.poll_group_poll = nvmf_mlnx_snap_poll_group_poll,

	.req_free = nvmf_mlnx_snap_request_free,
	.req_complete = nvmf_mlnx_snap_request_complete,

	.qpair_fini = nvmf_mlnx_snap_close_qpair,
	.qpair_get_peer_trid = nvmf_mlnx_snap_qpair_get_peer_trid,
	.qpair_get_local_trid = nvmf_mlnx_snap_qpair_get_local_trid,
	.qpair_get_listen_trid = nvmf_mlnx_snap_qpair_get_listen_trid,
	.qpair_abort_request = nvmf_mlnx_snap_qpair_abort_request,

//	.poll_group_get_stat = nvmf_mlnx_snap_poll_group_get_stat,
//	.poll_group_free_stat = nvmf_mlnx_snap_poll_group_free_stat,
};

SPDK_NVMF_TRANSPORT_REGISTER(rdma, &spdk_nvmf_transport_mlnx_snap);
SPDK_LOG_REGISTER_COMPONENT(mlnx_snap)
