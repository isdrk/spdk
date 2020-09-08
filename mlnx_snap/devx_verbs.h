#ifndef _DEVX_VERBS_H
#define _DEVX_VERBS_H

/* set up helper functions that we need to have a 'verbs' like
 * functionality over objects opened via DEVX
 */

#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

#include "devx_compat.h"
#include <infiniband/mlx5dv.h>
#include "mlnx_snap_utils.h"

#define DEVX_CQ_POLL_TO 1600000
#define DEVX_CQ_POLL_INF (-1)

/* number of bits in the QP */
#define DEVX_IB_QPN_ORDER 24

/* mlx5_hw.h does not like mlx5dv.h. So define only what is needed */
enum {
	MLX5_HCA_CAP_OPMOD_GET_MAX  = 0,
	MLX5_HCA_CAP_OPMOD_GET_CUR  = 1,
};

enum {
	MLX5_CAP_GENERAL = 0,
	MLX5_CAP_ETHERNET_OFFLOADS,
	MLX5_CAP_ODP,
	MLX5_CAP_ATOMIC,
	MLX5_CAP_ROCE,
	MLX5_CAP_IPOIB_OFFLOADS,
	MLX5_CAP_IPOIB_ENHANCED_OFFLOADS,
	MLX5_CAP_FLOW_TABLE,
	MLX5_CAP_ESWITCH_FLOW_TABLE,
	MLX5_CAP_ESWITCH,
	MLX5_CAP_RESERVED,
	MLX5_CAP_VECTOR_CALC,
	MLX5_CAP_QOS,
	MLX5_CAP_FPGA,
	MLX5_CAP_EMULATION = 0x10, /* NVMx specific */
};

struct mlx5_eqe_comp {
	__be32	reserved[6];
	__be32	cqn;
};

union ev_data {
	__be32				   raw[7];
	struct mlx5_eqe_comp   comp;
};

typedef struct devx_uar {
	struct devx_obj_handle *uar;
	uint32_t               uar_id;
	void                   *uar_ptr;
} devx_uar_t;

struct devx_vtunnel {
	devx_obj_t   super;
	uint16_t     vhca_id;
	uint16_t     vtun_id;
	uint32_t     dma_rkey;
	devx_ctx_t   *sf;
};

typedef struct {
	struct devx_obj_handle *memh;
	struct devx_obj_handle *objh;
	uint32_t                id;
	uint32_t                mkey;
} devx_mr_t;

struct devx_event {
	__u16 obj_type;
	__u32 obj_id;
	__u32 event_type;
};

/*
* managment
* thread safety: requires external lock (todo: internal lock)
*/
int devx_init_dev(const char *dev_name, devx_ctx_t *ctx);
void devx_reset_dev(devx_ctx_t *ctx);

/* create PD */
int devx_alloc_pd(devx_ctx_t *devx_ctx, devx_obj_t *pd);
/* destroy PD */
void devx_free_pd(devx_ctx_t *devx_ctx, devx_obj_t *pd);

/* query vport lid */
int devx_query_vport_lid(devx_ctx_t *ctx, uint16_t vport, int is_other, uint16_t *vport_lid);

static inline int devx_is_on_ib(devx_ctx_t *ctx)
{
	return ctx->type == MLX5_CAP_PORT_TYPE_IB;
}

#define DEVX_QP_SQ_PSN 0x4242
#define DEVX_QP_RQ_PSN 0x4242

struct ibv_qp_attr;

/* ROCE addr table management */
int devx_roce_addr_get(devx_ctx_t *ctx, int gid_idx, void **roce_addr_p);
int devx_roce_addr_set(devx_ctx_t *ctx, void *roce_addr, int gid_idx);
void devx_roce_addr_free(void *roce_addr);
/* dump to the stdout */
void devx_roce_addr_dump(void *roce_addr);

/* memory barriers */

#define devx_compiler_fence() asm volatile(""::: "memory")

#if defined(__x86_64__)

#define devx_memory_bus_fence()        asm volatile ("mfence"::: "memory")
#define devx_memory_bus_store_fence()  asm volatile ("sfence" ::: "memory")
#define devx_memory_bus_load_fence()   asm volatile ("lfence" ::: "memory")

#define devx_memory_cpu_fence()        devx_compiler_fence()
#define devx_memory_cpu_store_fence()  devx_compiler_fence()
#define devx_memory_cpu_load_fence()   devx_compiler_fence()


#elif defined(__aarch64__)

#define devx_memory_bus_fence()        asm volatile ("dsb sy" ::: "memory")
#define devx_memory_bus_store_fence()  asm volatile ("dsb st" ::: "memory")
#define devx_memory_bus_load_fence()   asm volatile ("dsb ld" ::: "memory")

#define devx_memory_cpu_fence()        asm volatile ("dmb ish" ::: "memory")
#define devx_memory_cpu_store_fence()  asm volatile ("dmb ishst" ::: "memory")
#define devx_memory_cpu_load_fence()   asm volatile ("dmb ishld" ::: "memory")

#else
# error "Unsupported architecture"
#endif

#endif
