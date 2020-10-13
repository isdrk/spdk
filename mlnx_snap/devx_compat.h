#ifndef _DEVX_COMPAT_H
#define _DEVX_COMPAT_H

/**
 * Compatibility layer to bridge gaps over proof of concept devx and the final
 * version that it is now part of the rdma-core
 */

#include "config.h"
#include "utils.h"
#include <limits.h>
#include <stdint.h>

#define u8 uint8_t
#define BIT(n) (1<<(n))
#define __packed
#include <infiniband/verbs.h>
#include <linux/types.h>

#include "mlx5_ifc.h"

/**
 * TODO:
 * sysconf(LEVEL2_CACHE_LINESIZE) works on x86 but
 * returns zero on arm.
 * rdma-core returns 64 on arm and 64 is also default on x86
 * Use constant as a workaround
 */
#define DEVX_VERBS_L2_CACHE_SIZE 64

struct devx_db_page;
typedef struct devx_vtunnel devx_vtunnel_t;

typedef struct devx_obj {
    struct devx_obj_handle *memh;
    struct devx_obj_handle *objh;
    void                   *buff;
    uint32_t               *dbr;
    int                     id;
} devx_obj_t;

typedef struct {
    struct ibv_context   *ibv_ctx;
    devx_obj_t            pd;
    int                   type;
    uint16_t              lid;
    uint8_t               gid[16];
    uint16_t              r_roce_min_udp_src_port;
    uint16_t              r_roce_max_udp_src_port;
    uint16_t              r_roce_udp_dst_port;
    char                  if_name[IFACE_MAX_LEN];
    uint16_t              vhca_id;
    size_t                page_size;
    int                   cache_line_size;
    struct devx_db_page  *db_list;
    devx_vtunnel_t       *emu_vf_tun; /* tunnel to pass commands to the VF on the emulation device */
    char                  ibdev_path[PATH_MAX];
} devx_ctx_t;

struct devx_obj_handle {
    devx_ctx_t *ctx;
    union {
        struct mlx5dv_devx_obj  *obj;
        struct mlx5dv_devx_umem *umem;
        struct mlx5dv_devx_uar  *uar;
        uint64_t                 handle; /* used for the steering rules */
    };
    uint8_t *dtor_in;
    size_t   dtor_in_len;
    uint8_t *dtor_out;
    size_t   dtor_out_len;
};

/* Open/close mlx5 devx context */
int devx_open_device(devx_ctx_t *ctx, struct ibv_device *device);
void devx_close_device(devx_ctx_t *ctx);

/* DEVX object */
struct devx_obj_handle *devx_obj_create(devx_ctx_t *ctx, void *in, size_t inlen,
                                        void *out, size_t outlen);
int devx_obj_destroy(struct devx_obj_handle *obj);

int devx_obj_query(struct devx_obj_handle *obj, void *in, size_t inlen,
                   void *out, size_t outlen);

int devx_obj_modify(struct devx_obj_handle *obj, void *in, size_t inlen,
		            void *out, size_t outlen);

/* set destructor for the 'tunneled object' */
void devx_obj_set_dtor(struct devx_obj_handle *obj, void *dtor,
                       size_t dtor_in_len, size_t dtor_out_len);

/* General command */
int devx_cmd(devx_ctx_t *ctx, void *in, size_t inlen, void *out,
             size_t outlen);

/* UAR */
struct devx_obj_handle *devx_alloc_uar(devx_ctx_t *ctx, uint32_t *idx, void **addr);
int devx_free_uar(struct devx_obj_handle *uar);

/* DB record */
void *devx_alloc_dbrec(devx_ctx_t *ctx, uint32_t *mem_id, size_t *off);
void devx_free_dbrec(devx_ctx_t *ctx, void *db);

/* UMEM */
struct devx_obj_handle *devx_umem_reg(devx_ctx_t *ctx, void *addr, size_t size,
				                      int access, uint32_t *id);
int devx_umem_dereg(struct devx_obj_handle *umem);

/* FLOW steering */
struct devx_obj_handle *devx_fs_rule_add(devx_ctx_t *ctx, void *in,
                    					 struct devx_obj_handle *dest,
                                         uint32_t vport);
int devx_fs_rule_del(struct devx_obj_handle *obj);

/* MISC */
int devx_get_async_fd(devx_ctx_t *ctx);
int devx_query_eqn(devx_ctx_t *ctx, uint32_t vector, uint32_t *eqn);
int devx_query_gid(devx_ctx_t *ctx, uint8_t port_num, int index, uint8_t *gid);

#if !HAVE_DEVX_IN_RDMA_CORE

/* macros are needed so that we can compile code
 * when devx is not available.
 * For example, check compilation on x86 and run tests
 */
#define __devx_nullp(typ) ((struct mlx5_ifc_##typ##_bits *)0)
#define __devx_bit_sz(typ, fld) sizeof(__devx_nullp(typ)->fld)
#define __devx_bit_off(typ, fld) (offsetof(struct mlx5_ifc_##typ##_bits, fld))
#define __devx_dw_off(typ, fld) (__devx_bit_off(typ, fld) / 32)
#define __devx_64_off(typ, fld) (__devx_bit_off(typ, fld) / 64)
#define __devx_dw_bit_off(typ, fld) (32 - __devx_bit_sz(typ, fld) - (__devx_bit_off(typ, fld) & 0x1f))
#define __devx_mask(typ, fld) ((uint32_t)((1ull << __devx_bit_sz(typ, fld)) - 1))
#define __devx_dw_mask(typ, fld) (__devx_mask(typ, fld) << __devx_dw_bit_off(typ, fld))
#define __devx_st_sz_bits(typ) sizeof(struct mlx5_ifc_##typ##_bits)

#define DEVX_FLD_SZ_BYTES(typ, fld) (__devx_bit_sz(typ, fld) / 8)
#define DEVX_ST_SZ_BYTES(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 8)
#define DEVX_ST_SZ_DW(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 32)
#define DEVX_ST_SZ_QW(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 64)
#define DEVX_UN_SZ_BYTES(typ) (sizeof(union mlx5_ifc_##typ##_bits) / 8)
#define DEVX_UN_SZ_DW(typ) (sizeof(union mlx5_ifc_##typ##_bits) / 32)
#define DEVX_BYTE_OFF(typ, fld) (__devx_bit_off(typ, fld) / 8)
#define DEVX_ADDR_OF(typ, p, fld) ((char *)(p) + DEVX_BYTE_OFF(typ, fld))

#define BUILD_BUG_ON(a) /*TODO*/
/* insert a value to a struct */
#define DEVX_SET(typ, p, fld, v) do { \
	uint32_t _v = v; \
	BUILD_BUG_ON(__devx_st_sz_bits(typ) % 32);   \
	*((__be32 *)(p) + __devx_dw_off(typ, fld)) = \
	htobe32((be32toh(*((__be32 *)(p) + __devx_dw_off(typ, fld))) & \
		     (~__devx_dw_mask(typ, fld))) | (((_v) & __devx_mask(typ, fld)) \
		     << __devx_dw_bit_off(typ, fld))); \
} while (0)

#define DEVX_GET(typ, p, fld) ((be32toh(*((__be32 *)(p) +\
	__devx_dw_off(typ, fld))) >> __devx_dw_bit_off(typ, fld)) & \
	__devx_mask(typ, fld))


#define __DEVX_SET64(typ, p, fld, v) do { \
	BUILD_BUG_ON(__devx_bit_sz(typ, fld) != 64); \
	*((__be64 *)(p) + __devx_64_off(typ, fld)) = htobe64(v); \
} while (0)

#define DEVX_SET64(typ, p, fld, v) do { \
	BUILD_BUG_ON(__devx_bit_off(typ, fld) % 64); \
	__DEVX_SET64(typ, p, fld, v); \
} while (0)

#define DEVX_GET64(typ, p, fld) \
	be64toh(*((__be64 *)(p) + __devx_64_off(typ, fld)))

#define DEVX_SET_TO_ONES(typ, p, fld) do { \
	BUILD_BUG_ON(__devx_st_sz_bits(typ) % 32);	       \
	*((__be32 *)(p) + __devx_dw_off(typ, fld)) = \
	htobe32((be32toh(*((__be32 *)(p) + __devx_dw_off(typ, fld))) & \
		     (~__devx_dw_mask(typ, fld))) | ((__devx_mask(typ, fld)) \
		     << __devx_dw_bit_off(typ, fld))); \
} while (0)

#endif

#endif
