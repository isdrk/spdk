/**
 * Compatibility layer to bridge gaps over proof of concept devx and the final
 * version that it is now part of the rdma-core
 */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <infiniband/mlx5dv.h>
#include <errno.h>
#include <unistd.h>

#include "mlx5_ifc.h"
#include "devx_verbs.h"
#include "devx_compat.h"
#include "nvme_mlx5_ifc.h"

#include <spdk/log.h>

#define HAVE_DEVX_IN_RDMA_CORE 1

#if HAVE_DEVX_IN_RDMA_CORE
static int read_file(const char *dir, const char *file,
		     char *buf, size_t size)
{
	char *path;
	int fd;
	size_t len;

	if (asprintf(&path, "%s/%s", dir, file) < 0) {
		return -1;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(path);
		return -1;
	}

	len = read(fd, buf, size);

	close(fd);
	free(path);

	if (len > 0) {
		if (buf[len - 1] == '\n') {
			buf[--len] = '\0';
		} else if (len < size) {
			buf[len] = '\0';
		} else {
			return -1;
		}
	}

	return len;
}

int devx_open_device(devx_ctx_t *ctx, struct ibv_device *device)
{
	struct mlx5dv_context_attr attrs = {0};

	if (!mlx5dv_is_supported(device)) {
		SPDK_ERRLOG("devx is not supported on device %s\n", device->name);
		return -errno;
	}

	attrs.flags = MLX5DV_CONTEXT_FLAGS_DEVX;
	ctx->ibv_ctx = mlx5dv_open_device(device, &attrs);
	if (!ctx->ibv_ctx) {
		SPDK_ERRLOG("devx: failed to open device %m errno=%d\n", errno);
		return -errno;
	}

	ctx->db_list         = NULL;
	ctx->page_size       = sysconf(_SC_PAGESIZE);
	ctx->cache_line_size = DEVX_VERBS_L2_CACHE_SIZE;

	strncpy(ctx->ibdev_path, device->ibdev_path, PATH_MAX);
	SPDK_DEBUGLOG(mlnx_snap_devx, "devx: opened device %s\n", device->name);
	return 0;
}

void devx_close_device(devx_ctx_t *ctx)
{
	ibv_close_device(ctx->ibv_ctx);
}

static struct devx_obj_handle *devx_obj_handle_alloc(devx_ctx_t *ctx)
{
	struct devx_obj_handle *h;

	h = (struct devx_obj_handle *)calloc(1, sizeof(*h));
	if (!h) {
		SPDK_ERRLOG("devx: failed to allocate object handle\n");
		return NULL;
	}

	h->ctx = ctx;
	return h;
}

static void devx_obj_handle_free(struct devx_obj_handle *h)
{
	free(h);
}

/* OBJECT */
struct mlx5dv_devx_obj {
	struct ibv_context *context;
	uint32_t handle;
};

struct devx_obj_handle *devx_obj_create(devx_ctx_t *ctx,
					void *in, size_t inlen,
					void *out, size_t outlen)
{
	struct devx_obj_handle *h;

	h = devx_obj_handle_alloc(ctx);
	if (!h) {
		return NULL;
	}

	if (ctx->emu_vf_tun) {
		h->dtor_in = NULL;
		h->dtor_out = NULL;
		h->obj = NULL;
		if (devx_cmd(ctx, in, inlen, out, outlen)) {
			goto err;
		}
	} else {
		h->obj = mlx5dv_devx_obj_create(ctx->ibv_ctx, in, inlen, out, outlen);
		if (!h->obj) {
			goto err;
		}
	}

	return h;

err:
	SPDK_ERRLOG("devx: failed to create object\n");
	free(h);
	return NULL;

}

/* set destructor for the 'tunneled object' */
void devx_obj_set_dtor(struct devx_obj_handle *h, void *dtor,
		       size_t dtor_in_len, size_t dtor_out_len)
{
	if (!h->ctx->emu_vf_tun) {
		return;
	}

	h->dtor_in = malloc(dtor_in_len);
	if (!h->dtor_in) {
		goto fatal;
	}

	memcpy(h->dtor_in, dtor, dtor_in_len);
	h->dtor_in_len  = dtor_in_len;
	h->dtor_out = calloc(dtor_out_len, sizeof(uint8_t));
	if (!h->dtor_out) {
		free(h->dtor_in);
		goto fatal;
	}
	h->dtor_out_len = dtor_out_len;
	return;

fatal:
	/* since the destructor is set after object was created
	 * we cannot really fail here. If we do, the main object
	 * will never be destroyed.
	 * TODO: fix
	 */
	SPDK_ERRLOG("destructor allocation failure\n");
}

int devx_obj_query(struct devx_obj_handle *h, void *in, size_t inlen,
		   void *out, size_t outlen)
{
	if (h->obj) {
		return mlx5dv_devx_obj_query(h->obj, in, inlen, out, outlen);
	} else {
		return devx_cmd(h->ctx, in, inlen, out, outlen);
	}
}

int devx_obj_modify(struct devx_obj_handle *h, void *in, size_t inlen,
		    void *out, size_t outlen)
{
	if (h->obj) {
		return mlx5dv_devx_obj_modify(h->obj, in, inlen, out, outlen);
	} else {
		return devx_cmd(h->ctx, in, inlen, out, outlen);
	}
}

int devx_obj_destroy(struct devx_obj_handle *h)
{
	int ret = 0;

	if (h->obj) {
		mlx5dv_devx_obj_destroy(h->obj);
	} else if (h->dtor_in && h->dtor_out) {
		ret = devx_cmd(h->ctx, h->dtor_in, h->dtor_in_len,
			       h->dtor_out, h->dtor_out_len);
		if (ret)
			SPDK_WARNLOG("FAILED to destroy tunneled object %p err %d dtor_length %zu\n",
				     h, ret, h->dtor_in_len);

		free(h->dtor_out);
		h->dtor_out = NULL;
		free(h->dtor_in);
		h->dtor_in = NULL;
	}

	devx_obj_handle_free(h);

	return ret;
}

/* General command */
int devx_cmd(devx_ctx_t *ctx, void *in, size_t inlen, void *out, size_t outlen)
{
	if (ctx->emu_vf_tun) {
		DEVX_SET(vhca_tunnel_cmd, in, vhca_tunnel_id, ctx->emu_vf_tun->vtun_id);
	}

	return mlx5dv_devx_general_cmd(ctx->ibv_ctx, in, inlen, out, outlen);
}

/* UMEM */
struct devx_obj_handle *devx_umem_reg(devx_ctx_t *ctx, void *addr, size_t size,
				      int access, uint32_t *id)
{
	struct mlx5dv_devx_umem *umem;
	struct devx_obj_handle *h;

	h = devx_obj_handle_alloc(ctx);
	if (!h) {
		return NULL;
	}

	umem = mlx5dv_devx_umem_reg(ctx->ibv_ctx, addr, size, access);
	if (!umem) {
		SPDK_ERRLOG("devx: failed to register umem: addr=%p size=%lld, flags=0x%x\n",
			    addr, (unsigned long long)addr, access);
		devx_obj_handle_free(h);
		return NULL;
	}

	*id = umem->umem_id;
	h->umem = umem;
	return h;
}

int devx_umem_dereg(struct devx_obj_handle *h)
{
	mlx5dv_devx_umem_dereg(h->umem);
	devx_obj_handle_free(h);
	return 0;
}

/* UAR */
struct devx_obj_handle *devx_alloc_uar(devx_ctx_t *ctx, uint32_t *idx, void **addr)
{
	struct mlx5dv_devx_uar *uar;
	struct devx_obj_handle *h;

	h = devx_obj_handle_alloc(ctx);
	if (!h) {
		return NULL;
	}

	uar = mlx5dv_devx_alloc_uar(ctx->ibv_ctx, 0);
	if (!uar) {
		SPDK_ERRLOG("devx: failed to alloc uar\n");
		return 0;
	}

	*idx  = uar->page_id;
	*addr = uar->reg_addr;
	h->uar = uar;
	return h;
}

int devx_free_uar(struct devx_obj_handle *h)
{
	mlx5dv_devx_free_uar(h->uar);
	devx_obj_handle_free(h);
	return 0;
}


struct devx_db_page {
	struct devx_db_page     *prev, *next;
	uint8_t                 *buf;
	int                      num_db;
	int                      use_cnt;
	struct devx_obj_handle  *mem;
	uint32_t                 mem_id;
	unsigned long            free[0];
};

/* DB record - picked from the devx code */
static struct devx_db_page *dbrec_add_page(devx_ctx_t *context)
{
	uintptr_t ps = context->page_size;
	struct devx_db_page *page;
	int pp;
	int i;
	int nlong;
	int ret;

	pp = ps / context->cache_line_size;
	nlong = (pp + 8 * sizeof(long) - 1) / (8 * sizeof(long));

	page = malloc(sizeof(*page) + nlong * sizeof(long));
	if (!page) {
		return NULL;
	}

	ret = posix_memalign((void **)&page->buf, ps, ps);
	if (ret) {
		free(page);
		return NULL;
	}

	page->num_db  = pp;
	page->use_cnt = 0;
	for (i = 0; i < nlong; ++i) {
		page->free[i] = ~0;
	}

	page->mem = devx_umem_reg(context, page->buf, ps, 7, &page->mem_id);

	page->prev = NULL;
	page->next = context->db_list;
	context->db_list = page;
	if (page->next) {
		page->next->prev = page;
	}

	return page;
}

void *devx_alloc_dbrec(devx_ctx_t *ctx, uint32_t *mem_id, size_t *off)
{
	void *db = NULL;
	struct devx_db_page *page;
	int i, j;

	for (page = ctx->db_list; page; page = page->next)
		if (page->use_cnt < page->num_db) {
			goto found;
		}

	page = dbrec_add_page(ctx);
	if (!page) {
		goto out;
	}

found:
	++page->use_cnt;

	for (i = 0; !page->free[i]; ++i)
		/* nothing */;

	j = ffsl(page->free[i]);
	--j;
	page->free[i] &= ~(1UL << j);

	*mem_id = page->mem_id;
	*off = (i * 8 * sizeof(long) + j) * ctx->cache_line_size;
	db = page->buf + *off;
out:
	return db;
}

void devx_free_dbrec(devx_ctx_t *ctx, void *db)
{
	uintptr_t ps = ctx->page_size;
	struct devx_db_page *page;
	int i;

	for (page = ctx->db_list; page; page = page->next)
		if (((uintptr_t) db & ~(ps - 1)) == (uintptr_t) page->buf) {
			break;
		}

	if (!page) {
		return;
	}

	i = ((uint8_t *)db - page->buf) / ctx->cache_line_size;
	page->free[i / (8 * sizeof(long))] |= 1UL << (i % (8 * sizeof(long)));

	if (!--page->use_cnt) {
		if (page->prev) {
			page->prev->next = page->next;
		} else {
			ctx->db_list = page->next;
		}
		if (page->next) {
			page->next->prev = page->prev;
		}

		devx_umem_dereg(page->mem);
		free(page->buf);
		free(page);
	}
}

/* MISC */
int devx_get_async_fd(devx_ctx_t *ctx)
{
	return ctx->ibv_ctx->async_fd;
}

int devx_query_eqn(devx_ctx_t *ctx, uint32_t vector, uint32_t *eqn)
{
	return mlx5dv_devx_query_eqn(ctx->ibv_ctx, vector, eqn);
}

/* TODO: do it with ibv_query_gid() */
int devx_query_gid(devx_ctx_t *ctx, uint8_t port_num, int index, uint8_t *gid)
{
	char name[24];
	char attr[41];
	uint16_t val;
	int i;

	snprintf(name, sizeof(name), "ports/%d/gids/%d", port_num, index);

	if (read_file(ctx->ibdev_path, name, attr, sizeof(attr)) < 0) {
		return -errno;
	}

	for (i = 0; i < 8; ++i) {
		if (sscanf(attr + i * 5, "%hx", &val) != 1) {
			return -EINVAL;
		}
		gid[i * 2    ] = val >> 8;
		gid[i * 2 + 1] = val & 0xff;
	}

	return 0;
}

struct devx_obj_handle *devx_fs_rule_add(devx_ctx_t *ctx, void *in,
		struct devx_obj_handle *dest,
		uint32_t vport)
{
	return NULL;
}

int devx_fs_rule_del(struct devx_obj_handle *fobj)
{
	return 0;
}

SPDK_LOG_REGISTER_COMPONENT(mlnx_snap_devx)

#else
int devx_open_device(devx_ctx_t *ctx, struct ibv_device *device)
{
	SPDK_ERRLOG("DEVX is not supported in this version of verbs\n");
	return -ENOTSUP;
}

void devx_close_device(devx_ctx_t *ctx)
{
}

/* OBJECT */
struct devx_obj_handle *devx_obj_create(devx_ctx_t *ctx,
					void *in, size_t inlen,
					void *out, size_t outlen)
{
	return 0;
}

int devx_obj_query(struct devx_obj_handle *h, void *in, size_t inlen,
		   void *out, size_t outlen)
{
	return -ENOTSUP;
}

int devx_obj_modify(struct devx_obj_handle *h, void *in, size_t inlen,
		    void *out, size_t outlen)
{
	return -ENOTSUP;
}


int devx_obj_destroy(struct devx_obj_handle *h)
{
	return -ENOTSUP;
}

/* General command */
int devx_cmd(devx_ctx_t *ctx, void *in, size_t inlen,
	     void *out, size_t outlen)
{
	return -ENOTSUP;
}

/* UMEM */
struct devx_obj_handle *devx_umem_reg(devx_ctx_t *ctx, void *addr, size_t size,
				      int access, uint32_t *id)
{
	return 0;
}

int devx_umem_dereg(struct devx_obj_handle *umem)
{
	return -ENOTSUP;
}

/* UAR */
struct devx_obj_handle *devx_alloc_uar(devx_ctx_t *ctx, uint32_t *idx, void **addr)
{
	return 0;
}

int devx_free_uar(struct devx_obj_handle *uar)
{
	return -ENOTSUP;
}

/* DB record */
void *devx_alloc_dbrec(devx_ctx_t *ctx, uint32_t *mem_id, size_t *off)
{
	return 0;
}

void devx_free_dbrec(devx_ctx_t *ctx, void *db)
{
	return;
}

/* MISC */
int devx_get_async_fd(devx_ctx_t *ctx)
{
	return -ENOTSUP;
}

int devx_query_eqn(devx_ctx_t *ctx, uint32_t vector, uint32_t *eqn)
{
	return -ENOTSUP;
}

int devx_query_gid(devx_ctx_t *ctx, uint8_t port_num, int index, uint8_t *gid)
{
	return -ENOTSUP;
}

/* FLOW steering */
struct devx_obj_handle *devx_fs_rule_add(devx_ctx_t *ctx, void *in,
		struct devx_obj_handle *dest,
		uint32_t vport)
{
	return 0;
}

int devx_fs_rule_del(struct devx_obj_handle *obj)
{
	return -ENOTSUP;
}

void devx_obj_set_dtor(struct devx_obj_handle *h, void *dtor,
		       size_t dtor_in_len, size_t dtor_out_len)
{
}

#endif

