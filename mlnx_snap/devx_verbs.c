#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <rdma/ib_user_verbs.h>
#include <infiniband/verbs.h>

#include "devx_verbs.h"
#include "mlnx_snap_utils.h"
//#include "nvme_mlx5_ifc.h"
//#include "nvme_mlx5_sig.h"

#include <spdk/log.h>

/* Declarations */
static int query_device(devx_ctx_t *devx_ctx, uint8_t *out, size_t out_size);
static void free_devx_obj(devx_ctx_t *devx_ctx, devx_obj_t *obj);

void devx_free_pd(devx_ctx_t *devx_ctx, devx_obj_t *pd)
{
	free_devx_obj(devx_ctx, pd);
}

int devx_alloc_pd(devx_ctx_t *devx_ctx, devx_obj_t *pd)
{
	uint8_t in[DEVX_ST_SZ_BYTES(alloc_pd_in)] = {0};
	uint8_t out[DEVX_ST_SZ_BYTES(alloc_pd_out)] = {0};

	DEVX_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
	pd->objh = devx_obj_create(devx_ctx, in, sizeof(in), out,
				   sizeof(out));
	if (!pd->objh) {
		SPDK_ERRLOG("devx_ctx %p failed to create pd: err=%d\n",
			    devx_ctx, errno);
		return -errno;
	}

	pd->id = DEVX_GET(alloc_pd_out, out, pd);

	if (devx_ctx->emu_vf_tun) {
		uint8_t din[DEVX_ST_SZ_BYTES(dealloc_pd_in)] = {0};

		DEVX_SET(dealloc_pd_in, din, opcode, MLX5_CMD_OP_DEALLOC_PD);
		DEVX_SET(dealloc_pd_in, din, pd, pd->id);

		devx_obj_set_dtor(pd->objh, din, sizeof(din),
				  DEVX_ST_SZ_BYTES(dealloc_pd_out));
	}

	SPDK_DEBUGLOG(mlnx_snap_devx, "devx_ctx %p created pd id=0x%x\n", devx_ctx, pd->id);
	return 0;
}

static int devx_query_udp_port(devx_ctx_t *devx_ctx)
{
	uint8_t in[DEVX_ST_SZ_BYTES(query_hca_cap_in)] = {0};
	uint8_t out[DEVX_ST_SZ_BYTES(query_hca_cap_out)] = {0};
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, MLX5_HCA_CAP_OPMOD_GET_MAX | (MLX5_CAP_ROCE << 1));
	ret = devx_cmd(devx_ctx, in, sizeof(in), out, sizeof(out));
	if (ret) {
		SPDK_ERRLOG("devx_ctx %p failed query generic hca caps: err=%d\n",
			    devx_ctx, errno);
		return ret;
	}

	devx_ctx->r_roce_min_udp_src_port = DEVX_GET(query_hca_cap_out, out,
					    capability.roce_cap.r_roce_min_src_udp_port);
	devx_ctx->r_roce_max_udp_src_port = DEVX_GET(query_hca_cap_out, out,
					    capability.roce_cap.r_roce_max_src_udp_port);
	devx_ctx->r_roce_udp_dst_port = DEVX_GET(query_hca_cap_out, out,
					capability.roce_cap.r_roce_dest_udp_port);

	SPDK_DEBUGLOG(mlnx_snap_devx, "ROCE Caps: src port (min=0x%x, max=0x%x), dst port 0x%x\n",
		      devx_ctx->r_roce_min_udp_src_port,
		      devx_ctx->r_roce_max_udp_src_port,
		      devx_ctx->r_roce_udp_dst_port);

	return 0;
}

static int query_device(devx_ctx_t *devx_ctx, uint8_t *out,
			size_t out_size)
{
	uint8_t in[DEVX_ST_SZ_BYTES(query_hca_cap_in)] = {0};
	int ret;

	memset(out, 0, out_size);

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, MLX5_HCA_CAP_OPMOD_GET_MAX |
		 (MLX5_CAP_GENERAL << 1));
	ret = devx_cmd(devx_ctx, in, sizeof(in), out, out_size);
	if (ret) {
		SPDK_ERRLOG("devx_ctx %p failed to query device\n", devx_ctx);
		return ret;
	}

	return 0;
}

int devx_query_vport_lid(devx_ctx_t *devx_ctx, uint16_t vport, int is_other, uint16_t *vport_lid)
{
	uint8_t in[DEVX_ST_SZ_BYTES(query_hca_vport_context_in)] = {0};
	uint8_t out[DEVX_ST_SZ_BYTES(query_hca_vport_context_out)] = {0};
	int err;

	DEVX_SET(query_hca_vport_context_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT);
	DEVX_SET(query_hca_vport_context_in, in, port_num, 1);
	DEVX_SET(query_hca_vport_context_in, in, vport_number, vport);
	DEVX_SET(query_hca_vport_context_in, in, other_vport, is_other);

	err = devx_cmd(devx_ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		SPDK_DEBUGLOG(mlnx_snap_devx, "ctx %p failed to get lid: err=%d\n", devx_ctx, errno);
		*vport_lid = 0;
		return err;
	}

	*vport_lid = DEVX_GET(query_hca_vport_context_out, out, hca_vport_context.lid);
	SPDK_DEBUGLOG(mlnx_snap_devx, "ctx %p lid %d\n", devx_ctx, *vport_lid);
	return 0;
}

static int devx_set_async_fd_nonblock(void *ctx)
{
	int flags;
	int ret;

	flags = fcntl(devx_get_async_fd(ctx), F_GETFL);
	ret = fcntl(devx_get_async_fd(ctx), F_SETFL, flags | O_NONBLOCK);
	if (ret < 0) {
		SPDK_ERRLOG("failed to set async fd to nonblock\n");
		return -1;
	}
	return 0;
}

int devx_init_dev(const char *dev_name, devx_ctx_t *ctx)
{
	uint8_t out[DEVX_ST_SZ_BYTES(query_hca_cap_out)] = {0};
	bool found = false;
	int i, dev_count;
	struct ibv_device **list;
	int ret;

	memset(ctx, 0, sizeof(*ctx));

	list = ibv_get_device_list(&dev_count);
	if (!list) {
		SPDK_ERRLOG("failed to open device list\n");
		goto err;
	}

	for (i = 0; i < dev_count; i++) {
		if (strcmp(dev_name, list[i]->name) == 0) {
			found = true;
			break;
		}
	}

	if (!found) {
		SPDK_ERRLOG("device %s not found\n", dev_name);
		goto out_free_devices;
	}

	ret = devx_open_device(ctx, list[i]);
	if (ret) {
		SPDK_ERRLOG("%s: failed to open devx\n", dev_name);
		goto out_free_devices;
	}

	if (devx_alloc_pd(ctx, &ctx->pd)) {
		SPDK_ERRLOG("%s: failed to alloc pd\n", dev_name);
		goto out_close_device;
	}

	if (query_device(ctx, out, sizeof(out))) {
		SPDK_ERRLOG("%s: failed to query device\n", dev_name);
		goto out_free_pd;
	}

	ctx->type = DEVX_GET(query_hca_cap_out, out,
			     capability.cmd_hca_cap.port_type);

	if (devx_is_on_ib(ctx)) {
		if (devx_query_vport_lid(ctx, 0, 0, &ctx->lid)) {
			SPDK_ERRLOG("%s: failed to query vport lid\n", dev_name);
			goto out_free_pd;
		}
	} else {
		if (devx_query_udp_port(ctx)) {
			SPDK_ERRLOG("%s: failed to read udp src/dst ports\n", dev_name);
			goto out_free_pd;
		}

		if (devx_query_gid(ctx, 1, 0, ctx->gid)) {
			SPDK_ERRLOG("%s:1 failed to read gid:0\n", dev_name);
			goto out_free_pd;
		}

		if (nvmf_mlnx_snap_dev_to_iface(dev_name, ctx->if_name)) {
			goto out_free_pd;
		}
	}

	if (devx_set_async_fd_nonblock(ctx)) {
		SPDK_ERRLOG("%s: failed to set async fd to non block\n", dev_name);
		goto out_free_pd;
	}

	ibv_free_device_list(list);

	ctx->vhca_id = DEVX_GET(query_hca_cap_out, out,
				capability.cmd_hca_cap.vhca_id);
	return 0;

out_free_pd:
	devx_free_pd(ctx, &ctx->pd);
out_close_device:
	devx_close_device(ctx);
out_free_devices:
	ibv_free_device_list(list);
err:
	return -1;
}

static void free_devx_obj(devx_ctx_t *devx_ctx, devx_obj_t *obj)
{
	if (!obj) {
		return;
	}

	if (obj->objh) {
		devx_obj_destroy(obj->objh);
		obj->objh = NULL;
	}
	if (obj->dbr) {
		devx_free_dbrec(devx_ctx, obj->dbr);
		obj->dbr = NULL;
	}
	if (obj->memh) {
		devx_umem_dereg(obj->memh);
		obj->memh = NULL;
	}
	if (obj->buff) {
		free(obj->buff);
		obj->buff = NULL;
	}
}


void devx_reset_dev(devx_ctx_t *devx_ctx)
{
	if (!devx_ctx) {
		return;
	}

	devx_free_pd(devx_ctx, &devx_ctx->pd);
	devx_close_device(devx_ctx);
	memset(devx_ctx, 0, sizeof(*devx_ctx));
}

enum {
	MLX5_QP_ST_RC               = 0x0,
	MLX5_QP_ST_UC               = 0x1,
	MLX5_QP_ST_UD               = 0x2,
	MLX5_QP_ST_XRC              = 0x3,
	MLX5_QP_ST_MLX              = 0x4,
	MLX5_QP_ST_DCI              = 0x5,
	MLX5_QP_ST_DCT              = 0x6,
	MLX5_QP_ST_QP0              = 0x7,
	MLX5_QP_ST_QP1              = 0x8,
	MLX5_QP_ST_RAW_ETHERTYPE    = 0x9,
	MLX5_QP_ST_RAW_IPV6         = 0xa,
	MLX5_QP_ST_SNIFFER          = 0xb,
	MLX5_QP_ST_SYNC_UMR         = 0xe,
	MLX5_QP_ST_PTP_1588         = 0xd,
	MLX5_QP_ST_REG_UMR          = 0xc,
	MLX5_QP_ST_MAX
};

enum {
	MLX5_QP_PM_MIGRATED         = 0x3,
	MLX5_QP_PM_ARMED            = 0x0,
	MLX5_QP_PM_REARM            = 0x1
};


enum {
	MLX5_RES_SCAT_DATA32_CQE    = 0x1,
	MLX5_RES_SCAT_DATA64_CQE    = 0x2,
	MLX5_REQ_SCAT_DATA32_CQE    = 0x11,
	MLX5_REQ_SCAT_DATA64_CQE    = 0x22,
};

/* roce addr table management */
/* TODO: roce_addr_get on_behalf, function_id */
int devx_roce_addr_get(devx_ctx_t *devx_ctx, int gid_idx, void **roce_addr_p)
{
	void *roce_addr;
	int roce_addr_len;
	int ret;
	uint32_t qin[DEVX_ST_SZ_DW(query_roce_address_in)] = {0};
	uint32_t qout[DEVX_ST_SZ_DW(query_roce_address_out)] = {0};

	roce_addr_len = DEVX_ST_SZ_BYTES(roce_addr_layout);
	roce_addr = calloc(roce_addr_len, 1);
	if (!roce_addr) {
		SPDK_ERRLOG("devx_ctx %p failed to alloc memory: err=%d\n", devx_ctx, errno);
		return -errno;
	}

	DEVX_SET(query_roce_address_in, qin, opcode, MLX5_CMD_OP_QUERY_ROCE_ADDRESS);
	DEVX_SET(query_roce_address_in, qin, roce_address_index, gid_idx);

	ret = devx_cmd(devx_ctx, qin, sizeof(qin), qout, sizeof(qout));
	if (ret) {
		SPDK_ERRLOG("devx_ctx %p failed to get ROCE address: err=%d\n", devx_ctx, errno);
		free(roce_addr);
		return ret;
	}

	memcpy(roce_addr,
	       DEVX_ADDR_OF(query_roce_address_out, qout, roce_address), roce_addr_len);

	*roce_addr_p = roce_addr;
	return 0;
}

int devx_roce_addr_set(devx_ctx_t *devx_ctx, void *roce_addr, int gid_idx)
{
	uint8_t sin[DEVX_ST_SZ_BYTES(set_roce_address_in)] = {0};
	uint8_t sout[DEVX_ST_SZ_BYTES(set_roce_address_out)] = {0};
	int ret;

	DEVX_SET(set_roce_address_in, sin, opcode, MLX5_CMD_OP_SET_ROCE_ADDRESS);
	DEVX_SET(set_roce_address_in, sin, roce_address_index, gid_idx);
	DEVX_SET(set_roce_address_in, sin, vhca_port_num, 0);

	memcpy(DEVX_ADDR_OF(set_roce_address_in, sin, roce_address),
	       roce_addr,
	       DEVX_ST_SZ_BYTES(roce_addr_layout));

	ret = devx_cmd(devx_ctx, sin, sizeof(sin), sout, sizeof(sout));
	if (ret) {
		SPDK_ERRLOG("devx_ctx %p failed to set ROCE address: err=%d\n", devx_ctx, errno);
		return ret;
	}

	return 0;
}

void devx_roce_addr_free(void *roce_addr)
{
	free(roce_addr);
}

static void print_gid(char *gid)
{
	int i;

	for (i = 0; i < 16; i += 2) {
		printf("%02x%02x", gid[i], gid[i + 1]);
		if (i < 14) {
			printf(":");
		}
	}
}

void devx_roce_addr_dump(void *roce_addr)
{
	char *l3_addr, *smac;
	int l3_type, ver;

	/* do explicit casting because devx in rdma core wants uint8_t * and
	 * our old devx wants char * */
	l3_addr = (char *)DEVX_ADDR_OF(roce_addr_layout, roce_addr, source_l3_address);
	smac    = (char *)DEVX_ADDR_OF(roce_addr_layout, roce_addr, source_mac_47_32);
	l3_type = DEVX_GET(roce_addr_layout, roce_addr, roce_l3_type);
	ver     = DEVX_GET(roce_addr_layout, roce_addr, roce_version);

	printf("v:%d l3_type: %d ", ver == 0 ? 1 : ver, l3_type);
	printf("GID: ");
	print_gid(l3_addr);
	printf(" MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
}
