/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "env_internal.h"
#include "pci_dpdk.h"

#include <rte_devargs.h>
#include <rte_pci.h>

#include "spdk/queue.h"
#include "spdk/util.h"
#ifdef __linux__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
#include <linux/vfio.h>
#include <rte_vfio.h>
#endif
#endif
#include <rte_bus_pci.h>


#define SYSFS_PCI_DEVICES "/sys/bus/pci/devices"

/*
 * Workaround to use new IOCTL in the VFIO APIs.
 * The following wiki page describes the issue and possible solutions:
 * https://kernelnewbies.org/KernelHeaders
 */

#ifndef VFIO_DEVICE_P2P_DMA_BUF
struct vfio_device_p2p_dma_buf {
	__u32 region_index;
	__u32 open_flags;
	__u32 offset;
	__u64 length;
};
#define VFIO_DEVICE_P2P_DMA_BUF _IO(VFIO_TYPE, VFIO_BASE + 22)

#endif /* VFIO_DEVICE_P2P_DMA_BUF */

#ifndef VFIO_DEVICE_P2P_DMA_BUF
struct spdk_dmabuf *
spdk_pci_device_create_dmabuf(__attribute__((unused)) struct spdk_pci_device *spdk_dev,
			      __attribute__((unused)) int bar)
{
	return -1;
}

int
spdk_pci_device_destroy_dmabuf(__attribute__((unused)) struct spdk_pci_device *spdk_dev,
			       __attribute__((unused)) struct spdk_dmabuf *dmabuf)
{
	return -1;
}

#else
static int
get_vfio_dev_fd(const char *pci_dev_name)
{
	int iommu_group_num;
	int group_fd;

	if (rte_vfio_get_group_num(SYSFS_PCI_DEVICES, pci_dev_name, &iommu_group_num) <= 0) {
		return -1;
	}

	group_fd = rte_vfio_get_group_fd(iommu_group_num);
	if (group_fd < 0) {
		return -1;
	}

	return ioctl(group_fd, VFIO_GROUP_GET_DEVICE_FD, pci_dev_name);
}

static int
get_vfio_dmabuf_fd(int vfio_dev_fd, int bar)
{
	struct vfio_device_p2p_dma_buf *dmabuf_args;
	int dmabuf_fd;

	dmabuf_args = calloc(1, sizeof(*dmabuf_args));
	if (!dmabuf_args) {
		return -ENOMEM;
	}

	dmabuf_args->region_index = bar;
	dmabuf_args->open_flags = O_RDWR;
	dmabuf_args->offset = 0;
	dmabuf_args->length = 0;

	dmabuf_fd = ioctl(vfio_dev_fd, VFIO_DEVICE_P2P_DMA_BUF, dmabuf_args);

	free(dmabuf_args);

	return dmabuf_fd;
}

struct spdk_dmabuf *
spdk_pci_device_create_dmabuf(struct spdk_pci_device *spdk_dev, int bar)
{
	struct rte_pci_device *rte_dev = spdk_dev->dev_handle;
	struct spdk_dmabuf *dmabuf;
	struct rte_mem_resource *mem_resource;

	if (spdk_dev->internal.vfio_dev_fd < 0) {
		spdk_dev->internal.vfio_dev_fd = get_vfio_dev_fd(dpdk_pci_device_get_name(rte_dev));
		if (spdk_dev->internal.vfio_dev_fd < 0) {
			return 0;
		}
	}

	dmabuf = calloc(1, sizeof(*dmabuf));
	if (!dmabuf) {
		goto err_close_vfio_fd;
	}

	dmabuf->fd = get_vfio_dmabuf_fd(spdk_dev->internal.vfio_dev_fd, bar);
	if (dmabuf->fd < 0) {
		goto err_free_dmabuf;
	}

	mem_resource = dpdk_pci_device_get_mem_resource(rte_dev, bar);
	dmabuf->addr = mem_resource->addr;
	dmabuf->length = mem_resource->len;

	return dmabuf;

err_free_dmabuf:
	free(dmabuf);
err_close_vfio_fd:
	close(spdk_dev->internal.vfio_dev_fd);
	spdk_dev->internal.vfio_dev_fd = -1;
	return NULL;
}

void
spdk_pci_device_destroy_dmabuf(struct spdk_pci_device *spdk_dev, struct spdk_dmabuf *dmabuf)
{
	assert(dmabuf);
	assert(dmabuf->fd >= 0);

	close(dmabuf->fd);
	free(dmabuf);
}
#endif
