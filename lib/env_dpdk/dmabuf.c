/*
 *   BSD LICENSE
 *
 *   Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef VFIO_DEVICE_FEATURE
/**
 * VFIO_DEVICE_FEATURE - _IOWR(VFIO_TYPE, VFIO_BASE + 17,
 *			       struct vfio_device_feature)
 *
 * Get, set, or probe feature data of the device.  The feature is selected
 * using the FEATURE_MASK portion of the flags field.  Support for a feature
 * can be probed by setting both the FEATURE_MASK and PROBE bits.  A probe
 * may optionally include the GET and/or SET bits to determine read vs write
 * access of the feature respectively.  Probing a feature will return success
 * if the feature is supported and all of the optionally indicated GET/SET
 * methods are supported.  The format of the data portion of the structure is
 * specific to the given feature.  The data portion is not required for
 * probing.  GET and SET are mutually exclusive, except for use with PROBE.
 *
 * Return 0 on success, -errno on failure.
 */
struct vfio_device_feature {
	__u32	argsz;
	__u32	flags;
#define VFIO_DEVICE_FEATURE_MASK	(0xffff) /* 16-bit feature index */
#define VFIO_DEVICE_FEATURE_GET		(1 << 16) /* Get feature into data[] */
#define VFIO_DEVICE_FEATURE_SET		(1 << 17) /* Set feature from data[] */
#define VFIO_DEVICE_FEATURE_PROBE	(1 << 18) /* Probe feature support */
	__u8	data[];
};

#define VFIO_DEVICE_FEATURE		_IO(VFIO_TYPE, VFIO_BASE + 17)

#endif /* VFIO_DEVICE_FEATURE */

#ifndef VFIO_DEVICE_FEATURE_DMA_BUF
/**
 * Upon VFIO_DEVICE_FEATURE_GET create a dma_buf fd for the
 * region selected.
 *
 * open_flags are the typical flags passed to open(2), eg O_RDWR, O_CLOEXEC,
 * etc. offset/length specify a slice of the region to create the dmabuf from.
 * If both are 0 then the whole region is used.
 *
 * Return: The fd number on success, -1 and errno is set on failure.
 */
struct vfio_device_feature_dma_buf {
	__u32 region_index;
	__u32 open_flags;
	__u32 offset;
	__u64 length;
};
#define VFIO_DEVICE_FEATURE_DMA_BUF 3

#endif /* VFIO_DEVICE_FEATURE_DMA_BUF */

#ifndef VFIO_DEVICE_FEATURE_DMA_BUF
int
spdk_pci_device_create_dmabuf(__attribute__((unused)) struct spdk_pci_device *spdk_dev,
			      __attribute__((unused)) int bar)
{
	return -1;
}

int
spdk_pci_device_destroy_dmabuf(__attribute__((unused)) struct spdk_pci_device *spdk_dev,
			       __attribute__((unused)) int bar)
{
	return -1;
}

struct spdk_dmabuf *
spdk_dmabuf_get(__attribute__((unused)) void *addr,
		__attribute__((unused)) uint64_t size)
{
	return NULL;
}

void
spdk_dmabuf_put(__attribute__((unused)) struct spdk_dmabuf *dmabuf)
{
}

int
spdk_dmabuf_pci_device_removed(__attribute__((unused)) struct spdk_pci_device *spdk_dev)
{
	return 0;
}
#else

struct dmabuf {
	struct spdk_dmabuf dmabuf;
	unsigned refcount;
	TAILQ_ENTRY(dmabuf) tailq;
};

struct dmabuf_device {
	struct rte_pci_device *device;
	int vfio_dev_fd;
	TAILQ_HEAD(, dmabuf) dmabufs;
	TAILQ_ENTRY(dmabuf_device) tailq;
};

static pthread_mutex_t g_dmabuf_devices_mutex = PTHREAD_MUTEX_INITIALIZER;
static TAILQ_HEAD(, dmabuf_device) g_dmabuf_devices_list =
	TAILQ_HEAD_INITIALIZER(g_dmabuf_devices_list);

static struct dmabuf *
find_dmabuf_by_addr(struct dmabuf_device *dev, void *addr)
{
	struct dmabuf *dmabuf;

	TAILQ_FOREACH(dmabuf, &dev->dmabufs, tailq) {
		if (addr >= dmabuf->dmabuf.addr &&
		    addr < (dmabuf->dmabuf.addr + dmabuf->dmabuf.length)) {
			break;
		}
	}

	return dmabuf;
}

static struct dmabuf *
find_dmabuf_by_bar(struct dmabuf_device *dev, int bar)
{
	struct rte_mem_resource *res = dpdk_pci_device_get_mem_resource(dev->device, bar);
	void *addr = res->addr;

	return find_dmabuf_by_addr(dev, addr);
}

struct spdk_dmabuf *
spdk_dmabuf_get(void *addr, uint64_t size)
{
	struct dmabuf_device *dev;
	struct dmabuf *dmabuf;
	struct spdk_dmabuf *spdk_dmabuf = NULL;

	pthread_mutex_lock(&g_dmabuf_devices_mutex);

	TAILQ_FOREACH(dev, &g_dmabuf_devices_list, tailq) {
		dmabuf = find_dmabuf_by_addr(dev, addr);

		if (dmabuf) {
			if ((dmabuf->dmabuf.addr + dmabuf->dmabuf.length) <
			    (addr + size)) {
				break;
			}

			dmabuf->refcount++;
			spdk_dmabuf = &dmabuf->dmabuf;
			break;
		}
	}

	pthread_mutex_unlock(&g_dmabuf_devices_mutex);

	return spdk_dmabuf;
}

void
spdk_dmabuf_put(struct spdk_dmabuf *spdk_dmabuf)
{
	struct dmabuf *dmabuf = SPDK_CONTAINEROF(spdk_dmabuf, struct dmabuf, dmabuf);

	assert(dmabuf);
	assert(dmabuf->refcount);

	pthread_mutex_lock(&g_dmabuf_devices_mutex);
	dmabuf->refcount--;
	pthread_mutex_unlock(&g_dmabuf_devices_mutex);
}

static struct dmabuf_device *
find_dmabuf_device(struct rte_pci_device *pci_dev)
{
	struct dmabuf_device *dev;

	TAILQ_FOREACH(dev, &g_dmabuf_devices_list, tailq) {
		if (dev->device == pci_dev) {
			break;
		}
	}

	return dev;
}

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
	struct vfio_device_feature *feature;
	struct vfio_device_feature_dma_buf *dmabuf;
	size_t args_size = sizeof(*feature) + sizeof(*dmabuf);
	int dmabuf_fd;

	feature = calloc(1, args_size);
	if (!feature) {
		return -ENOMEM;
	}

	feature->argsz = args_size;
	feature->flags = VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_DMA_BUF;

	dmabuf = (void *)feature->data;
	dmabuf->region_index = bar;
	dmabuf->open_flags = O_RDWR;
	dmabuf->offset = 0;
	dmabuf->length = 0;

	dmabuf_fd = ioctl(vfio_dev_fd, VFIO_DEVICE_FEATURE, feature);

	free(feature);

	return dmabuf_fd;
}

static struct dmabuf_device *
create_dmabuf_device(struct rte_pci_device *pci_dev)
{
	struct dmabuf_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		return NULL;
	}

	dev->vfio_dev_fd = get_vfio_dev_fd(dpdk_pci_device_get_name(pci_dev));
	if (dev->vfio_dev_fd < 0) {
		free(dev);
		return NULL;
	}

	dev->device = pci_dev;
	TAILQ_INIT(&dev->dmabufs);
	TAILQ_INSERT_TAIL(&g_dmabuf_devices_list, dev, tailq);

	return dev;
}

static int
destroy_dmabuf_device(struct dmabuf_device *dev)
{
	int ret;

	assert(dev);

	ret = close(dev->vfio_dev_fd);
	if (ret) {
		return ret;
	}

	TAILQ_REMOVE(&g_dmabuf_devices_list, dev, tailq);
	free(dev);

	return ret;
}

static int
create_dmabuf(struct dmabuf_device *dev, int bar)
{
	struct dmabuf *dmabuf;
	struct rte_mem_resource *mem_resource;

	dmabuf = calloc(1, sizeof(*dmabuf));
	if (!dmabuf) {
		return -ENOMEM;
	}

	dmabuf->dmabuf.fd = get_vfio_dmabuf_fd(dev->vfio_dev_fd, bar);
	if (dmabuf->dmabuf.fd < 0) {
		free(dmabuf);
		return dmabuf->dmabuf.fd;
	}

	mem_resource = dpdk_pci_device_get_mem_resource(dev->device, bar);
	dmabuf->dmabuf.addr = mem_resource->addr;
	dmabuf->dmabuf.length = mem_resource->len;
	TAILQ_INSERT_TAIL(&dev->dmabufs, dmabuf, tailq);

	return 0;
}

static int
destroy_dmabuf(struct dmabuf_device *dev, struct dmabuf *dmabuf)
{
	int ret;

	assert(dev);
	assert(dmabuf);

	ret = close(dmabuf->dmabuf.fd);
	if (ret) {
		return ret;
	}

	TAILQ_REMOVE(&dev->dmabufs, dmabuf, tailq);
	free(dmabuf);

	if (TAILQ_EMPTY(&dev->dmabufs)) {
		ret = destroy_dmabuf_device(dev);
	}

	return ret;
}

int
spdk_pci_device_create_dmabuf(struct spdk_pci_device *spdk_dev, int bar)
{
	struct rte_pci_device *pci_dev = spdk_dev->dev_handle;
	struct dmabuf_device *dev;
	struct dmabuf *dmabuf;
	int ret = -1;

	pthread_mutex_lock(&g_dmabuf_devices_mutex);

	dev = find_dmabuf_device(pci_dev);
	if (!dev) {
		dev = create_dmabuf_device(pci_dev);
	}

	if (!dev) {
		goto out;
	}

	dmabuf = find_dmabuf_by_bar(dev, bar);
	if (dmabuf) {
		goto out;
	}

	ret = create_dmabuf(dev, bar);
out:
	pthread_mutex_unlock(&g_dmabuf_devices_mutex);
	return ret;
}

int
spdk_pci_device_destroy_dmabuf(struct spdk_pci_device *spdk_dev, int bar)
{
	struct rte_pci_device *pci_dev = spdk_dev->dev_handle;
	struct dmabuf_device *dev;
	struct dmabuf *dmabuf;
	int ret = 0;

	pthread_mutex_lock(&g_dmabuf_devices_mutex);

	dev = find_dmabuf_device(pci_dev);
	if (!dev) {
		ret = -EINVAL;
		goto out;
	}

	dmabuf = find_dmabuf_by_bar(dev, bar);
	if (!dmabuf) {
		ret = -EINVAL;
		goto out;
	}

	if (dmabuf->refcount) {
		ret = -EBUSY;
		goto out;
	}

	destroy_dmabuf(dev, dmabuf);
out:
	pthread_mutex_unlock(&g_dmabuf_devices_mutex);
	return ret;
}

int
spdk_dmabuf_pci_device_removed(struct spdk_pci_device *spdk_dev)
{
	struct rte_pci_device *pci_dev = spdk_dev->dev_handle;
	struct dmabuf_device *dmabuf_dev;
	struct dmabuf *dmabuf;
	int ret = 0;

	assert(pci_dev);

	pthread_mutex_lock(&g_dmabuf_devices_mutex);
	dmabuf_dev = find_dmabuf_device(pci_dev);
	if (!dmabuf_dev) {
		goto out;
	}

	TAILQ_FOREACH(dmabuf, &dmabuf_dev->dmabufs, tailq) {
		if (dmabuf->refcount) {
			ret = -EBUSY;
			break;
		}

		ret = destroy_dmabuf(dmabuf_dev, dmabuf);
		if (ret) {
			break;
		}
	}
out:
	pthread_mutex_unlock(&g_dmabuf_devices_mutex);
	return ret;
}
#endif
