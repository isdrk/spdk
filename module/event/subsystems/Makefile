#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2015 Intel Corporation.
#  Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

DIRS-y += bdev accel scheduler iscsi nvmf scsi sock iobuf keyring rmem fuse telemetry

ifeq ($(OS),Linux)
DIRS-y += nbd
ifeq ($(CONFIG_UBLK),y)
DIRS-y += ublk
endif
endif

DIRS-$(CONFIG_XLIO) += xlio

DIRS-$(CONFIG_VHOST) += vhost_blk vhost_scsi
DIRS-$(CONFIG_VFIO_USER) += vfu_tgt
DIRS-$(CONFIG_FSDEV) += fsdev
DIRS-$(CONFIG_RDMA) += rdma_provider
DIRS-$(CONFIG_VMD) += vmd

# These dependencies are not based specifically on symbols, but rather
# the subsystem dependency tree defined within the event subsystem C files
# themselves. Should that tree change, these dependencies should change
# accordingly.
DEPDIRS-accel := iobuf
DEPDIRS-bdev := accel sock iobuf keyring telemetry
DEPDIRS-iscsi := scsi
DEPDIRS-nbd := bdev
DEPDIRS-ublk := bdev
DEPDIRS-nvmf := bdev
DEPDIRS-scsi := bdev
DEPDIRS-vhost_scsi := scsi
DEPDIRS-fsdev := accel rmem
DEPDIRS-fuse := fsdev
ifeq ($(CONFIG_XLIO),y)
DEPDIRS-sock := xlio
endif
ifeq ($(CONFIG_RDMA),y)
DEPDIRS-bdev += rdma_provider
DEPDIRS-accel += rdma_provider
DEPDIRS-nvmf += rdma_provider
endif
ifeq ($(CONFIG_VMD),y)
DEPDIRS-bdev += vmd
endif

.PHONY: all clean $(DIRS-y)

all: $(DIRS-y)
clean: $(DIRS-y)

include $(SPDK_ROOT_DIR)/mk/spdk.subdirs.mk
