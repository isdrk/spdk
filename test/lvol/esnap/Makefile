#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)

TEST_FILE = esnap.c

SPDK_LIB_LIST = accel bdev bdev_aio blob blob_bdev dma init notify

include $(SPDK_ROOT_DIR)/mk/spdk.unittest.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk
