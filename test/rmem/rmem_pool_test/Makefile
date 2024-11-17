#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = rmem_pool_test

C_SRCS := rmem_pool_test.c

SPDK_LIB_LIST = event event_rmem rmem

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
