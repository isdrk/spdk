#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = fsdevbench

C_SRCS := fsdevbench.c

SPDK_LIB_LIST = $(ALL_MODULES_LIST) conf event event_fsdev event_telemetry
SYS_LIBS += $(FSDEV_MODULES_PRIVATE_LIBS)

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
