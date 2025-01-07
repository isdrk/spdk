#  SPDX-License-Identifier: BSD-3-Clause
#  All rights reserved.
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0

C_SRCS = rmem.c rmem_rpc.c
LIBNAME = rmem

SPDK_MAP_FILE = $(abspath $(CURDIR)/spdk_rmem.map)

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
