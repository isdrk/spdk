# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0

C_SRCS = fuse.c
LIBNAME = fuse

SPDK_MAP_FILE = $(abspath $(CURDIR)/spdk_fuse.map)

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
