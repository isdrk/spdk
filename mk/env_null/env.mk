#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

# Null SPDK environment layer, selected with ./configure --without-env
#
# The SPDK libraries compile against include/spdk/env.h alone and never against
# DPDK headers, so a consumer that supplies its own implementation of the
# spdk_env_* API does not need the dpdk submodule present at all. This snippet
# declares an empty env for exactly that case; the consumer resolves the
# spdk_env_* symbols from its own implementation at its final link step.
#
# It lives under mk/ rather than lib/ deliberately: lib/Makefile adds
# $(notdir $(CONFIG_ENV)) to DIRS-y when CONFIG_ENV resolves under lib/, which
# would make SPDK try to build a library here.
#
# Because ENV_LIBS and ENV_LINKER_ARGS are empty, nothing that links a full
# SPDK binary can be built; configure disables apps, examples and tests when
# this env is selected.

# This makefile snippet must define the following flags:
# ENV_CFLAGS
# ENV_CXXFLAGS
# ENV_LIBS
# ENV_LINKER_ARGS
# ENV_DEPLIBS

ENV_CFLAGS =
ENV_CXXFLAGS =
ENV_LIBS =
ENV_LINKER_ARGS =
ENV_DEPLIBS =
