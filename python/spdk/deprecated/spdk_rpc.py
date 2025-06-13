# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

import sys
from spdk import spdk_rpc


def main():
    print('warning: spdk_rpc is deprecated, use spdk-rpc instead', file=sys.stderr)
    sys.exit(spdk_rpc.main())
