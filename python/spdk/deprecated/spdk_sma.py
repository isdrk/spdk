# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

import sys
from spdk import spdk_sma


def main():
    print('warning: spdk_sma is deprecated, use spdk-sma instead', file=sys.stderr)
    sys.exit(spdk_sma.main())
