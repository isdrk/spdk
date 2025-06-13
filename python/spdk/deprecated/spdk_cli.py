# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

import sys
from spdk import spdk_cli


def main():
    print('warning: spdk_cli is deprecated, use spdk-cli instead', file=sys.stderr)
    sys.exit(spdk_cli.main())
