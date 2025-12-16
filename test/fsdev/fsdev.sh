#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../")

source "${rootdir}/test/common/autotest_common.sh"

run_test "fstests_aio" "$rootdir/test/fsdev/aio/fstests.sh" --with-nvme
run_test "pjd_aio" "$rootdir/test/fsdev/aio/pjd.sh" --with-nvme
run_test "build_kernel_aio" "$rootdir/test/fsdev/aio/build_kernel.sh" --with-nvme
run_test "delays_aio" "$rootdir/test/fsdev/aio/delays.sh" --with-nvme
