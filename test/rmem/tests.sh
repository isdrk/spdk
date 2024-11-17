#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#
testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../..)
source $rootdir/test/common/autotest_common.sh

RMEM_POOL_TESTER=$rootdir/test/rmem/rmem_pool_test/rmem_pool_test
RMEM_POOL_WRITE_CRASH_TESTER=$rootdir/test/rmem/rmem_pool_write_crash_test/rmem_pool_write_crash_test

# simply check that rmem_pool works for both write and read
function rmem_pool_func_test() {
	$RMEM_POOL_TESTER -a 0
}

# check that rmem_pool allows recovery after crash
function rmem_pool_recovery_test() {
	$RMEM_POOL_TESTER -a 1 || true
	$RMEM_POOL_TESTER -a 2
}

# check that rmem_pool manages the blocks correctly
function rmem_pool_get_release() {
	$RMEM_POOL_TESTER -a 3
}

# check that rmem_pool write is non-destructive and can survivie a crash
function rmem_pool_write_crash() {
	CRASH_POINTS_NUM=$($RMEM_POOL_WRITE_CRASH_TESTER -C)
	for cp_num in $(seq 0 $((CRASH_POINTS_NUM - 1))); do
		# fill and crash
		$RMEM_POOL_WRITE_CRASH_TESTER -a $cp_num || true
		# restore and test
		$RMEM_POOL_WRITE_CRASH_TESTER -a $CRASH_POINTS_NUM
	done
}

rm -rf /tmp/rmem_test || true
mkdir -p /tmp/rmem_test

run_test "rmem_pool_func_test" rmem_pool_func_test
run_test "rmem_pool_recovery_test" rmem_pool_recovery_test
run_test "rmem_pool_get_release" rmem_pool_get_release
run_test "rmem_pool_write_crash" rmem_pool_write_crash
