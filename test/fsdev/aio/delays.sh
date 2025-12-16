#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../..")

source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/fsdev/common.sh"

mountdir="$testdir/mnt"
srcdir="$testdir/aio0"
fusepid=

cleanup() {
	[[ -n "$fusepid" ]] && killprocess "$fusepid" || :
	fstests_cleanup
}

run_fio() {
	fio --name=aio_test \
		--filename="$mountdir/fio_testfile" \
		--size=1M \
		--bs=4k \
		--rw=randrw \
		--direct=1 \
		--numjobs=1 \
		--iodepth=1 \
		--runtime=2 \
		--time_based \
		--do_verify=1 \
		--verify=crc32c
}

trap cleanup EXIT
fstests_init "$srcdir" "$mountdir" aio0
mkdir -p "$srcdir/aio0"

"$rootdir/build/examples/fuse" -D &
fusepid=$!

waitforlisten $fusepid
rpc_cmd << CMD
	fsdev_aio_create aio0 "$srcdir"
	fuse_mount aio0 "$mountdir"
CMD

rpc_cmd fsdev_set_delays aio0 --submit 1000
run_fio

rpc_cmd fsdev_set_delays aio0 --complete 2000
run_fio

rpc_cmd fsdev_set_delays aio0 --submit 100 --complete 200 --complete-99 100
run_fio

cleanup
trap - EXIT
