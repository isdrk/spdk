#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../..")

source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/fsdev/common.sh"

xfsdir="${SPDK_XFSTESTS_DIR:-"$testdir/xfstests"}"
mountdir="$testdir/mnt"
srcdir="$testdir/src"
fusepid=

cleanup() {
	[[ -n "$fusepid" ]] && killprocess "$fusepid" || :
	fstests_cleanup
}

trap cleanup EXIT
fstests_init "$xfsdir" "$srcdir" "$mountdir" aio0 aio1
mkdir -p "$srcdir/aio0" "$srcdir/aio1"

"$rootdir/build/examples/fuse" -D &
fusepid=$!

waitforlisten $fusepid
rpc_cmd << CMD
	fsdev_aio_create aio0 "$srcdir/aio0"
	fsdev_aio_create aio1 "$srcdir/aio1"
CMD

"$rootdir/test/fsdev/fstests.sh" -e -x "$xfsdir" -d "aio0:$mountdir/aio0" -s "aio1:$mountdir/aio1" \
	-- -g quick -E "$testdir/fstests.excludelist"

cleanup
trap - EXIT
