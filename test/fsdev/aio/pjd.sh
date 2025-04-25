#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../..")

source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/fsdev/common.sh"

pjddir="${SPDK_PJDFSTESTS_DIR:-"$testdir/pjdfstests"}"
mountdir="$testdir/mnt"
srcdir="$testdir/aio0"
fusepid=

cleanup() {
	[[ -n "$fusepid" ]] && killprocess "$fusepid" || :
	pjd_cleanup
}

trap cleanup EXIT
pjd_init "$pjddir" "$srcdir" "$mountdir" aio0
mkdir -p "$srcdir/aio0"

"$rootdir/build/examples/fuse" -D &
fusepid=$!

waitforlisten $fusepid
rpc_cmd << CMD
	fsdev_aio_create aio0 "$srcdir"
	fuse_mount aio0 "$mountdir"
CMD
(
	cd "$mountdir"
	prove -rv "$pjddir"
)
cleanup
trap - EXIT
