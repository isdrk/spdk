#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../..")

source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/fsdev/common.sh"

checkout_tag="${SPDK_CHECKOUT_TAG:-"v25.09"}"
mountdir="$testdir/mnt"
srcdir="$testdir/aio0"
fusepid=

cleanup() {
	[[ -n "$fusepid" ]] && killprocess "$fusepid" || :
	fstests_cleanup
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
(
	git clone --depth=1 --branch "$checkout_tag" https://github.com/spdk/spdk.git "${mountdir}/aio0/spdk"
	cd "${mountdir}/aio0/spdk"
	git submodule update --init --recursive
	./configure --enable-debug && make -j8
)
cleanup
trap - EXIT
