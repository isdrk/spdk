#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../..")

source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/fsdev/common.sh"

checkout_tag="${KERNEL_CHECKOUT_TAG:-"v6.8"}"
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
	git clone --depth=1 --branch "$checkout_tag" https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "${mountdir}/aio0/linux"
	cd "${mountdir}/aio0/linux" || exit 1
	make O=build tinyconfig
	make O=build -j"$(nproc)"
)
cleanup
trap - EXIT
