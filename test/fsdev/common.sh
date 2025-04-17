# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

SPDK_XFSTESTS_VERSION=${SPDK_XFSTESTS_VERSION:-v2025.04.13}

_get_pkgmgr() {
	local pkgdir pkgmgr

	for pkgdir in "$rootdir/test/common/config/pkgdep/"*; do
		pkgmgr=${pkgdir##*/}
		[[ "$pkgmgr" == git ]] && continue
		if hash "$pkgmgr" &> /dev/null; then
			echo $pkgmgr
			return 0
		fi
	done
	return 1
}

# TODO: remove this once the image is provision with these dependencies
_install_deps() {
	source "$rootdir/test/common/config/pkgdep/$(_get_pkgmgr)"
	install "${xfstests_packages[@]}"
}

_install_xfstests() {
	local -g _xfsdir

	[[ "$1" == "$SPDK_XFSTESTS_DIR" ]] && return 0
	_xfsdir="$1"
	_install_deps
	git clone https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git "$_xfsdir"
	git -C "$_xfsdir" checkout "$SPDK_XFSTESTS_VERSION"
	make -j$(nproc) -C "$_xfsdir"
}

_uninstall_xfstests() {
	[[ -n "$_xfsdir" ]] && rm -rf "$_xfsdir"
	return 0
}

fstests_init() {
	local xfsdir="$1"
	local -g _mountdir="$2" _testdev="$3" _scratchdev="$4"

	_install_xfstests "$xfsdir"
	mkdir -p "$_mountdir/$_testdev" "$_mountdir/$_scratchdev"
}

fstests_cleanup() {
	_uninstall_xfstests
	if [[ -n "$_mountdir" ]]; then
		umount "$_mountdir/$_testdev" || :
		umount "$_mountdir/$_scratchdev" || :
		rm -rf "$_mountdir"
	fi
}
