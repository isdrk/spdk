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
_install_xfstests_deps() {
	source "$rootdir/test/common/config/pkgdep/$(_get_pkgmgr)"
	install "${xfstests_packages[@]}"
}

_install_xfstests() {
	local -g _xfsdir

	[[ "$1" == "$SPDK_XFSTESTS_DIR" ]] && return 0
	_xfsdir="$1"
	_install_xfstests_deps
	git clone https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git "$_xfsdir"
	git -C "$_xfsdir" checkout "$SPDK_XFSTESTS_VERSION"
	make -j$(nproc) -C "$_xfsdir"
}

_uninstall_xfstests() {
	[[ -n "$_xfsdir" ]] && rm -rf "$_xfsdir"
	return 0
}

_setup_nvme() {
	local bdf srcdir
	local -g _nvme_fsdev

	bdf=$(get_first_nvme_bdf)
	PCI_ALLOWED="$bdf" "$rootdir/scripts/setup.sh" reset

	_nvme_fsdev="/dev/$(get_block_dev_from_nvme "$bdf")"
	mkfs.ext4 "$_nvme_fsdev"
	mount "$_nvme_fsdev" "$_srcdir"
}

_cleanup_nvme() {
	umount "$_nvme_fsdev" || :
	wipefs --all "$_nvme_fsdev"
	"$rootdir/scripts/setup.sh"
}

_fstests_init() {
	local -g _srcdir="$1" _mountdir="$2" _devices=("${@:3}")

	mkdir -p "$_srcdir" "${_devices[@]/#/$_mountdir/}"
	[[ "$_with_nvme" == true ]] && _setup_nvme
	return 0
}

_fstests_cleanup() {
	local dev

	if [[ -n "$_mountdir" ]]; then
		for dev in "${_devices[@]}"; do
			umount "$_mountdir/$dev" || :
		done
		rm -rf "$_mountdir"
	fi
	[[ -n "$_nvme_fsdev" ]] && _cleanup_nvme
	rm -rf "$_srcdir"
}

fstests_init() {
	_install_xfstests "$1"
	_fstests_init "${@:2}"
}

fstests_cleanup() {
	_uninstall_xfstests
	_fstests_cleanup
}

for opt in "$@"; do
	case "$opt" in
		--with-nvme)
			_with_nvme=true
			;;
	esac
done
