# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

SPDK_XFSTESTS_VERSION=${SPDK_XFSTESTS_VERSION:-v2025.04.13}
SPDK_PJDFSTESTS_VERSION=${SPDK_PJDFSTESTS_VERSION:-c711b5f6b666579846afba399a998f74f60c488b}

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

_install_xfstests() {
	local -g _xfsdir

	[[ "$1" == "$SPDK_XFSTESTS_DIR" ]] && return 0
	_xfsdir="$1"
	git clone https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git "$_xfsdir"
	git -C "$_xfsdir" checkout "$SPDK_XFSTESTS_VERSION"
	make -j$(nproc) -C "$_xfsdir"
}

_uninstall_xfstests() {
	[[ -n "$_xfsdir" ]] && rm -rf "$_xfsdir"
	return 0
}

_install_pjdfstests() {
	local -g _pjddir

	[[ "$1" == "$SPDK_PJDFSTESTS_DIR" ]] && return 0
	_pjddir="$1"
	git clone https://github.com/pjd/pjdfstest.git "$_pjddir"
	git -C "$_pjddir" checkout "$SPDK_PJDFSTESTS_VERSION"
	(
		cd "$_pjddir"
		autoreconf -ifs
		./configure
		make -j$(nproc)
	)
}

_uninstall_pjdfstests() {
	[[ -n "$_pjddir" ]] && rm -rf "$_pjddir"
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

fstests_init() {
	local -g _srcdir="$1" _mountdir="$2" _devices=("${@:3}")

	mkdir -p "$_srcdir" "${_devices[@]/#/$_mountdir/}"
	[[ "$_with_nvme" == true ]] && _setup_nvme
	return 0
}

fstests_cleanup() {
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

xfstests_init() {
	_install_xfstests "$1"
	fstests_init "${@:2}"
}

xfstests_cleanup() {
	_uninstall_xfstests
	fstests_cleanup
}

pjd_init() {
	_install_pjdfstests "$1"
	fstests_init "${@:2}"
}

pjd_cleanup() {
	_uninstall_pjdfstests
	fstests_cleanup
}

for opt in "$@"; do
	case "$opt" in
		--with-nvme)
			_with_nvme=true
			shift
			;;
	esac
done
