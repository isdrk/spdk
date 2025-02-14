#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

set -e

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../..")

mountprog="mount.fuse.spdk"
declare -A config

errmsg() { echo "$0: $*" >&2; }

cleanup() {
	if [[ "$(readlink -f "/sbin/$mountprog")" == "$rootdir/scripts/$mountprog" ]]; then
		rm -f "/sbin/$mountprog"
	fi
	rm -f "$rootdir/.mountenv" "$testdir/fstests.config"
}

install_mountprog() {
	local prog="$rootdir/scripts/$mountprog" link="/sbin/$mountprog"

	if [[ -e "$link" ]]; then
		if [[ "$(readlink -f "$link")" != "$prog" ]]; then
			errmsg "$prog already exists, aborting"
			return 1
		fi
	else
		ln -s "$prog" "$link"
	fi
	cat - > "$rootdir/.mountenv" <<- ENV
		FSDEV_FUSE_OPTIONS+=' -c $(readlink -f "${config[config]}")'
		FSDEV_FUSE_OPTIONS+=' -m ${config[mask]:-0x1} --fstype fuse'
		FSDEV_FUSE_LOG=${config[log]:-/dev/null}
	ENV
}

run() {
	cat - > "$testdir/fstests.config" <<- CONFIG
		export TEST_DEV="${config[fsdev]}"
		export TEST_DIR="${config[mountpoint]}"
		export FSTYPE=fuse
		export FUSE_SUBTYP=.spdk
	CONFIG
	export HOST_OPTIONS="$testdir/fstests.config"
	(
		cd "${config[xfsdir]}"
		./check "$@"
	)
}

parse_device() {
	if [[ "$1" == fsdev ]]; then
		cut -d: -f1 -
	elif [[ "$1" == mountpoint ]]; then
		cut -d: -f2 -
	fi <<< "$2"
}

check_options() {
	[[ -z "${config[xfsdir]}" ]] && errmsg "missing required option -x, --xfsdir" && return 1
	[[ -z "${config[config]}" ]] && errmsg "missing required option -c, --config" && return 1
	[[ -z "${config[fsdev]}" ]] && errmsg "missing required option -d, --device" && return 1
	[[ -z "${config[mountpoint]}" ]] && errmsg "missing required option -d, --device" && return 1

	return 0
}

usage() {
	cat <<- USAGE
		Usage: $0 [OPTIONS] [--] [XFSTESTS_OPTIONS]
		Options:
		 -x, --xfsdir=PATH               path to xfstests repo
		 -c, --config=CONFIG             config to the fuse application
		 -d, --device=FSDEV:MOUNTPOINT   use FSDEV and mount it at MOUNTPOINT
		 -m, --mask=CPUMASK              CPU mask to use
		 -h, --help                      show this help
		 -l, --log=FILE                  dump logs to FILE
	USAGE
}

while (($# > 0)); do
	case "$1" in
		--xfsdir=*) set -- "${1%%=*}" "${1##*=}" "${@:2}" ;&
		-x | --xfsdir)
			config[xfsdir]="$2"
			shift
			;;
		--config=*) set -- "${1%%=*}" "${1##*=}" "${@:2}" ;&
		-c | --config)
			config[config]="$2"
			shift
			;;
		--mask=*) set -- "${1%%=*}" "${1##*=}" "${@:2}" ;&
		-m | --mask)
			config[mask]="$2"
			shift
			;;
		--log=*) set -- "${1%%=*}" "${1##*=}" "${@:2}" ;&
		-l | --log)
			config[log]="$2"
			shift
			;;
		--device=*) set -- "${1%%=*}" "${1##*=}" "${@:2}" ;&
		-d | --device)
			config[fsdev]=$(parse_device fsdev "$2")
			config[mountpoint]=$(parse_device mountpoint "$2")
			shift
			;;
		--) shift && break ;;
		-h | --help) usage && exit 0 ;;
		*) usage && exit 1 ;;
	esac
	shift
done

trap cleanup EXIT
check_options
install_mountprog
run "$@"
