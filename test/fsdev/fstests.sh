#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

set -e

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../..")

mountprog="mount.fuse.spdk"
declare -A config
remove_mountprog=
fusepid=

errmsg() { echo "$0: $*" >&2; }

fuse_running() { "$rootdir/scripts/rpc.py" rpc_get_methods &> /dev/null; }

cleanup() {
	if [[ -n "$fusepid" ]]; then
		kill "$fusepid" || :
		wait "$fusepid" || :
	fi
	if [[ $remove_mountprog == true ]]; then
		rm -f "/sbin/$mountprog"
	fi
	rm -f "$rootdir/.mountenv" "$testdir/fstests.config"
}

install_mountprog() {
	local prog="$rootdir/scripts/$mountprog" link="/sbin/$mountprog"
	if [[ -e "$link" ]]; then
		if [[ "$(readlink -f "$link")" != "$prog" ]]; then
			errmsg "$link already exists, aborting"
			return 1
		fi
		remove_mountprog=false
	else
		ln -s "$prog" "$link"
		remove_mountprog=true
	fi
	cat - > "$rootdir/.mountenv" <<- ENV
		FSDEV_FUSE_MOUNT_OPTIONS+=' --fstype=fuse'
		FSDEV_FUSE_LOG=${config[log]:-/dev/null}
	ENV
}

start_fuse() {
	local i

	[[ "${config[external]}" == true ]] && return 0

	"$rootdir/build/examples/fuse" -m "${config[mask]:-0x1}" -c "${config[config]}" -D \
		&> ${config[log]:-/dev/null} &
	fusepid=$!

	for ((i = 0; i < 10; i++)); do
		kill -0 $fusepid || return 1
		fuse_running && return 0
		sleep 1s
	done
	return 1
}

show_summary() {
	local total failed skipped

	read -r total skipped failed < <(xmlstarlet sel -t -v '/testsuite/@tests' -o ' ' \
		-t -v '/testsuite/@skipped' -o ' ' -t -v '/testsuite/@failures' -n \
		"${config[xfsdir]}/results/result.xml")
	echo "Pass rate: $((total - skipped - failed))/$((total - skipped))"
}

run() {
	local options=()
	cat - > "$testdir/fstests.config" <<- CONFIG
		export TEST_DEV="${config[fsdev]}"
		export TEST_DIR="${config[mountpoint]}"
		export SCRATCH_DEV="${config[scratch_fsdev]}"
		export SCRATCH_MNT="${config[scratch_mountpoint]}"
		export FSTYP=fuse
		export FUSE_SUBTYP=.spdk
	CONFIG
	export HOST_OPTIONS="$testdir/fstests.config"
	[[ "${config[summary]}" == true ]] && options+=(-R xunit)
	(
		cd "${config[xfsdir]}"
		./check "${options[@]}" "$@"
	)
	[[ "${config[summary]}" == true ]] && show_summary
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
	[[ -z "${config[fsdev]}" ]] && errmsg "missing required option -d, --device" && return 1
	[[ -z "${config[mountpoint]}" ]] \
		&& errmsg "missing required option -d, --device" && return 1
	[[ -z "${config[config]}" ]] && [[ "${config[external]}" != true ]] \
		&& errmsg "missing required option -c, --config" && return 1

	return 0
}

usage() {
	cat <<- USAGE
		Usage: $0 [OPTIONS] [--] [XFSTESTS_OPTIONS]
		Options:
		 -x, --xfsdir=PATH               path to xfstests repo
		 -c, --config=CONFIG             config to the fuse application
		 -d, --device=FSDEV:MOUNTPOINT   use FSDEV and mount it at MOUNTPOINT
		 -s, --scratch=FSDEV:MOUNTPOINT  use FSDEV and mount it at MOUNTPOINT as scratch device
		 -m, --mask=CPUMASK              CPU mask to use
		 -h, --help                      show this help
		 -l, --log=FILE                  dump logs to FILE
		 -e, --external                  assume that the fuse application is already running
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
		--scratch=*) set -- "${1%%=*}" "${1##*=}" "${@:2}" ;&
		-s | --scratch)
			config[scratch_fsdev]=$(parse_device fsdev "$2")
			config[scratch_mountpoint]=$(parse_device mountpoint "$2")
			shift
			;;
		-e | --external)
			config[external]=true
			;;
		--) shift && break ;;
		-h | --help) usage && exit 0 ;;
		*) usage && exit 1 ;;
	esac
	shift
done

command -v xmlstarlet &> /dev/null && config[summary]=true
if [[ "${config[external]}" == true ]] && ! fuse_running; then
	errmsg "$rootdir/examples/fuse is not running, aborting"
	exit 1
fi

trap cleanup EXIT
check_options
install_mountprog
start_fuse
run "$@"
