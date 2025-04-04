#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2020 Intel Corporation
#  All rights reserved.
#
testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "$testdir/../../../")

# Have proper defaults in place
set -- "--transport=tcp" "--iso" "$@"

source "$rootdir/test/common/autotest_common.sh"
source "$rootdir/test/nvmf/common.sh"

NULL_META=16 NULL_BLOCK_SIZE=512 NULL_SIZE=64 NULL_DIF=1 LARGE_POOL_COUNT=2047 SMALL_POOL_COUNT=8192

create_subsystem() {
	local sub_id=${1:-0}

	# Make sure NQN matches what's used in gen_nvmf_target_json()
	rpc_cmd bdev_null_create "bdev_null$sub_id" "$NULL_SIZE" "$NULL_BLOCK_SIZE" --md-size "$NULL_META" --dif-type "$NULL_DIF"
	rpc_cmd nvmf_create_subsystem "nqn.2016-06.io.spdk:cnode$sub_id" --serial-number "53313233-$sub_id" --allow-any-host
	rpc_cmd nvmf_subsystem_add_ns "nqn.2016-06.io.spdk:cnode$sub_id" "bdev_null$sub_id"
	rpc_cmd nvmf_subsystem_add_listener "nqn.2016-06.io.spdk:cnode$sub_id" -t "$TEST_TRANSPORT" -a "$NVMF_FIRST_TARGET_IP" -s "$NVMF_PORT"
}

create_subsystems() {
	local sub

	for sub; do
		create_subsystem "$sub"
	done
}

destroy_subsystem() {
	local sub_id=${1:-0}

	rpc_cmd nvmf_delete_subsystem "nqn.2016-06.io.spdk:cnode$sub_id"
	rpc_cmd bdev_null_delete "bdev_null$sub_id"
}

destroy_subsystems() {
	local sub

	for sub; do
		destroy_subsystem "$sub"
	done
}

create_transport() { rpc_cmd nvmf_create_transport $NVMF_TRANSPORT_OPTS; }

function create_json_sub_conf() {
	local subsystem config=()

	for subsystem in "${@:-1}"; do
		config+=(
			"$(
				cat <<- EOF
					{
						"params": {
							"name": "Nvme$subsystem",
							"trtype": "$TEST_TRANSPORT",
							"traddr": "$NVMF_FIRST_TARGET_IP",
							"adrfam": "ipv4",
							"trsvcid": "$NVMF_PORT",
							"subnqn": "nqn.2016-06.io.spdk:cnode$subsystem",
							"hostnqn": "nqn.2016-06.io.spdk:host$subsystem"
						},
						"method": "bdev_nvme_attach_controller"
					}
				EOF
			)"
		)
	done
	jq . <<- JSON
		{
			"subsystems": [
			{
				"subsystem": "iobuf",
				"config": [
				{
					"method": "iobuf_set_options",
					"params": {
						"large_pool_count": $LARGE_POOL_COUNT,
						"small_pool_count": $SMALL_POOL_COUNT
					}
				}
			]
			},
			{
				"subsystem": "bdev",
				"config": [
				{
					"method": "bdev_nvme_set_options",
					"params": {
					"action_on_timeout": "none",
					"timeout_us": 0,
					"transport_retry_count": 4,
					"arbitration_burst": 0,
					"low_priority_weight": 0,
					"medium_priority_weight": 0,
					"high_priority_weight": 0,
					"nvme_adminq_poll_period_us": 10000,
					"keep_alive_timeout_ms" : 10000,
					"nvme_ioq_poll_period_us": 0,
					"io_queue_requests": 0,
					"delay_cmd_submit": true
				}
			},
						$(
			IFS=","
			printf '%s\n' "${config[*]}"
		),
			{
				"method": "bdev_wait_for_examine"
			}
					]
				}
			]
		}
	JSON
}

gen_fio_conf() {
	local file

	cat <<- FIO
		[global]
		thread=1
		direct=1
		rw=randread
		ramp_time=0
		norandommap=1
		time_based=1
		bs=${bs:-4k}
		numjobs=${numjobs:-1}
		runtime=${runtime:-10}

		[filename0]
		filename=Nvme${nvme:-0}n1
		iodepth=${iodepth:-4}
	FIO
	for ((file = 1; file <= files; file++)); do
		cat <<- FIO
			[filename$file]
			filename=Nvme${file}n1
			iodepth=${iodepth:-4}
		FIO
	done
}

fio() {
	fio_bdev --ioengine=spdk_bdev --spdk_json_conf "$@" <(gen_fio_conf)
}

fio_dif_1() {
	create_subsystems 0
	fio <(create_json_sub_conf 0)
	destroy_subsystems 0
}

fio_dif_1_multi_subsystems() {
	local files=1

	create_subsystems 0 1
	fio <(create_json_sub_conf 0 1)
	destroy_subsystems 0 1
}

fio_dif_rand_params() {
	local NULL_DIF
	local bs numjobs runtime iodepth files

	#this test uses more disks, default number of iobuf buffers is not enough due to additional consumption by bdev nvme
	NULL_DIF=3 bs=128k numjobs=3 iodepth=3 runtime=5 LARGE_POOL_COUNT=4095 SMALL_POOL_COUNT=16384

	create_subsystems 0
	fio <(create_json_sub_conf 0)
	destroy_subsystems 0

	NULL_DIF=2 bs=4k numjobs=8 iodepth=16 runtime="" files=2

	create_subsystems 0 1 2
	fio <(create_json_sub_conf 0 1 2)
	destroy_subsystems 0 1 2

	NULL_DIF=1 bs=8k,16k,128k numjobs=2 iodepth=8 runtime=5 files=1

	create_subsystems 0 1
	fio <(create_json_sub_conf 0 1)
	destroy_subsystems 0 1

	LARGE_POOL_COUNT=2047 SMALL_POOL_COUNT=8192
}

fio_dif_digest() {
	local NULL_DIF
	local bs numjobs runtime iodepth files
	local hdgst ddgst

	NULL_DIF=3 bs=128k,128k,128k numjobs=3 iodepth=3 runtime=10
	hdgst=true ddgst=true

	create_subsystems 0
	fio <(create_json_sub_conf 0)
	destroy_subsystems 0
}

nvmftestinit
NVMF_TRANSPORT_OPTS+=" --dif-insert-or-strip"
nvmfappstart

create_transport

run_test "fio_dif_1_default" fio_dif_1
run_test "fio_dif_1_multi_subsystems" fio_dif_1_multi_subsystems
run_test "fio_dif_rand_params" fio_dif_rand_params
run_test "fio_dif_digest" fio_dif_digest

trap - SIGINT SIGTERM EXIT
nvmftestfini
