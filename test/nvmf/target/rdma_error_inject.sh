#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

MALLOC_BDEV_SIZE=128
MALLOC_BLOCK_SIZE=512

tgt_core_mask='0x3'
bdevperf_core_mask='0xc'
bdevperf_rpc_sock=/var/tmp/bdevperf.sock
bdevperf_pid=
bdevperf_rpc_pid=-1

if [ "$TEST_TRANSPORT" != "rdma" ]; then
	exit 0
fi

nvmftestinit

function start_target() {
	nvmfappstart -m "$tgt_core_mask"

	$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS -u 8192 --no-srq
	$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0
	$rpc_py nvmf_create_subsystem $NVME_SUBNQN -a -s $NVMF_SERIAL
	$rpc_py nvmf_subsystem_add_ns $NVME_SUBNQN Malloc0
	$rpc_py nvmf_subsystem_add_listener $NVME_SUBNQN -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT
}

function start_bdevperf() {
	mkdir -p $testdir

	# -o 16384 io size, --io-unit-size 2048 splits each IO into fragmented buffers.
	# -f keeps the job running across I/O failures: injected errors may complete an
	# I/O with the DNR bit set, which the bdev layer does not retry, and without -f
	# the first such failure drains the job and exits bdevperf.
	$rootdir/build/examples/bdevperf -m $bdevperf_core_mask -z -r $bdevperf_rpc_sock \
		-q 128 -o 16384 --io-unit-size 2048 -w randrw -M 50 -t 90 -f -C &
	bdevperf_pid=$!

	trap 'process_shm --id $NVMF_APP_SHM_ID; kill -9 $bdevperf_pid; nvmftestfini; exit 1' SIGINT SIGTERM EXIT
	waitforlisten $bdevperf_pid $bdevperf_rpc_sock

	# bdev_retry_count -1 means infinite I/O retries at the bdev layer
	$rpc_py -s $bdevperf_rpc_sock bdev_nvme_set_options -r -1

	# -l -1 ctrlr_loss_timeout_sec -1 means infinite reconnects
	# -o 2 reconnect_delay_sec is 2 sec
	# With these set, I/O outstanding on a failed qpair is retried instead of failed.
	$rpc_py -s $bdevperf_rpc_sock bdev_nvme_attach_controller -b Nvme0 -t $TEST_TRANSPORT \
		-a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT -f ipv4 -n $NVME_SUBNQN -l -1 -o 2

	$rootdir/examples/bdev/bdevperf/bdevperf.py -t 120 -s $bdevperf_rpc_sock perform_tests &
	bdevperf_rpc_pid=$!

	# Let the IO traffic ramp up before injecting errors
	sleep 5
}

function stop_bdevperf() {
	killprocess $bdevperf_pid
	wait $bdevperf_pid

	bdevperf_pid=

	trap 'process_shm --id $NVMF_APP_SHM_ID || :; nvmftestfini' SIGINT SIGTERM EXIT
}

# Run the cq/mkey/rq/sq error injection sequence against the SPDK app reachable
# on the supplied RPC socket ("" selects the default target socket).
function inject_error_sequence() {
	local sock=$1
	local rpc_args=()

	[[ -n $sock ]] && rpc_args=(-s "$sock")

	# Inject cq errors with 1/1000 probability and let bdevperf hit one
	$rpc_py "${rpc_args[@]}" rdma_provider_inject_error cq 1 1000
	sleep 10
	$rpc_py "${rpc_args[@]}" rdma_provider_cancel_error cq

	# allow bdevperf to reconnect
	sleep 5

	# Inject mkey errors with 1/1000 probability
	$rpc_py "${rpc_args[@]}" rdma_provider_inject_error mkey 1 1000
	sleep 10
	$rpc_py "${rpc_args[@]}" rdma_provider_cancel_error mkey

	# allow bdevperf to reconnect
	sleep 5

	# Inject recv WR flush errors with 1/1000 probability
	$rpc_py "${rpc_args[@]}" rdma_provider_inject_error rq 1 1000
	sleep 10
	$rpc_py "${rpc_args[@]}" rdma_provider_cancel_error rq

	# allow bdevperf to reconnect
	sleep 5

	# Inject send WR flush errors with 1/1000 probability
	$rpc_py "${rpc_args[@]}" rdma_provider_inject_error sq 1 1000
	sleep 10
	$rpc_py "${rpc_args[@]}" rdma_provider_cancel_error sq

	# allow bdevperf to reconnect
	sleep 5
}

function test_inject_error_on_target() {
	start_target
	start_bdevperf

	inject_error_sequence ""

	stop_bdevperf

	killprocess $nvmfpid
	nvmfpid=
}

function test_inject_error_on_initiator() {
	start_target
	start_bdevperf

	inject_error_sequence "$bdevperf_rpc_sock"

	stop_bdevperf

	killprocess $nvmfpid
	nvmfpid=
}

run_test "nvmf_rdma_error_inject_target" test_inject_error_on_target
run_test "nvmf_rdma_error_inject_initiator" test_inject_error_on_initiator

nvmftestfini
