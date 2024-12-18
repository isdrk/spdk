#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#
testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

allowed_devices=${1:-"mlx5_0"}

MALLOC_BDEV_SIZE=1
MALLOC_BLOCK_SIZE=512
app_sock=/var/tmp/bdev.sock
bdevperf=$rootdir/build/examples/bdevperf
nvmeperf=$rootdir/build/bin/spdk_nvme_perf

function gen_bdevperf_json() {

	jq . <<- JSON
		{
		  "subsystems": [
		    {
		      "subsystem": "bdev",
		      "config": [
		        {
		          "method": "bdev_nvme_attach_controller",
		          "params": {
		            "name": "Nvme0",
		            "trtype": "$TEST_TRANSPORT",
		            "adrfam": "IPv4",
		            "traddr": "$NVMF_FIRST_TARGET_IP",
		            "trsvcid": "$NVMF_PORT",
		            "subnqn": "nqn.2016-06.io.spdk:cnode0"
		          }
		        },
		        {
		          "method": "bdev_set_options",
		          "params": {
		            "bdev_auto_examine": false
		          }
		        },
		        {
		          "method": "bdev_wait_for_examine"
		        }
		      ]
		    }
		  ]
		}
	JSON
}

if [ "$TEST_TRANSPORT" != "rdma" ]; then
	exit 0
fi

nvmftestinit
nvmfappstart -m 0xf0 --wait-for-rpc

$rpc_py mlx5_scan_accel_module --enable-driver --allowed-devs $allowed_devices
$rpc_py bdev_set_options --disable-auto-examine
$rpc_py framework_start_init
$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS --in-capsule-data-size 0
$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0 -m 8 -i -t 1 --disable-accel-support
$rpc_py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode0 -a
$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode0 Malloc0 -N
$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode0 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT

sleep 1

$bdevperf --json <(gen_bdevperf_json) -q 64 -o 4096 -t 5 -w randrw -M 50 -m 0xf -r $app_sock
$bdevperf --json <(gen_bdevperf_json) -q 64 -o 65536 -t 5 -w verify -m 0xf -r $app_sock

## By killing the target, we trigger qpair disconnect with outstanding IOs and test that nvme_rdma<->accel_mlx5
## interaction works well. No hang or crash expected.
$bdevperf --json <(gen_bdevperf_json) -q 64 -o 4096 -t 60 -w rw -M 50 -m 0xf -r $app_sock &
bdev_perf_pid=$!
waitforlisten $bdev_perf_pid $app_sock
sleep 5
killprocess $nvmfpid
wait $bdev_perf_pid || true

nvmftestfini

trap - SIGINT SIGTERM EXIT
