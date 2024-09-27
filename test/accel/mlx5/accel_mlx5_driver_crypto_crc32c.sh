#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2021 Intel Corporation
#  All rights reserved.
#

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

XLIO_PATH=$1
IP_ADDR=$2
allowed_devices=${3:-"mlx5_0"}

echo "Warning! test is not ready yet"
exit 1

if [ "$TEST_TRANSPORT" != "tcp" ]; then
	exit 0
fi

if [ -z "$XLIO_PATH" ]; then
	echo "ERR: XLIO PATH is not set"
	exit 1
fi

if [ -z "$IP_ADDR" ]; then
	echo "ERR: IP ADDR is not set"
	exit 1
fi

MALLOC_BDEV_SIZE=256
MALLOC_BLOCK_SIZE=512
bdevperf=$rootdir/build/examples/bdevperf
app_sock=/var/tmp/bdev.sock

XLIO_OPTS="
XLIO_STATS_FD_NUM=1000
XLIO_RING_ALLOCATION_LOGIC_TX=20
XLIO_RING_ALLOCATION_LOGIC_RX=20
XLIO_QP_COMPENSATION_LEVEL=8
XLIO_STRQ_NUM_STRIDES=8192
XLIO_STRQ_STRIDES_COMPENSATION_LEVEL=32768
XLIO_STRQ_STRIDE_SIZE_BYTES=64
XLIO_LRO=on
XLIO_FORK=0
XLIO_SPEC=latency
XLIO_INTERNAL_THREAD_AFFINITY=0x01
XLIO_THREAD_MODE=1
XLIO_RX_WRE_BATCHING=1
XLIO_TX_WRE_BATCHING=128
XLIO_TX_WRE=1024
XLIO_RX_WRE=32
XLIO_TSO=1
XLIO_SKIP_POLL_IN_RX=2
XLIO_RX_POLL=-1
XLIO_RX_PREFETCH_BYTES_BEFORE_POLL=256
XLIO_RING_DEV_MEM_TX=1024
XLIO_MEM_ALLOC_TYPE=HUGE
XLIO_AVOID_SYS_CALLS_ON_TCP_FD=1
XLIO_CQ_KEEP_QP_FULL=0
XLIO_CQ_AIM_INTERVAL_MSEC=0
XLIO_CQ_AIM_MAX_COUNT=64
XLIO_CQ_MODERATION_ENABLE=1
XLIO_PROGRESS_ENGINE_INTERVAL=0
XLIO_SELECT_POLL_OS_FORCE=1
XLIO_SELECT_POLL_OS_RATIO=1
XLIO_SELECT_SKIP_OS=1
XLIO_TCP_ABORT_ON_CLOSE=1
XLIO_MEMORY_LIMIT=256MB
XLIO_MEMORY_LIMIT_USER=4GB
XLIO_SOCKETXTREME=1
XLIO_BUFFER_BATCHING_MODE=0
XLIO_TCP_NODELAY=1
XLIO_TCP_NODELAY_TRESHOLD=1024
XLIO_DEFERRED_CLOSE=1
XLIO_TX_SEGS_BATCH_TCP=1
XLIO_TCP_CTL_THREAD=delegate
XLIO_TCP_QUICKACK=1
XLIO_GRO_STREAMS_MAX=9216
XLIO_RX_PREFETCH_BYTES_BEFORE_POLL=0
XLIO_RX_PREFETCH_BYTES=64
"

function gen_accel_mlx5_crypto_crc_json() {

	jq . <<- JSON
		{
		  "subsystems": [
		    {
		      "subsystem": "accel",
		      "config": [
		        {
		          "method": "mlx5_scan_accel_module",
		          "params": {
		            "enable_driver": true,
		            "allowed_devs" : "$allowed_devices"
		          }
		        },
		        {
		          "method": "accel_crypto_key_create",
		          "params": {
		            "name": "test_dek",
		            "cipher": "AES_XTS",
		            "key": "00112233445566778899001122334455",
		            "key2": "11223344556677889900112233445500"
		          }
		        }
		      ]
		    },
		    {
		      "subsystem": "bdev",
		      "config": [
		        {
		          "method": "bdev_nvme_attach_controller",
		          "params": {
		            "name": "Nvme0",
		            "trtype": "nvda_tcp",
		            "adrfam": "IPv4",
		            "traddr": "$IP_ADDR",
		            "trsvcid": "$NVMF_PORT",
		            "subnqn": "nqn.2016-06.io.spdk:cnode0",
		            "ddgst": true
		          }
		        },
		        {
		          "method": "bdev_crypto_create",
		          "params": {
		            "base_bdev_name": "Nvme0n1",
		            "name": "Crypto0",
		            "key_name": "test_dek"
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

validate_crypto_crc_stats() {
	rpc_sock=$1
	stats=$($rpc_py -s $rpc_sock accel_mlx5_dump_stats -l total)

	sig_crypto_umrs=$(echo $stats | jq -r '.total.umrs.sig_crypto_umrs')
	if [ "$sig_crypto_umrs" == 0 ]; then
		echo "Unexpected number of crypto_umrs: $sig_crypto_umrs, expected > 0"
		return 1
	fi
	sig_umrs=$(echo $stats | jq -r '.total.umrs.sig_umrs')
	crypto_umrs=$(echo $stats | jq -r '.total.umrs.crypto_umrs')
	if ((sig_umrs + crypto_umrs > 0)); then
		echo "Unexpected number of unmerged UMRs"
		return 1
	fi
}

nvmftestinit
nvmfappstart -m 0x3

$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS
$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0
$rpc_py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode0 -a -s SPDK00000000000001
$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode0 Malloc0
$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode0 -t $TEST_TRANSPORT -a $IP_ADDR -s $NVMF_PORT

# test crypto and crc32c with TCP data digest
env $XLIO_OPTS SPDK_XLIO_PATH=$XLIO_PATH $bdevperf --json <(gen_accel_mlx5_crypto_crc_json) -q 1 -o 4096 -t 10 -w randread -M 50 -m 0xc -r $app_sock &
bdevperf_pid=$!
waitforlisten $bdevperf_pid $app_sock
sleep 5
validate_crypto_crc_stats $app_sock
sleep 1
wait $bdevperf_pid

#$bdevperf --json <(gen_accel_mlx5_crypto_crc_json) -q 128 -o 131072 -t 10 -w randrw -M 50 -m 0xc -r $app_sock
#bdevperf_pid=$!
#waitforlisten $bdevperf_pid $app_sock
#sleep 5
#validate_crypto_crc_stats $app_sock
#sleep 1
#wait $bdevperf_pid

trap - SIGINT SIGTERM EXIT

nvmftestfini
