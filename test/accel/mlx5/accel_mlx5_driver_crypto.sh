#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

MALLOC_BDEV_SIZE=256
MALLOC_BLOCK_SIZE=512
app_sock=/var/tmp/bdev.sock

function gen_accel_mlx5_driver_crypto_rdma_json() {
	accel_qp_size=${1:-256}
	accel_num_requests=${2:-2047}

	jq . <<- JSON
		{
		  "subsystems": [
		    {
		      "subsystem": "accel",
		      "config": [
		        {
		          "method": "mlx5_scan_accel_module",
		          "params": {
		            "qp_size": ${accel_qp_size},
		            "num_requests": ${accel_num_requests},
		            "enable_driver": true
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
		           "method": "bdev_nvme_set_options",
		           "params": {
		             "allow_accel_sequence": true
		          }
		        },
		        {
		          "method": "bdev_nvme_attach_controller",
		          "params": {
		            "name": "Nvme0",
		            "trtype": "$TEST_TRANSPORT",
		            "adrfam": "IPv4",
		            "traddr": "$NVMF_FIRST_TARGET_IP",
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

validate_crypto_umr_stats() {
	rpc_sock=$1
	stats=$($rpc_py -s $rpc_sock accel_mlx5_dump_stats -l total)

	val=$(echo $stats | jq -r '.Total.UMRs.crypto_umrs')
	if [ "$val" == 0 ]; then
		echo "Unexpected number of crypto_umrs: $val, expected > 0"
		return 1
	fi
	val=$(echo $stats | jq -r '.Total.UMRs.sig_umrs')
	if [ "$val" != 0 ]; then
		echo "Unexpected number of sig_umrs: $val, expected 0"
		return 1
	fi
	val=$(echo $stats | jq -r '.Total.RDMA.total')
	if [ "$val" != 0 ]; then
		echo "Unexpected number of RDMA operations: $val, expected 0"
		return 1
	fi
	val=$(echo $stats | jq -r '.Total.tasks.crypto_mkey')
	if [ $val != 0 ] && [ $val != $(echo $stats | jq -r '.Total.tasks.total') ]; then
		echo "Unexpected number of tasks operations: $val, expected > 0 and no other tasks"
		return 1
	fi
}

if [ "$TEST_TRANSPORT" != "rdma" ]; then
	exit 0
fi

bdevperf=$rootdir/build/examples/bdevperf
testdma="$rootdir/test/dma/test_dma/test_dma"

# Test mlx5 platform driver with crypto bdev and bdev_nvme rdma
nvmftestinit
nvmfappstart -m 0x3

$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS
$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0
$rpc_py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode0 -a -s SPDK00000000000001
$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode0 Malloc0
$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode0 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT

sleep 1

# Test with bdevperf, without src memory domain
$bdevperf --json <(gen_accel_mlx5_driver_crypto_rdma_json) -q 64 -o 4096 -t 10 -w verify -M 50 -m 0xc -r $app_sock
$bdevperf --json <(gen_accel_mlx5_driver_crypto_rdma_json) -q 128 -o 65536 -t 10 -w verify -M 50 -m 0xc -r $app_sock

## By killing the target, we trigger qpair disconnect with outstanding IOs and test that nvme_rdma<->accel_mlx5
## interaction works well. No hang or crash expected.
$bdevperf --json <(gen_accel_mlx5_driver_crypto_rdma_json) -q 64 -o 4096 -t 60 -w rw -M 50 -m 0xc -r $app_sock &
bdev_perf_pid=$!
waitforlisten $bdev_perf_pid $app_sock
sleep 5
validate_crypto_umr_stats $app_sock
sleep 1
killprocess $nvmfpid
wait $bdev_perf_pid || true

nvmfappstart -m 0x3
$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS
$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0
$rpc_py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode0 -a -s SPDK00000000000001
$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode0 Malloc0
$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode0 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT

$bdevperf --json <(gen_accel_mlx5_driver_crypto_rdma_json) -q 64 -o 4096 -t 10 -w rw -M 50 -m 0xc -r $app_sock &
bdev_perf_pid=$!
waitforlisten $bdev_perf_pid $app_sock
sleep 5
validate_crypto_umr_stats $app_sock
sleep 1
wait $bdev_perf_pid

# Test with dma app which uses memory domains
$testdma --json <(gen_accel_mlx5_driver_crypto_rdma_json) -q 64 -o 4096 -t 10 -w verify -M 50 -m 0xc -r $app_sock -b "Crypto0" -f -x translate &
testdma_pid=$!
waitforlisten $testdma_pid $app_sock
sleep 5
validate_crypto_umr_stats $app_sock
sleep 1
wait $testdma_pid

# Test small qp size and number of MRs
$testdma --json <(gen_accel_mlx5_driver_crypto_rdma_json 16 32) -q 64 -o 32768 -t 10 -w verify -M 50 -m 0xc -r $app_sock -b "Crypto0" -f -x translate &
testdma_pid=$!
waitforlisten $testdma_pid $app_sock
sleep 5
validate_crypto_umr_stats $app_sock
sleep 1
wait $testdma_pid

# Test mkey corruption
testdma="$rootdir/test/dma/test_dma/test_dma"
$testdma --json <(gen_accel_mlx5_driver_crypto_rdma_json) -q 64 -o 4096 -t 10 -w randrw -M 50 -m 0xc -r $app_sock -b "Crypto0" -f -x translate -Y 500000 &
testdma_pid=$!
waitforlisten $testdma_pid $app_sock
sleep 5
validate_crypto_umr_stats $app_sock
sleep 1
wait $testdma_pid || true

nvmftestfini

trap - SIGINT SIGTERM EXIT
