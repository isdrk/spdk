#!/usr/bin/env bash

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh
source $rootdir/test/nvmf/common.sh

MALLOC_BDEV_SIZE=64
MALLOC_BLOCK_SIZE=512

rpc_py="$rootdir/scripts/rpc.py"

bdevperf_rpc_sock=/var/tmp/bdevperf.sock

nvmftestinit

# This issue brings up a weird error in soft roce where the RDMA WC doesn't point to the correct qpair.
if check_ip_is_soft_roce $NVMF_FIRST_TARGET_IP && [ "$TEST_TRANSPORT" == "rdma" ]; then
	echo "Using software RDMA, not running this test due to a known issue."
	exit 0
fi

nvmfappstart -m 0xF

$rpc_py nvmf_create_transport $NVMF_TRANSPORT_OPTS -u 8192

$rpc_py bdev_malloc_create $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE -b Malloc0
$rpc_py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode1 -a -s SPDK00000000000001 -r
$rpc_py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode1 Malloc0

$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode1 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT
$rpc_py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode1 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_SECOND_PORT

# Set ANA state to each listener
$rpc_py nvmf_subsystem_listener_set_ana_state nqn.2016-06.io.spdk:cnode1 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT -n optimized
$rpc_py nvmf_subsystem_listener_set_ana_state nqn.2016-06.io.spdk:cnode1 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_SECOND_PORT -n non_optimized

$rpc_py nvmf_subsystem_get_listeners nqn.2016-06.io.spdk:cnode1
$rootdir/test/bdev/bdevperf/bdevperf -z -r $bdevperf_rpc_sock -q 128 -o 4096 -w verify -t 30 &> $testdir/try.txt &
bdevperf_pid=$!

trap 'process_shm --id $NVMF_APP_SHM_ID; rm -f $testdir/try.txt; killprocess $bdevperf_pid; nvmftestfini; exit 1' SIGINT SIGTERM EXIT
waitforlisten $bdevperf_pid $bdevperf_rpc_sock

# Create a controller and set multipath behavior
$rpc_py -s $bdevperf_rpc_sock bdev_nvme_set_options -r -1 -b -1 -e 5
$rpc_py -s $bdevperf_rpc_sock bdev_nvme_attach_controller -b Nvme0 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT -f ipv4 -n nqn.2016-06.io.spdk:cnode1
$rpc_py -s $bdevperf_rpc_sock bdev_nvme_attach_controller -b Nvme0 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_SECOND_PORT -f ipv4 -n nqn.2016-06.io.spdk:cnode1 -x multipath

sleep 1

$rootdir/test/bdev/bdevperf/bdevperf.py -s $bdevperf_rpc_sock perform_tests &
rpc_pid=$!

sleep 5

#Remove listener to monitor multipath, should switch to second path
$rpc_py nvmf_subsystem_remove_listener nqn.2016-06.io.spdk:cnode1 -t $TEST_TRANSPORT -a $NVMF_FIRST_TARGET_IP -s $NVMF_PORT

wait $rpc_pid
cat $testdir/try.txt
$rpc_py nvmf_subsystem_get_listeners nqn.2016-06.io.spdk:cnode1
killprocess $bdevperf_pid

$rpc_py nvmf_delete_subsystem nqn.2016-06.io.spdk:cnode1

trap - SIGINT SIGTERM EXIT

rm -f $testdir/try.txt
nvmftestfini
