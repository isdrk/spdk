#!/usr/bin/env bash

# Change default setup here or run as 'SETUP=2 ./test.sh'
SETUP=${SETUP:-1}

# Adjust paths according to your setup or add new setup
if [ "1" == $SETUP ]; then
    # Test setup with SNIC initiator
    TGT_HOST=${TGT_HOST:-spdk05.swx.labs.mlnx}
    TGT_ADDR=${TGT_ADDR:-1.1.5.1}
    TGT_PORT=${TGT_PORT:-4420}
    SNAP_SSH=${SNAP_SSH:-ubuntu@snic}
    PERF_SSH=${PERF_SSH:-ubuntu@snic}
    PERF_BIN_PATH=${PERF_BIN_PATH:-/home/evgeniik/rx-zcopy/spdk/install-snic/bin}
    PERF_SPDK_PATH=${PERF_SPDK_PATH:-/home/evgeniik/rx-zcopy/spdk}
    LIBVMA=${LIBVMA:-/home/evgeniik/rx-zcopy/libxlio/install-snic/lib/libxlio.so}
    TGT_BIN_PATH=${TGT_BIN_PATH:-$PWD/install-$TGT_HOST/bin}
    TGT_SPDK_PATH=${TGT_SPDK_PATH:-$PWD}
    PERF_ENV_OPTS="LD_LIBRARY_PATH=$PERF_SPDK_PATH/install-snic/lib:$PERF_SPDK_PATH/dpdk/build/lib"
elif [ "2" == $SETUP ]; then
    # Test setup with x86 initiator
    TGT_HOST=${TGT_HOST:-spdk05.swx.labs.mlnx}
    TGT_ADDR=${TGT_ADDR:-1.1.5.1}
    TGT_PORT=${TGT_PORT:-4420}
    PERF_SSH=${PERF_SSH:-}
    PERF_BIN_PATH=${PERF_BIN_PATH:-$PWD/install-$HOSTNAME/bin}
    PERF_SPDK_PATH=${PERF_SPDK_PATH:-$PWD}
    LIBVMA=${LIBVMA:-$PWD/../libxlio/install-$HOSTNAME/lib/libxlio.so}
    TGT_BIN_PATH=${TGT_BIN_PATH:-$PWD/install-$TGT_HOST/bin}
    TGT_SPDK_PATH=${TGT_SPDK_PATH:-$PWD}
elif [ "3" == $SETUP ]; then
    # Test setup via SNAP
    TGT_HOST=${TGT_HOST:-spdk05.swx.labs.mlnx}
    TGT_ADDR=${TGT_ADDR:-1.1.5.1}
    TGT_PORT=${TGT_PORT:-4420}
    PCI_ADDR=${PCI_ADDR:-0000:60:00.2}
    SNAP_SSH=${SNAP_SSH:-ubuntu@snic}
    SNAP_BIN_PATH=${SNAP_BIN_PATH:-/home/evgeniik/rx-zcopy/nvmx/install-snic/bin}
    SNAP_DPDK_PATH=${SNAP_DPDK_PATH:-/home/evgeniik/rx-zcopy/spdk/dpdk/build/lib}
    SNIC_SPDK_PATH=${SNIC_SPDK_PATH:-/home/evgeniik/rx-zcopy/spdk}
    PERF_SSH=${PERF_SSH:-}
    PERF_BIN_PATH=${PERF_BIN_PATH:-$PWD/install-$HOSTNAME/bin}
    PERF_SPDK_PATH=${PERF_SPDK_PATH:-$PWD}
    LIBVMA=${LIBVMA:-/home/evgeniik/rx-zcopy/libxlio/install-snic/lib/libxlio.so}
    TGT_BIN_PATH=${TGT_BIN_PATH:-$PWD/install-$TGT_HOST/bin}
    TGT_SPDK_PATH=${TGT_SPDK_PATH:-$PWD}
    SNAP_ENV_OPTS="LD_LIBRARY_PATH=$SNAP_DPDK_PATH NVME_SNAP_LOGFILE_PATH=stderr"
elif [ "4" == $SETUP ]; then
    # Test setup via SNAP on spdk-perf-01/02
    TGT_MASK=0xFF00000
    TGT_HOST=${TGT_HOST:-spdk-perf-02}
    TGT_ADDR=${TGT_ADDR:-1.1.102.1}
    TGT_PORT=${TGT_PORT:-4420}
    PCI_ADDR=${PCI_ADDR:-0000:3d:00.2}
    SNAP_SSH=${SNAP_SSH:-ubuntu@snic}
    SNAP_BIN_PATH=${SNAP_BIN_PATH:-/home/evgeniik/rx-zcopy/nvmx/install-snic/bin}
    SNAP_DPDK_PATH=${SNAP_DPDK_PATH:-/home/evgeniik/rx-zcopy/spdk/dpdk/build/lib}
    SNIC_SPDK_PATH=${SNIC_SPDK_PATH:-/home/evgeniik/rx-zcopy/spdk}
    PERF_SSH=${PERF_SSH:-}
    PERF_BIN_PATH=${PERF_BIN_PATH:-$PWD/install-$HOSTNAME/bin}
    PERF_SPDK_PATH=${PERF_SPDK_PATH:-$PWD}
    LIBVMA=${LIBVMA:-/home/evgeniik/rx-zcopy/libxlio/install-snic/lib/libxlio.so}
    TGT_BIN_PATH=${TGT_BIN_PATH:-$PWD/install-$TGT_HOST/bin}
    TGT_SPDK_PATH=${TGT_SPDK_PATH:-$PWD}
    SNAP_ENV_OPTS="LD_LIBRARY_PATH=$SNAP_DPDK_PATH NVME_SNAP_LOGFILE_PATH=stderr"
else
    echo "Unknown setup"
    exit 1
fi

TGT_LIBVMA=${TGT_LIBVMA:-}

VMA_OPTS="
xVMA_TSO=1
xVMA_INTERNAL_THREAD_ARM_CQ=1
xVMA_GRO_STREAMS_MAX=0
xVMA_RX_POLL_ON_TX_TCP=1
xVMA_MEM_ALLOC_TYPE=2
xVMA_TX_BUFS=4096
xVMA_TX_BUF_SIZE=8192
xVMA_RX_BUFS=70000
xVMA_RX_WRE=4096
VMA_RING_ALLOCATION_LOGIC_TX=30
VMA_RING_ALLOCATION_LOGIC_RX=30
xVMA_TCP_NODELAY=1
xVMA_TRACELEVEL=4
xVMA_INTERNAL_THREAD_AFFINITY=0x80
xVMA_SELECT_POLL=0
xVMA_RX_POLL=0
"

TGT_MASK=${TGT_MASK:-0xFF}
SNAP_MASK=${SNAP_MASK:-0xFF}
PERF_TIME=${PERF_TIME:-60}
PERF_MASKS=${PERF_MASKS:-0x10 0x30 0xF0 0xFF 0xFC}
QUEUE_DEPTHS=${QUEUE_DEPTHS:-8 16 32 64 128}
IO_SIZES=${IO_SIZES:-4096 8192 16384 32768 65536 131072}
RW=${RW:-randread}
REPEAT=${REPEAT:-1}
#NVME_PERF_EXTRA_OPTS="-T vma -T nvme"
#BDEV_PERF_EXTRA_OPTS="-L vma -L nvme"
SSH_EXTRA_OPTS=${SSH_EXTRA_OPTS:-}
BDEV_NULL_OPTS="8192 512"
#SOCK_EXTRA_OPTS="--disable-recv-pipe"

function rpc_tgt() {
    local SSH=""
    if [ -n "$TGT_HOST" ]; then
	SSH="ssh $SSH_EXTRA_OPTS $TGT_HOST"
    fi
    $SSH sudo $TGT_SPDK_PATH/scripts/rpc.py $@ >> rpc_tgt.log 2>&1
}

function rpc_perf() {
    local SSH=""
    if [ -n "$PERF_SSH" ]; then
	SSH="ssh $SSH_EXTRA_OPTS $PERF_SSH"
    fi
    $SSH sudo $PERF_SPDK_PATH/scripts/rpc.py -s /var/tmp/bdevperf.sock $@ 2>&1 | tee -a perf.log
}

function start_tgt() {
    local SSH=""
    if [ -n "$TGT_HOST" ]; then
	SSH="ssh $SSH_EXTRA_OPTS $TGT_HOST"
    fi
    if [ -n "$TGT_LIBVMA" ]; then
	$SSH sudo $VMA_OPTS LD_PRELOAD=$TGT_LIBVMA $TGT_BIN_PATH/spdk_tgt -m $TGT_MASK 2>&1 | tee tgt.log > /dev/null &
    else
	$SSH sudo $TGT_BIN_PATH/spdk_tgt -m $TGT_MASK --wait-for-rpc 2>&1 | tee tgt.log > /dev/null &
    fi
    sleep 7
}

function stop_tgt() {
    rpc_tgt spdk_kill_instance 15
    sleep 3
}

function config_tgt() {
    #rpc_tgt sock_impl_set_options -i posix --enable-zerocopy-send
    rpc_tgt framework_start_init
    rpc_tgt nvmf_create_transport -t tcp -n 2048 -b 128
    rpc_tgt nvmf_create_subsystem -a nqn.2016-06.io.spdk:cnode1
    rpc_tgt nvmf_subsystem_add_listener -t tcp -a $TGT_ADDR -f ipv4 -s $TGT_PORT nqn.2016-06.io.spdk:cnode1
    rpc_tgt bdev_null_create Null0 $BDEV_NULL_OPTS
    rpc_tgt nvmf_subsystem_add_ns -n 1 nqn.2016-06.io.spdk:cnode1 Null0
    rpc_tgt save_config
}

function start_snap_service() {
    local SSH=""
    if [ -z "$SNAP_SSH" ]; then
	echo "SNAP_SSH is not set. Can not start SNAP"
	return
    fi

    SSH="ssh $SSH_EXTRA_OPTS $SNAP_SSH"

    $SSH sudo systemctl start mlnx_snap
}

function stop_snap_service() {
    local SSH=""
    if [ -z "$SNAP_SSH" ]; then
	echo "SNAP_SSH is not set. Can not start SNAP"
	return
    fi

    SSH="ssh $SSH_EXTRA_OPTS $SNAP_SSH"

    $SSH sudo systemctl stop mlnx_snap
}

function start_snap() {
    local SSH=""
    if [ -z "$SNAP_SSH" ]; then
	echo "SNAP_SSH is not set. Can not start SNAP"
	return
    fi

    SSH="ssh $SSH_EXTRA_OPTS $SNAP_SSH"

    $SSH sudo $VMA_OPTS \
	 $SNAP_ENV_OPTS LD_LIBRARY_PATH=$SNAP_DPDK_PATH NVME_SNAP_LOGFILE_PATH=stderr \
	 $SNAP_BIN_PATH/mlnx_snap_emu -m $SNAP_MASK -u --mem-size 1200 --wait-for-rpc \
	 2>&1 | tee snap.log &
    sleep 5
}

function stop_snap() {
    local SSH=""
    if [ -z "$SNAP_SSH" ]; then
	echo "SNAP_SSH is not set. Can not start SNAP"
	return
    fi

    SSH="ssh $SSH_EXTRA_OPTS $SNAP_SSH"

    $SSH sudo spdk_rpc.py spdk_kill_instance 15
    sleep 3
}

function snap_enable_debug() {
    local SSH=""
    if [ -z "$SNAP_SSH" ]; then
	echo "SNAP_SSH is not set. Can not start SNAP"
	return
    fi

    SSH="ssh $SSH_EXTRA_OPTS $SNAP_SSH"

    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py log_set_flag bdev
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py log_set_flag bdev_nvme
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py log_set_flag sock
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py log_set_flag vma
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py log_set_level DEBUG
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py log_set_print_level DEBUG
}

function config_snap() {
    local SSH=""
    if [ -z "$SNAP_SSH" ]; then
	echo "SNAP_SSH is not set. Can not start SNAP"
	return
    fi

    SSH="ssh $SSH_EXTRA_OPTS $SNAP_SSH"

    #snap_enable_debug

    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py sock_set_default_impl -i $SOCK_IMPL
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py sock_impl_set_options -i $SOCK_IMPL $SOCK_EXTRA_OPTS
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py framework_start_init
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py bdev_nvme_set_options -k 0
    $SSH sudo $SNIC_SPDK_PATH/scripts/rpc.py bdev_nvme_attach_controller $BDEV_NVME_ATTACH_CONTROLLER_EXTRA_OPTS -b Nvme0 -t TCP -f ipv4 -a $TGT_ADDR -s 4420 -n nqn.2016-06.io.spdk:cnode1
    $SSH sudo snap_rpc.py subsystem_nvme_create nqn.2020-12.mlnx.snap Mellanox_NVMe_SNAP \"Mellanox NVMe SNAP Controller\"
    $SSH sudo snap_rpc.py controller_nvme_create nqn.2020-12.mlnx.snap mlx5_0 --pf_id 0 -c /etc/mlnx_snap/mlnx_snap.json
    $SSH sudo snap_rpc.py controller_nvme_namespace_attach -c NvmeEmu0pf0 spdk Nvme0n1 1
}

function run_nvmeperf() {
    local ADDR=${ADDR:-$TGT_ADDR}
    local PORT=${PORT:-$TGT_PORT}
    local SSH=""

    if [ -n "$PERF_SSH" ]; then
	SSH="ssh $SSH_EXTRA_OPTS $PERF_SSH"
	$SSH sudo $PERF_ENV_OPTS $VMA_OPTS $PERF_BIN_PATH/spdk_nvme_perf \
	     -S $SOCK_IMPL -r \"trtype:tcp adrfam:ipv4 traddr:$ADDR trsvcid:$PORT\" \
	     -c $PERF_MASK -q $QUEUE_DEPTH -o $IO_SIZE -w $RW -t $PERF_TIME \
	     $NVME_PERF_EXTRA_OPTS 2>&1 | tee perf.log&
    else
	sudo $PERF_ENV_OPTS $VMA_OPTS $PERF_BIN_PATH/spdk_nvme_perf \
	     -S $SOCK_IMPL -r "trtype:tcp adrfam:ipv4 traddr:$ADDR trsvcid:$PORT" \
	     -c $PERF_MASK -q $QUEUE_DEPTH -o $IO_SIZE -w $RW -t $PERF_TIME \
	     $NVME_PERF_EXTRA_OPTS 2>&1 | tee perf.log&
    fi

    PERF_PID=$!
    echo "Perf PID is $PERF_PID" 2>&1 | tee -a perf.log
}

function run_nvmeperf_snap() {
    local ADDR=${ADDR:-$PCI_ADDR}

    sudo $PERF_BIN_PATH/spdk_nvme_perf \
	 -r "trtype:pcie traddr:$ADDR" \
	 -c $PERF_MASK -q $QUEUE_DEPTH -o $IO_SIZE -w $RW -t $PERF_TIME \
	 -A 4096 $NVME_PERF_EXTRA_OPTS 2>&1 | tee perf.log&
    PERF_PID=$!
    echo "Perf PID is $PERF_PID" 2>&1 | tee -a perf.log
}

function wait_nvmeperf() {
    echo "Waiting for perf $PERF_PID"
    wait $PERF_PID
}

function report_nvmeperf() {
    local OUT=$(grep "Total" perf.log | awk '{ print $3 " | " $4 " | " $5 " | " }')
    echo "| $TEST | $PERF_MASK | $TGT_MASK | $IO_SIZE | $QUEUE_DEPTH | $OUT" >> report.log
}

function run_bdevperf() {
    local ADDR=${ADDR:-$TGT_ADDR}
    local PORT=${PORT:-$TGT_PORT}
    local SSH=""

    if [ -n "$PERF_SSH" ]; then
	SSH="ssh $SSH_EXTRA_OPTS $PERF_SSH"
    fi

    $SSH sudo $PERF_ENV_OPTS $VMA_OPTS $PERF_SPDK_PATH/test/bdev/bdevperf/bdevperf \
	 -r /var/tmp/bdevperf.sock --wait-for-rpc -m $PERF_MASK -C \
	 -q $QUEUE_DEPTH -o $IO_SIZE -w $RW -t $PERF_TIME \
	 $BDEV_PERF_EXTRA_OPTS 2>&1 | tee perf.log &
    PERF_PID=$!
    echo "Perf PID is $PERF_PID" 2>&1 | tee -a perf.log
    sleep 3
    rpc_perf sock_set_default_impl -i $SOCK_IMPL
    rpc_perf sock_impl_set_options -i $SOCK_IMPL \
	     --enable-zerocopy-recv \
	     --disable-zerocopy-send \
	     --disable-zerocopy-send-client \
	     $SOCK_EXTRA_OPTS
    rpc_perf framework_start_init
    rpc_perf bdev_nvme_set_options -k 0
    rpc_perf bdev_nvme_attach_controller $BDEV_NVME_ATTACH_CONTROLLER_EXTRA_OPTS -b Nvme0 -t tcp -f ipv4 -a $ADDR -s $PORT \
	     -n nqn.2016-06.io.spdk:cnode1
    $SSH sudo PYTHONPATH="$PYTHONPATH:$PERF_SPDK_PATH/scripts" \
	 $PERF_SPDK_PATH/test/bdev/bdevperf/bdevperf.py \
	 -s /var/tmp/bdevperf.sock -t 3600 perform_tests 2>&1 | tee -a perf.log &
    RPC_TASK_PID=$!
    echo "RPC task PID is $RPC_TASK_PID" 2>&1 | tee -a perf.log
}

function wait_bdevperf() {
    echo "Waiting for RPC task $RPC_TASK_PID"
    wait $RPC_TASK_PID
    rpc_perf spdk_kill_instance 15
    sleep 3
    echo "Waiting for perf $PERF_PID"
    wait $PERF_PID
}

function report_bdevperf() {
    local OUT=$(grep "Total" perf.log | tail -1 | awk '{ print $4 " | " $6 " | " }')
    echo "| $TEST | $PERF_MASK | $TGT_MASK | $IO_SIZE | $QUEUE_DEPTH | $OUT" >> report.log
}

function basic_test_nvme() {
    start_tgt
    config_tgt
    for PERF_MASK in $PERF_MASKS; do
	for QUEUE_DEPTH in $QUEUE_DEPTHS; do
	    for IO_SIZE in $IO_SIZES; do
		for REP in $(seq $REPEAT); do
		    run_nvmeperf # > /dev/null 2>&1
		    wait_nvmeperf
		    report_nvmeperf
		done
	    done
	done
    done
    stop_tgt
}

function basic_test_nvme_snap_service() {
    start_tgt
    config_tgt
    start_snap_service
    for PERF_MASK in $PERF_MASKS; do
	for QUEUE_DEPTH in $QUEUE_DEPTHS; do
	    for IO_SIZE in $IO_SIZES; do
		for REP in $(seq $REPEAT); do
		    run_nvmeperf_snap # > /dev/null 2>&1
		    wait_nvmeperf
		    report_nvmeperf
		done
	    done
	done
    done
    stop_snap_service
    stop_tgt
}

function basic_test_nvme_snap() {
    start_tgt
    config_tgt
    start_snap
    config_snap
    for PERF_MASK in $PERF_MASKS; do
	for QUEUE_DEPTH in $QUEUE_DEPTHS; do
	    for IO_SIZE in $IO_SIZES; do
		for REP in $(seq $REPEAT); do
		    run_nvmeperf_snap # > /dev/null 2>&1
		    wait_nvmeperf
		    report_nvmeperf
		done
	    done
	done
    done
    stop_snap
    stop_tgt
}

function basic_test_bdev() {
    start_tgt
    config_tgt
    for PERF_MASK in $PERF_MASKS; do
	for QUEUE_DEPTH in $QUEUE_DEPTHS; do
	    for IO_SIZE in $IO_SIZES; do
		for REP in $(seq $REPEAT); do
		    run_bdevperf # > /dev/null 2>&1
		    wait_bdevperf
		    report_bdevperf
		done
	    done
	done
    done
    stop_tgt
}

# Test with spdk_nvme_perf VMA non zcopy
function test1() {
    SOCK_IMPL=vma \
	     NVME_PERF_EXTRA_OPTS="-z vma -P 2 $NVME_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_nvme
}

# Test with bdevperf VMA non zcopy
function test2() {
    SOCK_IMPL=vma \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_bdev
}

# Test with spdk_nvme_perf VMA zcopy
function test3() {
    SOCK_IMPL=vma \
	     NVME_PERF_EXTRA_OPTS="-n -z vma --enable-zcopy-recv vma -P 2 $NVME_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_nvme
}

# Test with bdevperf VMA zcopy
function test4() {
    SOCK_IMPL=vma \
	     BDEV_PERF_EXTRA_OPTS="-Z $BDEV_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_bdev
}

# Test with spdk_nvme_perf POSIX-VMA non zcopy
function test5() {
    SOCK_IMPL=posix \
	     NVME_PERF_EXTRA_OPTS="-z posix -P 2 $NVME_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="LD_PRELOAD=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_nvme
}

# Test with bdevperf POSIX-VMA non zcopy
function test6() {
    SOCK_IMPL=posix \
	     SOCK_EXTRA_OPTS="--disable-recv-pipe" \
	     PERF_ENV_OPTS="LD_PRELOAD=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_bdev
}

# Test with spdk_nvme_perf POSIX-Kernel non zcopy
function test7() {
    LIBVMA= \
	  SOCK_IMPL=posix \
	  NVME_PERF_EXTRA_OPTS="-P 2 $NVME_PERF_EXTRA_OPTS" \
	  basic_test_nvme
}

# Test with bdevperf POSIX-Kernel non zcopy
function test8() {
    LIBVMA= \
	  SOCK_IMPL=posix \
	  basic_test_bdev
}

# Test with PI + spdk_nvme_perf VMA non zcopy + PI
function test9() {
    SOCK_IMPL=vma \
	     BDEV_NULL_OPTS="8192 520 -m 8 -t 1" \
	     NVME_PERF_EXTRA_OPTS="-P 2 $NVME_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_nvme
}

# Test with bdevperf VMA non zcopy + PI
function test10() {
    SOCK_IMPL=vma \
	     BDEV_NULL_OPTS="8192 520 -m 8 -t 1" \
	     BDEV_NVME_ATTACH_CONTROLLER_EXTRA_OPTS="-r -g" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_bdev
}

# Test with spdk_nvme_perf VMA zcopy + PI
function test11() {
    SOCK_IMPL=vma \
	     BDEV_NULL_OPTS="8192 520 -m 8 -t 1" \
	     NVME_PERF_EXTRA_OPTS="-e PRACT=0,PRCHK=GUARD|REFTAG -n -Z vma -P 2 $NVME_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_nvme
}

# Test with bdevperf VMA zcopy + PI
function test12() {
    SOCK_IMPL=vma \
	     BDEV_NULL_OPTS="8192 520 -m 8 -t 1" \
	     BDEV_NVME_ATTACH_CONTROLLER_EXTRA_OPTS="-r -g" \
	     BDEV_PERF_EXTRA_OPTS="-Z $BDEV_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_bdev
}

# Test with spdk_nvme_perf VMA zcopy + digest
function test13() {
    SOCK_IMPL=vma \
	     NVME_PERF_EXTRA_OPTS="-H -I -n -Z vma -P 2 $NVME_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_nvme
}

# Test with spdk_nvme_perf VMA zcopy + PI + digest
function test14() {
    SOCK_IMPL=vma \
	     BDEV_NULL_OPTS="8192 520 -m 8 -t 1" \
	     NVME_PERF_EXTRA_OPTS="-H -I -e PRACT=0,PRCHK=GUARD|REFTAG -n -Z vma -P 2 $NVME_PERF_EXTRA_OPTS" \
	     PERF_ENV_OPTS="SPDK_VMA_PATH=$LIBVMA $PERF_ENV_OPTS" \
	     basic_test_nvme
}

# Test with spdk_nvme_perf via SNAP service
function test_snap_service() {
    basic_test_nvme_snap_service
}

# Test with spdk_nvme_perf via custom SNAP with zcopy and verbs DMA
function test_snap_1() {
    SNAP_ENV_OPTS="$SNAP_ENV_OPTS SPDK_VMA_PATH=$LIBVMA NVME_SNAP_RX_ZCOPY=1 SNAP_DMA_Q_MODE=0" \
		 SOCK_IMPL=vma \
		 SOCK_EXTRA_OPTS="--enable-zerocopy-recv --disable-zerocopy-send --disable-zerocopy-send-client" \
		 basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP without zcopy and verbs DMA
function test_snap_2() {
    SNAP_ENV_OPTS="$SNAP_ENV_OPTS SPDK_VMA_PATH=$LIBVMA NVME_SNAP_RX_ZCOPY=0 SNAP_DMA_Q_MODE=0" \
		 SOCK_IMPL=vma \
		 SOCK_EXTRA_OPTS="--disable-zerocopy-recv --disable-zerocopy-send --disable-zerocopy-send-client" \
		 basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP with zcopy and DV DMA
function test_snap_3() {
    SNAP_ENV_OPTS="$SNAP_ENV_OPTS SPDK_VMA_PATH=$LIBVMA NVME_SNAP_RX_ZCOPY=1 SNAP_DMA_Q_MODE=1" \
		 SOCK_IMPL=vma \
		 SOCK_EXTRA_OPTS="--enable-zerocopy-recv --disable-zerocopy-send --disable-zerocopy-send-client" \
		 basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP with zcopy and GGA DMA
function test_snap_3_tx() {
    RW=randwrite \
      SNAP_ENV_OPTS="$SNAP_ENV_OPTS SPDK_VMA_PATH=$LIBVMA NVME_SNAP_RX_ZCOPY=0 SNAP_DMA_Q_MODE=2" \
      SOCK_IMPL=vma \
      SOCK_EXTRA_OPTS="--disable-zerocopy-recv --enable-zerocopy-send --enable-zerocopy-send-client" \
      basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP with zcopy and GGA DMA
function test_snap_3_mix() {
    RW=randrw \
      NVME_PERF_EXTRA_OPTS="$NVME_PERF_EXTRA_OPTS -M 50" \
      SNAP_ENV_OPTS="$SNAP_ENV_OPTS SPDK_VMA_PATH=$LIBVMA NVME_SNAP_RX_ZCOPY=1 SNAP_DMA_Q_MODE=1" \
      SOCK_IMPL=vma \
      SOCK_EXTRA_OPTS="--enable-zerocopy-recv --enable-zerocopy-send --enable-zerocopy-send-client" \
      basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP without zcopy and DV DMA
function test_snap_4() {
    SNAP_ENV_OPTS="$SNAP_ENV_OPTS SPDK_VMA_PATH=$LIBVMA NVME_SNAP_RX_ZCOPY=0 SNAP_DMA_Q_MODE=1" \
		 SOCK_IMPL=vma \
		 SOCK_EXTRA_OPTS="--disable-zerocopy-recv --disable-zerocopy-send --disable-zerocopy-send-client" \
		 basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP, no zcopy, DV DMA, posix VMA socket impl
function test_snap_5() {
    SNAP_ENV_OPTS="$SNAP_ENV_OPTS LD_PRELOAD=$LIBVMA NVME_SNAP_RX_ZCOPY=0 SNAP_DMA_Q_MODE=1" \
		 SOCK_IMPL=posix \
		 SOCK_EXTRA_OPTS="--disable-zerocopy-send --disable-zerocopy-send-client --disable-recv-pipe" \
		 basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP, no zcopy, GGA DMA, posix VMA socket impl
function test_snap_5_tx() {
    RW=randwrite \
      SNAP_ENV_OPTS="$SNAP_ENV_OPTS LD_PRELOAD=$LIBVMA NVME_SNAP_RX_ZCOPY=0 SNAP_DMA_Q_MODE=2" \
      SOCK_IMPL=posix \
      SOCK_EXTRA_OPTS="--enable-zerocopy-send --enable-zerocopy-send-client --disable-recv-pipe" \
      basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP, no zcopy, GGA DMA, posix VMA socket impl
function test_snap_5_mix() {
    RW=randrw \
      NVME_PERF_EXTRA_OPTS="$NVME_PERF_EXTRA_OPTS -M 50" \
      SNAP_ENV_OPTS="$SNAP_ENV_OPTS LD_PRELOAD=$LIBVMA NVME_SNAP_RX_ZCOPY=0 SNAP_DMA_Q_MODE=1" \
      SOCK_IMPL=posix \
      SOCK_EXTRA_OPTS="--enable-zerocopy-send --enable-zerocopy-send-client --disable-recv-pipe" \
      basic_test_nvme_snap
}

# Test with spdk_nvme_perf via custom SNAP without zcopy and GGA DMA
function test_snap_6() {
    SNAP_ENV_OPTS="$SNAP_ENV_OPTS SPDK_VMA_PATH=$LIBVMA NVME_SNAP_RX_ZCOPY=0 SNAP_DMA_Q_MODE=2" \
		 SOCK_IMPL=vma \
		 SOCK_EXTRA_OPTS="--disable-zerocopy-recv --disable-zerocopy-send --disable-zerocopy-send-client" \
		 basic_test_nvme_snap
}

if [ -n "$1" ]; then
    tests="$@"
else
    tests="test1 \
	   test2 \
	   test3 \
	   test4 \
	   test5 \
	   test6 \
	   test7 \
	   test8 \
	   test9 \
	   test10 \
	   test11 \
	   test12 \
	   test13 \
	   test14"
fi

rm -rf rpc.log rpc_tgt.log perf.log tgt.log snap.log report.log
echo "| Test | Perf CPU | TGT CPU | IO size | QD | IOPS | BW | Lat |" >> report.log
echo "Running tests: $tests"
for t in $tests; do
    TEST="$t"
    echo "===== Start $t ====="
    $t | tee test.log
    echo "===== End $t ====="
    echo ""
done

cat report.log
