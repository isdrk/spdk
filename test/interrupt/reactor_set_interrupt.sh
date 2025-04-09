#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2021 Intel Corporation
#  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#
testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../..)
source $rootdir/test/common/autotest_common.sh
source $testdir/interrupt_common.sh

export PYTHONPATH=$PYTHONPATH:$rootdir/examples/interrupt_tgt

function reactor_set_intr_mode() {
	local spdk_pid=$1
	local without_thd=$2

	thd0_ids=($(reactor_get_thread_ids $r0_mask))
	thd2_ids=($(reactor_get_thread_ids $r2_mask))

	# Number of thd0_ids shouldn't be zero
	if [[ ${#thd0_ids[*]} -eq 0 ]]; then
		echo "spdk_thread is expected in reactor 0."
		return 1
	else
		echo "spdk_thread ids are ${thd0_ids[*]} on reactor0."
	fi

	$rpc_py --plugin interrupt_plugin pause_pollers

	# CPU utilization of reactor 0~2 should be idle
	for i in {0..2}; do
		reactor_is_idle $spdk_pid $i
	done

	if [ "$without_thd"x != x ]; then
		# Schedule all spdk_threads to reactor 1
		for i in "${thd0_ids[@]}"; do
			$rpc_py thread_set_cpumask -i $i -m $r1_mask
		done
		for i in "${thd2_ids[@]}"; do
			$rpc_py thread_set_cpumask -i $i -m $r1_mask
		done
	fi
	# Set reactor 0 and 2 to be poll mode
	$rpc_py --plugin interrupt_plugin reactor_set_interrupt_mode 0 -d
	$rpc_py --plugin interrupt_plugin reactor_set_interrupt_mode 2 -d
	# CPU utilization of reactor 0 and 2 should be busy
	for i in 0 2; do
		reactor_is_busy $spdk_pid $i
	done

	# Set reactor 2 back to intr mode
	$rpc_py --plugin interrupt_plugin reactor_set_interrupt_mode 2
	if [ "$without_thd"x != x ]; then
		# Schedule spdk_threads in thd2_ids back to reactor 2
		for i in "${thd2_ids[@]}"; do
			$rpc_py thread_set_cpumask -i $i -m $r2_mask
		done
	fi
	# CPU utilization of reactor 2 should be idle
	reactor_is_idle $spdk_pid 2

	# Set reactor 0 back to intr mode
	$rpc_py --plugin interrupt_plugin reactor_set_interrupt_mode 0
	if [ "$without_thd"x != x ]; then
		# Schedule spdk_threads in thd2_ids back to reactor 0
		for i in "${thd0_ids[@]}"; do
			$rpc_py thread_set_cpumask -i $i -m $r0_mask
		done
	fi
	# CPU utilization of reactor 0 should be idle
	reactor_is_idle $spdk_pid 0

	return 0
}

function pollers_are_active() {
	pollers_stats=$($rpc_py thread_get_pollers)
	active_count_1=$(echo "$pollers_stats" | jq -r '.threads | map(select(.name != "app_thread")) | map([.active_pollers[]?.run_count] | add // 0) | add ')
	timed_count_1=$(echo "$pollers_stats" | jq -r '.threads | map(select(.name != "app_thread")) | map([.timed_pollers[]?.run_count] | add // 0) | add ')
	sleep 1
	pollers_stats=$($rpc_py thread_get_pollers)
	active_count_2=$(echo "$pollers_stats" | jq -r '.threads | map(select(.name != "app_thread")) | map([.active_pollers[]?.run_count] | add // 0) | add ')
	timed_count_2=$(echo "$pollers_stats" | jq -r '.threads | map(select(.name != "app_thread")) | map([.timed_pollers[]?.run_count] | add // 0) | add ')
	if [[ $active_count_2 -gt $active_count_1 && $timed_count_2 -gt $timed_count_1 ]]; then
		echo 1
	else
		echo 0
	fi
}

function thread_pause_resume_pollers() {
	local spdk_pid=$1

	$rpc_py --plugin interrupt_plugin pause_pollers
	[[ $(pollers_are_active) == 0 ]]
	$rpc_py --plugin interrupt_plugin resume_pollers
	sleep 1
	[[ $(pollers_are_active) == 1 ]]
	$rpc_py --plugin interrupt_plugin pause_pollers
	sleep 1
	[[ $(pollers_are_active) == 0 ]]

	# Set reactor to poll mode while pollers are paused
	for i in {0..2}; do
		$rpc_py --plugin interrupt_plugin reactor_set_interrupt_mode $i -d
	done

	[[ $(pollers_are_active) == 0 ]]
	$rpc_py --plugin interrupt_plugin resume_pollers
	sleep 1
	[[ $(pollers_are_active) == 1 ]]
	$rpc_py --plugin interrupt_plugin pause_pollers
	sleep 1

	# Set reactor to interrupt mode while pollers are paused
	for i in {0..2}; do
		$rpc_py --plugin interrupt_plugin reactor_set_interrupt_mode $i
	done

	[[ $(pollers_are_active) == 0 ]]
	$rpc_py --plugin interrupt_plugin resume_pollers
	sleep 1
	[[ $(pollers_are_active) == 1 ]]

	# Set reactor to interrupt mode while pollers are running
	for i in {0..2}; do
		$rpc_py --plugin interrupt_plugin reactor_set_interrupt_mode $i -d
	done

	[[ $(pollers_are_active) == 1 ]]

	return 0
}

function reactor_set_mode_without_threads() {
	reactor_set_intr_mode $1 "without_thd"
	return 0
}

function reactor_set_mode_with_threads() {
	reactor_set_intr_mode $1
	return 0
}

# Set reactors with intr_tgt without spdk_thread
start_intr_tgt
setup_bdev_mem
setup_bdev_aio

reactor_set_mode_without_threads $intr_tgt_pid

trap - SIGINT SIGTERM EXIT
killprocess $intr_tgt_pid
cleanup

# Set reactors with intr_tgt with spdk_thread
start_intr_tgt
setup_bdev_mem
setup_bdev_aio

reactor_set_mode_with_threads $intr_tgt_pid

trap - SIGINT SIGTERM EXIT
killprocess $intr_tgt_pid
cleanup

# Pause/resume pollers during interrupt mode
start_intr_tgt

thread_pause_resume_pollers $intr_tgt_pid

trap - SIGINT SIGTERM EXIT
killprocess $intr_tgt_pid
cleanup
