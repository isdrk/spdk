#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2020 Intel Corporation.
#  All rights reserved.

bdevperf=$rootdir/build/examples/bdevperf

function create_job() {
	local job_section=$1
	local rw=$2
	local filename=$3
	local bs=${4:-1024}
	local rwmixread=${5:-70}
	local iodepth=${6:-256}
	local cpumask=${7:-0xff}
	local rate_iops=${8:-}
	local rate_mbps=${9:-}

	if [[ $job_section == "global" ]]; then
		cat <<- EOF
			[global]
			filename=${filename}
		EOF
	fi
	job="[${job_section}]"
	cat <<- EOF
		${job}
		bs=${bs}
	EOF
	if [[ -n $filename ]]; then
		echo "filename=${filename}"
	fi
	# Only output rwmixread if mode is randrw (mixed read/write)
	if [[ $rw == "randrw" ]]; then
		echo "rwmixread=${rwmixread}"
	fi
	if [[ -n $rw ]]; then
		echo "rw=${rw}"
	fi
	cat <<- EOF
		iodepth=${iodepth}
		cpumask=${cpumask}
	EOF
	if [[ -n $rate_iops ]]; then
		echo "rate_iops=${rate_iops}"
	fi
	if [[ -n $rate_mbps ]]; then
		echo "rate_mbps=${rate_mbps}"
	fi
}

function get_num_jobs() {
	echo "$1" | grep -oE "Using job config with [0-9]+ jobs" | grep -oE "[0-9]+"
}

function cleanup() {
	rm -f $testdir/test.conf
}
