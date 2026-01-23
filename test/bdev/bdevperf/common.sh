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
}

function get_num_jobs() {
	echo "$1" | grep -oE "Using job config with [0-9]+ jobs" | grep -oE "[0-9]+"
}

function cleanup() {
	rm -f $testdir/test.conf
}
