#!/bin/bash -ex
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

if [[ ! "$(hostname)" =~ "spdk-ver-hv01-" ]]; then
	echo "Most probably you are not on the VM host, exiting..."
	exit 1
fi

# Clean up the device before the test
wipefs -a  "/dev/nvme0n1"
