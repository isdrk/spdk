#!/bin/bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.

ci_dir=$(readlink -f "$(dirname "${0}")")
rootdir=$(readlink -f "${ci_dir}/..")

[[ -z "$COVERITY_PATH" ]] && echo "COVERITY_PATH is not set" && exit 1

export PATH=$COVERITY_PATH:$PATH
export CC=gcc-9
ret=0

systemctl start ypbind
systemctl start autofs

cd "$rootdir" || exit 1
./configure --with-rdma=mlx5_dv --disable-unit-tests
# Run Coverity scan
cov-build --dir cov_build make -j8
cov-analyze --jobs auto --security --concurrency --dir cov_build
cov-format-errors --dir cov_build --html-output cov_build/html
ret=$(cov-format-errors --dir cov_build |& awk '/Processing [0-9]+ errors?/ { print $2 }')
exit "$ret"
