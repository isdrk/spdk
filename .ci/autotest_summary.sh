#!/bin/bash -xe
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

set -e

testdir=$(readlink -f "$(dirname "$0")")
rootdir=$(readlink -f "${testdir}/..")
outputdir=$(readlink -f "${rootdir}/autotest_summary")

mkdir -p "${outputdir}"

ls -la "${rootdir}"/*.tar.gz 2>/dev/null || echo "No tar.gz artifacts found"

for f in "${rootdir}"/*.tar.gz; do
	dir_name="${f##*/}"; dir_name="${dir_name%_artifacts.tar.gz}"
	mkdir -p "${outputdir}/${dir_name}"
	tar xzf "$f" -C "${outputdir}/${dir_name}"
done

python3 "${rootdir}/autorun_post.py" -d "${outputdir}" -r "${rootdir}" --skip_confirm
