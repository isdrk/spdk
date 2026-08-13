#!/bin/bash -ex
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

branch=$(git name-rev --name-only HEAD | awk -F/ '{print $NF}')

if [ -z "$VER" ]; then
	export VER=$(echo $branch | grep -o '[0-9]\+\(\.[0-9]\+\)*')
fi

REV=${BUILD_NUMBER:-1}

git_tag="v$VER-${REV}"

# SCM checkout is from gitlab-master; also push the release tag to GitHub mirror.
GITLAB_REMOTE="${GITLAB_REMOTE:-ssh://git@gitlab-master.nvidia.com:12051/spdk_team/spdk.git}"
GITHUB_REMOTE="${GITHUB_REMOTE:-git@github.com:Mellanox/spdk.git}"

git tag $git_tag
git push "$GITLAB_REMOTE" $git_tag
git push "$GITHUB_REMOTE" $git_tag
