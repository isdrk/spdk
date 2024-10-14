#!/bin/bash -eE
#
# SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
#
set -x

# DOCA's internal private repository
export NGC_CLI_ACE=no-ace
export NGC_CLI_FORMAT_TYPE=ascii
export NGC_CLI_ORG=nvstaging
export NGC_CLI_TEAM=doca
export NGC_CLI_API_KEY=${NGC_CLI_API_KEY:-'no-apikey'}

# Download the (latest) YAML files
ngc registry resource download-version "${NGC_CLI_ORG}/${NGC_CLI_TEAM}/doca_container_configs" --format_type json | tee ngc_cli_output.txt
DOWNLOADED_FOLDER=$(cat ngc_cli_output.txt | jq -r '.local_path')
CURRENT_VERSION=$(echo $DOWNLOADED_FOLDER | egrep -o '[0-9]+\.[0-9]+\.[0-9]+')
rm -f ngc_cli_output.txt

# Calculate the new version
IFS='.'
read -a strarr <<< "$CURRENT_VERSION"

VERION_MAJOR="${strarr[0]}"
VERION_MINOR="${strarr[1]}"
VERION_PATCH="${strarr[2]}"

unset IFS

NEW_VERSION=${VERION_MAJOR}.${VERION_MINOR}."$(($VERION_PATCH + 1))"

# Copy the directory so to have a backup to diff against
cp -r ${DOWNLOADED_FOLDER} candidate_ngc_resource

# Update all the YAML files that we are aware of:
# Base Image
cp container/doca_nvmf_target_offload.yaml candidate_ngc_resource/configs/latest/

# Diff and check if there is a need for update
set +e
diff -r $DOWNLOADED_FOLDER candidate_ngc_resource
diff_rc=$?
set -e

if [[ "$diff_rc" != "0" ]]; then
    ngc registry resource upload-version "${NGC_CLI_ORG}/${NGC_CLI_TEAM}/doca_container_configs:${NEW_VERSION}" --source candidate_ngc_resource --format_type json
fi

echo "NGC=${NGC_CLI_ORG}/${NGC_CLI_TEAM}/doca_container_configs:${NEW_VERSION}" >> artifact.properties
rm -rf ${DOWNLOADED_FOLDER}
rm -rf candidate_ngc_resource
