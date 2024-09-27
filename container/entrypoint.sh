#!/bin/bash -e
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
NVMF_TARGET_OFFLOAD_PATH="/opt/nvidia/nvmf_target_offload"
NVMF_TARGET_OFFLOAD_APP="${NVMF_TARGET_OFFLOAD_PATH}/bin/spdk_tgt"
NVMF_TARGET_OFFLOAD_CONF="${NVMF_TARGET_OFFLOAD_CONF:=${NVMF_TARGET_OFFLOAD_PATH}/bin/set_environment_variables.sh}"
SPDK_SOCK="/var/tmp/spdk.sock"

# Stop the app when the container stops
function quit() {
    kill -SIGTERM "${pid}"
    wait "${pid}"
    exit 0
}
trap quit SIGTERM

echo "[$(date +"%Y-%m-%d %H:%M:%S.%N")] Launching service"

# cleanup to allow new process
rm -rf /var/tmp/spdk*

# Load configuration file
source $NVMF_TARGET_OFFLOAD_CONF

NVMF_TARGET_OFFLOAD_APP="${PRE_APP_ARGS} ${NVMF_TARGET_OFFLOAD_APP} ${APP_ARGS} &"

# Start the App
eval $NVMF_TARGET_OFFLOAD_APP

pid="${!}"

TIMEOUT=30  # Total timeout in seconds
RETRIES=60  # Number of retries
start_time=$(date +%s)

while (( $(date +%s) - start_time < TIMEOUT )); do
  for (( attempt=0; attempt<RETRIES; attempt++ )); do
    if spdk_rpc.py spdk_get_version &>/dev/null; then
      break 2
    fi
  done

  sleep 1
done

if (( $(date +%s) - start_time >= TIMEOUT )); then
  echo "[$(date +"%Y-%m-%d %H:%M:%S.%N")] Timeout of $TIMEOUT seconds reached. SPDK_SOCK has not been detected."
fi

set +e
[ -f "$SPDK_RPC_INIT_CONF" ] && [ -S "$SPDK_SOCK" ] && cat $SPDK_RPC_INIT_CONF | spdk_rpc.py
set -e

# Run until the app stops
wait "${pid}"
