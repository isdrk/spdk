#!/bin/sh -eux
# SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

export VAULT_ROLE_CREDS="${DPA_SIGN_USER}:${DPA_SIGN_PASS}"

APP_PATH=$1
SIGN_TOOL="/usr/bin/bf3_dpa_sign.sh"

[ ! -f "${SIGN_TOOL}" ] && { echo "[ERROR]: ${SIGN_TOOL} doesn't exist!"; exit 1; }

sed -i 's|docker run --rm -t|podman run --pid=host --network=host --uts=host --rm -t|' "${SIGN_TOOL}"

# run bf3_dpa_sign.sh to sign it
bf3_dpa_sign.sh -f $APP_PATH --platform ARM --prod -d 'Signing NVMF TARGET OFFLOAD APP' -o $APP_PATH
chmod +x $APP_PATH
