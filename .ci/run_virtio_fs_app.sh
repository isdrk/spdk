#!/bin/bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

test_virtio_fs_app(){
	if [[ -n "$VIRTIO_FS_CI_WEBREPO_URL" ]]; then
		REF_NAME=$(echo "$CI_COMMIT_REF_NAME" | tr '/' '_')
		wget "${VIRTIO_FS_CI_WEBREPO_URL}/ci-${REF_NAME}.json" || true
		if [[ -f "ci-${REF_NAME}.json" ]]; then
			VIRTIO_FS_TARGET_REF=$(jq -r .spdk.app_ref "ci-${REF_NAME}.json")
			echo "ci-${REF_NAME}.json found! Redefined VIRTIO_FS_TARGET_REF=${VIRTIO_FS_TARGET_REF}"
		else
			echo "ci-${REF_NAME}.json not found! Using VIRTIO_FS_TARGET_REF=${VIRTIO_FS_TARGET_REF}"
		fi
	fi

	curl -s --header "PRIVATE-TOKEN: ${VIRTIO_FS_TARGET_API_TOKEN}" --request POST \
	--form token="${VIRTIO_FS_TARGET_TRIGGER_TOKEN}" --form ref="${VIRTIO_FS_TARGET_REF}" \
	--form variables[SPDK_REPO_URL]="${CI_REPOSITORY_URL}" --form variables[SPDK_SHA]="${CI_COMMIT_SHA}" \
	--form variables[SPDK_PIPELINE_ID]="${CI_PIPELINE_ID}" --form variables[SPDK_PIPELINE_URL]="${CI_PIPELINE_URL}" \
	--form variables[SPDK_JOB_ID]="${CI_JOB_ID}" --form variables[SPDK_JOB_URL]="${CI_JOB_URL}" \
	"${VIRTIO_FS_TARGET_API_V4_URL}/projects/${VIRTIO_FS_TARGET_PROJECT_ID}/trigger/pipeline" > ./trigger.json

	VIRTIO_FS_PIPELINE_ID=$(jq -r .id ./trigger.json)
	VIRTIO_FS_PIPELINE_URL=$(jq -r .web_url ./trigger.json)
	echo "Virtio-fs-target app pipeline ${VIRTIO_FS_PIPELINE_ID} triggered. Pipeline URL: ${VIRTIO_FS_PIPELINE_URL}"
	echo "Waiting for the pipeline to finish..."

	while true; do
		sleep 10
		curl -s --header "PRIVATE-TOKEN: ${VIRTIO_FS_TARGET_API_TOKEN}" "${VIRTIO_FS_TARGET_API_V4_URL}/projects/${VIRTIO_FS_TARGET_PROJECT_ID}/pipelines/${VIRTIO_FS_PIPELINE_ID}" > ./pipeline.json
		PIPELINE_STATUS=$(jq -r .status ./pipeline.json)
		case ${PIPELINE_STATUS} in
			created | waiting_for_resource | preparing | pending | running)
				echo "Pipeline ${VIRTIO_FS_PIPELINE_ID} current status - ${PIPELINE_STATUS}"
				;;
			*)
				echo "Pipeline ${VIRTIO_FS_PIPELINE_ID} finished with status - ${PIPELINE_STATUS}"
				break
				;;
		esac
	done

	PIPELINE_STATUS=$(jq -r .status ./pipeline.json)
	if [[ "$PIPELINE_STATUS" != "success" ]]; then
		echo "Pipeline ${VIRTIO_FS_PIPELINE_ID} failed with status - ${PIPELINE_STATUS}"
		exit 1
	fi
}

test_virtio_fs_app
