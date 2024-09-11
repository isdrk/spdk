#!/usr/bin/env bash
#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/test/common/autotest_common.sh

allowed_devices=${1:-"mlx5_0"}

function gen_accel_mlx5_crypto_json() {
	crypto_split_blocks=${1:-0}

	jq . <<- JSON
		{
		  "subsystems": [
		    {
		      "subsystem": "accel",
		      "config": [
		        {
		          "method": "mlx5_scan_accel_module",
		          "params": {
		            "allowed_devs": "${allowed_devices}",
		            "split_mb_blocks": ${crypto_split_blocks}
		          }
		        },
		        {
		          "method": "accel_crypto_key_create",
		          "params": {
		            "name": "test_dek",
		            "cipher": "AES_XTS",
		            "key": "00112233445566778899001122334455",
		            "key2": "11223344556677889900112233445500",
		            "tweak_mode": "INCR_512_UPPER_LBA"
		          }
		        }
		      ]
		    }
		  ]
		}
	JSON
}

run_test "accel_mlx5_crypto_split_mb_8_bs_512_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 8) \
	-K test_dek -I 1 -b 512
run_test "accel_mlx5_crypto_split_mb_8_bs_512_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 8) \
	-K test_dek -I 0 -b 512
run_test "accel_mlx5_crypto_split_mb_8_bs_4096_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 8) \
	-K test_dek -I 1 -b 4096
run_test "accel_mlx5_crypto_split_mb_8_bs_4096_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 8) \
	-K test_dek -I 0 -b 4096

run_test "accel_mlx5_crypto_split_mb_12_bs_512_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 12) \
	-K test_dek -I 1 -b 512
run_test "accel_mlx5_crypto_split_mb_12_bs_512_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 12) \
	-K test_dek -I 0 -b 512
run_test "accel_mlx5_crypto_split_mb_12_bs_4096_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 12) \
	-K test_dek -I 1 -b 4096
run_test "accel_mlx5_crypto_split_mb_12_bs_4096_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 12) \
	-K test_dek -I 0 -b 4096

run_test "accel_mlx5_crypto_no_split_bs_512_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 0) \
	-K test_dek -I 1 -b 512
run_test "accel_mlx5_crypto_no_split_bs_512_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 0) \
	-K test_dek -I 0 -b 512
run_test "accel_mlx5_crypto_no_split_bs_4096_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 0) \
	-K test_dek -I 1 -b 4096
run_test "accel_mlx5_crypto_no_split_bs_4096_non_inplace" $SPDK_EXAMPLE_DIR/accel_mlx5_test -t 1 -q 64 -w encrypt -m 0xf -c <(gen_accel_mlx5_crypto_json 0) \
	-K test_dek -I 0 -b 4096
