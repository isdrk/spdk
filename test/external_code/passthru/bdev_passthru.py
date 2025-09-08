#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.

from spdk.rpc.client import print_json


def construct_ext_passthru_bdev(args):
    params = {
        'base_bdev_name': args.base_bdev_name,
        'name': args.name,
    }
    print_json(args.client.call('construct_ext_passthru_bdev', params))


def delete_ext_passthru_bdev(args):
    params = {'name': args.name}
    args.client.call('delete_ext_passthru_bdev', params)


def spdk_rpc_plugin_initialize(subparsers):
    p = subparsers.add_parser('construct_ext_passthru_bdev', help='Add a pass through bdev on existing bdev')
    p.add_argument('-b', '--base-bdev-name', help="Name of the existing bdev", required=True)
    p.add_argument('-p', '--name', help="Name of the pass through bdev", required=True)
    p.set_defaults(func=construct_ext_passthru_bdev)

    p = subparsers.add_parser('delete_ext_passthru_bdev', help='Delete a pass through bdev')
    p.add_argument('name', help='pass through bdev name')
    p.set_defaults(func=delete_ext_passthru_bdev)
