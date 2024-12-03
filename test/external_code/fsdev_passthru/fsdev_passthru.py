#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.

from spdk.rpc.client import print_json


def fsdev_passthru_ext_create(args):
    params = {
        'base_fsdev_name': args.base_fsdev_name,
        'name': args.name,
    }
    print_json(args.client.call('fsdev_passthru_ext_create', params))


def fsdev_passthru_ext_delete(args):
    params = {'name': args.name}
    args.client.call('fsdev_passthru_ext_delete', params)


def spdk_rpc_plugin_initialize(subparsers):
    p = subparsers.add_parser('fsdev_passthru_ext_create', help='Add a pass through fsdev on existing fsdev')
    p.add_argument('-b', '--base-fsdev-name', help="Name of the existing fsdev", required=True)
    p.add_argument('-p', '--name', help="Name of the pass through fsdev", required=True)
    p.set_defaults(func=fsdev_passthru_ext_create)

    p = subparsers.add_parser('fsdev_passthru_ext_delete', help='Delete a pass through fsdev')
    p.add_argument('name', help='pass through fsdev name')
    p.set_defaults(func=fsdev_passthru_ext_delete)
