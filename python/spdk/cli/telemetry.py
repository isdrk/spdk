#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.
#

import sys
import spdk.rpc as rpc  # noqa
from spdk.rpc.client import print_dict, print_json, print_array  # noqa


def add_parser(subparsers):

    def telemetry_start(args):
        print_json(rpc.telemetry.telemetry_start(args.client, interval_ms=args.interval_ms))

    p = subparsers.add_parser('telemetry_start', help='Start telemetry')
    p.add_argument('--interval-ms', help='Telemetry interval in milliseconds', type=int, default=5000)
    p.set_defaults(func=telemetry_start)

    def telemetry_stop(args):
        print_json(rpc.telemetry.telemetry_stop(args.client))

    p = subparsers.add_parser('telemetry_stop', help='Stop telemetry')
    p.set_defaults(func=telemetry_stop)

    def telemetry_get_info(args):
        print_json(rpc.telemetry.telemetry_get_info(args.client))

    p = subparsers.add_parser('telemetry_get_info', help='Get telemetry info')
    p.set_defaults(func=telemetry_get_info)

    def telemetry_get_types(args):
        print_json(rpc.telemetry.telemetry_get_types(args.client, name=args.name))

    p = subparsers.add_parser('telemetry_get_types', help='Get telemetry types info')
    p.add_argument('--name', help='specific telemetry type name to get info for', type=str, required=False)
    p.set_defaults(func=telemetry_get_types)

    def telemetry_enable_type(args):
        print_json(rpc.telemetry.telemetry_enable_type(args.client, name=args.name))

    p = subparsers.add_parser('telemetry_enable_type', help='Enable telemetry type')
    p.add_argument('--name', help='Telemetry type name to enable', type=str, required=True)
    p.set_defaults(func=telemetry_enable_type)

    def telemetry_disable_type(args):
        print_json(rpc.telemetry.telemetry_disable_type(args.client, name=args.name))

    p = subparsers.add_parser('telemetry_disable_type', help='Disable telemetry type')
    p.add_argument('--name', help='Telemetry type name to disable', type=str, required=True)
    p.set_defaults(func=telemetry_disable_type)
