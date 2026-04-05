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

    def telemetry_csv_create(args):
        print_json(rpc.telemetry.telemetry_csv_create(args.client, dst_dir=args.dst_dir))

    p = subparsers.add_parser('telemetry_csv_create', help='Create telemetry CSV exporter')
    p.add_argument('--dst-dir', help='Telemetry CSV exporter destination directory', type=str, required=True)
    p.set_defaults(func=telemetry_csv_create)

    def telemetry_csv_delete(args):
        print_json(rpc.telemetry.telemetry_csv_delete(args.client))

    p = subparsers.add_parser('telemetry_csv_delete', help='Delete telemetry CSV exporter')
    p.set_defaults(func=telemetry_csv_delete)

    def telemetry_dte_create_command(args):
        print_json(
            rpc.telemetry.telemetry_dte_create(args.client, data_root=args.data_root, ipc=args.ipc, ipc_sockets_dir=args.ipc_sockets_dir,
                                               ipc_reconnect_time=args.ipc_reconnect_time, ipc_reconnect_tries=args.ipc_reconnect_tries,
                                               ipc_socket_timeout=args.ipc_socket_timeout, file=args.file, file_max_size=args.file_max_size,
                                               file_max_age=args.file_max_age, otlp=args.otlp, otlp_address=args.otlp_address,
                                               otlp_port=args.otlp_port, prometheus=args.prometheus,
                                               prometheus_address=args.prometheus_address, prometheus_port=args.prometheus_port))

    p = subparsers.add_parser('telemetry_dte_create',
                              help='Create DOCA Telemetry Exporter')
    p.add_argument(
        '--data-root', help='Data root directory', type=str, required=False)
    p.add_argument('--ipc', help='Enable IPC Transport',
                   action='store_true', required=False)
    p.add_argument('--ipc-sockets-dir',
                   help='IPC sockets directory', type=str, required=False)
    p.add_argument('--ipc-reconnect-time',
                   help='IPC reconnect time in ms', type=int, required=False)
    p.add_argument('--ipc-reconnect-tries',
                   help='IPC max retries', type=int, required=False, choices=range(1, 255))
    p.add_argument('--ipc-socket-timeout',
                   help='IPC socket timeout in ms', type=int, required=False)
    p.add_argument('--file', help='Enable File Transport',
                   action='store_true', required=False)
    p.add_argument('--file-max-size',
                   help='File max size in bytes', type=int, required=False)
    p.add_argument(
        '--file-max-age', help='File max age in microseconds', type=int, required=False)
    p.add_argument('--otlp', help='Enable OTLP Transport',
                   action='store_true', required=False)
    p.add_argument(
        '--otlp-address', help='OTLP address (required when OTLP is enabled)', type=str, required=False)
    p.add_argument(
        '--otlp-port', help='OTLP port (default: 9502)', type=int, required=False)
    p.add_argument('--prometheus', help='Enable Prometheus Endpoint',
                   action='store_true', required=False)
    p.add_argument(
        '--prometheus-address', help='Prometheus address (default: 0.0.0.0)', type=str, required=False)
    p.add_argument(
        '--prometheus-port', help='Prometheus port (default: 9101)', type=int, required=False)
    p.set_defaults(func=telemetry_dte_create_command)

    def telemetry_dte_delete_command(args):
        print_json(rpc.telemetry.telemetry_dte_delete(args.client))

    p = subparsers.add_parser('telemetry_dte_delete',
                              help='Delete DOCA Telemetry Exporter')
    p.set_defaults(func=telemetry_dte_delete_command)
