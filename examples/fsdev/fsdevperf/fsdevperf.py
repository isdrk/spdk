#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

import argparse
import os
import sys

sys.path.append(os.path.dirname(__file__) + '/../../../python')
from spdk.rpc.client import print_dict  # noqa
from spdk.rpc.client import JSONRPCException  # noqa
from spdk.rpc.client import JSONRPCClient  # noqa


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', dest='server_addr',
                        help='RPC socket path', default='/var/tmp/spdk.sock')
    parser.add_argument('-t', dest='timeout',
                        help='Timeout to wait for a response',
                        default=60.0, type=float)
    subs = parser.add_subparsers(help='methods')

    def perform_tests(client, args):
        print_dict(client.call('perform_tests'))

    p = subs.add_parser('perform_tests')
    p.set_defaults(method=perform_tests)

    args = parser.parse_args(args)

    client = JSONRPCClient(addr=args.server_addr, timeout=args.timeout)
    args.method(client, args)


if __name__ == '__main__':
    main(sys.argv[1:])
