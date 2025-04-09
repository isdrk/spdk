#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2021 Intel Corporation.
#  Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.

from spdk.rpc.client import print_json


def reactor_set_interrupt_mode(args):
    params = {'lcore': args.lcore, 'disable_interrupt': args.disable_interrupt}
    return args.client.call('reactor_set_interrupt_mode', params)


def pause_pollers(args):
    return args.client.call('pause_pollers')


def resume_pollers(args):
    return args.client.call('resume_pollers')


def spdk_rpc_plugin_initialize(subparsers):
    p = subparsers.add_parser('reactor_set_interrupt_mode',
                              help="""Set reactor to interrupt or back to poll mode.""")
    p.add_argument('lcore', type=int, help='lcore of the reactor')
    p.add_argument('-d', '--disable-interrupt', dest='disable_interrupt', action='store_true',
                   help='Set reactor back to poll mode')
    p.set_defaults(func=reactor_set_interrupt_mode)

    p = subparsers.add_parser('pause_pollers',
                              help="""Pause all pollers in interrupt tgt.""")
    p.set_defaults(func=pause_pollers)

    p = subparsers.add_parser('resume_pollers',
                              help="""Resume all pollers in interrupt tgt.""")
    p.set_defaults(func=resume_pollers)
