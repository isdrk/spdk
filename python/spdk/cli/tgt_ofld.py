#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

import sys
import spdk.rpc as rpc  # noqa
from spdk.rpc.client import print_dict, print_json, print_array  # noqa


def add_parser(subparsers):

    def tgt_ofld_event_handler_list(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_event_handler_list(args.client,
                                                            type=args.type))

    p = subparsers.add_parser('tgt_ofld_event_handler_list', help='List of OFFLOAD event handlers')
    p.add_argument('--type', help='Event handler type', type=str, required=False,
                   choices=['comp', 'tx', 'beq'])
    p.set_defaults(func=tgt_ofld_event_handler_list)

    def tgt_ofld_event_handler_counter(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_event_handler_counter(args.client,
                                                               type=args.type,
                                                               name=args.name))

    p = subparsers.add_parser('tgt_ofld_event_handler_counter', help='Get counters of event handlers')
    p.add_argument('--type', help='Event handler type', type=str, required=False,
                   choices=['comp', 'tx', 'beq'])
    p.add_argument('--name', help='Event handler name', type=str, required=False)
    p.set_defaults(func=tgt_ofld_event_handler_counter)

    def tgt_ofld_event_handler_counter_reset(args):
        rpc.tgt_ofld.tgt_ofld_event_handler_counter_reset(args.client,
                                                          type=args.type,
                                                          name=args.name)

    p = subparsers.add_parser('tgt_ofld_event_handler_counter_reset',
                              help='Reset the counters of the specified event handler(s)')
    p.add_argument('--type', help='Event handler type', type=str, required=False,
                   choices=['comp', 'tx', 'beq'])
    p.add_argument('--name', help='Event handler name', type=str, required=False)
    p.set_defaults(func=tgt_ofld_event_handler_counter_reset)

    def tgt_ofld_connect_qp_list(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_connect_qp_list(args.client,
                                                         group=args.group))

    p = subparsers.add_parser('tgt_ofld_connect_qp_list', help='List of the connected QPs')
    p.add_argument('--group', help='Completion group EU index [0..max]. Default is all groups.',
                   type=int, required=False)
    p.set_defaults(func=tgt_ofld_connect_qp_list)

    def tgt_ofld_connect_qp_count(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_connect_qp_count(args.client,
                                                          group=args.group))

    p = subparsers.add_parser('tgt_ofld_connect_qp_count', help='Total number of the connected QPs')
    p.add_argument('--group', help='Completion group EU index [0..max]. Default is all groups.',
                   type=int, required=False)
    p.set_defaults(func=tgt_ofld_connect_qp_count)

    def tgt_ofld_get_backend_ctrl_stat(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_get_backend_ctrl_stat(args.client,
                                                               name=args.name))

    p = subparsers.add_parser('tgt_ofld_get_backend_ctrl_stat',
                              help='Display statistics of all the offload backend controllers or specified conroller.')
    p.add_argument('-b', '--name', help='Name of the offload backend controller. Example: Nvme0', required=False)
    p.set_defaults(func=tgt_ofld_get_backend_ctrl_stat)

    def tgt_ofld_get_bdev_stat(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_get_bdev_stat(args.client,
                                                       name=args.name))

    p = subparsers.add_parser('tgt_ofld_get_bdev_stat',
                              help='Display statistics of all the offload bdevs or specified bdev.')
    p.add_argument('-b', '--name', help='Name of the offload bdev. Example: Nvme0n1', required=False)
    p.set_defaults(func=tgt_ofld_get_bdev_stat)

    def tgt_ofld_get_bdev_queue_mapping(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_get_bdev_queue_mapping(args.client,
                                                                name=args.name))

    p = subparsers.add_parser('tgt_ofld_get_bdev_queue_mapping',
                              help="""Display a mapping of the backend queue to an event handler for
    all the offload bdevs or specified bdev.""")
    p.add_argument('-b', '--name', help='Name of the offload bdev. Example: Nvme0n1', required=False)
    p.set_defaults(func=tgt_ofld_get_bdev_queue_mapping)

    def tgt_ofld_get_log(args):
        print_dict(rpc.tgt_ofld.tgt_ofld_get_log(args.client,
                                                 subnqn=args.subnqn,
                                                 log_type=args.log_type,
                                                 num_entries=args.num_entries))

    p = subparsers.add_parser('tgt_ofld_get_log', help='Get nvme logs')
    p.add_argument('-s', '--subnqn', help='Subsystem NQN to filter. If not specified, show logs for all subsystems', required=False)
    p.add_argument('-t', '--log_type', type=str, choices=['cve', 'pce'],
                   help='Log type to filter: cve=NVMeoF capsule validation error, '
                        'pce=NVMe PCI command completion error. Default is cve.',
                   required=False)
    p.add_argument('-n', '--num_entries', type=int,
                   help='Maximum number of log entries per log type per subsystem. If not specified, show all entries',
                   required=False)
    p.set_defaults(func=tgt_ofld_get_log)
