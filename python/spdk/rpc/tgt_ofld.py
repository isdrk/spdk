# SPDX-FileCopyrightText: Copyright (c) <year> NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

from .cmd_parser import *


def tgt_ofld_event_handler_list(client, type):
    """List of OFFLOAD event handlers.

    Args:
        type: Event handler type (comp, tx, sqb, cqb, beq, all)

    Returns:
        An array of event handlers.
    """
    params = {'type': type}

    params['type'] = type
    return client.call('tgt_ofld_event_handler_list', params)


def tgt_ofld_event_handler_counter(client, type=None, name=None):
    """Get counters of event handlers.

    Args:
        type: Event handler type (comp, tx, sqb, cqb, beq, all)
        name: Event handler name

    Returns:
        Counters of event handlers.
    """
    params = {}

    if type:
        params['type'] = type
    if name:
        params['name'] = name

    return client.call('tgt_ofld_event_handler_counter', params)


def tgt_ofld_event_handler_counter_reset(client, type=None, name=None):
    """Reset the counters of the specified event handler(s)

    Args:
        type: Event handler type (comp, tx, sqb, cqb, beq, all)
        name: Event handler name

    Returns:
        True or false
    """
    params = {}

    if type:
        params['type'] = type
    if name:
        params['name'] = name

    return client.call('tgt_ofld_event_handler_counter_reset', params)


def tgt_ofld_connect_qp_list(client, group):
    """List of the connected QPs

    Args:
        group: Completion group EU index [0..max]. Default is all groups (-1)

    Returns:
        An array of connected QPs.
    """
    params = {'group': group}

    return client.call('tgt_ofld_connect_qp_list', params)


def tgt_ofld_connect_qp_count(client, group):
    """Total number of the connected QPs

    Args:
        group: Completion group EU index [0..max]. Default is all groups (-1)

    Returns:
        Number of connected QPs.
    """
    params = {'group': group}

    return client.call('tgt_ofld_connect_qp_count', params)
