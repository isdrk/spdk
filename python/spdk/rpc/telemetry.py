#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.

import json


def telemetry_stop(client):
    """Stop telemetry.

    Args:
        NONE
    """
    return client.call('telemetry_stop')


def telemetry_start(client, interval_ms: int = None):
    """Start telemetry.

    Args:
        interval_ms: telemetry interval in milliseconds
    """
    params = {
    }

    if interval_ms is not None:
        params['interval_ms'] = interval_ms

    return client.call('telemetry_start', params)


def telemetry_get_info(client):
    """Get telemetry info.

    Args:
        NONE
    """
    return client.call('telemetry_get_info')


def telemetry_get_types(client, name: str = None):
    """Get telemetry types info.

    Args:
        name: specific telemetry type name to get info for
    """
    params = {
    }

    if name is not None:
        params['name'] = name

    return client.call('telemetry_get_types', params)


def telemetry_enable_type(client, name: str):
    """Enable telemetry type.

    Args:
        name: Telemetry type name to enable
    """
    params = {
        'name': name
    }
    return client.call('telemetry_enable_type', params)


def telemetry_disable_type(client, name: str):
    """Disable telemetry type.

    Args:
        name: Telemetry type name to disable
    """
    params = {
        'name': name
    }
    return client.call('telemetry_disable_type', params)


def telemetry_csv_create(client, dst_dir: str):
    """Create telemetry CSV exporter.

    Args:
        dst_dir: path on the system directory to be used to store the CSV files
    """

    params = {
        'dst_dir': dst_dir
    }

    return client.call('telemetry_csv_create', params)


def telemetry_csv_delete(client):
    """Delete telemetry CSV exporter.
    """

    return client.call('telemetry_csv_delete')
