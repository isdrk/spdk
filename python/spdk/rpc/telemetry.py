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


def telemetry_dte_create(client, data_root,
                         ipc, ipc_sockets_dir, ipc_reconnect_time, ipc_reconnect_tries,
                         ipc_socket_timeout, file, file_max_size, file_max_age,
                         otlp, otlp_address, otlp_port, prometheus, prometheus_address, prometheus_port):
    """Create telemetry DOCA exporter.
    """
    params = {}
    if data_root is not None:
        params['data_root'] = data_root
    if ipc is not None:
        params['ipc'] = ipc
    if ipc_sockets_dir is not None:
        params['ipc_sockets_dir'] = ipc_sockets_dir
    if ipc_reconnect_time is not None:
        params['ipc_reconnect_time'] = ipc_reconnect_time
    if ipc_reconnect_tries is not None:
        params['ipc_reconnect_tries'] = ipc_reconnect_tries
    if ipc_socket_timeout is not None:
        params['ipc_socket_timeout'] = ipc_socket_timeout
    if file is not None:
        params['file'] = file
    if file_max_size is not None:
        params['file_max_size'] = file_max_size
    if file_max_age is not None:
        params['file_max_age'] = file_max_age
    if otlp is not None:
        params['otlp'] = otlp
    if otlp_address is not None:
        params['otlp_address'] = otlp_address
    if otlp_port is not None:
        params['otlp_port'] = otlp_port
    if prometheus is not None:
        params['prometheus'] = prometheus
    if prometheus_address is not None:
        params['prometheus_address'] = prometheus_address
    if prometheus_port is not None:
        params['prometheus_port'] = prometheus_port
    return client.call('telemetry_dte_create', params)


def telemetry_dte_delete(client):
    """Delete telemetry DOCA exporter.
    """

    return client.call('telemetry_dte_delete')
