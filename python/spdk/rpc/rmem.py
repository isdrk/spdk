#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#  All rights reserved.

import json


def rmem_get_config(client):
    """Get the rmem config.

    Args:
        NONE
    """
    return client.call('rmem_get_config')


def rmem_enable(client, backend_dir: str = None):
    """Enable/disable rmem if --backend-dir is specified or disable it otherwise.

    Args:
        backend_dir: directory where rmem_pool stores backend files
    """
    params = {
    }

    if backend_dir is not None:
        params['backend_dir'] = backend_dir

    return client.call('rmem_enable', params)
