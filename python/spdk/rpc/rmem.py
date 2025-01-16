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


def rmem_set_config(client, backend_dir: str):
    """Set backend directory for rmem_pool.

    Args:
        backend_dir: directory where rmem_pool stores backend files
    """
    params = {
        'backend_dir': backend_dir,
    }

    return client.call('rmem_set_config', params)
