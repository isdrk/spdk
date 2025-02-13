# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

def fuse_set_options(client, **kwargs):
    return client.call('fuse_set_options', {k: v for k, v in kwargs.items() if v is not None})
