# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

def fuse_set_options(client, **kwargs):
    return client.call('fuse_set_options', {k: v for k, v in kwargs.items() if v is not None})


def fuse_mount(client, fsdev, mountpoint, **kwargs):
    return client.call('fuse_mount',
                       {'fsdev': fsdev, 'mountpoint': mountpoint,
                        'options': {k: v for k, v in kwargs.items() if v is not None}})


def fuse_umount(client, mount):
    return client.call('fuse_umount', {'mount': mount})


def fuse_get_mounts(client):
    return client.call('fuse_get_mounts')
