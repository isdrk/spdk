#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

def rdma_provider_get_opts(client):
    """Get RDMA provider options.

    Returns:
        RDMA provider options
    """

    return client.call('env_dpdk_get_mem_stats')


def rdma_provider_set_opts(client, support_offload_on_qp=None):
    """Set RDMA provider options.

    Args:
        support_offload_on_qp: Enable or disable support of HW offloads on network QP
    """

    params = {}

    if support_offload_on_qp is not None:
        params['support_offload_on_qp'] = support_offload_on_qp

    return client.call('rdma_provider_set_opts', params)
