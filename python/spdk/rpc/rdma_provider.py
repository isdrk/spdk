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


def rdma_provider_inject_error(client, type, rate_num, rate_denom, wc_status=None):
    """Enable RDMA provider error injection.

    Args:
        type: Error injection type, one of 'cq', 'mkey', 'rq' or 'sq'
        rate_num: Error rate numerator
        rate_denom: Error rate denominator
        wc_status: (optional) ibv_wc_status value to inject, only valid for 'cq' type
    """

    params = {
        'type': type,
        'rate_num': rate_num,
        'rate_denom': rate_denom,
    }

    if wc_status is not None:
        params['wc_status'] = wc_status

    return client.call('rdma_provider_inject_error', params)


def rdma_provider_cancel_error(client, type):
    """Disable RDMA provider error injection.

    Args:
        type: Error injection type, one of 'cq', 'mkey', 'rq' or 'sq'
    """

    return client.call('rdma_provider_cancel_error', {'type': type})
