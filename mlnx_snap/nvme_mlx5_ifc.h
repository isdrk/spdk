/*
* Copyright (C) Mellanox Technologies Ltd, 2001-2018. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef NVME_MLX5_IFC_H
#define NVME_MLX5_IFC_H

#include "mlx5_ifc.h"

enum {
    MLX5_CMD_OPCODE_SEND_QP_NVMF_CC                = 0xb01,
    MLX5_CMD_OPCODE_QUERY_NVMF_CC_RESPONSE         = 0xb02,
    MLX5_CMD_OPCODE_QUERY_EMULATED_FUNCTIONS_INFO  = 0xb03,
};

enum {
	MLX5_QPC_OFFLOAD_TYPE_NVMX         = 0x3,
};

enum {
	MLX5_NVME_SQ_OFFLOAD_TYPE_SQE = 0x0,
	MLX5_NVME_SQ_OFFLOAD_TYPE_DOORBELL_ONLY = 0x1,
	MLX5_NVME_SQ_OFFLOAD_TYPE_NVMF_CC = 0x2,
};

enum {
    MLX5_NVME_SQ_STATE_INIT   = 0x0,
    MLX5_NVME_SQ_STATE_RDY    = 0x1,
    MLX5_NVME_SQ_STATE_ERROR  = 0x2,
};

enum {
    MLX5_NVME_SQ_FIELD_SELECT_QPN   = 1 << 0,
    MLX5_NVME_SQ_FIELD_SELECT_STATE = 1 << 1,
};

enum {
	MLX5_NVME_CQ_OFFLOAD_TYPE_CQE = 0x0,
	MLX5_NVME_CQ_OFFLOAD_TYPE_NVMF_CQE_CC = 0x2
};

struct mlx5_ifc_nvme_namespace_bits {
    uint8_t    modify_field_select[0x40];

    uint8_t    device_emulation_id[0x20];

    uint8_t    src_nsid[0x20];

    uint8_t    dst_nsid[0x20];

    uint8_t    reserved_at_a0[0x8];
    uint8_t    lba_size[0x8];
    uint8_t    metadata_size[0x10];

    uint8_t    nvme_namespace_counter_set_id[0x20];

    uint8_t    reserved_at_e0[0x720];
};


struct mlx5_ifc_nvme_cq_bits {
    uint8_t    modify_field_select[0x40];

    uint8_t    device_emulation_id[0x20];

    uint8_t    reserved_at_60[0x20];

    uint8_t    reserved_at_80[0x4];
    uint8_t    offload_type[0x4];
    uint8_t    reserved_at_88[0x18];

    uint8_t    reserved_at_a0[0x18];
    uint8_t    msix_vector[0x8];

    uint8_t    nvme_base_addr[0x40];

    uint8_t    reserved_at_100[0x8];
    uint8_t    nvme_log_entry_size[0x8];
    uint8_t    nvme_num_of_entries[0x10];

    uint8_t    nvme_doorbell_offset[0x20];

    uint8_t    cq_period_mode[0x1];
    uint8_t    reserved_at_144[0x3];
    uint8_t    cq_period[0xc];
    uint8_t    cq_max_count[0x10];

    uint8_t    reserved_at_160[0x6a0];
};

struct mlx5_ifc_nvme_sq_bits {
    uint8_t    modify_field_select[0x40];

    uint8_t    device_emulation_id[0x20];

    uint8_t    reserved_at_60[0x8];
    uint8_t    pd[0x18];

    uint8_t    network_state[0x4];
    uint8_t    offload_type[0x4];
    uint8_t    qpn[0x18];

    uint8_t    qpn_vhca_id[0x10];
    uint8_t    reserved_at_b0[0x3];
    uint8_t    log_nvme_page_size[0x5];
    uint8_t    msix_vector[0x8];

    uint8_t    nvme_base_addr[0x40];

    uint8_t    max_transaction_size[0x8];
    uint8_t    nvme_log_entry_size[0x8];
    uint8_t    nvme_num_of_entries[0x10];

    uint8_t    nvme_doorbell_offset[0x20];

    uint8_t    reserved_at_140[0x60];

    uint8_t    nvme_cq_id[0x20];

    uint8_t    reserved_at_1c0[0x640];
};

struct mlx5_ifc_query_nvmf_cc_in_bits {
    uint8_t    opcode[0x10];
    uint8_t    uid[0x10];

    uint8_t    vhca_tunnel_id[0x10];
    uint8_t    op_mod[0x10];

    uint8_t    nvme_sq[0x20];

    uint8_t    reserved_at_60[0x20];
};

struct mlx5_ifc_query_nvmf_cc_out_bits {
    uint8_t    status[0x8];
    uint8_t    reserved_at_8[0x18];

    uint8_t    syndrome[0x20];

    uint8_t    reserved_at_40[0x3c];
    uint8_t    cc_response_status[0x4];

    uint8_t    cc_response[0x80];

};

struct mlx5_ifc_send_qp_nvmf_cc_in_bits {
    uint8_t    opcode[0x10];
    uint8_t    uid[0x10];

    uint8_t    reserved_at_20[0x10];
    uint8_t    op_mod[0x10];

    uint8_t    nvme_sq[0x20];

    uint8_t    reserved_at_60[0x20];

    uint8_t    reserved_at_80[0x10];
    uint8_t    ext_data_length[0x10];

    uint8_t    ext_data_umem_id[0x20];

    uint8_t    ext_data_umem_offset[0x40];

    uint8_t    reserved_at_100[0x100];

    uint8_t    nvmf_cc[16][0x20];
};

struct mlx5_ifc_send_qp_nvmf_cc_out_bits {
    uint8_t    status[0x8];
    uint8_t    reserved_at_8[0x18];

    uint8_t    syndrome[0x20];

    uint8_t    reserved_at_40[0x8];
    uint8_t    qpn[0x18];

    uint8_t    reserved_at_60[0x20];
};

struct mlx5_ifc_device_pci_parameters_bits {
    uint8_t    device_id[0x10];
    uint8_t    vendor_id[0x10];

    uint8_t    revision_id[0x08];
    uint8_t    class_code[0x18];

    uint8_t    subsystem_id[0x10];
    uint8_t    subsystem_vendor_id[0x10];

    uint8_t    reserved_at_60[0x10];
    uint8_t    num_msix[0x10];
};

struct mlx5_ifc_nvme_device_emulation_object_bits {
    uint8_t    modify_field_select[0x40];

    uint8_t    reserved_at_40[0x10];
    uint8_t    vhca_id[0x10];

    uint8_t    enabled[0x1];
    uint8_t    reserved_at_61[0x1f];

    uint8_t    counter_set_id[0x20];

    uint8_t    reserved_at_a0[0x60];

    struct mlx5_ifc_device_pci_parameters_bits pci_params;

    uint8_t    register_data[0][0x20];
};

struct mlx5_ifc_nvme_emulation_cap_bits {
    uint8_t    nvme_offload_type_sqe[0x1];
    uint8_t    nvme_offload_type_doorbell_only[0x1];
    uint8_t    nvme_offload_type_command_capsule[0x1];
    uint8_t    log_max_nvme_offload_namespaces[0x5];
    uint8_t    reserved_at_7[0x10];
    uint8_t    total_emulated_pfs[0x8];

    uint8_t    reserved_at_20[0x10];
    uint8_t    registers_size[0x10];

    uint8_t    reserved_at_40[0x13];
    uint8_t    log_max_emulated_sq[0x5];
    uint8_t    reserved_at_58[0x3];
    uint8_t    log_max_emulated_cq[0x5];

    uint8_t    reserved_at_60[0x7a0];
};

struct mlx5_ifc_nvme_query_emulated_functions_info_in_bits {
    uint8_t         opcode[0x10];
    uint8_t         uid[0x10];

    uint8_t         reserved_at_20[0x10];

    uint8_t         op_mod[0x10];
    uint8_t         reserved_at_40[0x40];
};

struct mlx5_ifc_nvme_emulated_pf_info_bits {
    uint8_t         pf_pci_number[0x10];
    uint8_t         pf_vhca_id[0x10];

    uint8_t         num_of_vfs[0x10];
    uint8_t         vfs_base_vhca_id[0x10];
};

struct mlx5_ifc_nvme_query_emulated_functions_info_out_bits {
    uint8_t    status[0x8];
    uint8_t    reserved_at_8[0x18];

    uint8_t    syndrome[0x20];
    uint8_t    reserved_at_46[0x38];

    uint8_t    num_emulated_pfs[0x8];
    struct     mlx5_ifc_nvme_emulated_pf_info_bits emulated_pf_info[0];
};

struct mlx5_ifc_vhca_tunnel_bits {
    uint8_t    modify_field_select[0x40];

    uint8_t    reserved_at_40[0x10];
    uint8_t    vhca_id[0x10];
};

struct mlx5_ifc_vhca_tunnel_cmd_bits {
    uint8_t     reserved_at_0[0x20];
    uint8_t     vhca_tunnel_id[0x10];
    uint8_t     op_mod[0x10];
};

#endif /* NVME_MLX5_IFC_H */
