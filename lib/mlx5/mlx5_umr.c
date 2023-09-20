/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "infiniband/mlx5dv.h"
#include "infiniband/verbs.h"
#include "mlx5_ifc.h"
#include "spdk/log.h"
#include "spdk/util.h"
#include "spdk/likely.h"

#include "spdk_internal/rdma_utils.h"
#include "spdk_internal/mlx5.h"
#include "mlx5_priv.h"

static inline void
_set_umr_ctrl_seg_mtt(struct mlx5_wqe_umr_ctrl_seg *ctrl, uint32_t klms_octowords, uint64_t mkey_mask)
{
	ctrl->flags |= MLX5_WQE_UMR_CTRL_FLAG_INLINE;
	ctrl->klm_octowords = htobe16(klms_octowords);
	/*
	 * Going to modify two properties of KLM mkey:
	 *  1. 'free' field: change this mkey from in free to in use
	 *  2. 'len' field: to include the total bytes in iovec
	 **/
	mkey_mask |= MLX5_WQE_UMR_CTRL_MKEY_MASK_FREE | MLX5_WQE_UMR_CTRL_MKEY_MASK_LEN;

	ctrl->mkey_mask |= htobe64(mkey_mask);
}

static inline void
set_umr_ctrl_seg_mtt(struct mlx5_wqe_umr_ctrl_seg *ctrl, uint32_t klms_octowords)
{
	_set_umr_ctrl_seg_mtt(ctrl, klms_octowords, 0);
}

static inline void
set_umr_ctrl_seg_mtt_sig(struct mlx5_wqe_umr_ctrl_seg *ctrl, uint32_t klms_octowords)
{
	_set_umr_ctrl_seg_mtt(ctrl, klms_octowords, MLX5_WQE_UMR_CTRL_MKEY_MASK_SIG_ERR);
}

static inline void
set_umr_ctrl_seg_bsf_size(struct mlx5_wqe_umr_ctrl_seg *ctrl, int bsf_size)
{
	/* Place for BSF entries in 16B units (inline or pointers).
	 BSF list should be aligned to 64B. SW can add PAD to the list
	 of BSFs for this.
	 16 LSB bits of translation_offset in 16B units is used to write
	 klms/mtts at some offset from the start of the klm/mtt list
	 describing the memory region. This enables changing only
	 some of the klms/mtts of a region. translation_offset and size
	 should be aligned to 64B */
	ctrl->bsf_octowords = htobe16(SPDK_ALIGN_CEIL(SPDK_CEIL_DIV(bsf_size, 16), 4));
}

static inline void
set_umr_mkey_seg_mtt(struct mlx5_wqe_mkey_context_seg *mkey,
		     struct spdk_mlx5_umr_attr *umr_attr)
{
	mkey->len = htobe64(umr_attr->umr_len);
}

static void
mlx5_set_umr_mkey_seg(struct mlx5_wqe_mkey_context_seg *mkey,
		      struct spdk_mlx5_umr_attr *umr_attr)
{
	memset(mkey, 0, 64);
	set_umr_mkey_seg_mtt(mkey, umr_attr);
}

static void
set_umr_mkey_seg_sig(struct mlx5_wqe_mkey_context_seg *mkey,
		     struct spdk_mlx5_umr_sig_attr *sig_attr)
{
	mkey->flags_pd = htobe32((sig_attr->sigerr_count & 1) << 26);
}

static inline void
set_umr_inline_klm_seg(union mlx5_wqe_umr_inline_seg *klm, struct mlx5_wqe_data_seg *sge)
{
	klm->klm.byte_count = htobe32(sge->byte_count);
	klm->klm.mkey = htobe32(sge->lkey);
	klm->klm.address = htobe64(sge->addr);
}

static void *
mlx5_build_inline_mtt(struct spdk_mlx5_hw_qp *qp,
		      uint32_t *to_end,
		      union mlx5_wqe_umr_inline_seg *dst_klm,
		      struct spdk_mlx5_umr_attr *umr_attr)
{
	struct mlx5_wqe_data_seg *src_klm = umr_attr->klm;
	int num_wqebbs = umr_attr->klm_count / 4;
	int tail = umr_attr->klm_count & 0x3;
	int i;

	for (i = 0; i < num_wqebbs; i++) {
		set_umr_inline_klm_seg(&dst_klm[0], src_klm++);
		set_umr_inline_klm_seg(&dst_klm[1], src_klm++);
		set_umr_inline_klm_seg(&dst_klm[2], src_klm++);
		set_umr_inline_klm_seg(&dst_klm[3], src_klm++);
		/* sizeof(*dst_klm) * 4 == MLX5_SEND_WQE_BB */
		dst_klm = mlx5_qp_get_next_wqbb(qp, to_end, dst_klm);
	}

	if (!tail)
		return dst_klm;

	for (i = 0; i < tail; i++)
		set_umr_inline_klm_seg(&dst_klm[i], src_klm++);

	/* Fill PAD entries to make whole mtt aligned to 64B(MLX5_SEND_WQE_BB) */
	memset(&dst_klm[i], 0,
	       MLX5_SEND_WQE_BB - sizeof(union mlx5_wqe_umr_inline_seg) * tail);

	return mlx5_qp_get_next_wqbb(qp, to_end, dst_klm);
}

static inline void
_set_umr_crypto_bsf_seg(struct mlx5_crypto_bsf_seg *bsf, struct spdk_mlx5_umr_crypto_attr *attr,
			uint32_t raw_data_size, bool tweak_inc_64, uint8_t bsf_size)
{
	uint64_t *iv = (void *)bsf->xts_initial_tweak;

	memset(bsf, 0, sizeof(*bsf));
	switch (attr->tweak_mode) {
	case SPDK_MLX5_CRYPTO_KEY_TWEAK_MODE_UPPER_LBA_LE:
		iv[0] = 0;
		iv[1] = htole64(attr->xts_iv);
		break;
	case SPDK_MLX5_CRYPTO_KEY_TWEAK_MODE_UPPER_LBA_BE:
		iv[0] = htobe64(attr->xts_iv);
		iv[1] = 0;
		break;
	case SPDK_MLX5_CRYPTO_KEY_TWEAK_MODE_SIMPLE_LBA_LE:
		iv[0] = htole64(attr->xts_iv);
		iv[1] = tweak_inc_64 ? UINT64_MAX : 0;
		break;
	case SPDK_MLX5_CRYPTO_KEY_TWEAK_MODE_SIMPLE_LBA_BE:
		iv[0] = tweak_inc_64 ? UINT64_MAX : 0;
		iv[1] = htobe64(attr->xts_iv);
		break;
	default:
		assert(false && "unsupported tweak mode");
	}

	bsf->size_type = (bsf_size << 6) | MLX5_CRYPTO_BSF_P_TYPE_CRYPTO;
	bsf->enc_order = attr->enc_order;
	bsf->raw_data_size = htobe32(raw_data_size);
	bsf->crypto_block_size_pointer = attr->bs_selector;
	bsf->dek_pointer = htobe32(attr->dek_obj_id);
	*((uint64_t *)bsf->keytag) = attr->keytag;
}

static inline void
set_umr_crypto_bsf_seg(struct mlx5_crypto_bsf_seg *bsf, struct spdk_mlx5_umr_crypto_attr *attr,
		       uint32_t raw_data_size, bool tweak_inc_64)
{
	_set_umr_crypto_bsf_seg(bsf, attr, raw_data_size, tweak_inc_64, MLX5_CRYPTO_BSF_SIZE_64B);
}

static inline void
set_umr_crypto_bsf_seg_with_sig(struct mlx5_crypto_bsf_seg *bsf, struct spdk_mlx5_umr_crypto_attr *attr,
			        uint32_t raw_data_size, bool tweak_inc_64)
{
	_set_umr_crypto_bsf_seg(bsf, attr, raw_data_size, tweak_inc_64, MLX5_CRYPTO_BSF_SIZE_WITH_SIG);
}

static inline uint8_t
get_crc32c_tfs(uint32_t seed)
{
	assert(seed == 0 || seed == 0xffffffff);
	return MLX5_SIG_BSF_TFS_CRC32C | !seed;
}

static inline void
_set_umr_sig_bsf_seg(struct mlx5_sig_bsf_seg *bsf,
		     struct spdk_mlx5_umr_sig_attr *attr,
		     uint8_t bsf_size)
{
	uint32_t tfs_psv;
	uint32_t init_gen;

	memset(bsf, 0, sizeof(*bsf));
	bsf->basic.bsf_size_sbs = (bsf_size << 6);
	bsf->basic.raw_data_size = htobe32(attr->raw_data_size);
	bsf->basic.check_byte_mask = 0xff;

	tfs_psv = get_crc32c_tfs(attr->seed);
	tfs_psv = tfs_psv << MLX5_SIG_BSF_TFS_SHIFT;
	tfs_psv |= attr->psv_index & 0xffffff;

	if (attr->domain == SPDK_MLX5_UMR_SIG_DOMAIN_WIRE) {
		bsf->ext.w_tfs_psv = htobe32(tfs_psv);
		init_gen = attr->init ? MLX5_SIG_BSF_EXT_W_T_INIT : 0;
		if (attr->check_gen) {
			init_gen |= MLX5_SIG_BSF_EXT_W_T_CHECK_GEN;
		}
		bsf->ext.t_init_gen_pro_size = htobe32(init_gen);
	} else {
		bsf->ext.m_tfs_psv = htobe32(tfs_psv);
		init_gen = attr->init ? MLX5_SIG_BSF_EXT_M_T_INIT : 0;
		if (attr->check_gen) {
			init_gen |= MLX5_SIG_BSF_EXT_M_T_CHECK_GEN;
		}
		bsf->ext.t_init_gen_pro_size = htobe32(init_gen);
	}
}

static inline void
set_umr_sig_bsf_seg(struct mlx5_sig_bsf_seg *bsf,
		    struct spdk_mlx5_umr_sig_attr *attr)
{
	_set_umr_sig_bsf_seg(bsf, attr, MLX5_SIG_BSF_SIZE_32B);
}

static inline void
set_umr_sig_bsf_seg_with_crypto(struct mlx5_sig_bsf_seg *bsf,
				struct spdk_mlx5_umr_sig_attr *attr)
{
	_set_umr_sig_bsf_seg(bsf, attr, MLX5_SIG_BSF_SIZE_WITH_CRYPTO);
}

static inline void
mlx5_umr_configure_full_crypto(struct spdk_mlx5_qp *dv_qp, struct spdk_mlx5_umr_attr *umr_attr,
			       struct spdk_mlx5_umr_crypto_attr *crypto_attr, uint64_t wr_id,
			       uint32_t flags, uint32_t wqe_size, uint32_t umr_wqe_n_bb,
			       uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	struct mlx5_crypto_bsf_seg *bsf;
	uint8_t fm_ce_se;
	uint32_t pi;
	uint32_t i;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt(umr_ctrl, mtt_size);
	set_umr_ctrl_seg_bsf_size(umr_ctrl, sizeof(struct mlx5_crypto_bsf_seg));

	/* build mkey context segment */
	mkey = (struct mlx5_wqe_mkey_context_seg *)(umr_ctrl + 1);
	memset(mkey, 0, sizeof (*mkey));
	set_umr_mkey_seg_mtt(mkey, umr_attr);

	klm = (union mlx5_wqe_umr_inline_seg *)(mkey + 1);
	for (i = 0; i < umr_attr->klm_count; i++) {
		set_umr_inline_klm_seg(klm, &umr_attr->klm[i]);
		/* sizeof(*klm) * 4 == MLX5_SEND_WQE_BB */
		klm = klm + 1;
	}
	/* fill PAD if existing */
	/* PAD entries is to make whole mtt aligned to 64B(MLX5_SEND_WQE_BB),
	 * So it will not happen warp around during fill PAD entries. */
	for (; i < mtt_size; i++) {
		memset(klm, 0, sizeof(*klm));
		klm = klm + 1;
	}

	bsf = (struct mlx5_crypto_bsf_seg *)klm;
	set_umr_crypto_bsf_seg(bsf, crypto_attr, umr_attr->umr_len, dv_qp->aes_xts_inc_64);

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

static inline void
mlx5_umr_configure_full_sig(struct spdk_mlx5_qp *dv_qp, struct spdk_mlx5_umr_attr *umr_attr,
			    struct spdk_mlx5_umr_sig_attr *sig_attr, uint64_t wr_id,
			    uint32_t flags, uint32_t wqe_size, uint32_t umr_wqe_n_bb,
			    uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	struct mlx5_sig_bsf_seg *bsf;
	uint8_t fm_ce_se;
	uint32_t pi;
	uint32_t i;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt_sig(umr_ctrl, mtt_size);
	set_umr_ctrl_seg_bsf_size(umr_ctrl, sizeof(struct mlx5_sig_bsf_seg));

	/* build mkey context segment */
	mkey = (struct mlx5_wqe_mkey_context_seg *)(umr_ctrl + 1);
	memset(mkey, 0, sizeof (*mkey));
	set_umr_mkey_seg_mtt(mkey, umr_attr);
	set_umr_mkey_seg_sig(mkey, sig_attr);

	klm = (union mlx5_wqe_umr_inline_seg *)(mkey + 1);
	for (i = 0; i < umr_attr->klm_count; i++) {
		set_umr_inline_klm_seg(klm, &umr_attr->klm[i]);
		/* sizeof(*klm) * 4 == MLX5_SEND_WQE_BB */
		klm = klm + 1;
	}
	/* fill PAD if existing */
	/* PAD entries is to make whole mtt aligned to 64B(MLX5_SEND_WQE_BB),
	 * So it will not happen warp around during fill PAD entries. */
	for (; i < mtt_size; i++) {
		memset(klm, 0, sizeof(*klm));
		klm = klm + 1;
	}

	bsf = (struct mlx5_sig_bsf_seg *)klm;
	set_umr_sig_bsf_seg(bsf, sig_attr);

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

static inline void
mlx5_umr_configure_full_sig_crypto(struct spdk_mlx5_qp *dv_qp, struct spdk_mlx5_umr_attr *umr_attr,
				   struct spdk_mlx5_umr_sig_attr *sig_attr,
				   struct spdk_mlx5_umr_crypto_attr *crypto_attr, uint64_t wr_id, uint32_t flags,
				   uint32_t wqe_size, uint32_t umr_wqe_n_bb, uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	struct mlx5_sig_bsf_seg *sig_bsf;
	struct mlx5_crypto_bsf_seg *crypto_bsf;
	uint8_t fm_ce_se;
	uint32_t pi;
	uint32_t i;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt_sig(umr_ctrl, mtt_size);
	set_umr_ctrl_seg_bsf_size(umr_ctrl, sizeof(*sig_bsf) + sizeof(*crypto_bsf));

	/* build mkey context segment */
	mkey = (struct mlx5_wqe_mkey_context_seg *)(umr_ctrl + 1);
	memset(mkey, 0, sizeof (*mkey));
	set_umr_mkey_seg_mtt(mkey, umr_attr);
	set_umr_mkey_seg_sig(mkey, sig_attr);

	klm = (union mlx5_wqe_umr_inline_seg *)(mkey + 1);
	for (i = 0; i < umr_attr->klm_count; i++) {
		set_umr_inline_klm_seg(klm, &umr_attr->klm[i]);
		/* sizeof(*klm) * 4 == MLX5_SEND_WQE_BB */
		klm = klm + 1;
	}
	/* fill PAD if existing */
	/* PAD entries is to make whole mtt aligned to 64B(MLX5_SEND_WQE_BB),
	 * So it will not happen warp around during fill PAD entries. */
	for (; i < mtt_size; i++) {
		memset(klm, 0, sizeof(*klm));
		klm = klm + 1;
	}

	/* build signature BSF */
	sig_bsf = (struct mlx5_sig_bsf_seg *)klm;
	set_umr_sig_bsf_seg_with_crypto(sig_bsf, sig_attr);

	/* build crypto BSF */
	crypto_bsf = (struct mlx5_crypto_bsf_seg *)(sig_bsf + 1);
	/*
	 * raw_data_size is equal for signature and crypto operations because we apply both
	 * operations for the same data.
	 */
	set_umr_crypto_bsf_seg_with_sig(crypto_bsf, crypto_attr, sig_attr->raw_data_size, dv_qp->aes_xts_inc_64);

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

static inline void
mlx5_umr_configure_full(struct spdk_mlx5_qp *dv_qp, struct spdk_mlx5_umr_attr *umr_attr,
			uint64_t wr_id, uint32_t flags, uint32_t wqe_size, uint32_t umr_wqe_n_bb,
			uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	uint8_t fm_ce_se;
	uint32_t pi;
	uint32_t i;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);

	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt(umr_ctrl, mtt_size);

	/* build mkey context segment */
	mkey = (struct mlx5_wqe_mkey_context_seg *)(umr_ctrl + 1);
	mlx5_set_umr_mkey_seg(mkey, umr_attr);

	klm = (union mlx5_wqe_umr_inline_seg *)(mkey + 1);
	for (i = 0; i < umr_attr->klm_count; i++) {
		set_umr_inline_klm_seg(klm, &umr_attr->klm[i]);
		/* sizeof(*klm) * 4 == MLX5_SEND_WQE_BB */
		klm = klm + 1;
	}
	/* fill PAD if existing */
	/* PAD entries is to make whole mtt aligned to 64B(MLX5_SEND_WQE_BB),
	 * So it will not happen warp around during fill PAD entries. */
	for (; i < mtt_size; i++) {
		memset(klm, 0, sizeof(*klm));
		klm = klm + 1;
	}

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

static inline void
mlx5_umr_configure_with_wrap_around_crypto(struct spdk_mlx5_qp *dv_qp, struct spdk_mlx5_umr_attr *umr_attr,
					   struct spdk_mlx5_umr_crypto_attr *crypto_attr, uint64_t wr_id,
					   uint32_t flags, uint32_t wqe_size, uint32_t umr_wqe_n_bb, uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	struct mlx5_crypto_bsf_seg *bsf;
	uint8_t fm_ce_se;
	uint32_t pi, to_end;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;

	/*
	 * sizeof(gen_ctrl) + sizeof(umr_ctrl) == MLX5_SEND_WQE_BB,
	 * so do not need to worry about wqe buffer wrap around.
	 *
	 * build genenal ctrl segment
	 */
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt(umr_ctrl, mtt_size);
	set_umr_ctrl_seg_bsf_size(umr_ctrl, sizeof(struct mlx5_crypto_bsf_seg));

	/* build mkey context segment */
	mkey = mlx5_qp_get_next_wqbb(hw, &to_end, ctrl);
	mlx5_set_umr_mkey_seg(mkey, umr_attr);

	klm = mlx5_qp_get_next_wqbb(hw, &to_end, mkey);
	bsf = mlx5_build_inline_mtt(hw, &to_end, klm, umr_attr);

	set_umr_crypto_bsf_seg(bsf, crypto_attr, umr_attr->umr_len, dv_qp->aes_xts_inc_64);

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

static inline void
mlx5_umr_configure_with_wrap_around_sig(struct spdk_mlx5_qp *dv_qp,
					struct spdk_mlx5_umr_attr *umr_attr,
					struct spdk_mlx5_umr_sig_attr *sig_attr, uint64_t wr_id,
					uint32_t flags, uint32_t wqe_size, uint32_t umr_wqe_n_bb, uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	struct mlx5_sig_bsf_seg *bsf;
	uint8_t fm_ce_se;
	uint32_t pi, to_end;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;

	/*
	 * sizeof(gen_ctrl) + sizeof(umr_ctrl) == MLX5_SEND_WQE_BB,
	 * so do not need to worry about wqe buffer wrap around.
	 *
	 * build genenal ctrl segment
	 */
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt_sig(umr_ctrl, mtt_size);
	set_umr_ctrl_seg_bsf_size(umr_ctrl, sizeof(struct mlx5_sig_bsf_seg));

	/* build mkey context segment */
	mkey = mlx5_qp_get_next_wqbb(hw, &to_end, ctrl);
	mlx5_set_umr_mkey_seg(mkey, umr_attr);
	set_umr_mkey_seg_sig(mkey, sig_attr);

	klm = mlx5_qp_get_next_wqbb(hw, &to_end, mkey);
	bsf = mlx5_build_inline_mtt(hw, &to_end, klm, umr_attr);

	set_umr_sig_bsf_seg(bsf, sig_attr);

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

static inline void
mlx5_umr_configure_with_wrap_around_sig_crypto(struct spdk_mlx5_qp *dv_qp, struct spdk_mlx5_umr_attr *umr_attr,
					       struct spdk_mlx5_umr_sig_attr *sig_attr,
					       struct spdk_mlx5_umr_crypto_attr *crypto_attr,
					       uint64_t wr_id, uint32_t flags, uint32_t wqe_size,
					       uint32_t umr_wqe_n_bb, uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	struct mlx5_sig_bsf_seg *sig_bsf;
	struct mlx5_crypto_bsf_seg *crypto_bsf;
	uint8_t fm_ce_se;
	uint32_t pi, to_end;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;

	/*
	 * sizeof(gen_ctrl) + sizeof(umr_ctrl) == MLX5_SEND_WQE_BB,
	 * so do not need to worry about wqe buffer wrap around.
	 *
	 * build genenal ctrl segment
	 */
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt_sig(umr_ctrl, mtt_size);
	set_umr_ctrl_seg_bsf_size(umr_ctrl, sizeof(*sig_bsf) + sizeof(*crypto_bsf));

	/* build mkey context segment */
	mkey = mlx5_qp_get_next_wqbb(hw, &to_end, ctrl);
	mlx5_set_umr_mkey_seg(mkey, umr_attr);
	set_umr_mkey_seg_sig(mkey, sig_attr);

	/* build KLM */
	klm = mlx5_qp_get_next_wqbb(hw, &to_end, mkey);
	sig_bsf = mlx5_build_inline_mtt(hw, &to_end, klm, umr_attr);

	/* build signature BSF */
	set_umr_sig_bsf_seg_with_crypto(sig_bsf, sig_attr);

	/* build crypto BSF */
	crypto_bsf = mlx5_qp_get_next_wqbb(hw, &to_end, sig_bsf);
	/*
	 * raw_data_size is equal for signature and crypto operations because we apply both
	 * operations for the same data.
	 */
	set_umr_crypto_bsf_seg_with_sig(crypto_bsf, crypto_attr, sig_attr->raw_data_size, dv_qp->aes_xts_inc_64);

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

static inline void
mlx5_umr_configure_with_wrap_around(struct spdk_mlx5_qp *dv_qp, struct spdk_mlx5_umr_attr *umr_attr,
				    uint64_t wr_id, uint32_t flags, uint32_t wqe_size, uint32_t umr_wqe_n_bb,
				    uint32_t mtt_size)
{
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_umr_ctrl_seg *umr_ctrl;
	struct mlx5_wqe_mkey_context_seg *mkey;
	union mlx5_wqe_umr_inline_seg *klm;
	uint8_t fm_ce_se;
	uint32_t pi, to_end;

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;
	/*
	 * sizeof(gen_ctrl) + sizeof(umr_ctrl) == MLX5_SEND_WQE_BB,
	 * so do not need to worry about wqe buffer wrap around.
	 *
	 * build genenal ctrl segment
	 */
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_UMR, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0,
			  htobe32(umr_attr->dv_mkey));

	/* build umr ctrl segment */
	umr_ctrl = (struct mlx5_wqe_umr_ctrl_seg *)(gen_ctrl + 1);
	memset(umr_ctrl, 0, sizeof(*umr_ctrl));
	set_umr_ctrl_seg_mtt(umr_ctrl, mtt_size);

	/* build mkey context segment */
	mkey = mlx5_qp_get_next_wqbb(hw, &to_end, ctrl);
	mlx5_set_umr_mkey_seg(mkey, umr_attr);

	klm = mlx5_qp_get_next_wqbb(hw, &to_end, mkey);
	mlx5_build_inline_mtt(hw, &to_end, klm, umr_attr);

	mlx5_qp_wqe_submit(dv_qp, ctrl, umr_wqe_n_bb, pi);

	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, umr_wqe_n_bb);
	assert(dv_qp->tx_available >= umr_wqe_n_bb);
	dv_qp->tx_available -= umr_wqe_n_bb;
}

int
spdk_mlx5_umr_configure_crypto(struct spdk_mlx5_dma_qp *dma_qp, struct spdk_mlx5_umr_attr *umr_attr,
			       struct spdk_mlx5_umr_crypto_attr *crypto_attr, uint64_t wr_id, uint32_t flags)
{
	struct spdk_mlx5_qp *dv_qp = &dma_qp->qp;
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	uint32_t pi, to_end, umr_wqe_n_bb;
	uint32_t wqe_size, mtt_size;
	uint32_t inline_klm_size;

	if (!spdk_unlikely(umr_attr->klm_count)) {
		return -EINVAL;
	}

	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;

	/*
	 * UMR WQE LAYOUT:
	 * -----------------------------------------------------------------------
	 * | gen_ctrl | umr_ctrl | mkey_ctx | inline klm mtt | inline crypto bsf |
	 * -----------------------------------------------------------------------
	 *   16bytes    48bytes    64bytes   sg_count*16 bytes      64 bytes
	 *
	 * Note: size of inline klm mtt should be aligned to 64 bytes.
	 */
	wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) + sizeof(struct mlx5_wqe_umr_ctrl_seg) + sizeof(struct mlx5_wqe_mkey_context_seg);
	mtt_size = SPDK_ALIGN_CEIL(umr_attr->klm_count, 4);
	inline_klm_size = mtt_size * sizeof(union mlx5_wqe_umr_inline_seg);
	wqe_size += inline_klm_size;
	wqe_size += sizeof(struct mlx5_crypto_bsf_seg);

	umr_wqe_n_bb = SPDK_CEIL_DIV(wqe_size, MLX5_SEND_WQE_BB);
	if (spdk_unlikely(umr_wqe_n_bb > dv_qp->tx_available)) {
		return -ENOMEM;
	}
	if (spdk_unlikely(umr_attr->klm_count > dv_qp->max_sge)) {
		return -E2BIG;
	}

	if (spdk_unlikely(to_end < wqe_size)) {
		mlx5_umr_configure_with_wrap_around_crypto(dv_qp, umr_attr, crypto_attr, wr_id, flags, wqe_size, umr_wqe_n_bb,
							   mtt_size);
	} else {
		mlx5_umr_configure_full_crypto(dv_qp, umr_attr, crypto_attr, wr_id, flags, wqe_size, umr_wqe_n_bb, mtt_size);
	}

	return 0;
}

int
spdk_mlx5_umr_configure_sig(struct spdk_mlx5_dma_qp *dma_qp, struct spdk_mlx5_umr_attr *umr_attr,
			    struct spdk_mlx5_umr_sig_attr *sig_attr, uint64_t wr_id, uint32_t flags)
{
	struct spdk_mlx5_qp *dv_qp = &dma_qp->qp;
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	uint32_t pi, to_end, umr_wqe_n_bb;
	uint32_t wqe_size, mtt_size;
	uint32_t inline_klm_size;

	if (!spdk_unlikely(umr_attr->klm_count)) {
		return -EINVAL;
	}

	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;

	/*
	 * UMR WQE LAYOUT:
	 * -----------------------------------------------------------------------
	 * | gen_ctrl | umr_ctrl | mkey_ctx | inline klm mtt | inline sig bsf |
	 * -----------------------------------------------------------------------
	 *   16bytes    48bytes    64bytes   sg_count*16 bytes      64 bytes
	 *
	 * Note: size of inline klm mtt should be aligned to 64 bytes.
	 */
	wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) + sizeof(struct mlx5_wqe_umr_ctrl_seg) +
		   sizeof(struct mlx5_wqe_mkey_context_seg);
	mtt_size = SPDK_ALIGN_CEIL(umr_attr->klm_count, 4);
	inline_klm_size = mtt_size * sizeof(union mlx5_wqe_umr_inline_seg);
	wqe_size += inline_klm_size;
	wqe_size += sizeof(struct mlx5_sig_bsf_seg);

	umr_wqe_n_bb = SPDK_CEIL_DIV(wqe_size, MLX5_SEND_WQE_BB);
	if (spdk_unlikely(umr_wqe_n_bb > dv_qp->tx_available)) {
		return -ENOMEM;
	}
	if (spdk_unlikely(umr_attr->klm_count > dv_qp->max_sge)) {
		return -E2BIG;
	}

	if (spdk_unlikely(to_end < wqe_size)) {
		mlx5_umr_configure_with_wrap_around_sig(dv_qp, umr_attr, sig_attr, wr_id, flags, wqe_size,
							umr_wqe_n_bb, mtt_size);
	} else {
		mlx5_umr_configure_full_sig(dv_qp, umr_attr, sig_attr, wr_id, flags, wqe_size, umr_wqe_n_bb,
					    mtt_size);
	}

	return 0;
}

int
spdk_mlx5_umr_configure_sig_crypto(struct spdk_mlx5_dma_qp *dma_qp, struct spdk_mlx5_umr_attr *umr_attr,
				   struct spdk_mlx5_umr_sig_attr *sig_attr,
				   struct spdk_mlx5_umr_crypto_attr *crypto_attr,
				   uint64_t wr_id, uint32_t flags)
{
	struct spdk_mlx5_qp *dv_qp = &dma_qp->qp;
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	uint32_t pi, to_end, umr_wqe_n_bb;
	uint32_t wqe_size, mtt_size;
	uint32_t inline_klm_size;

	if (!spdk_unlikely(umr_attr->klm_count)) {
		return -EINVAL;
	}

	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;

	/*
	 * UMR WQE LAYOUT:
	 * ----------------------------------------------------------------------------------------
	 * | gen_ctrl | umr_ctrl | mkey_ctx | inline klm mtt | inline sig bsf | inline crypto bsf |
	 * ----------------------------------------------------------------------------------------
	 *   16bytes    48bytes    64bytes   sg_count*16 bytes    64 bytes         64 bytes
	 *
	 * Note: size of inline klm mtt should be aligned to 64 bytes.
	 */
	wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) + sizeof(struct mlx5_wqe_umr_ctrl_seg) + sizeof(struct mlx5_wqe_mkey_context_seg);
	mtt_size = SPDK_ALIGN_CEIL(umr_attr->klm_count, 4);
	inline_klm_size = mtt_size * sizeof(union mlx5_wqe_umr_inline_seg);
	wqe_size += inline_klm_size;
	wqe_size += sizeof(struct mlx5_sig_bsf_seg);
	wqe_size += sizeof(struct mlx5_crypto_bsf_seg);

	umr_wqe_n_bb = SPDK_CEIL_DIV(wqe_size, MLX5_SEND_WQE_BB);
	if (spdk_unlikely(umr_wqe_n_bb > dv_qp->tx_available)) {
		return -ENOMEM;
	}
	if (spdk_unlikely(umr_attr->klm_count > dv_qp->max_sge)) {
		return -E2BIG;
	}

	if (spdk_unlikely(to_end < wqe_size)) {
		mlx5_umr_configure_with_wrap_around_sig_crypto(dv_qp, umr_attr, sig_attr, crypto_attr, wr_id, flags,
							       wqe_size, umr_wqe_n_bb, mtt_size);
	} else {
		mlx5_umr_configure_full_sig_crypto(dv_qp, umr_attr, sig_attr, crypto_attr, wr_id, flags, wqe_size,
						   umr_wqe_n_bb, mtt_size);
	}

	return 0;
}

int
spdk_mlx5_umr_configure(struct spdk_mlx5_dma_qp *dma_qp, struct spdk_mlx5_umr_attr *umr_attr,
			uint64_t wr_id, uint32_t flags)
{
	struct spdk_mlx5_qp *dv_qp = &dma_qp->qp;
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	uint32_t pi, to_end, umr_wqe_n_bb;
	uint32_t wqe_size, mtt_size;
	uint32_t inline_klm_size;

	if (!spdk_unlikely(umr_attr->klm_count)) {
		return -EINVAL;
	}

	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);
	to_end = (hw->sq_wqe_cnt - pi) * MLX5_SEND_WQE_BB;

	/*
	 * UMR WQE LAYOUT:
	 * -----------------------------------------------------------------------
	 * | gen_ctrl | umr_ctrl | mkey_ctx | inline klm mtt | inline crypto bsf |
	 * -----------------------------------------------------------------------
	 *   16bytes    48bytes    64bytes   sg_count*16 bytes      64 bytes
	 *
	 * Note: size of inline klm mtt should be aligned to 64 bytes.
	 */
	wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) + sizeof(struct mlx5_wqe_umr_ctrl_seg) + sizeof(struct mlx5_wqe_mkey_context_seg);
	mtt_size = SPDK_ALIGN_CEIL(umr_attr->klm_count, 4);
	inline_klm_size = mtt_size * sizeof(union mlx5_wqe_umr_inline_seg);
	wqe_size += inline_klm_size;

	umr_wqe_n_bb = SPDK_CEIL_DIV(wqe_size, MLX5_SEND_WQE_BB);
	if (spdk_unlikely(umr_wqe_n_bb > dv_qp->tx_available)) {
		return -ENOMEM;
	}
	if (spdk_unlikely(umr_attr->klm_count > dv_qp->max_sge)) {
		return -E2BIG;
	}

	if (spdk_unlikely(to_end < wqe_size)) {
		mlx5_umr_configure_with_wrap_around(dv_qp, umr_attr, wr_id, flags, wqe_size, umr_wqe_n_bb,
							   mtt_size);
	} else {
		mlx5_umr_configure_full(dv_qp, umr_attr, wr_id, flags, wqe_size, umr_wqe_n_bb, mtt_size);
	}

	return 0;
}

int
spdk_mlx5_set_psv(struct spdk_mlx5_dma_qp *dma_qp, uint32_t psv_index, uint32_t crc_seed, uint64_t wr_id, uint32_t flags)
{
	struct spdk_mlx5_qp *dv_qp = &dma_qp->qp;
	struct spdk_mlx5_hw_qp *hw = &dv_qp->hw;
	uint32_t pi, wqe_size, wqe_n_bb;
	struct mlx5_wqe_ctrl_seg *ctrl;
	struct mlx5_wqe_ctrl_seg *gen_ctrl;
	struct mlx5_wqe_set_psv_seg *psv;
	uint8_t fm_ce_se;
	uint64_t transient_signature = (uint64_t)crc_seed << 32;

	wqe_size = sizeof(struct mlx5_wqe_ctrl_seg) + sizeof(struct mlx5_wqe_set_psv_seg);
	/* The size of SET_PSV WQE is constant and smaller than WQE BB. */
	assert(wqe_size < MLX5_SEND_WQE_BB);
	wqe_n_bb = 1;
	if (spdk_unlikely(wqe_n_bb > dv_qp->tx_available)) {
		return -ENOMEM;
	}

	fm_ce_se = flags | dv_qp->tx_flags;
	fm_ce_se &= dv_qp->tx_revert_flags;

	pi = hw->sq_pi & (hw->sq_wqe_cnt - 1);

	ctrl = (struct mlx5_wqe_ctrl_seg *)mlx5_qp_get_wqe_bb(hw);
	gen_ctrl = ctrl;
	mlx5_set_ctrl_seg(gen_ctrl, hw->sq_pi, MLX5_OPCODE_SET_PSV, 0,
			  hw->qp_num, fm_ce_se,
			  SPDK_CEIL_DIV(wqe_size, 16), 0, 0);

	/* build umr PSV segment */
	psv = (struct mlx5_wqe_set_psv_seg *)(gen_ctrl + 1);
	/* Zeroing the set_psv segment and WQE padding. */
	memset(psv, 0, MLX5_SEND_WQE_BB - sizeof(struct mlx5_wqe_ctrl_seg));
	psv->psv_index = htobe32(psv_index);
	psv->transient_signature = htobe64(transient_signature);

	mlx5_qp_wqe_submit(dv_qp, ctrl, wqe_n_bb, pi);
	mlx5_qp_set_comp(dv_qp, pi, wr_id, fm_ce_se, wqe_n_bb);
	assert(dv_qp->tx_available >= wqe_n_bb);
	dv_qp->tx_available -= wqe_n_bb;

	return 0;
}

int
spdk_mlx5_query_relaxed_ordering_caps(struct ibv_context *context,
				      struct spdk_mlx5_relaxed_ordering_caps *caps)
{
	uint8_t in[DEVX_ST_SZ_BYTES(query_hca_cap_in)] = {};
	uint8_t out[DEVX_ST_SZ_BYTES(query_hca_cap_out)] = {};
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE_CAP_2);
	ret = mlx5dv_devx_general_cmd(context, in, sizeof(in),
				      out, sizeof(out));
	if (ret) {
		return ret;
	}

	caps->relaxed_ordering_write_pci_enabled = DEVX_GET(query_hca_cap_out,
			out, capability.cmd_hca_cap.relaxed_ordering_write_pci_enabled);
	caps->relaxed_ordering_write = DEVX_GET(query_hca_cap_out, out,
						capability.cmd_hca_cap.relaxed_ordering_write);
	caps->relaxed_ordering_read = DEVX_GET(query_hca_cap_out, out,
					       capability.cmd_hca_cap.relaxed_ordering_read);
	caps->relaxed_ordering_write_umr = DEVX_GET(query_hca_cap_out,
					   out, capability.cmd_hca_cap.relaxed_ordering_write_umr);
	caps->relaxed_ordering_read_umr = DEVX_GET(query_hca_cap_out,
					  out, capability.cmd_hca_cap.relaxed_ordering_read_umr);
	return 0;
}

#define SPDK_KLM_MAX_TRANSLATION_ENTRIES_NUM   128

static int
mlx5_get_pd_id(struct ibv_pd *pd, uint32_t *pd_id)
{
	int ret = 0;
	struct mlx5dv_pd pd_info;
	struct mlx5dv_obj obj;

	if (!pd) {
		return -EINVAL;
	}
	obj.pd.in = pd;
	obj.pd.out = &pd_info;
	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_PD);
	if (ret) {
		return ret;
	}
	*pd_id = pd_info.pdn;
	return 0;
}

struct spdk_mlx5_indirect_mkey *
spdk_mlx5_create_indirect_mkey(struct ibv_pd *pd, struct mlx5_devx_mkey_attr *attr)
{
	struct ibv_sge *sg = attr->sg;
	uint32_t sg_count = attr->sg_count;
	int in_size_dw = DEVX_ST_SZ_DW(create_mkey_in) +
			 (sg_count ? SPDK_ALIGN_CEIL(sg_count, 4) : 0) * DEVX_ST_SZ_DW(klm);
	uint32_t in[in_size_dw];
	uint32_t out[DEVX_ST_SZ_DW(create_mkey_out)] = {0};
	void *mkc;
	uint32_t translation_size = 0;
	struct spdk_mlx5_indirect_mkey *cmkey;
	struct ibv_context *ctx = pd->context;
	uint32_t pd_id = 0;
	uint32_t i = 0;
	uint8_t *klm;

	cmkey = calloc(1, sizeof(*cmkey));
	if (!cmkey) {
		SPDK_ERRLOG("failed to alloc cross_mkey\n");
		return NULL;
	}

	memset(in, 0, in_size_dw * 4);
	DEVX_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	mkc = DEVX_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	klm = (uint8_t *)DEVX_ADDR_OF(create_mkey_in, in, klm_pas_mtt);

	if (sg_count > 0) {
		translation_size = SPDK_ALIGN_CEIL(sg_count, 4);

		for (i = 0; i < sg_count; i++) {
			DEVX_SET(klm, klm, byte_count, sg[i].length);
			DEVX_SET(klm, klm, mkey, sg[i].lkey);
			DEVX_SET64(klm, klm, address, sg[i].addr);
			klm += DEVX_ST_SZ_BYTES(klm);
		}

		for (; i < translation_size; i++) {
			DEVX_SET(klm, klm, byte_count, 0x0);
			DEVX_SET(klm, klm, mkey, 0x0);
			DEVX_SET64(klm, klm, address, 0x0);
			klm += DEVX_ST_SZ_BYTES(klm);
		}
	}

	DEVX_SET(mkc, mkc, access_mode_1_0, attr->log_entity_size ?
		 MLX5_MKC_ACCESS_MODE_KLMFBS :
		 MLX5_MKC_ACCESS_MODE_KLMS);
	DEVX_SET(mkc, mkc, log_page_size, attr->log_entity_size);

	mlx5_get_pd_id(pd, &pd_id);
	DEVX_SET(create_mkey_in, in, translations_octword_actual_size, sg_count);
	if (sg_count == 0) {
		DEVX_SET(mkc, mkc, free, 0x1);
	}
	DEVX_SET(mkc, mkc, lw, 0x1);
	DEVX_SET(mkc, mkc, lr, 0x1);
	DEVX_SET(mkc, mkc, rw, 0x1);
	DEVX_SET(mkc, mkc, rr, 0x1);
	DEVX_SET(mkc, mkc, umr_en, 1);
	DEVX_SET(mkc, mkc, qpn, 0xffffff);
	DEVX_SET(mkc, mkc, pd, pd_id);
	DEVX_SET(mkc, mkc, translations_octword_size_crossing_target_mkey,
		 SPDK_KLM_MAX_TRANSLATION_ENTRIES_NUM);
	DEVX_SET(mkc, mkc, relaxed_ordering_write,
		 attr->relaxed_ordering_write);
	DEVX_SET(mkc, mkc, relaxed_ordering_read,
		 attr->relaxed_ordering_read);
	DEVX_SET64(mkc, mkc, start_addr, attr->addr);
	DEVX_SET64(mkc, mkc, len, attr->size);
	/* TODO: change mkey_7_0 to increasing counter */
	DEVX_SET(mkc, mkc, mkey_7_0, 0x42);
	if (attr->crypto_en) {
		DEVX_SET(mkc, mkc, crypto_en, 1);
	}
	if (attr->bsf_octowords) {
		DEVX_SET(mkc, mkc, bsf_en, 1);
		DEVX_SET(mkc, mkc, bsf_octword_size, attr->bsf_octowords);
	}

	cmkey->devx_obj = mlx5dv_devx_obj_create(ctx, in, sizeof(in), out,
			  sizeof(out));
	if (!cmkey->devx_obj) {
		SPDK_ERRLOG("mlx5dv_devx_obj_create() failed to mkey, errno:%d\n", errno);
		goto out_err;
	}

	cmkey->mkey = DEVX_GET(create_mkey_out, out, mkey_index) << 8 | 0x42;
	return cmkey;

out_err:
	free(cmkey);
	return NULL;
}

/**
 * spdk_mlx5_destroy_indirect_mkey() - Destroy 'indirect' mkey
 * @mkey: mkey to destroy
 *
 * The function destroys 'indirect' mkey
 *
 * Return:
 * 0 or -errno on error
 */
int
spdk_mlx5_destroy_indirect_mkey(struct spdk_mlx5_indirect_mkey *mkey)
{
	int ret = 0;

	if (mkey->devx_obj) {
		ret = mlx5dv_devx_obj_destroy(mkey->devx_obj);
	}

	free(mkey);

	return ret;
}

static struct mlx5dv_devx_obj *
mlx5_cmd_create_psv(struct ibv_context *context, uint32_t pdn, uint32_t *psv_index)
{
	uint32_t out[DEVX_ST_SZ_DW(create_psv_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(create_psv_in)] = {};
	struct mlx5dv_devx_obj *obj;

	assert(context);
	assert(psv_index);

	DEVX_SET(create_psv_in, in, opcode, MLX5_CMD_OP_CREATE_PSV);
	DEVX_SET(create_psv_in, in, pd, pdn);
	DEVX_SET(create_psv_in, in, num_psv, 1);

	obj = mlx5dv_devx_obj_create(context, in, sizeof(in), out, sizeof(out));
	if (obj) {
		*psv_index = DEVX_GET(create_psv_out, out, psv0_index);
	}

	return obj;
}

struct spdk_mlx5_psv *
spdk_mlx5_create_psv(struct ibv_pd *pd)
{
	uint32_t pdn;
	struct spdk_mlx5_psv *psv;
	int err;

	assert(pd);

	err = mlx5_get_pd_id(pd, &pdn);
	if (err) {
		return NULL;
	}

	psv = calloc(1, sizeof(*psv));
	if (!psv) {
		return NULL;
	}

	psv->devx_obj = mlx5_cmd_create_psv(pd->context, pdn, &psv->index);
	if (!psv->devx_obj) {
		free(psv);
		return NULL;
	}

	return psv;
}

int
spdk_mlx5_destroy_psv(struct spdk_mlx5_psv *psv)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(psv->devx_obj);
	if (!ret) {
		free(psv);
	}

	return ret;
}
