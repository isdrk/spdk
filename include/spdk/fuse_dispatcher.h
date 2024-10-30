/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/** \file
 * Operations on a FUSE fsdev dispatcher
 */

#ifndef SPDK_FUSE_DISPATCHER_H
#define SPDK_FUSE_DISPATCHER_H

#include "spdk/stdinc.h"
#include "spdk/fsdev.h"

#ifdef __cplusplus
extern "C" {
#endif

struct spdk_fuse_dispatcher;

enum spdk_fuse_arch {
	SPDK_FUSE_ARCH_NATIVE,
	SPDK_FUSE_ARCH_X86,
	SPDK_FUSE_ARCH_X86_64,
	SPDK_FUSE_ARCH_ARM,
	SPDK_FUSE_ARCH_ARM64,
	_SPDK_FUSE_ARCH_LAST,
};

/**
 * FUSE fsdev dispatcher submit completion callback.
 *
 * \param cb_arg Callback argument specified upon submit operation.
 * \param error 0 if the operation succeeded, a negative error code otherwise.
 */
typedef void (*spdk_fuse_dispatcher_submit_cpl_cb)(void *cb_arg, int error);

/**
 * Create a FUSE fsdev dispatcher
 *
 * \param desc fsdev descriptor to work with
 *
 * \return FUSE fsdev dispatcher object on success, NULL otherwise.
 */
struct spdk_fuse_dispatcher *spdk_fuse_dispatcher_create(struct spdk_fsdev_desc *desc);

/**
 * Set a FUSE request source's HW architecture.
 *
 * Unless this function is called explicitly, the arch set to SPDK_FUSE_ARCH_NATIVE.
 *
 * \param disp FUSE fsdev dispatcher object.
 * \param fuse_arch FUSE request source's HW architecture
 *
 * \return 0 on success or -EINVAL if the architecture is not supported
 */
int spdk_fuse_dispatcher_set_arch(struct spdk_fuse_dispatcher *disp, enum spdk_fuse_arch fuse_arch);

/**
 * Get the size of the io_ctx buffer.
 *
 * \return The size of struct fuse_io
 */
size_t spdk_fuse_dispatcher_get_io_ctx_size(void);

/**
 * Submit FUSE request
 *
 * \param disp FUSE fsdev dispatcher object.
 * \param ch I/O channel obtained from the \p spdk_fuse_dispatcher_get_io_channel.
 * \param in_iov Input IO vectors array.
 * \param in_iovcnt Size of the input IO vectors array.
 * \param out_iov Output IO vectors array.
 * \param out_iovcnt Size of the output IO vectors array.
 * \param cb Completion callback.
 * \param cb_arg Context to be passed to the completion callback.
 *
 * \return 0 on success. On success, the callback will always
 * be called (even if the request ultimately failed). Return
 * negated errno on failure, in which case the callback will not be called.
 *  -ENOBUFS - the request cannot be submitted due to a lack of the internal IO objects
 *  -EINVAL - the request cannot be submitted as some FUSE request data is incorrect
 */
int spdk_fuse_dispatcher_submit_request(struct spdk_fuse_dispatcher *disp,
					struct spdk_io_channel *ch,
					struct iovec *in_iov, int in_iovcnt,
					struct iovec *out_iov, int out_iovcnt, void *io_ctx,
					spdk_fuse_dispatcher_submit_cpl_cb cb, void *cb_arg);

/**
 * Delete a FUSE fsdev dispatcher
 *
 * \param disp FUSE fsdev dispatcher object.
 */
void spdk_fuse_dispatcher_delete(struct spdk_fuse_dispatcher *disp);

#ifdef __cplusplus
}
#endif

#endif /* SPDK_FUSE_DISPATCHER_H */
