/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   All rights reserved.
 */

#ifndef SPDK_VBDEV_PASSTHRU_H
#define SPDK_VBDEV_PASSTHRU_H

#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/bdev_module.h"

struct passthru_bdev_opts {
	char *base_bdev_name;
	char *name;
	struct spdk_uuid uuid;
	bool hide_metadata;
};

/**
 * Create new pass through bdev.
 *
 * \param opts Options to create new pass through bdev.
 * \return 0 on success, other on failure.
 */
int bdev_passthru_create_disk(const struct passthru_bdev_opts *opts);

/**
 * Delete passthru bdev.
 *
 * \param bdev_name Name of the pass through bdev.
 * \param cb_fn Function to call after deletion.
 * \param cb_arg Argument to pass to cb_fn.
 */
void bdev_passthru_delete_disk(const char *bdev_name, spdk_bdev_unregister_cb cb_fn,
			       void *cb_arg);

#endif /* SPDK_VBDEV_PASSTHRU_H */
