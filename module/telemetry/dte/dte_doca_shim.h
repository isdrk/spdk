/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/*
 * DOCA does not permit direct (link-time) dependencies from third-party
 * software. To comply with this restriction, the telemetry DTE module
 * implements a weak/optional dependency: the DOCA shared libraries are
 * loaded at runtime with dlopen(3) and every required symbol is resolved
 * with dlsym(3).  The wrappers that forward calls to those symbols live in
 * dte_doca_shim.c.
 *
 * dte_doca_shim_init() must be called before any DOCA function is used.
 * dte_doca_shim_fini() releases the library handles when they are no longer
 * needed.
 *
 * Forwarding functions should use the "shim_doca_XXX" naming convention,
 * where "doca_XXX" matches the DOCA API name. We need the "shim_" prefix
 * to ensure the symbol here does not collide with the same symbol from
 * DOCA.
 */

#ifndef SPDK_DTE_DOCA_SHIM_H_
#define SPDK_DTE_DOCA_SHIM_H_

#include <doca_error.h>

int dte_doca_shim_init(void);
void dte_doca_shim_fini(void);

const char *shim_doca_error_get_name(doca_error_t error);

#endif /* SPDK_DTE_DOCA_SHIM_H_ */
