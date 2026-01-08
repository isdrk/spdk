/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

/** \file
 * Telemetry Internal API for RPCs
 */

#ifndef SPDK_TELEMETRY_INTERNAL_H_
#define SPDK_TELEMETRY_INTERNAL_H_

#include "spdk/stdinc.h"
#include "spdk/json.h"

void telemetry_dump_types_json(struct spdk_json_write_ctx *w, const char *name);
int telemetry_type_enable(const char *name, bool enable);

#endif /* SPDK_TELEMETRY_INTERNAL_H_ */
