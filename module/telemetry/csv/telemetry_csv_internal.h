/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#ifndef SPDK_TELEMETRY_CSV_INT_H
#define SPDK_TELEMETRY_CSV_INT_H

#include "spdk/stdinc.h"

int telemetry_csv_create(const char *dst_dir);
int telemetry_csv_delete(void);

#endif /* SPDK_TELEMETRY_CSV_INT_H */
