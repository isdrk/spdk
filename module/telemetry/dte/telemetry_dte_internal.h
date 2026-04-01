
/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */
#ifndef SPDK_DOCA_TELEMETRY_INT_H_
#define SPDK_DOCA_TELEMETRY_INT_H_

#include "spdk/stdinc.h"
#include "spdk/telemetry.h"

struct dte_config {
	char telemetry_data_root[PATH_MAX];
	struct {
		bool enabled;
		char sockets_dir[PATH_MAX];
		uint8_t reconnect_tries;
		uint32_t reconnect_time;
		uint32_t socket_timeout;
	} ipc;
	struct {
		bool enabled;
		uint64_t max_size;
		uint32_t max_age;
	} file;
	struct {
		bool enabled;
		char address[256];
		uint16_t port;
	} otlp;
	struct {
		bool enabled;
		char address[256];
		uint16_t port;
	} prometheus;
};

int dte_create(const struct dte_config *config);
int dte_delete(void);

#endif /* SPDK_DOCA_TELEMETRY_INT_H_ */
