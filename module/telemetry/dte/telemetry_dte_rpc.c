/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/telemetry.h"
#include "telemetry_dte_internal.h"

struct rpc_telemetry_dte_start_opts {
	char *data_root;
	char *ipc_sockets_dir;
	char *otlp_address;
	char *prometheus_address;
	struct dte_config config;
};

static const struct spdk_json_object_decoder rpc_telemetry_dte_start_opts_decoders[] = {
	{"data_root", offsetof(struct rpc_telemetry_dte_start_opts, data_root), spdk_json_decode_string, true},
	{"ipc", offsetof(struct rpc_telemetry_dte_start_opts, config.ipc.enabled), spdk_json_decode_bool, true},
	{"ipc_sockets_dir", offsetof(struct rpc_telemetry_dte_start_opts, ipc_sockets_dir), spdk_json_decode_string, true},
	{"ipc_reconnect_time", offsetof(struct rpc_telemetry_dte_start_opts, config.ipc.reconnect_time), spdk_json_decode_uint32, true},
	{"ipc_reconnect_tries", offsetof(struct rpc_telemetry_dte_start_opts, config.ipc.reconnect_tries), spdk_json_decode_uint8, true},
	{"ipc_socket_timeout", offsetof(struct rpc_telemetry_dte_start_opts, config.ipc.socket_timeout), spdk_json_decode_uint32, true},
	{"file", offsetof(struct rpc_telemetry_dte_start_opts, config.file.enabled), spdk_json_decode_bool, true},
	{"file_max_size", offsetof(struct rpc_telemetry_dte_start_opts, config.file.max_size), spdk_json_decode_uint64, true},
	{"file_max_age", offsetof(struct rpc_telemetry_dte_start_opts, config.file.max_age), spdk_json_decode_uint32, true},
	{"otlp", offsetof(struct rpc_telemetry_dte_start_opts, config.otlp.enabled), spdk_json_decode_bool, true},
	{"otlp_address", offsetof(struct rpc_telemetry_dte_start_opts, otlp_address), spdk_json_decode_string, true},
	{"otlp_port", offsetof(struct rpc_telemetry_dte_start_opts, config.otlp.port), spdk_json_decode_uint16, true},
	{"prometheus", offsetof(struct rpc_telemetry_dte_start_opts, config.prometheus.enabled), spdk_json_decode_bool, true},
	{"prometheus_address", offsetof(struct rpc_telemetry_dte_start_opts, prometheus_address), spdk_json_decode_string, true},
	{"prometheus_port", offsetof(struct rpc_telemetry_dte_start_opts, config.prometheus.port), spdk_json_decode_uint16, true},
};

static void
rpc_telemetry_dte_create(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	struct rpc_telemetry_dte_start_opts opts = {0};
	int res;

	if (spdk_json_decode_object(params, rpc_telemetry_dte_start_opts_decoders,
				    SPDK_COUNTOF(rpc_telemetry_dte_start_opts_decoders),
				    &opts)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		return;
	}

	if (opts.data_root) {
		size_t len = strlen(opts.data_root);
		if (len >= sizeof(opts.config.telemetry_data_root)) {
			SPDK_ERRLOG("data_root is too long: %s\n", opts.data_root);
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
							 "telemetry_data_root too long");
			goto do_free;
		}
		memcpy(opts.config.telemetry_data_root, opts.data_root, len + 1);
	}

	if (opts.ipc_sockets_dir) {
		size_t len = strlen(opts.ipc_sockets_dir);
		if (len >= sizeof(opts.config.ipc.sockets_dir)) {
			SPDK_ERRLOG("ipc_sockets_dir is too long: %s\n", opts.ipc_sockets_dir);
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
							 "ipc_sockets_dir too long");
			goto do_free;
		}
		memcpy(opts.config.ipc.sockets_dir, opts.ipc_sockets_dir, len + 1);
	}

	if (opts.otlp_address) {
		size_t len = strlen(opts.otlp_address);
		if (len >= sizeof(opts.config.otlp.address)) {
			SPDK_ERRLOG("otlp_address is too long: %s\n", opts.otlp_address);
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
							 "otlp_address too long");
			goto do_free;
		}
		memcpy(opts.config.otlp.address, opts.otlp_address, len + 1);
	}

	if (opts.prometheus_address) {
		size_t len = strlen(opts.prometheus_address);
		if (len >= sizeof(opts.config.prometheus.address)) {
			SPDK_ERRLOG("prometheus_address is too long: %s\n", opts.prometheus_address);
			spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
							 "prometheus_address too long");
			goto do_free;
		}
		memcpy(opts.config.prometheus.address, opts.prometheus_address, len + 1);
	}

	res = dte_create(&opts.config);
	if (res != 0) {
		SPDK_ERRLOG("Failed to create DTE exporter: %d\n", res);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, spdk_strerror(-res));
		goto do_free;
	}

	spdk_jsonrpc_send_bool_response(request, true);

do_free:
	free(opts.prometheus_address);
	free(opts.otlp_address);
	free(opts.ipc_sockets_dir);
	free(opts.data_root);
}
SPDK_RPC_REGISTER("telemetry_dte_create", rpc_telemetry_dte_create,
		  SPDK_RPC_RUNTIME)

static void
rpc_telemetry_dte_delete(struct spdk_jsonrpc_request *request, const struct spdk_json_val *params)
{
	int res;

	if (params != NULL) {
		spdk_jsonrpc_send_error_response(request,
						 SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "No parameters required");
		return;
	}

	res = dte_delete();
	if (res != 0) {
		SPDK_ERRLOG("Failed to destroy DTE exporter: %d\n", res);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, spdk_strerror(-res));
		return;
	}

	spdk_jsonrpc_send_bool_response(request, true);
}
SPDK_RPC_REGISTER("telemetry_dte_delete", rpc_telemetry_dte_delete,
		  SPDK_RPC_RUNTIME)
