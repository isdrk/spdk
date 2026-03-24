/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/string.h"
#include "spdk/event.h"
#include "spdk/telemetry.h"
#include "telemetry_dte_internal.h"
#include "dte_doca_shim.h"

#include <doca_telemetry_exporter.h>

#define DOCA_TELEMETRY_DEFAULT_OTLP_PORT 9502
#define DOCA_TELEMETRY_ADDRESS_PREFIX "http://"
#define DOCA_TELEMETRY_OTLP_WRITE_ENDPOINT "/v1/metrics"
#define DOCA_TELEMETRY_DEFAULT_PROMETHEUS_ADDRESS "0.0.0.0"
#define DOCA_TELEMETRY_DEFAULT_PROMETHEUS_PORT 9101

/* Port is uint16_t, so it can be at most 65535 */
#define OTLP_ADDRESS_BUFFER_SIZE \
	(sizeof(DOCA_TELEMETRY_ADDRESS_PREFIX) + \
	 SPDK_SIZEOF_MEMBER(struct dte_config, otlp.address) + \
	 sizeof(":65535") + \
	 sizeof(DOCA_TELEMETRY_OTLP_WRITE_ENDPOINT))

#define PROMETHEUS_ADDRESS_BUFFER_SIZE \
	(sizeof(DOCA_TELEMETRY_ADDRESS_PREFIX) + \
	 SPDK_SIZEOF_MEMBER(struct dte_config, prometheus.address) + \
	sizeof(":65535"))

struct dte_type;

struct dte_source {
	struct dte_type *type;
	struct doca_telemetry_exporter_source *doca_source;
	TAILQ_ENTRY(dte_source) link; /* For the type's sources list */
	char name[];
};

struct dte_type {
	doca_telemetry_exporter_type_index_t type_index;
	TAILQ_ENTRY(dte_type) link; /* For the types list */
	TAILQ_HEAD(, dte_source) sources;
	const struct spdk_telemetry_type_info *info;
};

struct dte_mgr {
	bool initialized;
	bool started;
	struct doca_telemetry_exporter_schema *schema;
	struct spdk_telemetry_exporter exporter;
	struct dte_config config;
	char hostname[HOST_NAME_MAX + 1];
	TAILQ_HEAD(, dte_type) types;
};

static struct dte_mgr g_dte_mgr = {0};

static void
dte_set_env(bool set)
{
	struct dte_config *config = &g_dte_mgr.config;

	/* Configure OTLP destination
	 * See https://docs.nvidia.com/doca/sdk/doca-telemetry-exporter/index.html#src-4537125472_id-.DOCATelemetryExporterv3.2.1Nov_LTS-OpenTelemetry
	 */
	if (set && config->otlp.enabled) {
		char env_value[OTLP_ADDRESS_BUFFER_SIZE];
		uint16_t port = config->otlp.port;

		if (port == 0) {
			port = DOCA_TELEMETRY_DEFAULT_OTLP_PORT; /* Default OTLP port */
		}
		snprintf(env_value, sizeof(env_value),
			 DOCA_TELEMETRY_ADDRESS_PREFIX "%s:%d" DOCA_TELEMETRY_OTLP_WRITE_ENDPOINT,
			 config->otlp.address, port);
		setenv("CLX_OPEN_TELEMETRY_RECEIVER", env_value, 1);
		setenv("CLX_OPEN_TELEMETRY_WITH_DATA_POINT_ATTRIBUTES", "true", 1);
		setenv("CLX_OPEN_TELEMETRY_TYPE_AS_LABEL", "true", 1);
		setenv("CLX_OPEN_TELEMETRY_SERVICE_NAME", spdk_app_get_name(), 1);
		setenv("CLX_OPEN_TELEMETRY_TAG_AS_LABEL", "true", 1);

		SPDK_DEBUGLOG(telemetry_dte, "CLX_OPEN_TELEMETRY_RECEIVER set to %s\n", env_value);
	} else {
		/* Other CLX_OPEN_TELEMETRY_* vars are only relevant when RECEIVER is set */
		unsetenv("CLX_OPEN_TELEMETRY_RECEIVER");

		SPDK_DEBUGLOG(telemetry_dte, "CLX_OPEN_TELEMETRY_RECEIVER unset\n");
	}

	/* Configure Prometheus Endpoint
	 * See https://docs.nvidia.com/doca/sdk/doca-telemetry-exporter/index.html#src-4584130014_id-.DOCATelemetryExporterv3.3.0_Jan26GA-PrometheusEndpoint
	 */
	if (set && config->prometheus.enabled) {
		char env_value[PROMETHEUS_ADDRESS_BUFFER_SIZE];
		uint16_t port = config->prometheus.port;
		const char *address = config->prometheus.address;
		char *const_labels;

		if (address == NULL || address[0] == '\0') {
			address = DOCA_TELEMETRY_DEFAULT_PROMETHEUS_ADDRESS;
		}

		if (port == 0) {
			port = DOCA_TELEMETRY_DEFAULT_PROMETHEUS_PORT;
		}

		snprintf(env_value, sizeof(env_value), DOCA_TELEMETRY_ADDRESS_PREFIX "%s:%d", address, port);

		setenv("PROMETHEUS_ENDPOINT", env_value, 1);

		/* Format: name1=value1,name2=value2,name3=value3... */
		const_labels = spdk_sprintf_alloc("app=%s", spdk_app_get_name());
		if (const_labels) {
			setenv("CLX_PROMETHEUS_CONSTANT_LABELS", const_labels, 1);
			free(const_labels);
		} else {
			SPDK_NOTICELOG("Failed to allocate memory for const_labels\n");
		}

		SPDK_DEBUGLOG(telemetry_dte, "PROMETHEUS_ENDPOINT set to %s\n", env_value);
	} else {
		unsetenv("PROMETHEUS_ENDPOINT");
		SPDK_DEBUGLOG(telemetry_dte, "PROMETHEUS_ENDPOINT unset\n");
	}
}

static struct doca_telemetry_exporter_field *
dte_create_telemetry_field(const struct spdk_telemetry_stat_info *stat_info)
{
	struct doca_telemetry_exporter_field *field;
	doca_error_t ret;
	const char *type_name;

	switch (stat_info->type) {
	case SPDK_TELEMETRY_STAT_TYPE_UINT64:
		type_name = "uint64_t";
		break;
	case SPDK_TELEMETRY_STAT_TYPE_SUBTYPE:
		assert(stat_info->extra.type_name != NULL);
		type_name = stat_info->extra.type_name;
		break;
	default:
		SPDK_ERRLOG("Unsupported stat type %d for %s\n", stat_info->type, stat_info->name);
		return NULL;
	}

	ret = doca_telemetry_exporter_field_create(&field);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to create field %s: %s\n", stat_info->name, doca_error_get_name(ret));
		return NULL;
	}

	doca_telemetry_exporter_field_set_name(field, stat_info->name);
	doca_telemetry_exporter_field_set_description(field, stat_info->name);
	doca_telemetry_exporter_field_set_type_name(field, type_name);
	doca_telemetry_exporter_field_set_array_len(field, stat_info->count);

	return field;
}

static doca_error_t
dte_type_add_stats(struct doca_telemetry_exporter_type *type,
		   const struct spdk_telemetry_type_info *type_info)
{
	doca_error_t ret = DOCA_SUCCESS;
	uint64_t i;

	for (i = 0; i < type_info->num_stats; i++) {
		const struct spdk_telemetry_stat_info *stat_info = &type_info->stats[i];
		struct doca_telemetry_exporter_field *field;

		field = dte_create_telemetry_field(stat_info);
		if (field == NULL) {
			SPDK_ERRLOG("Failed to create field %s\n", stat_info->name);
			return DOCA_ERROR_NO_MEMORY;
		}

		ret = doca_telemetry_exporter_type_add_field(type, field);
		if (ret != DOCA_SUCCESS) {
			SPDK_ERRLOG("Failed to add field %s to type: %s\n", stat_info->name,
				    doca_error_get_name(ret));
			doca_telemetry_exporter_field_destroy(field);
			return ret;
		}
	}

	return ret;
}

static doca_error_t
dte_telemetry_register_type(struct doca_telemetry_exporter_schema *schema,
			    const struct spdk_telemetry_type_info *type_info,
			    doca_telemetry_exporter_type_index_t *type_index)
{
	doca_error_t ret;
	struct doca_telemetry_exporter_type *type = NULL;

	/* Register type */
	ret = doca_telemetry_exporter_type_create(&type);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to create type %s: %s\n", type_info->name, doca_error_get_name(ret));
		return ret;
	}

	/* Add stats to the type */
	ret = dte_type_add_stats(type, type_info);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to add stats to type %s: %s\n", type_info->name, doca_error_get_name(ret));
		goto type_error;
	}

	/* Register the type to the schema */
	ret = doca_telemetry_exporter_schema_add_type(schema, type_info->name, type, type_index);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to add type %s to schema: %s\n", type_info->name, doca_error_get_name(ret));
		goto type_error;
	}

	SPDK_DEBUGLOG(telemetry_dte, "Registered type %s with index %" PRIu64 "\n", type_info->name,
		      (uint64_t)*type_index);

	return DOCA_SUCCESS;

type_error:
	doca_telemetry_exporter_type_destroy(type);
	return ret;
}

static struct dte_source *
dte_source_create(struct dte_type *type, const char *name)
{
	doca_error_t ret;
	struct dte_source *source;
	size_t len = strlen(name);

	source = calloc(1, sizeof(*source) + len + 1);
	if (source == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for %s:%s\n", type->info->name, name);
		return NULL;
	}

	ret = doca_telemetry_exporter_source_create(g_dte_mgr.schema, &source->doca_source);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to create doca telemetry source for %s:%s: %s\n", type->info->name, name,
			    doca_error_get_name(ret));
		goto source_create_error;
	}

	doca_telemetry_exporter_source_set_id(source->doca_source, g_dte_mgr.hostname);
	doca_telemetry_exporter_source_set_tag(source->doca_source, name);

	if (g_dte_mgr.started) {
		ret = doca_telemetry_exporter_source_start(source->doca_source);
		if (ret != DOCA_SUCCESS) {
			SPDK_ERRLOG("Failed to start doca telemetry source for %s:%s: %s\n", type->info->name, name,
				    doca_error_get_name(ret));
			goto source_start_error;
		}
	}

	memcpy(source->name, name, len + 1);
	source->type = type;

	SPDK_DEBUGLOG(telemetry_dte, "source %s:%s created\n", type->info->name, name);

	return source;

source_start_error:
	doca_telemetry_exporter_source_destroy(source->doca_source);
source_create_error:
	free(source);
	return NULL;
}

static void
dte_source_destroy(struct dte_source *source)
{
	doca_telemetry_exporter_source_destroy(source->doca_source);
	SPDK_DEBUGLOG(telemetry_dte, "source %s:%s destroyed\n", source->type->info->name, source->name);
	free(source);
}

static void
dte_type_destroy(struct dte_type *type)
{
	while (!TAILQ_EMPTY(&type->sources)) {
		struct dte_source *source = TAILQ_FIRST(&type->sources);
		TAILQ_REMOVE(&type->sources, source, link);
		dte_source_destroy(source);
	}
	TAILQ_REMOVE(&g_dte_mgr.types, type, link);
	SPDK_DEBUGLOG(telemetry_dte, "type %s destroyed\n", type->info->name);
	free(type);
}

static void
dte_schema_destroy(void)
{
	assert(g_dte_mgr.initialized);

	if (g_dte_mgr.schema) {
		doca_telemetry_exporter_schema_destroy(g_dte_mgr.schema);
		g_dte_mgr.schema = NULL;
	}
}

static struct doca_telemetry_exporter_schema *
dte_schema_create(const char *name)
{
	doca_error_t ret;
	struct dte_config *config = &g_dte_mgr.config;
	struct doca_telemetry_exporter_schema *schema;

	/* Init DOCA schema */
	ret = doca_telemetry_exporter_schema_init(name, &schema);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to init DOCA schema for %s: %s\n", name, doca_error_get_name(ret));
		return NULL;
	}

	/* NOTE: doca_telemetry_exporter_schema_set_buf_size() has a bug. It treats the size it gets as the final internal
	 * buffer size which is incorrect as it stores a lot of metadata in the buffer. So we cannot use sizeof(event) * N
	 * here, especially for the small events (like bdev statistics) and relatively small N.
	 *
	 * Thus, for now, as a workaround, we just use a fixed size of PAGE_SIZE and flush manually after each report.
	 */
	doca_telemetry_exporter_schema_set_buf_size(schema, PAGE_SIZE);

	/* Configure DOCA Telemetry Exporter Schema */

	/* Configure IPC destination */
	if (config->ipc.enabled) {
		doca_telemetry_exporter_schema_set_ipc_enabled(schema);
		if (config->ipc.sockets_dir[0] != '\0') {
			doca_telemetry_exporter_schema_set_ipc_sockets_dir(schema,
					config->ipc.sockets_dir);
		}
		if (config->ipc.reconnect_time) {
			doca_telemetry_exporter_schema_set_ipc_reconnect_time(schema,
					config->ipc.reconnect_time);
		}
		if (config->ipc.reconnect_tries) {
			doca_telemetry_exporter_schema_set_ipc_reconnect_tries(schema,
					config->ipc.reconnect_tries);
		}
		if (config->ipc.socket_timeout) {
			doca_telemetry_exporter_schema_set_ipc_socket_timeout(schema,
					config->ipc.socket_timeout);
		}
	}

	/* Configure file destination */
	if (config->file.enabled) {
		doca_telemetry_exporter_schema_set_file_write_enabled(schema);
		if (config->file.max_size) {
			doca_telemetry_exporter_schema_set_file_write_max_size(schema,
					config->file.max_size);
		}
		if (config->file.max_age) {
			doca_telemetry_exporter_schema_set_file_write_max_age(schema,
					config->file.max_age);
		}
	}

	/* Configure DOCA Telemetry Exporter buffer data root */
	if (config->telemetry_data_root[0] != '\0') {
		doca_telemetry_exporter_schema_set_buf_data_root(schema,
				config->telemetry_data_root);
	}

	return schema;
}

static doca_error_t
dte_schema_start(void)
{
	doca_error_t ret;
	struct dte_type *type;

	/* Start the schema */
	ret = doca_telemetry_exporter_schema_start(g_dte_mgr.schema);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to start the doca telemetry schema: %s\n", doca_error_get_name(ret));
		return ret;
	}

	/* Start the sources */
	TAILQ_FOREACH(type, &g_dte_mgr.types, link) {
		struct dte_source *source;
		TAILQ_FOREACH(source, &type->sources, link) {
			ret = doca_telemetry_exporter_source_start(source->doca_source);
			if (ret != DOCA_SUCCESS) {
				/* NOTE: Unfortunately, there's no DOCA API to stop the schema or sources. So we just log the error and continue. */
				SPDK_WARNLOG("Failed to start doca telemetry source for %s:%s: %s\n", type->info->name,
					     source->name, doca_error_get_name(ret));
			}
		}
	}

	SPDK_DEBUGLOG(telemetry_dte, "Schema started\n");

	return DOCA_SUCCESS;
}

static struct dte_type *
dte_type_create(const struct spdk_telemetry_type_info *type_info)
{
	doca_error_t ret;
	struct dte_type *type;

	type = calloc(1, sizeof(*type));
	if (type == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for type\n");
		return NULL;
	}

	/* Register type */
	ret = dte_telemetry_register_type(g_dte_mgr.schema, type_info, &type->type_index);
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to register %s type\n", type_info->name);
		free(type);
		return NULL;
	}

	type->info = type_info;
	TAILQ_INIT(&type->sources);

	SPDK_DEBUGLOG(telemetry_dte, "Type %s with %" PRIu64 " stats created\n", type_info->name,
		      type_info->num_stats);

	return type;
}

static int
dte_init(void)
{
	assert(!g_dte_mgr.initialized);

	TAILQ_INIT(&g_dte_mgr.types);
	g_dte_mgr.initialized = true;

	SPDK_DEBUGLOG(telemetry_dte, "DTE initialized\n");
	return 0;
}

static void
dte_fini(void)
{
	assert(g_dte_mgr.initialized);
	while (!TAILQ_EMPTY(&g_dte_mgr.types)) {
		struct dte_type *type = TAILQ_FIRST(&g_dte_mgr.types);
		dte_type_destroy(type);
	}
	dte_schema_destroy();
	g_dte_mgr.started = false;
	g_dte_mgr.initialized = false;
	SPDK_DEBUGLOG(telemetry_dte, "DTE finalized\n");
}

static struct spdk_telemetry_exporter_module dte_module = {
	.name = "dte",
	.init = dte_init,
	.fini = dte_fini,
};

static int
dte_start(void *ctx)
{
	doca_error_t ret;
	assert(g_dte_mgr.initialized);
	assert(!g_dte_mgr.started);

	ret = dte_schema_start();
	if (ret != DOCA_SUCCESS) {
		SPDK_ERRLOG("Failed to start schema: %s\n", doca_error_get_name(ret));
		return -EINVAL;
	}

	g_dte_mgr.started = true;
	return 0;
}

static void
dte_stop(void *ctx)
{
	assert(g_dte_mgr.initialized);
	assert(g_dte_mgr.started);

	/* NOTE: As there's no way to stop the schema, stop is logical only, restart is unsupported,
	 * and a destruct/recreate cycle is required to start exporting again.
	 * So we just set the started flag to false and return.
	 */

	g_dte_mgr.started = false;
}

static struct spdk_telemetry_type_handle *
dte_register_type(void *ctx, const struct spdk_telemetry_type_info *type_info)
{
	struct dte_type *type;

	assert(!g_dte_mgr.started);

	type = dte_type_create(type_info);
	if (type == NULL) {
		return NULL;
	}

	TAILQ_INSERT_TAIL(&g_dte_mgr.types, type, link);

	return (struct spdk_telemetry_type_handle *)type;
}

static void
dte_do_unregister_source(struct dte_source *source)
{
	assert(source != NULL);

	TAILQ_REMOVE(&source->type->sources, source, link);
	dte_source_destroy(source);
}


static void
dte_unregister_type(void *ctx, struct spdk_telemetry_type_handle *_type)
{
	struct dte_type *type = (struct dte_type *)_type;

	assert(type != NULL);
	assert(!g_dte_mgr.started);
	assert(TAILQ_EMPTY(&type->sources));

	dte_type_destroy(type);
}

static struct spdk_telemetry_source_handle *
dte_register_source(void *ctx, struct spdk_telemetry_type_handle *type_handle, const char *name)
{
	struct dte_type *type = (struct dte_type *)type_handle;
	struct dte_source *source;

	source = dte_source_create(type, name);
	if (source == NULL) {
		return NULL;
	}

	TAILQ_INSERT_TAIL(&type->sources, source, link);

	return (struct spdk_telemetry_source_handle *)source;
}

static void
dte_unregister_source(void *ctx, struct spdk_telemetry_source_handle *_source)
{
	struct dte_source *source = (struct dte_source *)_source;

	dte_do_unregister_source(source);
}

static bool
dte_report_stats(void *ctx, struct spdk_telemetry_source_handle *_source, const void *stats_buffer,
		 uint64_t stats_buffer_size)
{
	doca_error_t ret;
	struct dte_source *source = (struct dte_source *)_source;
	struct dte_type *type = source->type;

	/* NOTE: We cast the stats_buffer to void * to avoid a warning about the const qualifier.
	 * We'll remove the casting once the doca_telemetry_exporter_schema_set_buf_size() prototype is fixed.
	 */
	ret = doca_telemetry_exporter_source_report(source->doca_source, type->type_index,
			(void *)stats_buffer, 1);
	if (ret != DOCA_SUCCESS) {
		SPDK_NOTICELOG("Failed to report stats for %s:%s: %s\n",
			       type->info->name, source->name, doca_error_get_name(ret));
		return true;
	}

	/* We flush the doca telemetry source manually due to a bug in doca_telemetry_exporter_schema_set_buf_size */
	ret = doca_telemetry_exporter_source_flush(source->doca_source);
	if (ret != DOCA_SUCCESS) {
		SPDK_NOTICELOG("Failed to flush doca telemetry source for %s:%s: %s\n",
			       type->info->name, source->name, doca_error_get_name(ret));
	}

	SPDK_DEBUGLOG(telemetry_dte, "Reported stats for %s:%s\n", type->info->name, source->name);
	return true;
}

static void
dte_dump_config_json(struct spdk_json_write_ctx *w)
{
	if (g_dte_mgr.config.telemetry_data_root[0] != '\0') {
		spdk_json_write_named_string(w, "data_root", g_dte_mgr.config.telemetry_data_root);
	}
	if (g_dte_mgr.config.ipc.enabled) {
		spdk_json_write_named_bool(w, "ipc", g_dte_mgr.config.ipc.enabled);
		if (g_dte_mgr.config.ipc.sockets_dir[0] != '\0') {
			spdk_json_write_named_string(w, "ipc_sockets_dir",
						     g_dte_mgr.config.ipc.sockets_dir);
		}
		if (g_dte_mgr.config.ipc.reconnect_time) {
			spdk_json_write_named_uint32(w, "ipc_reconnect_time",
						     g_dte_mgr.config.ipc.reconnect_time);
		}
		if (g_dte_mgr.config.ipc.reconnect_tries) {
			spdk_json_write_named_uint32(w, "ipc_reconnect_tries",
						     g_dte_mgr.config.ipc.reconnect_tries);
		}
		if (g_dte_mgr.config.ipc.socket_timeout) {
			spdk_json_write_named_uint32(w, "ipc_socket_timeout",
						     g_dte_mgr.config.ipc.socket_timeout);
		}
	}
	if (g_dte_mgr.config.file.enabled) {
		spdk_json_write_named_bool(w, "file", g_dte_mgr.config.file.enabled);
		if (g_dte_mgr.config.file.max_size) {
			spdk_json_write_named_uint64(w, "file_max_size", g_dte_mgr.config.file.max_size);
		}
		if (g_dte_mgr.config.file.max_age) {
			spdk_json_write_named_uint32(w, "file_max_age", g_dte_mgr.config.file.max_age);
		}
	}
	if (g_dte_mgr.config.otlp.enabled) {
		spdk_json_write_named_bool(w, "otlp", g_dte_mgr.config.otlp.enabled);
		spdk_json_write_named_string(w, "otlp_address", g_dte_mgr.config.otlp.address);
		spdk_json_write_named_uint16(w, "otlp_port", g_dte_mgr.config.otlp.port);
	}
	if (g_dte_mgr.config.prometheus.enabled) {
		spdk_json_write_named_bool(w, "prometheus", g_dte_mgr.config.prometheus.enabled);
		if (g_dte_mgr.config.prometheus.address[0] != '\0') {
			spdk_json_write_named_string(w, "prometheus_address", g_dte_mgr.config.prometheus.address);
		}
		if (g_dte_mgr.config.prometheus.port != 0) {
			spdk_json_write_named_uint16(w, "prometheus_port", g_dte_mgr.config.prometheus.port);
		}
	}
}

static void
dte_write_config_json(void *ctx, struct spdk_json_write_ctx *w)
{
	if (g_dte_mgr.exporter.ctxt) {
		spdk_json_write_object_begin(w);

		spdk_json_write_named_string(w, "method", "telemetry_dte_create");

		spdk_json_write_named_object_begin(w, "params");
		dte_dump_config_json(w);
		spdk_json_write_object_end(w);
		spdk_json_write_object_end(w);

	}
}

static void
dte_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	if (g_dte_mgr.exporter.ctxt) {
		dte_dump_config_json(w);
	}
}

static int
dte_destruct(void *ctx)
{
	int res;

	res = spdk_telemetry_exporter_unregister(&g_dte_mgr.exporter);
	if (res != 0) {
		SPDK_ERRLOG("Failed to unregister telemetry DTE exporter: %d\n", res);
		return res;
	}

	dte_set_env(false);

	while (!TAILQ_EMPTY(&g_dte_mgr.types)) {
		struct dte_type *type = TAILQ_FIRST(&g_dte_mgr.types);
		dte_type_destroy(type);
	}

	dte_schema_destroy();
	dte_doca_shim_fini();

	g_dte_mgr.exporter.ctxt = NULL;

	SPDK_DEBUGLOG(telemetry_dte, "DTE exporter destroyed\n");

	return 0; /* synchronous destruct */
}

static struct spdk_telemetry_exporter_fn_table dte_fn_table = {
	.destruct = dte_destruct,
	.start = dte_start,
	.stop = dte_stop,
	.register_type = dte_register_type,
	.unregister_type = dte_unregister_type,
	.register_source = dte_register_source,
	.unregister_source = dte_unregister_source,
	.report_stats = dte_report_stats,
	.write_config_json = dte_write_config_json,
	.dump_info_json = dte_dump_info_json,
};

int
dte_create(const struct dte_config *config)
{
	int res = 0;

	if (g_dte_mgr.exporter.ctxt != NULL) {
		SPDK_ERRLOG("DTE exporter has already been created\n");
		return -EEXIST;
	}

	if (!config->ipc.enabled && !config->file.enabled && !config->otlp.enabled &&
	    !config->prometheus.enabled) {
		SPDK_ERRLOG("DTE exporter requires at least one destination\n");
		return -EINVAL;
	}

	if (config->otlp.enabled && config->otlp.address[0] == '\0') {
		SPDK_ERRLOG("OTLP address is required when OTLP is enabled\n");
		return -EINVAL;
	}

	if (gethostname(g_dte_mgr.hostname, sizeof(g_dte_mgr.hostname)) < 0) {
		res = -errno;
		SPDK_ERRLOG("gethostname failed with error: %s\n", spdk_strerror(-res));
		return res;
	}

	res = dte_doca_shim_init();
	if (res != 0) {
		SPDK_ERRLOG("Failed to initialize DOCA shim: %d\n", res);
		return res;
	}

	g_dte_mgr.exporter.ctxt = &g_dte_mgr.exporter;
	g_dte_mgr.exporter.fn_table = &dte_fn_table;
	g_dte_mgr.exporter.module = &dte_module;
	g_dte_mgr.config = *config;

	g_dte_mgr.schema = dte_schema_create("SPDK DTE");
	if (g_dte_mgr.schema == NULL) {
		SPDK_ERRLOG("Failed to create schema\n");
		res = -ENOMEM;
		goto dte_create_error;
	}

	dte_set_env(true);

	res = spdk_telemetry_exporter_register(&g_dte_mgr.exporter);
	if (res != 0) {
		SPDK_ERRLOG("Failed to register DTE exporter: %d\n", res);
		goto exporter_register_error;
	}

	return 0;

exporter_register_error:
	dte_schema_destroy();
dte_create_error:
	g_dte_mgr.exporter.ctxt = NULL;
	memset(&g_dte_mgr.config, 0, sizeof(g_dte_mgr.config));
	dte_set_env(false);
	dte_doca_shim_fini();
	return res;
}

int
dte_delete(void)
{
	int res;

	if (g_dte_mgr.exporter.ctxt == NULL) {
		SPDK_ERRLOG("DTE exporter has not been created\n");
		return -ENOENT;
	}

	res = dte_destruct(NULL);
	if (res != 0) {
		SPDK_ERRLOG("Failed to destroy DTE exporter: %d\n", res);
		return res;
	}

	return 0;
}

SPDK_TELEMETRY_MODULE_REGISTER(doca, &dte_module);
SPDK_LOG_REGISTER_COMPONENT(telemetry_dte);
