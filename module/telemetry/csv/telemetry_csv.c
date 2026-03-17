/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */
#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/string.h"
#include "spdk/telemetry.h"
#include "telemetry_csv_internal.h"

struct telemetry_csv_exporter {
	struct spdk_telemetry_exporter exporter;
};

struct spdk_telemetry_source_handle {
	struct spdk_telemetry_type_handle *type;
	TAILQ_ENTRY(spdk_telemetry_source_handle) link;
	char name[];
};

struct spdk_telemetry_type_handle {
	FILE *file;
	const struct spdk_telemetry_type_info *info;
	TAILQ_ENTRY(spdk_telemetry_type_handle) link;
	TAILQ_HEAD(, spdk_telemetry_source_handle) sources;
};

struct telemetry_csv {
	struct telemetry_csv_exporter exporter;
	TAILQ_HEAD(, spdk_telemetry_type_handle) types;
	char *dst_dir;
};

static struct telemetry_csv g_telemetry_csv = {0};

static int
telemetry_csv_init(void)
{
	TAILQ_INIT(&g_telemetry_csv.types);

	return 0;
}

static void
telemetry_csv_destroy_source(struct spdk_telemetry_source_handle *source)
{
	TAILQ_REMOVE(&source->type->sources, source, link);
	free(source);
}

static void
telemetry_csv_destroy_type(struct spdk_telemetry_type_handle *type)
{
	TAILQ_REMOVE(&g_telemetry_csv.types, type, link);
	while (!TAILQ_EMPTY(&type->sources)) {
		struct spdk_telemetry_source_handle *source;
		source = TAILQ_FIRST(&type->sources);
		telemetry_csv_destroy_source(source);
	}
	if (type->file != NULL) {
		fclose(type->file);
	}
	free(type);
}

static void
telemetry_csv_fini(void)
{
	if (g_telemetry_csv.exporter.exporter.ctxt) {
		telemetry_csv_delete();
	}

	assert(TAILQ_EMPTY(&g_telemetry_csv.types));

	free(g_telemetry_csv.dst_dir);
}

static struct spdk_telemetry_exporter_module telemetry_csv_module = {
	.name = "csv",
	.init = telemetry_csv_init,
	.fini = telemetry_csv_fini,
};

static void
telemetry_csv_write_config_json(void *ctx, struct spdk_json_write_ctx *w)
{
	assert(g_telemetry_csv.exporter.exporter.ctxt != NULL);
	assert(g_telemetry_csv.dst_dir != NULL);

	spdk_json_write_object_begin(w); /* method */
	spdk_json_write_named_string(w, "method", "telemetry_csv_create");
	spdk_json_write_named_object_begin(w, "params"); /* params */
	spdk_json_write_named_string(w, "dst_dir", g_telemetry_csv.dst_dir);
	spdk_json_write_object_end(w); /* params */
	spdk_json_write_object_end(w); /* method */
}

static void
telemetry_csv_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	assert(g_telemetry_csv.exporter.exporter.ctxt != NULL);
	assert(g_telemetry_csv.dst_dir != NULL);

	spdk_json_write_named_string(w, "dst_dir", g_telemetry_csv.dst_dir);
}

static int
telemetry_csv_destruct(void *ctx)
{
	telemetry_csv_fini();

	return 0; /* synchronous destruct */
}

static void
telemetry_csv_write_header(struct spdk_telemetry_type_handle *type)
{
	const struct spdk_telemetry_type_info *type_info = type->info;
	uint64_t i;

	fprintf(type->file, "name");
	for (i = 0; i < type_info->num_stats; i++) {
		fprintf(type->file, ",%s", type_info->stats[i].name);
	}

	fprintf(type->file, "\n");
}

static int
telemetry_csv_prepare_file(struct spdk_telemetry_type_handle *type)
{
	const struct spdk_telemetry_type_info *type_info = type->info;
	int res;
	char *file_path;

	file_path = spdk_sprintf_alloc("%s/%s.csv", g_telemetry_csv.dst_dir, type_info->name);
	if (file_path == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for %s file path\n", type_info->name);
		return -ENOMEM;
	}

	type->file = fopen(file_path, "w");
	free(file_path);
	if (type->file == NULL) {
		res = -errno;
		SPDK_ERRLOG("Failed to open file %s/%s.csv: %s\n", g_telemetry_csv.dst_dir, type_info->name,
			    spdk_strerror(-res));
		return res;
	}

	telemetry_csv_write_header(type);

	return 0;
}

static struct spdk_telemetry_type_handle *
telemetry_csv_register_type(void *ctx, const struct spdk_telemetry_type_info *type_info)
{
	struct spdk_telemetry_type_handle *type;

	type = calloc(1, sizeof(*type));
	if (type == NULL) {
		return NULL;
	}

	type->info = type_info;
	TAILQ_INIT(&type->sources);
	TAILQ_INSERT_TAIL(&g_telemetry_csv.types, type, link);

	return type;
}

static bool
telemetry_csv_report_stats(void *ctx, struct spdk_telemetry_source_handle *source,
			   const uint64_t *stats, uint64_t num_stats)
{
	uint64_t i;
	struct spdk_telemetry_type_handle *type;

	assert(source != NULL);
	assert(stats != NULL);
	assert(num_stats > 0);

	type = source->type;
	fprintf(type->file, "%s", source->name);
	for (i = 0; i < num_stats; i++) {
		fprintf(type->file, ",%" PRIu64, stats[i]);
	}
	fprintf(type->file, "\n");
	fflush(type->file);

	return true;
}

static void
telemetry_csv_unregister_type(void *ctx, struct spdk_telemetry_type_handle *type)
{
	telemetry_csv_destroy_type(type);
}

static struct spdk_telemetry_source_handle *
telemetry_csv_register_source(void *ctx, struct spdk_telemetry_type_handle *type, const char *name)
{
	struct spdk_telemetry_source_handle *source;
	size_t len = strlen(name);

	source = calloc(1, sizeof(*source) + len + 1);
	if (source == NULL) {
		return NULL;
	}

	if (type->file == NULL) {
		int rc = telemetry_csv_prepare_file(type);
		if (rc != 0) {
			SPDK_ERRLOG("Failed to prepare file for type %s: %s\n", type->info->name, spdk_strerror(-rc));
			free(source);
			return NULL;
		}
	}

	source->type = type;
	memcpy(source->name, name, len + 1);

	TAILQ_INSERT_TAIL(&type->sources, source, link);

	return source;
}

static void
telemetry_csv_unregister_source(void *ctx, struct spdk_telemetry_source_handle *source)
{
	telemetry_csv_destroy_source(source);
}

static struct spdk_telemetry_exporter_fn_table telemetry_csv_fn_table = {
	.destruct = telemetry_csv_destruct,
	.register_type = telemetry_csv_register_type,
	.unregister_type = telemetry_csv_unregister_type,
	.register_source = telemetry_csv_register_source,
	.unregister_source = telemetry_csv_unregister_source,
	.report_stats = telemetry_csv_report_stats,
	.write_config_json = telemetry_csv_write_config_json,
	.dump_info_json = telemetry_csv_dump_info_json,
};

int
telemetry_csv_create(const char *dst_dir)
{
	int res;

	if (g_telemetry_csv.exporter.exporter.ctxt != NULL) {
		SPDK_ERRLOG("Telemetry CSV exporter already registered\n");
		return -EEXIST;
	}

	g_telemetry_csv.dst_dir = strdup(dst_dir);
	if (g_telemetry_csv.dst_dir == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for dst_dir\n");
		return -ENOMEM;
	}

	g_telemetry_csv.exporter.exporter.ctxt = &g_telemetry_csv.exporter.exporter;
	g_telemetry_csv.exporter.exporter.fn_table = &telemetry_csv_fn_table;
	g_telemetry_csv.exporter.exporter.module = &telemetry_csv_module;

	res = spdk_telemetry_exporter_register(&g_telemetry_csv.exporter.exporter);
	if (res != 0) {
		SPDK_ERRLOG("Failed to register telemetry CSV exporter: %d\n", res);
		free(g_telemetry_csv.dst_dir);
		g_telemetry_csv.dst_dir = NULL;
		return res;
	}

	return 0;
}

int
telemetry_csv_delete(void)
{
	int res;

	if (g_telemetry_csv.exporter.exporter.ctxt == NULL) {
		SPDK_ERRLOG("Telemetry CSV exporter not registered\n");
		return -ENOENT;
	}

	res = spdk_telemetry_exporter_unregister(&g_telemetry_csv.exporter.exporter);
	if (res != 0) {
		SPDK_ERRLOG("Failed to unregister telemetry CSV exporter: %d\n", res);
		return res;
	}

	while (!TAILQ_EMPTY(&g_telemetry_csv.types)) {
		struct spdk_telemetry_type_handle *type;
		type = TAILQ_FIRST(&g_telemetry_csv.types);
		telemetry_csv_destroy_type(type);
	}

	free(g_telemetry_csv.dst_dir);
	g_telemetry_csv.dst_dir = NULL;
	g_telemetry_csv.exporter.exporter.ctxt = NULL;
	return 0;
}

SPDK_TELEMETRY_MODULE_REGISTER(csv, &telemetry_csv_module);
