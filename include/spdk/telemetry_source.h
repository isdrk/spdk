/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef SPDK_TELEMETRY_SOURCE_H
#define SPDK_TELEMETRY_SOURCE_H

#include "spdk/stdinc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A struct that represents a telemetry type, for example a bdev io stats or a fsdev io stats.
 */
struct spdk_telemetry_type;

/**
 * A struct that represents a telemetry source, for example a bdev instance or a fsdev instance.
 */
struct spdk_telemetry_source;

/**
 * Callback function to be called by telemetry core to pull the telemetry source.
 *
 * \param pull_cb_arg Callback argument passed to spdk_telemetry_register_source().
 * \param src Pointer to the telemetry source.
 *
 * \note The telemetry core ensures that only one stats array per source is pulled at a time.
 * So, if the \p spdk_telemetry_pull_cb has been called, the telemetry core will not call it again until
 * the stats are ready and the \p spdk_telemetry_source_pull_complete() is called.
 */
typedef void (*spdk_telemetry_pull_cb)(void *pull_cb_arg, struct spdk_telemetry_source *src);

/**
 * Information about a telemetry stat.
 */
struct spdk_telemetry_stat_info {
	/**
	 * Name of the telemetry field.
	 */
	const char *name;
};

/**
 * Information about a telemetry type.
 */
struct spdk_telemetry_type_info {
	/**
	 * Name of the telemetry type.
	 */
	const char *name;

	/**
	 * Number of stats in the telemetry type.
	 */
	uint64_t num_stats;

	/**
	 * Array of stats info.
	 */
	const struct spdk_telemetry_stat_info *stats;
};

/**
 * Register a telemetry type.
 *
 * \param type_info Information about the telemetry type.
 * \param type Pointer to the telemetry type.
 * \return 0 on success, negative errno on failure.
 *
 * \note The \p type_info must remain valid until the telemetry type is unregistered.
 *
 */
int spdk_telemetry_register_type(const struct spdk_telemetry_type_info *type_info,
				 struct spdk_telemetry_type **type);

/**
 * Unregister a telemetry type.
 *
 * \param type Pointer to the telemetry type.
 */
void spdk_telemetry_unregister_type(struct spdk_telemetry_type *type);

/**
 * Register a telemetry source.
 *
 * \param type Pointer to the telemetry type.
 * \param name Name of the telemetry source instance.
 * \param pull_cb Callback function to be called by telemetry core to pull the telemetry source.
 * \param pull_cb_arg Callback argument to be passed to spdk_telemetry_pull_cb.
 * \param src Pointer to the telemetry source.
 * \return 0 on success, negative errno on failure.
 */
int spdk_telemetry_register_source(struct spdk_telemetry_type *type, const char *name,
				   spdk_telemetry_pull_cb pull_cb, void *pull_cb_arg,
				   struct spdk_telemetry_source **src);

/**
 * Unregister a telemetry source.
 *
 * \param src Pointer to the telemetry source.
 */
void spdk_telemetry_unregister_source(struct spdk_telemetry_source *src);


/**
 * Get the stats buffer assigned to the telemetry source.
 *
 * \param src Pointer to the telemetry source.
 * \return Pointer to the stats buffer.
 */
void *spdk_telemetry_source_get_stats_buffer(struct spdk_telemetry_source *src);

/**
 * Get buffer size for the stats buffer assigned to the telemetry source.
 *
 * \param src Pointer to the telemetry source.
 * \return Buffer size of the stats buffer in bytes.
 */
uint64_t spdk_telemetry_source_get_stats_buffer_size(struct spdk_telemetry_source *src);

/**
 * Complete the telemetry source pull operation.
 *
 * \param src Pointer to the telemetry source.
 * \param status Status of the telemetry source pull operation.
 */
void spdk_telemetry_source_pull_complete(struct spdk_telemetry_source *src, int status);

#ifdef __cplusplus
}
#endif

#endif /* SPDK_TELEMETRY_SOURCE_H */
