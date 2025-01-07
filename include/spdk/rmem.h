/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

/** \file
 * Recovery Memory abstraction.
 *
 * The rmem abstraction is designed to allow hot recovery, for example, in case of application crash.
 *
 * It allows the SPDK components to store some information in runtime and then recover it, if needed. For example,
 * upon the next invocation of the same application.
 *
 * The rmem_pool is an rmem flavor. Basically, it's a dynamic array of rmem entries (struct spdk_rmem_entry) of the
 * same size. Currently, the rmem_pool can only grow.
 *
 * Entry (struct spdk_rmem_entry) represents a shared memory region of \p entry_size bytes which can be accessed
 * in atomic manner using the spdk_rmem_entry_write() and spdk_rmem_entry_read() APIs.
 *
 * One can get a entry object pointer using the spdk_rmem_pool_get() API and release it later using the
 * spdk_rmem_entry_release() API.
 *
 * The rmem (and, in turn, rmem_pool) is currently implemented using shared memory backed by file. The rmem functionality
 * can be enabled and disabled globally using the spdk_rmem_enable() API that gets a backup folder location as an
 * argument. Once enabled, the rmem stores all the backend files in the backup folder - a file per instance. For the
 * rmem_pool, a pool is used as the backend file name. The backend file is deleted once the corresponding rmem_pool object
 * is destroyed.
 *
 * NOTE 1: Released rmem_pool entries are re-used.
 * NOTE 2: It's important to distinguish between a shared memory region and a rmem_pool entry object (struct
 *         spdk_rmem_entry). Each entry object has an underlying shared memory region assigned to it. Such a shared memory
 *         region can not be accessed directly, but only using the corresponding rmem_pool APIs.
 */

#ifndef SPDK_RMEM_H
#define SPDK_RMEM_H

#include "spdk/stdinc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct spdk_json_write_ctx;

/**
 * \brief rmem pool object.
 */
struct spdk_rmem_pool;

/**
 * \brief rmem entry object.
 */
struct spdk_rmem_entry;

/**
 * per-entry rmem pool restore callback.
 *
 * \param entry Restored entry.
 * \param ctx Callback argument.
 *
 * \return 0 to continue the rmem pool restoration, a negative error code otherwise.
 */
typedef int (*spdk_rmem_pool_restore_entry_cb)(struct spdk_rmem_entry *entry, void *ctx);

/**
 * Initialize rmem module.
 *
 * \return 0 on success, a negative error code otherwise.
 */
int spdk_rmem_init(void);

/**
 * Deinitialize rmem module.
 */
void spdk_rmem_fini(void);

/**
 * Reports whether the rmem functionality is enabled.
 *
 * \return true on if enabled, false otherwise.
 */
bool spdk_rmem_is_enabled(void);

/**
 * Enable/disable rmem functionality.
 *
 * \param backend_dir Path to a dir where the underlying files will be stored. Enables the
 *                    rmem functionality if not NULL, disables it otherwise.
 *
 * NOTE: an attempt to create/restore an rmem_pool if the rmem functionality is disable will
 *       fail. However, disabling the rmem_pool functionality do not affect the currently instantiated
 *       rmem_pools.
 *
 * \return true on success, false on failure.
 */
bool spdk_rmem_enable(const char *backend_dir);

/**
 * Get the full configuration options for the rmem module.
 *
 * \param w pointer to a JSON write context where the configuration will be written.
 */
void spdk_rmem_subsystem_config_json(struct spdk_json_write_ctx *w);

/**
 * Output rmem module information to a JSON stream.
 *
 * \param w JSON write context. It will store the driver-specific configuration context.
 */
void spdk_rmem_dump_info_json(struct spdk_json_write_ctx *w);

/**
 * Create rmem pool.
 *
 * \param name Pool name.
 * \param entry_size Desired entry size.
 * \param num_entries Initial number of entries.
 * \param ext_num_entries Pool extension step size in entries.
 *
 * \return Pool object on success, NULL on failure.
 */
struct spdk_rmem_pool *spdk_rmem_pool_create(const char *name, uint32_t entry_size,
		uint32_t num_entries, uint32_t ext_num_entries);

/**
 * Restore rmem pool.
 *
 * \param name Pool name.
 * \param entry_size Desired entry size.
 * \param cb_fn Callback to be called per restored entry during the restoration process.
 * \param ctx Context passed to the callback.
 *
 * \return Pool object on success, NULL on failure.
 */
struct spdk_rmem_pool *spdk_rmem_pool_restore(const char *name, uint32_t entry_size,
		spdk_rmem_pool_restore_entry_cb cb_fn, void *ctx);

/**
 * Destroy rmem pool.
 *
 * \param pool Pool object.
 */
void spdk_rmem_pool_destroy(struct spdk_rmem_pool *pool);

/**
 * Get rmem entry.
 *
 * \param pool Pool object.
 *
 * \return Entry object on success, NULL on failure.
 */
struct spdk_rmem_entry *spdk_rmem_pool_get(struct spdk_rmem_pool *pool);

/**
 * Write data into rmem entry.
 *
 * \param entry Entry object.
 * \param buf Data to write.
 */
void spdk_rmem_entry_write(struct spdk_rmem_entry *entry, const void *buf);

/**
 * Read data from rmem entry.
 *
 * \param entry Entry object.
 * \param buf Buffer to read the data to.
 *
 * \return true if valid data has been read, false otherwise.
 */
bool spdk_rmem_entry_read(struct spdk_rmem_entry *entry, void *buf);

/**
 * Release rmem entry.
 *
 * \param entry Entry object.
 */
void spdk_rmem_entry_release(struct spdk_rmem_entry *entry);

/**
 * Get number of rmem pool entries.
 *
 * \param pool Pool object.
 *
 * \return Number of entries in pool.
 */
uint32_t spdk_rmem_pool_num_entries(struct spdk_rmem_pool *pool);

#ifdef __cplusplus
}
#endif

#endif /* SPDK_RMEM_H */
