/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

/*
 * Recovery Memory Pool implementation.
 */

#include "spdk/assert.h"
#include "spdk/env.h"
#include "spdk/util.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/json.h"
#include "spdk/barrier.h"
#include "spdk/rmem.h"

#define NUM_RMEM_POOL_VERSION		1
#define NUM_RMEM_POOL_BUCKETS		10
#define MAX_RMEM_POOL_NAME_LEN		31

#define RMEM_POOL_ALIGNMENT		8 /* bytes */

static pthread_spinlock_t		g_lock;
static TAILQ_HEAD(, spdk_rmem_pool)	g_pools;
static char				*g_backend_dir_name = NULL;
static int				g_backend_dir = -1;

/* NOTE: The RMEM_DBG_DO_CRASH macro and enum rmem_dbg_crash_point are only used in
 * the test/rmem_pool/rmem_pool_write_crash_test - the SPDK rmem_pool write crash test
 * For normal compilation the RMEM_DBG_DO_CRASH() is defined as empty.
 */
#ifdef RMEM_DBG_DO_CRASH
enum rmem_dbg_crash_point {
	RMEM_DBG_CRASH_POINT_OLD_COPY,
	RMEM_DBG_CRASH_POINT_BOTH_COPIES,
	RMEM_DBG_CRASH_POINT_NEW_COPY,
	__RMEM_DBG_CRASH_POINT_LAST
};
#else
#define RMEM_DBG_DO_CRASH(x)
#endif

struct rmem_pool_hdr {
	uint16_t hdr_size;
	uint16_t version;
	uint32_t entry_size;
	uint32_t num_entries;
	uint32_t ext_num_entries;
};

/* NOTE: sizeof(struct rmem_pool_hdr) must be aligned to uint64_t */
SPDK_STATIC_ASSERT(sizeof(struct rmem_pool_hdr) == 16, "Incorrect size");

#define ENTRY_HDR_VALID_OFFS 32
#define ENTRY_HDR_VALID_MASK 0x100000000
#define ENTRY_HDR_MIRROR_OFFS 0
#define ENTRY_HDR_MIRROR_MASK 0xFFFFFFFF

#define INVALID_MIRROR_IDX UINT32_MAX

struct rmem_entry_hdr {
	uint64_t state;
};

SPDK_STATIC_ASSERT(sizeof(struct rmem_entry_hdr) == 8, "Incorrect size");

struct spdk_rmem_entry {
	struct spdk_rmem_pool *pool;
	uint32_t idx;
	TAILQ_ENTRY(spdk_rmem_entry) link;
};

struct spdk_rmem_pool {
	struct {
		int fd;
		uint8_t *addr;
		uint64_t size;
	} mapped;
	pthread_spinlock_t lock;
	TAILQ_ENTRY(spdk_rmem_pool) link;
	char name[MAX_RMEM_POOL_NAME_LEN + 1];
	TAILQ_HEAD(, spdk_rmem_entry) active_entries;
	TAILQ_HEAD(, spdk_rmem_entry) free_entries;
	struct spdk_rmem_entry **mirror_entries;
};

static inline void
rmem_entry_set_state(struct rmem_entry_hdr *hdr, bool valid, uint32_t mirror_idx)
{
	uint64_t new_state = ((uint64_t)(!!valid) << ENTRY_HDR_VALID_OFFS) |
			     ((uint64_t)mirror_idx << ENTRY_HDR_MIRROR_OFFS);

	/* To make sure that the write cannot be interrupted
	 * NOTE: __ATOMIC_RELAXED as we handle the ordering manually.
	 */
	__atomic_store_n(&hdr->state, new_state, __ATOMIC_RELAXED);

	/* To prevent reordering by compiler */
	spdk_compiler_barrier();
}

static inline bool
rmem_entry_is_valid(struct rmem_entry_hdr *hdr)
{
	uint64_t state = __atomic_load_n(&hdr->state, __ATOMIC_RELAXED);
	return (state & ENTRY_HDR_VALID_MASK) != 0;
}

static inline uint32_t
rmem_entry_mirror_idx(struct rmem_entry_hdr *hdr)
{
	uint64_t state = __atomic_load_n(&hdr->state, __ATOMIC_RELAXED);
	return (uint32_t)((state & ENTRY_HDR_MIRROR_MASK) >> ENTRY_HDR_MIRROR_OFFS);
}

static inline uint32_t
rmem_pool_full_entry_size(uint32_t entry_size)
{
	/* entries will be aligned  to uint64_t */
	return SPDK_ALIGN_CEIL(sizeof(struct rmem_entry_hdr) + entry_size, RMEM_POOL_ALIGNMENT);
}

static uint32_t
rmem_pool_file_size(uint32_t num_entries, uint32_t entry_size)
{
	size_t pg_size = sysconf(_SC_PAGE_SIZE);
	size_t file_size = sizeof(struct rmem_pool_hdr);

	file_size += rmem_pool_full_entry_size(entry_size) * num_entries;

	/* mmap works with pages, so the size is aligned to the page size */
	file_size = SPDK_ALIGN_CEIL(file_size, pg_size);

	return file_size;
}

static uint32_t
rmem_pool_num_entries_by_file_size(uint32_t size, uint32_t entry_size)
{
	assert(size % sysconf(_SC_PAGE_SIZE) == 0);

	return (size - sizeof(struct rmem_pool_hdr)) / rmem_pool_full_entry_size(entry_size);
}

static inline struct rmem_pool_hdr *
rmem_pool_hdr(struct spdk_rmem_pool *pool)
{
	return (struct rmem_pool_hdr *)pool->mapped.addr;
}

static inline uint8_t *
rmem_pool_entries(struct spdk_rmem_pool *pool)
{
	return pool->mapped.addr + sizeof(struct rmem_pool_hdr);
}

static inline struct rmem_entry_hdr *
rmem_pool_get_mapped_entry(struct spdk_rmem_pool *pool, uint32_t idx)
{
	assert(idx < rmem_pool_hdr(pool)->num_entries);

	return (struct rmem_entry_hdr *)(rmem_pool_entries(pool) +
					 rmem_pool_full_entry_size(rmem_pool_hdr(pool)->entry_size) * idx);
}

static inline void *
rmem_pool_entry_data(struct spdk_rmem_entry *entry)
{
	struct rmem_entry_hdr *hdr = rmem_pool_get_mapped_entry(entry->pool, entry->idx);

	return ((uint8_t *)hdr) + sizeof(*hdr);
}

static bool
rmem_pool_extend(struct spdk_rmem_pool *pool, uint32_t num_entries, uint32_t delta,
		 uint32_t entry_size, bool restore)
{
	uint32_t new_num_entries;
	uint32_t new_size;
	uint8_t *new_addr;
	uint32_t i;
	struct spdk_rmem_entry *entry;
	TAILQ_HEAD(, spdk_rmem_entry) new_entries;

	new_num_entries = num_entries + delta;
	new_size = rmem_pool_file_size(new_num_entries, entry_size);

	/* As the mmap only works with pages, the new_size >= old_size + PAGE_SIZE
	 * So, despite the fact that we've been asked to extend the pool by delta entries,
	 * it's possible that we actually extend it by more, up to the next page boundary.
	 */
	new_num_entries = rmem_pool_num_entries_by_file_size(new_size, entry_size);

	if (ftruncate(pool->mapped.fd, new_size) != 0) {
		SPDK_ERRLOG("%s: truncate to %" PRIu32 " bytes failed (err=%d)\n", pool->name, new_size, errno);
		return false;
	}

	new_addr = pool->mapped.addr ?
		   mremap(pool->mapped.addr, pool->mapped.size, new_size, MREMAP_MAYMOVE) :
		   mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, pool->mapped.fd, 0);
	if (new_addr == MAP_FAILED) {
		SPDK_ERRLOG("%s: %s to %" PRIu32 " bytes failed (err=%d)\n",
			    pool->mapped.addr ? "mremap" : "mmap", pool->name, new_size, errno);
		return false;
	}

	TAILQ_INIT(&new_entries);
	for (i = num_entries; i < new_num_entries; i++) {
		entry = calloc(1, sizeof(*entry));
		if (!entry) {
			SPDK_ERRLOG("%s: cannot allocate entry object\n", pool->name);
			while (!TAILQ_EMPTY(&new_entries)) {
				entry = TAILQ_FIRST(&new_entries);
				TAILQ_REMOVE(&new_entries, entry, link);
				free(entry);
			}
			munmap(new_addr, new_size);
			return false;
		}

		entry->idx = i;
		entry->pool = pool;
		TAILQ_INSERT_TAIL(&new_entries, entry, link);
	}

	pool->mapped.addr = new_addr;
	pool->mapped.size = new_size;

	rmem_pool_hdr(pool)->num_entries = new_num_entries;

	for (i = num_entries; i < new_num_entries; i++) {
		struct rmem_entry_hdr *hdr, *mirror_hdr;
		uint32_t entry_mirror_idx;

		entry = TAILQ_FIRST(&new_entries);
		TAILQ_REMOVE(&new_entries, entry, link);

		hdr = rmem_pool_get_mapped_entry(pool, entry->idx);
		if (!restore) {
			rmem_entry_set_state(hdr, false, INVALID_MIRROR_IDX);
			TAILQ_INSERT_TAIL(&pool->free_entries, entry, link);
			continue;
		}

		if (!rmem_entry_is_valid(hdr)) {
			TAILQ_INSERT_TAIL(&pool->free_entries, entry, link);
			continue;
		}

		entry_mirror_idx = rmem_entry_mirror_idx(hdr);
		if (entry_mirror_idx == INVALID_MIRROR_IDX) {
			TAILQ_INSERT_TAIL(&pool->active_entries, entry, link);
			continue;
		}

		/* The app was terminated while updating this entry, so check whether the updated copy is valid */
		mirror_hdr = rmem_pool_get_mapped_entry(pool, entry_mirror_idx);
		if (rmem_entry_is_valid(mirror_hdr)) {
			/*
			 * The update had actually finished, so mark this entry as invalid and add to the free pool.
			 * The updated copy will be added to the active pool automatically.
			 */
			rmem_entry_set_state(hdr, false, INVALID_MIRROR_IDX);
			TAILQ_INSERT_TAIL(&pool->free_entries, entry, link);
		} else {
			/* The update was interrupted, so add this entry to active pool */
			TAILQ_INSERT_TAIL(&pool->active_entries, entry, link);
		}
	}

	return true;
}

int
spdk_rmem_init(void)
{
	TAILQ_INIT(&g_pools);
	pthread_spin_init(&g_lock, PTHREAD_PROCESS_PRIVATE);
	g_backend_dir = -1;
	g_backend_dir_name = NULL;
	return 0;
}

bool
spdk_rmem_is_enabled(void)
{
	return g_backend_dir != -1;
}

bool
spdk_rmem_enable(const char *backend_dir)
{
	assert(TAILQ_EMPTY(&g_pools));

	if (g_backend_dir != -1) {
		close(g_backend_dir);
		g_backend_dir = -1;
	}

	free(g_backend_dir_name);
	g_backend_dir_name = NULL;

	if (!backend_dir) {
		SPDK_INFOLOG(rmem_pool, "Disabled");
		return true;
	}

	g_backend_dir = open(backend_dir, O_PATH);
	if (g_backend_dir == -1) {
		SPDK_ERRLOG("Cannot open backend dir '%s' (err=%d)\n", backend_dir, errno);
		return false;
	}

	g_backend_dir_name = strdup(backend_dir);
	if (!g_backend_dir_name) {
		SPDK_ERRLOG("Cannot duplicate backend dir path '%s'\n", backend_dir);
		close(g_backend_dir);
		g_backend_dir = -1;
		return false;
	}

	SPDK_INFOLOG(rmem_pool, "Enabled with backend dir '%s'\n", backend_dir);
	return true;
}

void
spdk_rmem_fini(void)
{
	assert(TAILQ_EMPTY(&g_pools));
	if (g_backend_dir != -1) {
		close(g_backend_dir);
	}
	free(g_backend_dir_name);
	pthread_spin_destroy(&g_lock);
}

void
spdk_rmem_subsystem_config_json(struct spdk_json_write_ctx *w)
{
	spdk_json_write_array_begin(w);
	pthread_spin_lock(&g_lock);

	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "method", "rmem_enable");
	spdk_json_write_named_object_begin(w, "params");
	if (g_backend_dir_name) {
		spdk_json_write_named_string(w, "backend_dir", g_backend_dir_name);
	}
	spdk_json_write_object_end(w); /* params */
	spdk_json_write_object_end(w);

	pthread_spin_unlock(&g_lock);
	spdk_json_write_array_end(w);
}

void
spdk_rmem_dump_info_json(struct spdk_json_write_ctx *w)
{
	spdk_json_write_named_object_begin(w, "params");
	if (g_backend_dir_name) {
		spdk_json_write_named_string(w, "backend_dir", g_backend_dir_name);
	} else {
		spdk_json_write_named_null(w, "backend_dir");
	}
	spdk_json_write_object_end(w); /* params */
}

static struct spdk_rmem_pool *
rmem_pool_create_or_restore(const char *name, bool restore, uint32_t entry_size,
			    uint32_t num_entries, uint32_t ext_num_entries)
{
	struct spdk_rmem_pool *pool = NULL;
	size_t name_len;
	int oflags;
	int fd;
	uint32_t i;
	uint32_t core_count;

	if (!spdk_rmem_is_enabled()) {
		SPDK_ERRLOG("rmem is disabled\n");
		goto bad_params;
	}

	if (!name) {
		SPDK_ERRLOG("rmem pool name is mandatory\n");
		goto bad_params;
	}

	name_len = strnlen(name, SPDK_SIZEOF_MEMBER(struct spdk_rmem_pool, name));
	if (!name_len) {
		SPDK_ERRLOG("rmem pool name cannot be empty\n");
		goto bad_params;
	} else if (name_len == SPDK_SIZEOF_MEMBER(struct spdk_rmem_pool, name)) {
		SPDK_ERRLOG("rmem pool name is too long (max %zu chars)\n",
			    SPDK_SIZEOF_MEMBER(struct spdk_rmem_pool, name) - 1);
		goto bad_params;
	}

	oflags = restore ? O_RDWR : (O_RDWR | O_CREAT);
	fd = openat(g_backend_dir, name, oflags, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		SPDK_ERRLOG("%s: open failed (err=%d)\n", name, errno);
		goto open_failed;
	}

	if (!restore && ftruncate(fd, 0) != 0) {
		SPDK_ERRLOG("%s: truncate failed (err=%d)\n", name, errno);
		goto file_error;
	}

	if (restore) {
		/* Get num_entries from shmem */
		struct rmem_pool_hdr *hdr;

		hdr = mmap(NULL, sizeof(*hdr), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (hdr == MAP_FAILED) {
			SPDK_ERRLOG("%s: header mmap failed (err=%d)\n", name, errno);
			goto file_error;
		}

		if (hdr->hdr_size != sizeof(*hdr)) {
			SPDK_ERRLOG("%s: incorrect header size (%" PRIu16 "! = %zu)\n",
				    name, hdr->hdr_size, sizeof(*hdr));
			munmap(hdr, sizeof(*hdr));
			goto file_error;
		}

		if (hdr->version != NUM_RMEM_POOL_VERSION) {
			SPDK_ERRLOG("%s: unsupported pool version (%" PRIu16 "! = %d)\n",
				    name, hdr->version, NUM_RMEM_POOL_VERSION);
			munmap(hdr, sizeof(*hdr));
			goto file_error;
		}

		if (hdr->entry_size != entry_size) {
			SPDK_ERRLOG("%s: incorrect entry size (%" PRIu32 "! = %" PRIu32 ")\n",
				    name, hdr->entry_size, entry_size);
			munmap(hdr, sizeof(*hdr));
			goto file_error;
		}

		num_entries = hdr->num_entries;

		munmap(hdr, sizeof(*hdr));
	}

	pthread_spin_lock(&g_lock);
	TAILQ_FOREACH(pool, &g_pools, link) {
		if (!strcmp(name, pool->name)) {
			SPDK_ERRLOG("%s: already registered.\n", name);
			goto pool_registered;
		}
	}

	pool = calloc(1, sizeof(*pool));
	if (!pool) {
		SPDK_ERRLOG("%s: cannot be allocated\n", name);
		goto alloc_failed;
	}

	core_count = spdk_env_get_core_count();
	pool->mirror_entries = calloc(core_count, sizeof(struct spdk_rmem_entry *));
	if (!pool->mirror_entries) {
		SPDK_ERRLOG("%s: extra entries array cannot be allocated\n", name);
		goto extra_alloc_failed;
	}

	memcpy(pool->name, name, name_len + 1);
	pool->mapped.fd = fd;
	TAILQ_INIT(&pool->active_entries);
	TAILQ_INIT(&pool->free_entries);

	if (!rmem_pool_extend(pool, 0, num_entries + core_count, entry_size, restore)) {
		SPDK_ERRLOG("%s: pool_extend failed\n", name);
		goto pool_extend_failed;
	}

	for (i = 0; i < core_count; i++) {
		struct spdk_rmem_entry *entry = NULL;

		entry = TAILQ_FIRST(&pool->free_entries);
		TAILQ_REMOVE(&pool->free_entries, entry, link);

		pool->mirror_entries[i] = entry;
	}

	SPDK_DEBUGLOG(rmem_pool, "%s: %" PRIu32 " entries reserved for the non-destructive write\n",
		      name, i);

	if (!restore) {
		/* Init the pool header */
		rmem_pool_hdr(pool)->hdr_size = sizeof(struct rmem_pool_hdr);
		rmem_pool_hdr(pool)->version = NUM_RMEM_POOL_VERSION;
		rmem_pool_hdr(pool)->entry_size = entry_size;
		rmem_pool_hdr(pool)->ext_num_entries = ext_num_entries;
	}

	pthread_spin_init(&pool->lock, PTHREAD_PROCESS_PRIVATE);
	TAILQ_INSERT_HEAD(&g_pools, pool, link);
	pthread_spin_unlock(&g_lock);

	SPDK_DEBUGLOG(rmem_pool, "%s: rmem pool successfully %s\n", name, restore ? "restored" : "created");
	return pool;

pool_extend_failed:
	free(pool->mirror_entries);
extra_alloc_failed:
	free(pool);
alloc_failed:
pool_registered:
	pthread_spin_unlock(&g_lock);
file_error:
	close(fd);
open_failed:
bad_params:
	return NULL;
}

struct spdk_rmem_pool *
spdk_rmem_pool_create(const char *name, uint32_t entry_size, uint32_t num_entries,
		      uint32_t ext_num_entries)
{
	return rmem_pool_create_or_restore(name, false, entry_size, num_entries, ext_num_entries);
}

struct spdk_rmem_pool *
spdk_rmem_pool_restore(const char *name, uint32_t entry_size, spdk_rmem_pool_restore_entry_cb cb_fn,
		       void *ctx)
{
	struct spdk_rmem_pool *pool;
	struct spdk_rmem_entry *entry;

	pool = rmem_pool_create_or_restore(name, true, entry_size, 0, 0);
	if (!pool) {
		goto restore_failed;
	}

	TAILQ_FOREACH(entry, &pool->active_entries, link) {
		struct rmem_entry_hdr *hdr;

		hdr = rmem_pool_get_mapped_entry(pool, entry->idx);
		if (rmem_entry_is_valid(hdr)) {
			int res;

			res = cb_fn(entry, ctx);
			if (res) {
				SPDK_ERRLOG("%s: restore_entry_clb failed (err=%d)\n", name, res);
				goto clb_failed;
			}
		}
	}

	return pool;

clb_failed:
	spdk_rmem_pool_destroy(pool);
restore_failed:
	return NULL;
}

void
spdk_rmem_pool_destroy(struct spdk_rmem_pool *pool)
{
	struct spdk_rmem_entry *entry;
	uint32_t i;

	pthread_spin_lock(&g_lock);
	TAILQ_REMOVE(&g_pools, pool, link);
	pthread_spin_unlock(&g_lock);

	for (i = 0; i < spdk_env_get_core_count(); i++) {
		free(pool->mirror_entries[i]);
	}
	while ((entry = TAILQ_FIRST(&pool->active_entries))) {
		TAILQ_REMOVE(&pool->active_entries, entry, link);
		free(entry);
	}
	while ((entry = TAILQ_FIRST(&pool->free_entries))) {
		TAILQ_REMOVE(&pool->free_entries, entry, link);
		free(entry);
	}
	pthread_spin_destroy(&pool->lock);
	munmap(pool->mapped.addr, pool->mapped.size);
	unlinkat(g_backend_dir, pool->name, 0);
	SPDK_DEBUGLOG(rmem_pool, "%s: rmem pool destroyed\n", pool->name);
	free(pool->mirror_entries);
	free(pool);
}

struct spdk_rmem_entry *
spdk_rmem_pool_get(struct spdk_rmem_pool *pool)
{
	struct spdk_rmem_entry *entry = NULL;

	pthread_spin_lock(&pool->lock);
	if (TAILQ_EMPTY(&pool->free_entries)) {
		if (!rmem_pool_extend(pool, rmem_pool_hdr(pool)->num_entries,
				      rmem_pool_hdr(pool)->ext_num_entries,
				      rmem_pool_hdr(pool)->entry_size, false)) {
			SPDK_ERRLOG("%s: segment cannot be added\n", pool->name);
			goto out;
		}
	}

	entry = TAILQ_FIRST(&pool->free_entries);
	TAILQ_REMOVE(&pool->free_entries, entry, link);
	TAILQ_INSERT_TAIL(&pool->active_entries, entry, link);

out:
	pthread_spin_unlock(&pool->lock);

	return entry;
}

void
spdk_rmem_entry_write(struct spdk_rmem_entry *entry, const void *buf)
{
	struct spdk_rmem_pool *pool = entry->pool;
	struct rmem_entry_hdr *old_hdr;
	struct spdk_rmem_entry *new_entry;
	struct rmem_entry_hdr *new_hdr;
	uint32_t core_idx, old_entry_idx;

	old_hdr = rmem_pool_get_mapped_entry(pool, entry->idx);

	if (!rmem_entry_is_valid(old_hdr)) {
		memcpy(rmem_pool_entry_data(entry), buf, rmem_pool_hdr(pool)->entry_size);
		spdk_compiler_barrier(); /* memcpy should be done before the following state change */
		rmem_entry_set_state(old_hdr, true, INVALID_MIRROR_IDX);
		return;
	}

	/* Get new (mirror) entry from the pre-core mirror entries pool */
	core_idx = spdk_env_get_core_index(spdk_env_get_current_core());
	new_entry = pool->mirror_entries[core_idx];
	new_hdr = rmem_pool_get_mapped_entry(pool, new_entry->idx);

	/* Write data to the mirror entry
	 * NOTE: there's no need in barrier here as this memcpy and the following set_state can be reordered
	 */
	memcpy(rmem_pool_entry_data(new_entry), buf, rmem_pool_hdr(pool)->entry_size);

	/* Set old entry's mirror index.
	 * NOTE: if the app crashes after this step, the old copy will prevail as the new one is still invalid
	 */
	rmem_entry_set_state(old_hdr, true, new_entry->idx);

	RMEM_DBG_DO_CRASH(RMEM_DBG_CRASH_POINT_OLD_COPY);

	/* Mark new copy valid.
	 * NOTE: if the app crashes after this step, the new copy will prevail as it's already been marked as valid
	 */
	rmem_entry_set_state(new_hdr, true, INVALID_MIRROR_IDX);

	RMEM_DBG_DO_CRASH(RMEM_DBG_CRASH_POINT_BOTH_COPIES);

	/* Finally, release the old copy by marking it as invalid and resetting the mirror index */
	rmem_entry_set_state(old_hdr, false, INVALID_MIRROR_IDX);

	RMEM_DBG_DO_CRASH(RMEM_DBG_CRASH_POINT_NEW_COPY);

	/* Swap indexes, so the entry object will now point to the mirror index */
	old_entry_idx = entry->idx;
	entry->idx = new_entry->idx;
	new_entry->idx = old_entry_idx;
}

bool
spdk_rmem_entry_read(struct spdk_rmem_entry *entry, void *buf)
{
	struct spdk_rmem_pool *pool = entry->pool;
	struct rmem_entry_hdr *hdr = rmem_pool_get_mapped_entry(pool, entry->idx);
	bool res = false;

	if (rmem_entry_is_valid(hdr)) {
		memcpy(buf, rmem_pool_entry_data(entry), rmem_pool_hdr(pool)->entry_size);
		res = true;
	}

	return res;
}

void
spdk_rmem_entry_release(struct spdk_rmem_entry *entry)
{
	struct spdk_rmem_pool *pool = entry->pool;
	struct rmem_entry_hdr *hdr;

	pthread_spin_lock(&pool->lock);
	hdr = rmem_pool_get_mapped_entry(pool, entry->idx);
	rmem_entry_set_state(hdr, false, INVALID_MIRROR_IDX);
	TAILQ_REMOVE(&pool->active_entries, entry, link);
	TAILQ_INSERT_TAIL(&pool->free_entries, entry, link);
	pthread_spin_unlock(&pool->lock);
}

uint32_t
spdk_rmem_pool_num_entries(struct spdk_rmem_pool *pool)
{
	return rmem_pool_hdr(pool)->num_entries - spdk_env_get_core_count();
}

SPDK_LOG_REGISTER_COMPONENT(rmem_pool)
