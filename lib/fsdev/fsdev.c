/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/fsdev.h"
#include "spdk/config.h"
#include "spdk/env.h"
#include "spdk/likely.h"
#include "spdk/queue.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/notify.h"
#include "spdk/fsdev_module.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "fsdev_internal.h"

#define SPDK_FSDEV_IO_POOL_SIZE (64 * 1024 - 1)
#define SPDK_FSDEV_IO_CACHE_SIZE 256

static struct spdk_fsdev_opts g_fsdev_opts = {
	.fsdev_io_pool_size = SPDK_FSDEV_IO_POOL_SIZE,
	.fsdev_io_cache_size = SPDK_FSDEV_IO_CACHE_SIZE,
};

TAILQ_HEAD(spdk_fsdev_list, spdk_fsdev);

RB_HEAD(fsdev_name_tree, spdk_fsdev_name);

static int
fsdev_name_cmp(struct spdk_fsdev_name *name1, struct spdk_fsdev_name *name2)
{
	return strcmp(name1->name, name2->name);
}

RB_GENERATE_STATIC(fsdev_name_tree, spdk_fsdev_name, node, fsdev_name_cmp);

struct spdk_fsdev_mgr {
	struct spdk_mempool *fsdev_io_pool;

	TAILQ_HEAD(fsdev_module_list, spdk_fsdev_module) fsdev_modules;

	struct spdk_fsdev_list fsdevs;
	struct fsdev_name_tree fsdev_names;

	bool init_complete;
	bool module_init_complete;

	struct spdk_spinlock spinlock;
};

static struct spdk_fsdev_mgr g_fsdev_mgr = {
	.fsdev_modules = TAILQ_HEAD_INITIALIZER(g_fsdev_mgr.fsdev_modules),
	.fsdevs = TAILQ_HEAD_INITIALIZER(g_fsdev_mgr.fsdevs),
	.fsdev_names = RB_INITIALIZER(g_fsdev_mgr.fsdev_names),
	.init_complete = false,
	.module_init_complete = false,
};

static void
__attribute__((constructor))
_fsdev_init(void)
{
	spdk_spin_init(&g_fsdev_mgr.spinlock);
}


static spdk_fsdev_init_cb	g_init_cb_fn = NULL;
static void			*g_init_cb_arg = NULL;

static spdk_fsdev_fini_cb	g_fini_cb_fn = NULL;
static void			*g_fini_cb_arg = NULL;
static struct spdk_thread	*g_fini_thread = NULL;

typedef STAILQ_HEAD(, spdk_fsdev_io) fsdev_io_stailq_t;

static const char *fsdev_io_type_names[] = {
	"mount",
	"umount",
	"lookup",
	"forget",
	"getattr",
	"setattr",
	"readlink",
	"symlink",
	"mknod",
	"mkdir",
	"unlink",
	"rmdir",
	"rename",
	"link",
	"open",
	"read",
	"write",
	"statfs",
	"release",
	"fsync",
	"setxattr",
	"getxattr",
	"listxattr",
	"removexattr",
	"flush",
	"opendir",
	"readdir",
	"releasedir",
	"fsyncdir",
	"flock",
	"create",
	"abort",
	"fallocate",
	"copy_file_range",
	"syncfs",
	"access",
	"lseek",
	"poll",
	"ioctl",
	"getlk",
	"setlk",
};
SPDK_STATIC_ASSERT(SPDK_COUNTOF(fsdev_io_type_names) == __SPDK_FSDEV_IO_LAST, "Incorrect size");

static const char *fsdev_notify_type_names[] = {
	"inval_data",
	"inval_entry"
};
SPDK_STATIC_ASSERT(SPDK_COUNTOF(fsdev_notify_type_names) == SPDK_FSDEV_NOTIFY_NUM_TYPES,
		   "Incorrect size");

struct spdk_fsdev_mgmt_channel {
	/*
	 * Each thread keeps a cache of fsdev_io - this allows
	 *  fsdev threads which are *not* DPDK threads to still
	 *  benefit from a per-thread fsdev_io cache.  Without
	 *  this, non-DPDK threads fetching from the mempool
	 *  incur a cmpxchg on get and put.
	 */
	fsdev_io_stailq_t per_thread_cache;
	uint32_t	per_thread_cache_count;
	uint32_t	fsdev_io_cache_size;

	TAILQ_HEAD(, spdk_fsdev_shared_resource) shared_resources;
};

/*
 * Per-module (or per-io_device) data. Multiple fsdevs built on the same io_device
 * will queue here their IO that awaits retry. It makes it possible to retry sending
 * IO to one fsdev after IO from other fsdev completes.
 */
struct spdk_fsdev_shared_resource {
	/* The fsdev management channel */
	struct spdk_fsdev_mgmt_channel *mgmt_ch;

	/*
	 * Count of I/O submitted to fsdev module and waiting for completion.
	 * Incremented before submit_request() is called on an spdk_fsdev_io.
	 */
	uint64_t		io_outstanding;

	/* I/O channel allocated by a fsdev module */
	struct spdk_io_channel	*shared_ch;

	/* Refcount of fsdev channels using this resource */
	uint32_t		ref;

	TAILQ_ENTRY(spdk_fsdev_shared_resource) link;
};

#define FSDEV_CH_RESET_IN_PROGRESS	(1 << 0)

struct spdk_fsdev_desc {
	struct spdk_fsdev		*fsdev;
	struct spdk_thread		*thread;
	struct {
		spdk_fsdev_event_cb_t event_fn;
		void *ctx;
	}				callback;
	bool				closed;
	struct spdk_spinlock		spinlock;
	uint32_t			refs;
	TAILQ_ENTRY(spdk_fsdev_desc)	link;
};

struct spdk_fsdev_channel_iter {
	spdk_fsdev_for_each_channel_msg fn;
	spdk_fsdev_for_each_channel_done cpl;
	struct spdk_io_channel_iter *i;
	void *ctx;
};

#define __fsdev_to_io_dev(fsdev)	(((char *)fsdev) + 1)
#define __fsdev_from_io_dev(io_dev)	((struct spdk_fsdev *)(((char *)io_dev) - 1))
#define __io_ch_to_fsdev_mgmt_ch(io_ch)	((struct spdk_fsdev_mgmt_channel *)spdk_io_channel_get_ctx(io_ch))

static struct spdk_fsdev *
fsdev_get_by_name(const char *fsdev_name)
{
	struct spdk_fsdev_name find;
	struct spdk_fsdev_name *res;

	find.name = (char *)fsdev_name;
	res = RB_FIND(fsdev_name_tree, &g_fsdev_mgr.fsdev_names, &find);
	if (res != NULL) {
		return res->fsdev;
	}

	return NULL;
}

static int
fsdev_module_get_max_ctx_size(void)
{
	struct spdk_fsdev_module *fsdev_module;
	int max_fsdev_module_size = 0;

	TAILQ_FOREACH(fsdev_module, &g_fsdev_mgr.fsdev_modules, internal.tailq) {
		if (fsdev_module->get_ctx_size && fsdev_module->get_ctx_size() > max_fsdev_module_size) {
			max_fsdev_module_size = fsdev_module->get_ctx_size();
		}
	}

	return max_fsdev_module_size;
}

void
spdk_fsdev_subsystem_config_json(struct spdk_json_write_ctx *w)
{
	struct spdk_fsdev_module *fsdev_module;
	struct spdk_fsdev *fsdev;

	assert(w != NULL);

	spdk_json_write_array_begin(w);

	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "method", "fsdev_set_opts");
	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_uint32(w, "fsdev_io_pool_size", g_fsdev_opts.fsdev_io_pool_size);
	spdk_json_write_named_uint32(w, "fsdev_io_cache_size", g_fsdev_opts.fsdev_io_cache_size);
	spdk_json_write_object_end(w); /* params */
	spdk_json_write_object_end(w);

	TAILQ_FOREACH(fsdev_module, &g_fsdev_mgr.fsdev_modules, internal.tailq) {
		if (fsdev_module->config_json) {
			fsdev_module->config_json(w);
		}
	}

	spdk_spin_lock(&g_fsdev_mgr.spinlock);

	TAILQ_FOREACH(fsdev, &g_fsdev_mgr.fsdevs, internal.link) {
		if (fsdev->fn_table->write_config_json) {
			fsdev->fn_table->write_config_json(fsdev, w);
		}
	}

	spdk_spin_unlock(&g_fsdev_mgr.spinlock);
	spdk_json_write_array_end(w);
}

static void
fsdev_mgmt_channel_destroy(void *io_device, void *ctx_buf)
{
	struct spdk_fsdev_mgmt_channel *ch = ctx_buf;
	struct spdk_fsdev_io *fsdev_io;

	if (!TAILQ_EMPTY(&ch->shared_resources)) {
		SPDK_ERRLOG("Module channel list wasn't empty on mgmt channel free\n");
	}

	while (!STAILQ_EMPTY(&ch->per_thread_cache)) {
		fsdev_io = STAILQ_FIRST(&ch->per_thread_cache);
		STAILQ_REMOVE_HEAD(&ch->per_thread_cache, internal.buf_link);
		ch->per_thread_cache_count--;
		spdk_mempool_put(g_fsdev_mgr.fsdev_io_pool, (void *)fsdev_io);
	}

	assert(ch->per_thread_cache_count == 0);
	return;
}

static int
fsdev_mgmt_channel_create(void *io_device, void *ctx_buf)
{
	struct spdk_fsdev_mgmt_channel *ch = ctx_buf;
	struct spdk_fsdev_io *fsdev_io;
	uint32_t i;

	STAILQ_INIT(&ch->per_thread_cache);
	ch->fsdev_io_cache_size = g_fsdev_opts.fsdev_io_cache_size;

	/* Pre-populate fsdev_io cache to ensure this thread cannot be starved. */
	ch->per_thread_cache_count = 0;
	for (i = 0; i < ch->fsdev_io_cache_size; i++) {
		fsdev_io = spdk_mempool_get(g_fsdev_mgr.fsdev_io_pool);
		if (fsdev_io == NULL) {
			SPDK_ERRLOG("You need to increase fsdev_io_pool_size using fsdev_set_options RPC.\n");
			assert(false);
			fsdev_mgmt_channel_destroy(io_device, ctx_buf);
			return -1;
		}
		ch->per_thread_cache_count++;
		STAILQ_INSERT_HEAD(&ch->per_thread_cache, fsdev_io, internal.buf_link);
	}

	TAILQ_INIT(&ch->shared_resources);
	return 0;
}

static void
fsdev_init_complete(int rc)
{
	spdk_fsdev_init_cb cb_fn = g_init_cb_fn;
	void *cb_arg = g_init_cb_arg;

	g_fsdev_mgr.init_complete = true;
	g_init_cb_fn = NULL;
	g_init_cb_arg = NULL;

	cb_fn(cb_arg, rc);
}

static void
fsdev_init_failed(void *cb_arg)
{
	fsdev_init_complete(-1);
}

static int
fsdev_modules_init(void)
{
	struct spdk_fsdev_module *module;
	int rc = 0;

	TAILQ_FOREACH(module, &g_fsdev_mgr.fsdev_modules, internal.tailq) {
		rc = module->module_init();
		if (rc != 0) {
			spdk_thread_send_msg(spdk_get_thread(), fsdev_init_failed, module);
			return rc;
		}
	}

	return 0;
}

void
spdk_fsdev_initialize(spdk_fsdev_init_cb cb_fn, void *cb_arg)
{
	int rc = 0;
	char mempool_name[32];

	assert(cb_fn != NULL);

	g_init_cb_fn = cb_fn;
	g_init_cb_arg = cb_arg;

	spdk_notify_type_register("fsdev_register");
	spdk_notify_type_register("fsdev_unregister");

	snprintf(mempool_name, sizeof(mempool_name), "fsdev_io_%d", getpid());

	g_fsdev_mgr.fsdev_io_pool = spdk_mempool_create(mempool_name,
				    g_fsdev_opts.fsdev_io_pool_size,
				    sizeof(struct spdk_fsdev_io) +
				    fsdev_module_get_max_ctx_size(),
				    0,
				    SPDK_ENV_SOCKET_ID_ANY);

	if (g_fsdev_mgr.fsdev_io_pool == NULL) {
		SPDK_ERRLOG("Could not allocate spdk_fsdev_io pool\n");
		fsdev_init_complete(-1);
		return;
	}

	spdk_io_device_register(&g_fsdev_mgr, fsdev_mgmt_channel_create,
				fsdev_mgmt_channel_destroy,
				sizeof(struct spdk_fsdev_mgmt_channel),
				"fsdev_mgr");

	rc = fsdev_modules_init();
	g_fsdev_mgr.module_init_complete = true;
	if (rc != 0) {
		SPDK_ERRLOG("fsdev modules init failed\n");
		return;
	}

	fsdev_init_complete(0);
}

static void
fsdev_mgr_unregister_cb(void *io_device)
{
	spdk_fsdev_fini_cb cb_fn = g_fini_cb_fn;

	if (g_fsdev_mgr.fsdev_io_pool) {
		if (spdk_mempool_count(g_fsdev_mgr.fsdev_io_pool) != g_fsdev_opts.fsdev_io_pool_size) {
			SPDK_ERRLOG("fsdev IO pool count is %zu but should be %u\n",
				    spdk_mempool_count(g_fsdev_mgr.fsdev_io_pool),
				    g_fsdev_opts.fsdev_io_pool_size);
		}

		spdk_mempool_free(g_fsdev_mgr.fsdev_io_pool);
	}

	cb_fn(g_fini_cb_arg);
	g_fini_cb_fn = NULL;
	g_fini_cb_arg = NULL;
	g_fsdev_mgr.init_complete = false;
	g_fsdev_mgr.module_init_complete = false;
}

static void
fsdev_module_fini_iter(void *arg)
{
	struct spdk_fsdev_module *fsdev_module;

	/* FIXME: Handling initialization failures is broken now,
	 * so we won't even try cleaning up after successfully
	 * initialized modules. if module_init_complete is false,
	 * just call spdk_fsdev_mgr_unregister_cb
	 */
	if (!g_fsdev_mgr.module_init_complete) {
		fsdev_mgr_unregister_cb(NULL);
		return;
	}

	/* Start iterating from the last touched module */
	fsdev_module = TAILQ_LAST(&g_fsdev_mgr.fsdev_modules, fsdev_module_list);
	while (fsdev_module) {
		if (fsdev_module->module_fini) {
			fsdev_module->module_fini();
		}

		fsdev_module = TAILQ_PREV(fsdev_module, fsdev_module_list,
					  internal.tailq);
	}

	spdk_io_device_unregister(&g_fsdev_mgr, fsdev_mgr_unregister_cb);
}

static void
fsdev_finish_unregister_fsdevs_iter(void *cb_arg, int fsdeverrno)
{
	struct spdk_fsdev *fsdev = cb_arg;

	if (fsdeverrno && fsdev) {
		SPDK_WARNLOG("Unable to unregister fsdev '%s' during spdk_fsdev_finish()\n",
			     fsdev->name);

		/*
		 * Since the call to spdk_fsdev_unregister() failed, we have no way to free this
		 *  fsdev; try to continue by manually removing this fsdev from the list and continue
		 *  with the next fsdev in the list.
		 */
		TAILQ_REMOVE(&g_fsdev_mgr.fsdevs, fsdev, internal.link);
	}

	fsdev = TAILQ_FIRST(&g_fsdev_mgr.fsdevs);
	if (!fsdev) {
		SPDK_DEBUGLOG(fsdev, "Done unregistering fsdevs\n");
		/*
		 * Fsdev module finish need to be deferred as we might be in the middle of some context
		 * that will use this fsdev (or private fsdev driver ctx data)
		 * after returning.
		 */
		spdk_thread_send_msg(spdk_get_thread(), fsdev_module_fini_iter, NULL);
		return;
	}

	SPDK_DEBUGLOG(fsdev, "Unregistering fsdev '%s'\n", fsdev->name);
	spdk_fsdev_unregister(fsdev, fsdev_finish_unregister_fsdevs_iter, fsdev);
	return;
}

void
spdk_fsdev_finish(spdk_fsdev_fini_cb cb_fn, void *cb_arg)
{
	assert(cb_fn != NULL);
	g_fini_thread = spdk_get_thread();
	g_fini_cb_fn = cb_fn;
	g_fini_cb_arg = cb_arg;
	fsdev_finish_unregister_fsdevs_iter(NULL, 0);
}

struct spdk_fsdev_io *
fsdev_channel_get_io(struct spdk_fsdev_channel *channel)
{
	struct spdk_fsdev_mgmt_channel *ch = channel->shared_resource->mgmt_ch;
	struct spdk_fsdev_io *fsdev_io;

	if (spdk_unlikely(channel->flags & FSDEV_CH_RESET_IN_PROGRESS)) {
		SPDK_DEBUGLOG(fsdev, "Reset in progress: no IO allowed\n");
		return NULL;
	}

	if (ch->per_thread_cache_count > 0) {
		fsdev_io = STAILQ_FIRST(&ch->per_thread_cache);
		STAILQ_REMOVE_HEAD(&ch->per_thread_cache, internal.buf_link);
		ch->per_thread_cache_count--;
	} else {
		fsdev_io = spdk_mempool_get(g_fsdev_mgr.fsdev_io_pool);
	}

	return fsdev_io;
}

void
spdk_fsdev_free_io(struct spdk_fsdev_io *fsdev_io)
{
	struct spdk_fsdev_mgmt_channel *ch;

	assert(fsdev_io != NULL);

	ch = fsdev_io->internal.ch->shared_resource->mgmt_ch;

	if (ch->per_thread_cache_count < ch->fsdev_io_cache_size) {
		ch->per_thread_cache_count++;
		STAILQ_INSERT_HEAD(&ch->per_thread_cache, fsdev_io, internal.buf_link);
	} else {
		spdk_mempool_put(g_fsdev_mgr.fsdev_io_pool, (void *)fsdev_io);
	}
}

void
fsdev_io_submit(struct spdk_fsdev_io *fsdev_io)
{
	struct spdk_fsdev *fsdev = fsdev_io->fsdev;
	struct spdk_fsdev_channel *ch = fsdev_io->internal.ch;
	struct spdk_fsdev_shared_resource *shared_resource = ch->shared_resource;

	TAILQ_INSERT_TAIL(&ch->io_submitted, fsdev_io, internal.ch_link);

	ch->io_outstanding++;
	shared_resource->io_outstanding++;
	fsdev_io->internal.in_submit_request = true;
	fsdev->fn_table->submit_request(ch->channel, fsdev_io);
	fsdev_io->internal.in_submit_request = false;
}

static void
fsdev_channel_destroy_resource(struct spdk_fsdev_channel *ch)
{
	struct spdk_fsdev_shared_resource *shared_resource;

	spdk_put_io_channel(ch->channel);

	shared_resource = ch->shared_resource;

	assert(TAILQ_EMPTY(&ch->io_submitted));
	assert(ch->io_outstanding == 0);
	assert(shared_resource->ref > 0);
	shared_resource->ref--;
	if (shared_resource->ref == 0) {
		assert(shared_resource->io_outstanding == 0);
		TAILQ_REMOVE(&shared_resource->mgmt_ch->shared_resources, shared_resource, link);
		spdk_put_io_channel(spdk_io_channel_from_ctx(shared_resource->mgmt_ch));
		free(shared_resource);
	}
}

static void
fsdev_desc_free(struct spdk_fsdev_desc *desc)
{
	spdk_spin_destroy(&desc->spinlock);
	free(desc);
}

static void
fsdev_init_io_stat(struct spdk_fsdev_io_stat *stat)
{
	size_t i;

	memset(stat, 0, sizeof(*stat));

	for (i = 0; i < SPDK_COUNTOF(stat->io); i++) {
		stat->io[i].min_latency_ticks = UINT64_MAX;
	}
}

static int
fsdev_channel_create(void *io_device, void *ctx_buf)
{
	struct spdk_fsdev		*fsdev = __fsdev_from_io_dev(io_device);
	struct spdk_fsdev_channel	*ch = ctx_buf;
	struct spdk_io_channel		*mgmt_io_ch;
	struct spdk_fsdev_mgmt_channel	*mgmt_ch;
	struct spdk_fsdev_shared_resource *shared_resource;

	ch->fsdev = fsdev;

	ch->stat = calloc(1, sizeof(*ch->stat));
	if (!ch->stat) {
		return -1;
	}

	ch->channel = fsdev->fn_table->get_io_channel(fsdev->ctxt);
	if (!ch->channel) {
		free(ch->stat);
		return -1;
	}

	mgmt_io_ch = spdk_get_io_channel(&g_fsdev_mgr);
	if (!mgmt_io_ch) {
		spdk_put_io_channel(ch->channel);
		free(ch->stat);
		return -1;
	}

	mgmt_ch = __io_ch_to_fsdev_mgmt_ch(mgmt_io_ch);
	TAILQ_FOREACH(shared_resource, &mgmt_ch->shared_resources, link) {
		if (shared_resource->shared_ch == ch->channel) {
			spdk_put_io_channel(mgmt_io_ch);
			shared_resource->ref++;
			break;
		}
	}

	if (shared_resource == NULL) {
		shared_resource = calloc(1, sizeof(*shared_resource));
		if (shared_resource == NULL) {
			spdk_put_io_channel(ch->channel);
			spdk_put_io_channel(mgmt_io_ch);
			return -1;
		}

		shared_resource->mgmt_ch = mgmt_ch;
		shared_resource->io_outstanding = 0;
		shared_resource->shared_ch = ch->channel;
		shared_resource->ref = 1;
		TAILQ_INSERT_TAIL(&mgmt_ch->shared_resources, shared_resource, link);
	}

	ch->io_outstanding = 0;
	ch->shared_resource = shared_resource;
	TAILQ_INIT(&ch->io_submitted);
	fsdev_init_io_stat(ch->stat);

	return 0;
}

static void
fsdev_add_io_stat(struct spdk_fsdev_io_stat *to_stat, const struct spdk_fsdev_io_stat *from_stat)
{
	size_t i;

	for (i = 0; i < SPDK_COUNTOF(from_stat->io); i++) {
		to_stat->io[i].count += from_stat->io[i].count;

		if (to_stat->io[i].max_latency_ticks < from_stat->io[i].max_latency_ticks) {
			to_stat->io[i].max_latency_ticks = from_stat->io[i].max_latency_ticks;
		}

		if (to_stat->io[i].min_latency_ticks > from_stat->io[i].min_latency_ticks) {
			to_stat->io[i].min_latency_ticks = from_stat->io[i].min_latency_ticks;
		}
	}

	to_stat->bytes_read += from_stat->bytes_read;
	to_stat->bytes_written += from_stat->bytes_written;
	to_stat->num_out_of_io += from_stat->num_out_of_io;
	to_stat->num_io_errors += from_stat->num_io_errors;
	for (i = 0; i < SPDK_COUNTOF(from_stat->num_notifies); i++) {
		to_stat->num_notifies[i] += from_stat->num_notifies[i];
	}
}

static void
fsdev_channel_destroy(void *io_device, void *ctx_buf)
{
	struct spdk_fsdev_channel *ch = ctx_buf;
	struct spdk_fsdev *fsdev = ch->fsdev;

	SPDK_DEBUGLOG(fsdev, "Destroying channel %p for fsdev %s on thread %p\n",
		      ch, fsdev->name, spdk_get_thread());

	spdk_spin_lock(&fsdev->internal.spinlock);
	fsdev_add_io_stat(fsdev->internal.hist_stat, ch->stat);
	spdk_spin_unlock(&fsdev->internal.spinlock);

	free(ch->stat);
	fsdev_channel_destroy_resource(ch);
}

/*
 * If the name already exists in the global fsdev name tree, RB_INSERT() returns a pointer
 * to it. Hence we do not have to call fsdev_get_by_name() when using this function.
 */
static int
fsdev_name_add(struct spdk_fsdev_name *fsdev_name, struct spdk_fsdev *fsdev, const char *name)
{
	struct spdk_fsdev_name *tmp;

	fsdev_name->name = strdup(name);
	if (fsdev_name->name == NULL) {
		SPDK_ERRLOG("Unable to allocate fsdev name\n");
		return -ENOMEM;
	}

	fsdev_name->fsdev = fsdev;

	spdk_spin_lock(&g_fsdev_mgr.spinlock);
	tmp = RB_INSERT(fsdev_name_tree, &g_fsdev_mgr.fsdev_names, fsdev_name);
	spdk_spin_unlock(&g_fsdev_mgr.spinlock);
	if (tmp != NULL) {
		SPDK_ERRLOG("Fsdev name %s already exists\n", name);
		free(fsdev_name->name);
		return -EEXIST;
	}

	return 0;
}

static void
fsdev_name_del_unsafe(struct spdk_fsdev_name *fsdev_name)
{
	RB_REMOVE(fsdev_name_tree, &g_fsdev_mgr.fsdev_names, fsdev_name);
	free(fsdev_name->name);
}

struct spdk_io_channel *
spdk_fsdev_get_io_channel(struct spdk_fsdev_desc *desc)
{
	return spdk_get_io_channel(__fsdev_to_io_dev(spdk_fsdev_desc_get_fsdev(desc)));
}

int
spdk_fsdev_set_opts(const struct spdk_fsdev_opts *opts)
{
	uint32_t min_pool_size;

	if (!opts) {
		SPDK_ERRLOG("opts cannot be NULL\n");
		return -EINVAL;
	}

	if (!opts->opts_size) {
		SPDK_ERRLOG("opts_size inside opts cannot be zero value\n");
		return -EINVAL;
	}

	/*
	 * Add 1 to the thread count to account for the extra mgmt_ch that gets created during subsystem
	 *  initialization.  A second mgmt_ch will be created on the same thread when the application starts
	 *  but before the deferred put_io_channel event is executed for the first mgmt_ch.
	 */
	min_pool_size = opts->fsdev_io_cache_size * (spdk_thread_get_count() + 1);
	if (opts->fsdev_io_pool_size < min_pool_size) {
		SPDK_ERRLOG("fsdev_io_pool_size %" PRIu32 " is not compatible with fsdev_io_cache_size %" PRIu32
			    " and %" PRIu32 " threads\n", opts->fsdev_io_pool_size, opts->fsdev_io_cache_size,
			    spdk_thread_get_count());
		SPDK_ERRLOG("fsdev_io_pool_size must be at least %" PRIu32 "\n", min_pool_size);
		return -EINVAL;
	}

#define SET_FIELD(field) \
        if (offsetof(struct spdk_fsdev_opts, field) + sizeof(opts->field) <= opts->opts_size) { \
                g_fsdev_opts.field = opts->field; \
        } \

	SET_FIELD(fsdev_io_pool_size);
	SET_FIELD(fsdev_io_cache_size);

	g_fsdev_opts.opts_size = opts->opts_size;

#undef SET_FIELD

	return 0;
}

int
spdk_fsdev_get_opts(struct spdk_fsdev_opts *opts, size_t opts_size)
{
	if (!opts) {
		SPDK_ERRLOG("opts should not be NULL\n");
		return -EINVAL;
	}

	if (!opts_size) {
		SPDK_ERRLOG("opts_size should not be zero value\n");
		return -EINVAL;
	}

	opts->opts_size = opts_size;

#define SET_FIELD(field) \
	if (offsetof(struct spdk_fsdev_opts, field) + sizeof(opts->field) <= opts_size) { \
		opts->field = g_fsdev_opts.field; \
	}

	SET_FIELD(fsdev_io_pool_size);
	SET_FIELD(fsdev_io_cache_size);

	/* Do not remove this statement, you should always update this statement when you adding a new field,
	 * and do not forget to add the SET_FIELD statement for your added field. */
	SPDK_STATIC_ASSERT(sizeof(struct spdk_fsdev_opts) == 12, "Incorrect size");

#undef SET_FIELD
	return 0;
}

int
spdk_fsdev_get_memory_domains(struct spdk_fsdev *fsdev, struct spdk_memory_domain **domains,
			      int array_size)
{
	if (!fsdev) {
		return -EINVAL;
	}

	if (fsdev->fn_table->get_memory_domains) {
		return fsdev->fn_table->get_memory_domains(fsdev->ctxt, domains, array_size);
	}

	return 0;
}


int
spdk_fsdev_dump_info_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w)
{
	if (fsdev->fn_table->dump_info_json) {
		return fsdev->fn_table->dump_info_json(fsdev->ctxt, w);
	}

	return 0;
}

void
spdk_fsdev_for_each_channel_continue(struct spdk_fsdev_channel_iter *iter, int status)
{
	spdk_for_each_channel_continue(iter->i, status);
}

static struct spdk_fsdev *
io_channel_iter_get_fsdev(struct spdk_io_channel_iter *i)
{
	void *io_device = spdk_io_channel_iter_get_io_device(i);

	return __fsdev_from_io_dev(io_device);
}

static void
fsdev_each_channel_msg(struct spdk_io_channel_iter *i)
{
	struct spdk_fsdev_channel_iter *iter = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fsdev *fsdev = io_channel_iter_get_fsdev(i);
	struct spdk_io_channel *ch = spdk_io_channel_iter_get_channel(i);

	iter->i = i;
	iter->fn(iter, fsdev, ch, iter->ctx);
}

static void
fsdev_each_channel_cpl(struct spdk_io_channel_iter *i, int status)
{
	struct spdk_fsdev_channel_iter *iter = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fsdev *fsdev = io_channel_iter_get_fsdev(i);

	iter->i = i;
	iter->cpl(fsdev, iter->ctx, status);

	free(iter);
}

void
spdk_fsdev_for_each_channel(struct spdk_fsdev *fsdev, spdk_fsdev_for_each_channel_msg fn,
			    void *ctx, spdk_fsdev_for_each_channel_done cpl)
{
	struct spdk_fsdev_channel_iter *iter;

	assert(fsdev != NULL && fn != NULL && ctx != NULL);

	iter = calloc(1, sizeof(struct spdk_fsdev_channel_iter));
	if (iter == NULL) {
		SPDK_ERRLOG("Unable to allocate iterator\n");
		assert(false);
		return;
	}

	iter->fn = fn;
	iter->cpl = cpl;
	iter->ctx = ctx;

	spdk_for_each_channel(__fsdev_to_io_dev(fsdev), fsdev_each_channel_msg,
			      iter, fsdev_each_channel_cpl);
}

struct fsdev_reset_ctx {
	struct spdk_fsdev_desc *desc;
	spdk_fsdev_reset_completion_cb cb;
	void *cb_arg;
	bool success;
};

static void
fsdev_reset_done(struct fsdev_reset_ctx *ctx)
{
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(ctx->desc);

	__atomic_clear(&fsdev->internal.reset_in_progress, __ATOMIC_RELAXED);
	ctx->cb(ctx->desc, ctx->success, ctx->cb_arg);
	free(ctx);
}

static void
fsdev_reset_unfreeze_channel_msg_cb(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *_ch = spdk_io_channel_iter_get_channel(i);
	struct spdk_fsdev_channel *ch = __io_ch_to_fsdev_ch(_ch);

	ch->flags &= ~FSDEV_CH_RESET_IN_PROGRESS;

	spdk_for_each_channel_continue(i, 0);
}

static void
fsdev_reset_unfreeze_channel_cpl_cb(struct spdk_io_channel_iter *i, int status)
{
	struct fsdev_reset_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(ctx->desc);

	if (status) {
		SPDK_ERRLOG("%s: channels unfreeze failed with %d\n", spdk_fsdev_get_name(fsdev), status);
		ctx->success = false;
	}

	fsdev_reset_done(ctx);
}

static void
fsdev_reset_finalize(struct fsdev_reset_ctx *ctx)
{
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(ctx->desc);

	spdk_for_each_channel(__fsdev_to_io_dev(fsdev), fsdev_reset_unfreeze_channel_msg_cb, ctx,
			      fsdev_reset_unfreeze_channel_cpl_cb);
}

static void
fsdev_reset_purge_channel_msg_cb(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *_ch = spdk_io_channel_iter_get_channel(i);
	struct fsdev_reset_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fsdev_channel *ch = __io_ch_to_fsdev_ch(_ch);

	if (ch->io_outstanding) {
		struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(ctx->desc);
		SPDK_WARNLOG("%s: %s: still has %" PRIu64 " uncompleted IOs. Purging them...\n",
			     spdk_fsdev_get_name(fsdev), spdk_thread_get_name(spdk_get_thread()), ch->io_outstanding);
		/* Force the remained outstanding IOs */
		while (!TAILQ_EMPTY(&ch->io_submitted)) {
			struct spdk_fsdev_io *fsdev_io = TAILQ_FIRST(&ch->io_submitted);
			spdk_fsdev_io_complete(fsdev_io, -ECANCELED);
		}
	}

	spdk_for_each_channel_continue(i, 0);
}

static void
fsdev_reset_purge_channel_cpl_cb(struct spdk_io_channel_iter *i, int status)
{
	struct fsdev_reset_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(ctx->desc);

	if (status) {
		SPDK_ERRLOG("%s: channels purge failed with %d\n", spdk_fsdev_get_name(fsdev), status);
	} else {
		SPDK_DEBUGLOG(fsdev, "%s: channels purge succeeded\n", spdk_fsdev_get_name(fsdev));
		ctx->success = true;
	}

	fsdev_reset_finalize(ctx);
}

static void
fsdev_module_reset_done_cb(void *cb_arg, int rc)
{
	struct fsdev_reset_ctx *ctx = cb_arg;
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(ctx->desc);

	if (rc) {
		/* Module's reset failed */
		SPDK_ERRLOG("%s: module reset failed with %d\n", spdk_fsdev_get_name(fsdev), rc);
		fsdev_reset_finalize(ctx);
		return;
	}

	/* Now we sweep the remaining IOs (theoretically there should be none) */
	spdk_for_each_channel(__fsdev_to_io_dev(fsdev), fsdev_reset_purge_channel_msg_cb, ctx,
			      fsdev_reset_purge_channel_cpl_cb);
}

static void
fsdev_reset_freeze_channel_msg_cb(struct spdk_io_channel_iter *i)
{
	struct spdk_io_channel *_ch = spdk_io_channel_iter_get_channel(i);
	struct spdk_fsdev_channel *ch = __io_ch_to_fsdev_ch(_ch);

	ch->flags |= FSDEV_CH_RESET_IN_PROGRESS;

	spdk_for_each_channel_continue(i, 0);
}

static void
fsdev_reset_freeze_channel_cpl_cb(struct spdk_io_channel_iter *i, int status)
{
	struct fsdev_reset_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(ctx->desc);
	int res;

	if (status) {
		SPDK_ERRLOG("%s: channels freeze failed with %d\n", spdk_fsdev_get_name(fsdev), status);
		fsdev_reset_finalize(ctx);
		return;
	}

	/* Then we give the module an opportunity to complete all the outstanding IOs and reset itself */
	res = fsdev->fn_table->reset(fsdev->ctxt, fsdev_module_reset_done_cb, ctx);
	if (res) {
		SPDK_ERRLOG("%s: module reset failed with %d\n", spdk_fsdev_get_name(fsdev), res);
		fsdev_reset_finalize(ctx);
	}
}

int
spdk_fsdev_reset(struct spdk_fsdev_desc *desc, spdk_fsdev_reset_completion_cb cb, void *cb_arg)
{
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(desc);
	struct fsdev_reset_ctx *ctx;

	if (!spdk_fsdev_reset_supported(fsdev)) {
		return -EOPNOTSUPP;
	}

	if (__atomic_test_and_set(&fsdev->internal.reset_in_progress, __ATOMIC_RELAXED)) {
		SPDK_ERRLOG("Previous reset is in progress\n");
		return -EINPROGRESS;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		SPDK_ERRLOG("Failed to allocate memory for reset context\n");
		return -ENOMEM;
	}

	ctx->desc = desc;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;
	ctx->success = false;

	/* First we freeze the channels */
	spdk_for_each_channel(__fsdev_to_io_dev(fsdev), fsdev_reset_freeze_channel_msg_cb, ctx,
			      fsdev_reset_freeze_channel_cpl_cb);

	return 0;
}

int
spdk_fsdev_enable_notifications(struct spdk_fsdev_desc *desc, spdk_fsdev_notify_cb_t notify_cb,
				void *ctx)
{
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(desc);
	int res = 0;

	if (!fsdev->fn_table->set_notifications) {
		return -EOPNOTSUPP;
	}

	spdk_spin_lock(&fsdev->internal.spinlock);
	if (!fsdev->internal.notify_cb) {
		res = fsdev->fn_table->set_notifications(fsdev->ctxt, true);
		if (!res) {
			fsdev->internal.notify_cb = notify_cb;
			fsdev->internal.notify_ctx = ctx;
		}
	} else {
		res = -EALREADY;
	}
	spdk_spin_unlock(&fsdev->internal.spinlock);

	return res;
}

int
spdk_fsdev_disable_notifications(struct spdk_fsdev_desc *desc)
{
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(desc);
	int res = 0;

	if (!fsdev->fn_table->set_notifications) {
		return -EOPNOTSUPP;
	}

	spdk_spin_lock(&fsdev->internal.spinlock);
	if (fsdev->internal.notify_cb) {
		res = fsdev->fn_table->set_notifications(fsdev->ctxt, false);
		if (!res) {
			fsdev->internal.notify_cb = NULL;
			fsdev->internal.notify_ctx = NULL;
		}
	} else {
		res = -EALREADY;
	}
	spdk_spin_unlock(&fsdev->internal.spinlock);

	return res;
}

uint32_t
spdk_fsdev_get_notify_max_data_size(const struct spdk_fsdev *fsdev)
{
	return fsdev->notify_max_data_size;
}

static int
fsdev_notify(struct spdk_fsdev *fsdev, const struct spdk_fsdev_notify_data *notify_data,
	     spdk_fsdev_notify_reply_cb_t reply_cb, void *reply_ctx)
{
	int res = -ENODEV;

	if (fsdev->internal.notify_cb) {
		fsdev->internal.notify_cb(fsdev, fsdev->internal.notify_ctx, notify_data,
					  reply_cb, reply_ctx);
		res = 0;
		spdk_spin_lock(&fsdev->internal.spinlock);
		fsdev->internal.hist_stat->num_notifies[notify_data->type]++;
		spdk_spin_unlock(&fsdev->internal.spinlock);
	}

	return res;
}

int
spdk_fsdev_notify_inval_data(struct spdk_fsdev *fsdev,
			     struct spdk_fsdev_file_object *fobject,
			     uint64_t offset, size_t size,
			     spdk_fsdev_notify_reply_cb_t reply_cb,
			     void *reply_ctx)
{
	struct spdk_fsdev_notify_data notify_data = {
		.type = SPDK_FSDEV_NOTIFY_INVAL_DATA,
		.inval_data.fobject = fobject,
		.inval_data.offset = offset,
		.inval_data.size = size
	};

	return fsdev_notify(fsdev, &notify_data, reply_cb, reply_ctx);
}

int
spdk_fsdev_notify_inval_entry(struct spdk_fsdev *fsdev,
			      struct spdk_fsdev_file_object *parent_fobject,
			      const char *name,
			      spdk_fsdev_notify_reply_cb_t reply_cb,
			      void *reply_ctx)
{
	struct spdk_fsdev_notify_data notify_data = {
		.type = SPDK_FSDEV_NOTIFY_INVAL_ENTRY,
		.inval_entry.parent_fobject = parent_fobject,
		.inval_entry.name = name
	};

	return fsdev_notify(fsdev, &notify_data, reply_cb, reply_ctx);
}

bool
spdk_fsdev_reset_supported(struct spdk_fsdev *fsdev)
{
	return fsdev->fn_table->reset ? true : false;
}

bool
spdk_fsdev_is_recovered(struct spdk_fsdev *fsdev)
{
	return fsdev->fn_table->is_recovered ? fsdev->fn_table->is_recovered(fsdev->ctxt) : false;
}

void
spdk_fsdev_get_io_stat(struct spdk_fsdev *fsdev, struct spdk_io_channel *_ch,
		       struct spdk_fsdev_io_stat *stat)
{
	struct spdk_fsdev_channel *ch = __io_ch_to_fsdev_ch(_ch);

	fsdev_init_io_stat(stat);

	fsdev_add_io_stat(stat, ch->stat);
}

struct spdk_fsdev_get_stat_ctx {
	struct spdk_fsdev_io_stat *stat;
	spdk_fsdev_get_device_stat_cb cb;
	void *cb_arg;
};

static void
fsdev_get_channel_stat(struct spdk_fsdev_channel_iter *i, struct spdk_fsdev *fsdev,
		       struct spdk_io_channel *_ch, void *_ctx)
{
	struct spdk_fsdev_get_stat_ctx *ctx = _ctx;
	struct spdk_fsdev_channel *ch = __io_ch_to_fsdev_ch(_ch);

	fsdev_add_io_stat(ctx->stat, ch->stat);

	spdk_fsdev_for_each_channel_continue(i, 0);
}

static void
fsdev_get_device_stat_done(struct spdk_fsdev *fsdev, void *_ctx, int status)
{
	struct spdk_fsdev_get_stat_ctx *ctx = _ctx;

	ctx->cb(fsdev, ctx->stat, ctx->cb_arg, status);

	free(ctx);
}

void
spdk_fsdev_get_device_stat(struct spdk_fsdev *fsdev, struct spdk_fsdev_io_stat *stat,
			   spdk_fsdev_get_device_stat_cb cb, void *cb_arg)
{
	struct spdk_fsdev_get_stat_ctx *ctx;

	assert(fsdev != NULL);
	assert(stat != NULL);
	assert(cb != NULL);

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		SPDK_ERRLOG("Unable to allocate context\n");
		cb(fsdev, stat, cb_arg, -ENOMEM);
		return;
	}

	fsdev_init_io_stat(stat);

	/* Start with the statistics from previously deleted channels. */
	spdk_spin_lock(&fsdev->internal.spinlock);
	fsdev_add_io_stat(stat, fsdev->internal.hist_stat);
	spdk_spin_unlock(&fsdev->internal.spinlock);

	ctx->stat = stat;
	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	/* Then iterate and add the statistics from each existing channel. */
	spdk_fsdev_for_each_channel(fsdev, fsdev_get_channel_stat, ctx,
				    fsdev_get_device_stat_done);
}

struct spdk_fsdev_reset_stat_ctx {
	spdk_fsdev_reset_device_stat_cb cb;
	void *cb_arg;
};

static void
fsdev_reset_channel_stat(struct spdk_fsdev_channel_iter *i, struct spdk_fsdev *fsdev,
			 struct spdk_io_channel *_ch, void *_ctx)
{
	struct spdk_fsdev_channel *ch = __io_ch_to_fsdev_ch(_ch);

	fsdev_init_io_stat(ch->stat);

	spdk_fsdev_for_each_channel_continue(i, 0);
}

static void
fsdev_reset_device_stat_done(struct spdk_fsdev *fsdev, void *_ctx, int status)
{
	struct spdk_fsdev_reset_stat_ctx *ctx = _ctx;

	ctx->cb(fsdev, ctx->cb_arg, status);

	free(ctx);
}

void
spdk_fsdev_reset_device_stat(struct spdk_fsdev *fsdev, spdk_fsdev_reset_device_stat_cb cb,
			     void *cb_arg)
{
	struct spdk_fsdev_reset_stat_ctx *ctx;

	assert(fsdev != NULL);
	assert(cb != NULL);

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		SPDK_ERRLOG("Unable to allocate context\n");
		cb(fsdev, cb_arg, -ENOMEM);
		return;
	}

	/* Start with the statistics from previously deleted channels. */
	spdk_spin_lock(&fsdev->internal.spinlock);
	fsdev_init_io_stat(fsdev->internal.hist_stat);
	spdk_spin_unlock(&fsdev->internal.spinlock);

	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	/* Then iterate and add the statistics from each existing channel. */
	spdk_fsdev_for_each_channel(fsdev, fsdev_reset_channel_stat, ctx,
				    fsdev_reset_device_stat_done);
}

const char *
spdk_fsdev_get_module_name(const struct spdk_fsdev *fsdev)
{
	return fsdev->module->name;
}

const char *
spdk_fsdev_get_name(const struct spdk_fsdev *fsdev)
{
	return fsdev->name;
}

static inline void
fsdev_io_complete(void *ctx)
{
	struct spdk_fsdev_io *fsdev_io = ctx;
	struct spdk_fsdev_channel *fsdev_ch = fsdev_io->internal.ch;

	if (spdk_unlikely(fsdev_io->internal.in_submit_request)) {
		/*
		 * Defer completion to avoid potential infinite recursion if the
		 * user's completion callback issues a new I/O.
		 */
		spdk_thread_send_msg(spdk_fsdev_io_get_thread(fsdev_io),
				     fsdev_io_complete, fsdev_io);
		return;
	}

	TAILQ_REMOVE(&fsdev_ch->io_submitted, fsdev_io, internal.ch_link);

	assert(fsdev_io->internal.cb_fn != NULL);
	assert(spdk_get_thread() == spdk_fsdev_io_get_thread(fsdev_io));
	fsdev_io->internal.cb_fn(fsdev_io, fsdev_io->internal.cb_arg);
}


void
spdk_fsdev_io_complete(struct spdk_fsdev_io *fsdev_io, int status)
{
	struct spdk_fsdev_channel *fsdev_ch = fsdev_io->internal.ch;
	struct spdk_fsdev_shared_resource *shared_resource = fsdev_ch->shared_resource;

	assert(status <= 0);
	fsdev_io->internal.status = status;
	assert(fsdev_ch->io_outstanding > 0);
	assert(shared_resource->io_outstanding > 0);
	fsdev_ch->io_outstanding--;
	shared_resource->io_outstanding--;
	fsdev_io_complete(fsdev_io);
}

struct spdk_thread *
spdk_fsdev_io_get_thread(struct spdk_fsdev_io *fsdev_io)
{
	return spdk_io_channel_get_thread(fsdev_io->internal.ch->channel);
}

struct spdk_io_channel *
spdk_fsdev_io_get_io_channel(struct spdk_fsdev_io *fsdev_io)
{
	return fsdev_io->internal.ch->channel;
}

static int
fsdev_register(struct spdk_fsdev *fsdev)
{
	char *fsdev_name;
	int ret;

	assert(fsdev->module != NULL);

	if (!fsdev->name) {
		SPDK_ERRLOG("Fsdev name is NULL\n");
		return -EINVAL;
	}

	if (!strlen(fsdev->name)) {
		SPDK_ERRLOG("Fsdev name must not be an empty string\n");
		return -EINVAL;
	}

	/* Users often register their own I/O devices using the fsdev name. In
	 * order to avoid conflicts, prepend fsdev_. */
	fsdev_name = spdk_sprintf_alloc("fsdev_%s", fsdev->name);
	if (!fsdev_name) {
		SPDK_ERRLOG("Unable to allocate memory for internal fsdev name.\n");
		return -ENOMEM;
	}

	fsdev->internal.hist_stat = calloc(1, sizeof(*fsdev->internal.hist_stat));
	if (!fsdev->internal.hist_stat) {
		SPDK_ERRLOG("Unable to allocate memory for the stats history.\n");
		free(fsdev_name);
		return -ENOMEM;
	}

	fsdev->internal.status = SPDK_FSDEV_STATUS_READY;
	TAILQ_INIT(&fsdev->internal.open_descs);
	fsdev_init_io_stat(fsdev->internal.hist_stat);

	ret = fsdev_name_add(&fsdev->internal.fsdev_name, fsdev, fsdev->name);
	if (ret != 0) {
		free(fsdev_name);
		free(fsdev->internal.hist_stat);
		return ret;
	}

	spdk_io_device_register(__fsdev_to_io_dev(fsdev),
				fsdev_channel_create, fsdev_channel_destroy,
				sizeof(struct spdk_fsdev_channel),
				fsdev_name);

	free(fsdev_name);

	spdk_spin_init(&fsdev->internal.spinlock);

	SPDK_DEBUGLOG(fsdev, "Inserting fsdev %s into list\n", fsdev->name);
	TAILQ_INSERT_TAIL(&g_fsdev_mgr.fsdevs, fsdev, internal.link);
	return 0;
}

static void
fsdev_destroy_cb(void *io_device)
{
	int			rc;
	struct spdk_fsdev	*fsdev;
	spdk_fsdev_unregister_cb cb_fn;
	void			*cb_arg;

	fsdev = __fsdev_from_io_dev(io_device);
	cb_fn = fsdev->internal.unregister_cb;
	cb_arg = fsdev->internal.unregister_ctx;

	free(fsdev->internal.hist_stat);
	spdk_spin_destroy(&fsdev->internal.spinlock);

	rc = fsdev->fn_table->destruct(fsdev->ctxt);
	if (rc < 0) {
		SPDK_ERRLOG("destruct failed\n");
	}
	if (rc <= 0 && cb_fn != NULL) {
		cb_fn(cb_arg, rc);
	}
}

void
spdk_fsdev_destruct_done(struct spdk_fsdev *fsdev, int fsdeverrno)
{
	if (fsdev->internal.unregister_cb != NULL) {
		fsdev->internal.unregister_cb(fsdev->internal.unregister_ctx, fsdeverrno);
	}
}

static void
_remove_notify(void *arg)
{
	struct spdk_fsdev_desc *desc = arg;

	spdk_spin_lock(&desc->spinlock);
	desc->refs--;

	if (!desc->closed) {
		spdk_spin_unlock(&desc->spinlock);
		desc->callback.event_fn(SPDK_FSDEV_EVENT_REMOVE, desc->fsdev, desc->callback.ctx);
		return;
	} else if (0 == desc->refs) {
		/* This descriptor was closed after this remove_notify message was sent.
		 * spdk_fsdev_close() could not free the descriptor since this message was
		 * in flight, so we free it now using fsdev_desc_free().
		 */
		spdk_spin_unlock(&desc->spinlock);
		fsdev_desc_free(desc);
		return;
	}
	spdk_spin_unlock(&desc->spinlock);
}

/* Must be called while holding g_fsdev_mgr.mutex and fsdev->internal.spinlock.
 * returns: 0 - fsdev removed and ready to be destructed.
 *          -EBUSY - fsdev can't be destructed yet.  */
static int
fsdev_unregister_unsafe(struct spdk_fsdev *fsdev)
{
	struct spdk_fsdev_desc	*desc, *tmp;
	int			rc = 0;

	/* Notify each descriptor about hotremoval */
	TAILQ_FOREACH_SAFE(desc, &fsdev->internal.open_descs, link, tmp) {
		rc = -EBUSY;
		spdk_spin_lock(&desc->spinlock);
		/*
		 * Defer invocation of the event_cb to a separate message that will
		 *  run later on its thread.  This ensures this context unwinds and
		 *  we don't recursively unregister this fsdev again if the event_cb
		 *  immediately closes its descriptor.
		 */
		desc->refs++;
		spdk_thread_send_msg(desc->thread, _remove_notify, desc);
		spdk_spin_unlock(&desc->spinlock);
	}

	/* If there are no descriptors, proceed removing the fsdev */
	if (rc == 0) {
		TAILQ_REMOVE(&g_fsdev_mgr.fsdevs, fsdev, internal.link);
		SPDK_DEBUGLOG(fsdev, "Removing fsdev %s from list done\n", fsdev->name);
		fsdev_name_del_unsafe(&fsdev->internal.fsdev_name);
		spdk_notify_send("fsdev_unregister", spdk_fsdev_get_name(fsdev));
	}

	return rc;
}

static void
fsdev_unregister(struct spdk_fsdev *fsdev, void *_ctx, int status)
{
	int rc;

	spdk_spin_lock(&g_fsdev_mgr.spinlock);
	spdk_spin_lock(&fsdev->internal.spinlock);
	/*
	 * Set the status to REMOVING after completing to abort channels. Otherwise,
	 * the last spdk_fsdev_close() may call spdk_io_device_unregister() while
	 * spdk_fsdev_for_each_channel() is executed and spdk_io_device_unregister()
	 * may fail.
	 */
	fsdev->internal.status = SPDK_FSDEV_STATUS_REMOVING;
	rc = fsdev_unregister_unsafe(fsdev);
	spdk_spin_unlock(&fsdev->internal.spinlock);
	spdk_spin_unlock(&g_fsdev_mgr.spinlock);

	if (rc == 0) {
		spdk_io_device_unregister(__fsdev_to_io_dev(fsdev), fsdev_destroy_cb);
	}
}

void
spdk_fsdev_unregister(struct spdk_fsdev *fsdev, spdk_fsdev_unregister_cb cb_fn, void *cb_arg)
{
	struct spdk_thread	*thread;

	SPDK_DEBUGLOG(fsdev, "Removing fsdev %s from list\n", fsdev->name);

	thread = spdk_get_thread();
	if (!thread) {
		/* The user called this from a non-SPDK thread. */
		if (cb_fn != NULL) {
			cb_fn(cb_arg, -ENOTSUP);
		}
		return;
	}

	spdk_spin_lock(&g_fsdev_mgr.spinlock);
	if (fsdev->internal.status == SPDK_FSDEV_STATUS_UNREGISTERING ||
	    fsdev->internal.status == SPDK_FSDEV_STATUS_REMOVING) {
		spdk_spin_unlock(&g_fsdev_mgr.spinlock);
		if (cb_fn) {
			cb_fn(cb_arg, -EBUSY);
		}
		return;
	}

	spdk_spin_lock(&fsdev->internal.spinlock);
	fsdev->internal.status = SPDK_FSDEV_STATUS_UNREGISTERING;
	fsdev->internal.unregister_cb = cb_fn;
	fsdev->internal.unregister_ctx = cb_arg;
	spdk_spin_unlock(&fsdev->internal.spinlock);
	spdk_spin_unlock(&g_fsdev_mgr.spinlock);

	/* @todo: fsdev aborts IOs on all channels here. */
	fsdev_unregister(fsdev, fsdev, 0);
}

static void
_tmp_fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *ctx)
{
	SPDK_NOTICELOG("Unexpected fsdev event type: %d\n", type);
}

int
spdk_fsdev_unregister_by_name(const char *fsdev_name, struct spdk_fsdev_module *module,
			      spdk_fsdev_unregister_cb cb_fn, void *cb_arg)
{
	struct spdk_fsdev_desc *desc;
	struct spdk_fsdev *fsdev;
	int rc;

	rc = spdk_fsdev_open(fsdev_name, _tmp_fsdev_event_cb, NULL, &desc);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to open fsdev with name: %s\n", fsdev_name);
		return rc;
	}

	fsdev = spdk_fsdev_desc_get_fsdev(desc);

	if (fsdev->module != module) {
		spdk_fsdev_close(desc);
		SPDK_ERRLOG("Fsdev %s was not registered by the specified module.\n",
			    fsdev_name);
		return -ENODEV;
	}

	spdk_fsdev_unregister(fsdev, cb_fn, cb_arg);
	spdk_fsdev_close(desc);

	return 0;
}

static int
fsdev_open(struct spdk_fsdev *fsdev, struct spdk_fsdev_desc *desc)
{
	struct spdk_thread *thread;

	thread = spdk_get_thread();
	if (!thread) {
		SPDK_ERRLOG("Cannot open fsdev from non-SPDK thread.\n");
		return -ENOTSUP;
	}

	SPDK_DEBUGLOG(fsdev, "Opening descriptor %p for fsdev %s on thread %p\n",
		      desc, fsdev->name, spdk_get_thread());

	desc->fsdev = fsdev;
	desc->thread = thread;

	spdk_spin_lock(&fsdev->internal.spinlock);
	if (fsdev->internal.status == SPDK_FSDEV_STATUS_UNREGISTERING ||
	    fsdev->internal.status == SPDK_FSDEV_STATUS_REMOVING) {
		spdk_spin_unlock(&fsdev->internal.spinlock);
		return -ENODEV;
	}

	TAILQ_INSERT_TAIL(&fsdev->internal.open_descs, desc, link);
	spdk_spin_unlock(&fsdev->internal.spinlock);
	return 0;
}

static int
fsdev_desc_alloc(struct spdk_fsdev *fsdev, spdk_fsdev_event_cb_t event_cb, void *event_ctx,
		 struct spdk_fsdev_desc **_desc)
{
	struct spdk_fsdev_desc *desc;

	desc = calloc(1, sizeof(*desc));
	if (desc == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for fsdev descriptor\n");
		return -ENOMEM;
	}

	desc->callback.event_fn = event_cb;
	desc->callback.ctx = event_ctx;
	spdk_spin_init(&desc->spinlock);
	*_desc = desc;
	return 0;
}

int
spdk_fsdev_open(const char *fsdev_name, spdk_fsdev_event_cb_t event_cb, void *event_ctx,
		struct spdk_fsdev_desc **_desc)
{
	struct spdk_fsdev_desc *desc;
	struct spdk_fsdev *fsdev;
	int rc;

	if (event_cb == NULL) {
		SPDK_ERRLOG("Missing event callback function\n");
		return -EINVAL;
	}

	spdk_spin_lock(&g_fsdev_mgr.spinlock);

	fsdev = fsdev_get_by_name(fsdev_name);
	if (fsdev == NULL) {
		SPDK_NOTICELOG("Currently unable to find fsdev with name: %s\n", fsdev_name);
		spdk_spin_unlock(&g_fsdev_mgr.spinlock);
		return -ENODEV;
	}

	rc = fsdev_desc_alloc(fsdev, event_cb, event_ctx, &desc);
	if (rc != 0) {
		spdk_spin_unlock(&g_fsdev_mgr.spinlock);
		return rc;
	}

	rc = fsdev_open(fsdev, desc);
	if (rc != 0) {
		fsdev_desc_free(desc);
		desc = NULL;
	}

	*_desc = desc;
	spdk_spin_unlock(&g_fsdev_mgr.spinlock);
	return rc;
}

static void
fsdev_close(struct spdk_fsdev *fsdev, struct spdk_fsdev_desc *desc)
{
	int rc;

	spdk_spin_lock(&fsdev->internal.spinlock);
	spdk_spin_lock(&desc->spinlock);

	TAILQ_REMOVE(&fsdev->internal.open_descs, desc, link);
	desc->closed = true;
	if (0 == desc->refs) {
		spdk_spin_unlock(&desc->spinlock);
		fsdev_desc_free(desc);
	} else {
		spdk_spin_unlock(&desc->spinlock);
	}

	if (fsdev->internal.status == SPDK_FSDEV_STATUS_REMOVING &&
	    TAILQ_EMPTY(&fsdev->internal.open_descs)) {
		rc = fsdev_unregister_unsafe(fsdev);
		spdk_spin_unlock(&fsdev->internal.spinlock);

		if (rc == 0) {
			spdk_io_device_unregister(__fsdev_to_io_dev(fsdev), fsdev_destroy_cb);
		}
	} else {
		spdk_spin_unlock(&fsdev->internal.spinlock);
	}
}

void
spdk_fsdev_close(struct spdk_fsdev_desc *desc)
{
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(desc);

	SPDK_DEBUGLOG(fsdev, "Closing descriptor %p for fsdev %s on thread %p\n",
		      desc, fsdev->name, spdk_get_thread());
	assert(desc->thread == spdk_get_thread());
	spdk_spin_lock(&g_fsdev_mgr.spinlock);
	fsdev_close(fsdev, desc);
	spdk_spin_unlock(&g_fsdev_mgr.spinlock);
}

static struct spdk_fsdev *
spdk_fsdev_first(void)
{
	struct spdk_fsdev *fsdev;

	fsdev = TAILQ_FIRST(&g_fsdev_mgr.fsdevs);
	if (fsdev) {
		SPDK_DEBUGLOG(fsdev, "Starting fsdev iteration at %s\n", fsdev->name);
	}

	return fsdev;
}

static struct spdk_fsdev *
spdk_fsdev_next(struct spdk_fsdev *prev)
{
	struct spdk_fsdev *fsdev;

	fsdev = TAILQ_NEXT(prev, internal.link);
	if (fsdev) {
		SPDK_DEBUGLOG(fsdev, "Continuing fsdev iteration at %s\n", fsdev->name);
	}

	return fsdev;
}

int
spdk_for_each_fsdev(void *ctx, spdk_for_each_fsdev_fn fn)
{
	struct spdk_fsdev *fsdev, *tmp;
	struct spdk_fsdev_desc *desc;
	int rc = 0;

	assert(fn != NULL);

	spdk_spin_lock(&g_fsdev_mgr.spinlock);
	fsdev = spdk_fsdev_first();
	while (fsdev != NULL) {
		rc = fsdev_desc_alloc(fsdev, _tmp_fsdev_event_cb, NULL, &desc);
		if (rc != 0) {
			break;
		}
		rc = fsdev_open(fsdev, desc);
		if (rc != 0) {
			fsdev_desc_free(desc);
			if (rc == -ENODEV) {
				/* Ignore the error and move to the next fsdev. */
				rc = 0;
				fsdev = spdk_fsdev_next(fsdev);
				continue;
			}
			break;
		}
		spdk_spin_unlock(&g_fsdev_mgr.spinlock);

		rc = fn(ctx, fsdev);

		spdk_spin_lock(&g_fsdev_mgr.spinlock);
		tmp = spdk_fsdev_next(fsdev);
		fsdev_close(fsdev, desc);
		if (rc != 0) {
			break;
		}
		fsdev = tmp;
	}
	spdk_spin_unlock(&g_fsdev_mgr.spinlock);

	return rc;
}

const char *
spdk_fsdev_io_type_get_name(enum spdk_fsdev_io_type type)
{
	return (type < SPDK_COUNTOF(fsdev_io_type_names)) ? fsdev_io_type_names[type] : NULL;
}

const char *
fsdev_notify_type_get_name(enum spdk_fsdev_notify_type type)
{
	assert(type < SPDK_FSDEV_NOTIFY_NUM_TYPES);
	return (type < SPDK_COUNTOF(fsdev_notify_type_names)) ? fsdev_notify_type_names[type] : NULL;
}

int
spdk_fsdev_register(struct spdk_fsdev *fsdev)
{
	int rc;

	rc = fsdev_register(fsdev);
	if (rc != 0) {
		return rc;
	}

	spdk_notify_send("fsdev_register", spdk_fsdev_get_name(fsdev));
	return rc;
}

struct spdk_fsdev *
spdk_fsdev_desc_get_fsdev(struct spdk_fsdev_desc *desc)
{
	assert(desc != NULL);
	return desc->fsdev;
}

void
spdk_fsdev_module_list_add(struct spdk_fsdev_module *fsdev_module)
{

	if (spdk_fsdev_module_list_find(fsdev_module->name)) {
		SPDK_ERRLOG("ERROR: module '%s' already registered.\n", fsdev_module->name);
		assert(false);
	}

	TAILQ_INSERT_TAIL(&g_fsdev_mgr.fsdev_modules, fsdev_module, internal.tailq);
}

struct spdk_fsdev_module *
spdk_fsdev_module_list_find(const char *name)
{
	struct spdk_fsdev_module *fsdev_module;

	TAILQ_FOREACH(fsdev_module, &g_fsdev_mgr.fsdev_modules, internal.tailq) {
		if (strcmp(name, fsdev_module->name) == 0) {
			break;
		}
	}

	return fsdev_module;
}

SPDK_LOG_REGISTER_COMPONENT(fsdev)
