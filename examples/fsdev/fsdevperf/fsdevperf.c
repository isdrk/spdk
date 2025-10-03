/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/conf.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/fsdev.h"
#include "spdk/likely.h"
#include "spdk/rpc.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"

#ifdef SPDK_CONFIG_RDMA
#include "spdk_internal/rdma_utils.h"
#endif

/*
 * fsdevperf_job describes a single job (i.e. pattern, io_size, etc.), spawned across multiple
 * threads, while fsdevperf_task represents part of that job responsible for submitting IOs to a
 * given file on a given thread.
 */
struct fsdevperf_task;

struct fsdevperf_thread {
	struct spdk_thread		*thread;
	uint32_t			core;
	uint64_t			id;
	TAILQ_HEAD(, fsdevperf_task)	tasks;
	TAILQ_ENTRY(fsdevperf_thread)	tailq;
};

struct fsdevperf_fuse_io {
	struct {
		struct fuse_in_header		hdr;
		union {
			struct fuse_init_in	init;
			struct fuse_open_in	open;
			struct fuse_create_in	create;
			struct fuse_release_in	release;
			struct fuse_forget_in	forget;
			struct fuse_read_in	read;
			struct fuse_write_in	write;
		} op;
		struct iovec			iovs[1];
	} in;
	struct {
		struct fuse_out_header			hdr;
		union {
			struct fuse_init_out		init;
			struct fuse_entry_out		entry;
			struct fuse_open_out		open;
			struct fuse_statfs_out		statfs;
			struct spdk_fuse_create_out	create;
			struct fuse_write_out		write;
		} op;
	} out;
};

struct fsdevperf_io {
	struct fsdevperf_fuse_io		fuse_io;
	struct spdk_fsdev_io			fsdev_io;
};
SPDK_STATIC_ASSERT(offsetof(struct fsdevperf_io, fsdev_io) % 8 == 0, "misalignment");

struct fsdevperf_request {
	struct fsdevperf_task	*task;
	struct iovec		*iovs;
	uint32_t		iovcnt;
	struct fsdevperf_io	io;
};
SPDK_STATIC_ASSERT(offsetof(struct fsdevperf_request, io) % 8 == 0, "misalignment");

struct fsdevperf_stats {
	uint64_t	num_ios;
	uint64_t	num_bytes;
};

struct fsdevperf_filesystem {
	struct spdk_fsdev_desc			*fsdev_desc;
	uint64_t				supported_fuse_opcodes;
	struct spdk_fsdev_file_object		*root;
	struct spdk_io_channel			*ioch;
	TAILQ_ENTRY(fsdevperf_filesystem)	tailq;
	struct fsdevperf_fuse_io		fuse_io;
	int					io_ctx_size;
	struct fsdevperf_io			io;
};
SPDK_STATIC_ASSERT(offsetof(struct fsdevperf_filesystem, io) % 8 == 0, "misalignment");

struct fsdevperf_file {
	struct fsdevperf_filesystem		*fs;
	struct spdk_fsdev_file_object		*fobj;
	struct spdk_fsdev_file_handle		*fh;
	size_t					size;
	char					*name;
	TAILQ_ENTRY(fsdevperf_file)		tailq;
};

struct fsdevperf_domain {
	struct spdk_memory_domain	*domain;
#ifdef SPDK_CONFIG_RDMA
	struct spdk_rdma_utils_mem_map	*map;
#endif
	STAILQ_ENTRY(fsdevperf_domain)	stailq;
};

struct fsdevperf_task {
	struct fsdevperf_filesystem		*fs;
	struct fsdevperf_job			*job;
	struct fsdevperf_thread			*thread;
	struct spdk_io_channel			*ioch;
	struct spdk_fsdev_file_object		*fobj;
	struct spdk_fsdev_file_handle		*fh;
	STAILQ_HEAD(, fsdevperf_domain)		domains;
	uint64_t				offset;
	uint64_t				filesize;
	uint64_t				size;
	uint32_t				num_outstanding;
	unsigned int				seed;
	size_t					io_size;
	size_t					io_depth;
	int					io_pattern;
	uint16_t				source_id;
	bool					unique_data;
	bool					stop;
	struct fsdevperf_stats			stats;
	uint64_t				tsc_finish;
	uint64_t				tsc_start;
	struct fsdevperf_file			*file;
	int					status;
	char					*requests_buf;
	void					*buf;
	struct {
		TAILQ_ENTRY(fsdevperf_task)	job;
		TAILQ_ENTRY(fsdevperf_task)	thread;
	} tailq;
	struct fsdevperf_io			io;
};
SPDK_STATIC_ASSERT(offsetof(struct fsdevperf_task, io) % 8 == 0, "misalignment");

#define FSDEVPERF_FS_SIZE(io_ctx_size)	(sizeof(struct fsdevperf_filesystem) + io_ctx_size)
#define FSDEVPERF_TASK_SIZE(fs)		(sizeof(struct fsdevperf_task) + (fs)->io_ctx_size)
#define FSDEVPERF_REQUEST_SIZE(task)	(sizeof(struct fsdevperf_request) + (task)->fs->io_ctx_size)

#define FSDEVPERF_POLLER_PERIOD 1ull

#define fsdevperf_task_request(task, i) \
	((struct fsdevperf_request *)((task)->requests_buf + (i) * FSDEVPERF_REQUEST_SIZE(task)))


static inline struct spdk_fsdev_io *
fsdevperf_fs_get_fsdev_io(struct fsdevperf_filesystem *fs)
{
	return &fs->io.fsdev_io;
}

static inline struct spdk_fsdev_io *
fsdevperf_task_get_fsdev_io(struct fsdevperf_task *task)
{
	return &task->io.fsdev_io;
}

static inline struct spdk_fsdev_io *
fsdevperf_request_get_fsdev_io(struct fsdevperf_request *request)
{
	return &request->io.fsdev_io;
}

struct fsdevperf_job;

struct fsdevperf_job_ops {
	void (*start_task)(struct fsdevperf_task *task);
	void (*job_done)(struct fsdevperf_job *job, int status);
};

#define FSDEVPERF_JOB_RANDOM			(1 << 0)
#define FSDEVPERF_JOB_SINGLE_BUFFER		(1 << 1)
#define FSDEVPERF_JOB_UNIQUE_DATA		(1 << 2)
#define FSDEVPERF_JOB_INTERNAL			(1 << 3)
#define FSDEVPERF_JOB_DIRECT			(1 << 4)
#define FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN	(1 << 5)
#define FSDEVPERF_JOB_SKIP_COPY			(1 << 6)

struct fsdevperf_job {
	int					io_pattern;
	int					status;
	size_t					io_size;
	size_t					io_depth;
	size_t					io_segment_size;
	size_t					filesize;
	size_t					size;
	size_t					num_files;
	uint32_t				runtime;
	uint32_t				flags;
	char					*name;
	char					*path;
	size_t					num_active;
	size_t					num_tasks;
	size_t					num_ready;
	void					*buf;
	struct fsdevperf_job_ops		ops;
	TAILQ_HEAD(, fsdevperf_task)		tasks;
	TAILQ_HEAD(, fsdevperf_job)		children;
	struct {
		TAILQ_ENTRY(fsdevperf_job)	app;
		TAILQ_ENTRY(fsdevperf_job)	child;
	} tailq;
};

struct fsdevperf_app {
	const char				*name;
	struct fsdevperf_job			*main_job;
	struct fsdevperf_job			*cleanup_job;
	size_t					num_active;
	int					status;
	struct {
		struct fsdevperf_stats		current_stats;
		struct fsdevperf_stats		prev_stats;
		struct spdk_poller		*poller;
	} poller;
	mode_t					umask;
	size_t					num_threads_per_core;
	uint32_t				uid;
	uint32_t				gid;
	TAILQ_HEAD(, fsdevperf_job)		jobs;
	TAILQ_HEAD(, fsdevperf_thread)		threads;
	TAILQ_HEAD(, fsdevperf_file)		files;
	TAILQ_HEAD(, fsdevperf_filesystem)	filesystems;
	struct {
		bool				enabled;
		struct spdk_jsonrpc_request	*request;
	} rpc;
	struct spdk_memory_domain		*domain;
} g_app = {
	.num_threads_per_core = 1,
	.jobs = TAILQ_HEAD_INITIALIZER(g_app.jobs),
	.threads = TAILQ_HEAD_INITIALIZER(g_app.threads),
	.files = TAILQ_HEAD_INITIALIZER(g_app.files),
	.filesystems = TAILQ_HEAD_INITIALIZER(g_app.filesystems),
};

#define fsdevperf_errmsg(fmt, ...) \
	fprintf(stderr, "%s: " fmt, g_app.name, ## __VA_ARGS__)

#define fsdevperf_foreach_leaf_job(job) \
	for ((job) = fsdevperf_first_leaf_job(); (job) != NULL; \
	     (job) = fsdevperf_next_leaf_job(job))

struct fsdevperf_aux_io_type {
	const char	*name;
	int		value;
	bool		random;
} g_aux_io_types[] = {
	{ "randread", FUSE_READ, true },
	{ "randwrite", FUSE_WRITE, true },
};

static struct fsdevperf_job *
fsdevperf_next_leaf_job(struct fsdevperf_job *job)
{
	for (job = TAILQ_NEXT(job, tailq.app);
	     job != NULL;
	     job = TAILQ_NEXT(job, tailq.app)) {
		if (TAILQ_EMPTY(&job->children)) {
			return job;
		}
	}

	return NULL;
}

static struct fsdevperf_job *
fsdevperf_first_leaf_job(void)
{
	struct fsdevperf_job *job;

	job = TAILQ_FIRST(&g_app.jobs);
	if (TAILQ_EMPTY(&job->children)) {
		return job;
	}

	return fsdevperf_next_leaf_job(job);
}

static int
fsdevperf_get_fsdev_name(const char *path, char *name, size_t len)
{
	const char *dname, *root;
	size_t namelen;

	/* Skip the leading / */
	assert(path[0] == '/');
	dname = path + 1;
	root = strstr(dname, "/");
	namelen = root != NULL ? (uintptr_t)root - (uintptr_t)dname : strlen(dname);
	if (namelen >= len) {
		return -EINVAL;
	}

	memcpy(name, dname, namelen);
	name[namelen] = '\0';

	return 0;
}

static int
fsdevperf_job_check_path(struct fsdevperf_job *job)
{
	const char *path = job->path;

	/* The first component in the path is the name of the fsdev, e.g. /foo/bar refers to a
	 * file called "bar" on an fsdev "foo".
	 */
	if (path[0] != '/') {
		fsdevperf_errmsg("%s: invalid path: '%s', path must be absolute\n",
				 job->name, job->path);
		return -EINVAL;
	}

	/* We don't support files inside subdirectories */
	path = strstr(path + 1, "/");
	if (path != NULL && strstr(path + 1, "/") != NULL) {
		fsdevperf_errmsg("%s: invalid path: '%s', path must point to fsdev's root or a file "
				 "in fsdev's root, not a subdirectory\n", job->name, job->path);
		return -EINVAL;
	}

	return 0;
}

static bool
fsdevperf_job_is_multi(struct fsdevperf_job *job)
{
	char name[PATH_MAX];
	int rc;

	rc = fsdevperf_get_fsdev_name(job->path, name, sizeof(name));
	if (rc != 0) {
		return false;
	}

	return strcmp(name, "*") == 0 || strstr(name, ",") != NULL;
}

static bool
fsdevperf_job_is_random(struct fsdevperf_job *job)
{
	return job->flags & FSDEVPERF_JOB_RANDOM;
}

static bool
fsdevperf_job_is_internal(struct fsdevperf_job *job)
{
	return job->flags & FSDEVPERF_JOB_INTERNAL;
}

static const char *
fsdevperf_get_filename(const char *path)
{
	path = strstr(path + 1, "/");
	if (path == NULL || strlen(path + 1) == 0) {
		return NULL;
	}

	return path + 1;
}

static int
fsdevperf_parse_io_pattern(const char *pattern, bool *random)
{
	const char *name;
	int i;

	*random = false;
	for (i = 0; i < SPDK_FSDEV_MAX_FUSE_OPC; i++) {
		name = spdk_fsdev_get_opcode_name(i);
		if (name != NULL && strcmp(name, pattern) == 0) {
			return i;
		}
	}

	for (i = 0; i < (int)SPDK_COUNTOF(g_aux_io_types); i++) {
		if (strcmp(g_aux_io_types[i].name, pattern) == 0) {
			*random = g_aux_io_types[i].random;
			return g_aux_io_types[i].value;
		}
	}

	return -EINVAL;
}

static const char *
fsdevperf_job_get_io_pattern_name(struct fsdevperf_job *job)
{
	size_t i;

	for (i = 0; i < SPDK_COUNTOF(g_aux_io_types); i++) {
		if (g_aux_io_types[i].value == job->io_pattern &&
		    g_aux_io_types[i].random == fsdevperf_job_is_random(job)) {
			return g_aux_io_types[i].name;
		}
	}

	return spdk_fsdev_get_opcode_name(job->io_pattern);
}

static struct fsdevperf_thread *
fsdevperf_get_thread(void)
{
	struct fsdevperf_thread *thread;

	TAILQ_FOREACH(thread, &g_app.threads, tailq) {
		if (thread->thread == spdk_get_thread()) {
			return thread;
		}
	}

	return NULL;
}

static bool
fsdevperf_filesystem_supports_opcode(struct fsdevperf_filesystem *fs, uint64_t opcode)
{
	return fs->supported_fuse_opcodes & SPDK_BIT(opcode);
}

static void
fsdevperf_job_set_status(struct fsdevperf_job *job, int status)
{
	if (job->status == 0) {
		job->status = status;
	}
}

static void
fsdevperf_set_status(int status)
{
	if (g_app.status == 0) {
		g_app.status = status;
	}
}

static void
fsdevperf_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *event_ctx)
{
	fsdevperf_errmsg("unhandled event %d on fsdev %s\n", type, spdk_fsdev_get_name(fsdev));
}

static void
fsdevperf_filesystem_free(struct fsdevperf_filesystem *fs)
{
	if (fs->ioch != NULL) {
		spdk_put_io_channel(fs->ioch);
	}
	if (fs->fsdev_desc != NULL) {
		spdk_fsdev_close(fs->fsdev_desc);
	}
	free(fs);
}

static struct fsdevperf_filesystem *
fsdevperf_filesystem_alloc(const char *name)
{
	struct spdk_fsdev *fsdev;
	struct fsdevperf_filesystem *fs;
	int rc, io_ctx_size;

	io_ctx_size = spdk_fsdev_get_io_ctx_size();

	fs = calloc(1, FSDEVPERF_FS_SIZE(io_ctx_size));
	if (fs == NULL) {
		fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
		return NULL;
	}

	rc = spdk_fsdev_open(name, fsdevperf_event_cb, NULL, &fs->fsdev_desc);
	if (rc != 0) {
		fsdevperf_errmsg("couldn't open /%s: %s\n", name, spdk_strerror(-rc));
		goto error;
	}

	fs->ioch = spdk_fsdev_get_io_channel(fs->fsdev_desc);
	if (fs->ioch == NULL) {
		fsdevperf_errmsg("failed to get IO channel for /%s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)));
		goto error;
	}

	fsdev = spdk_fsdev_desc_get_fsdev(fs->fsdev_desc);
	fs->supported_fuse_opcodes = spdk_fsdev_get_supported_fuse_opcodes(fsdev);
	fs->io_ctx_size = io_ctx_size;

	return fs;
error:
	fsdevperf_filesystem_free(fs);
	return NULL;
}

static int
fsdevperf_init_filesystems(void)
{
	struct fsdevperf_filesystem *fs;
	struct fsdevperf_job *job;
	struct spdk_fsdev *fsdev;
	char name[PATH_MAX];
	int rc;

	fsdevperf_foreach_leaf_job(job) {
		rc = fsdevperf_get_fsdev_name(job->path, name, sizeof(name));
		if (rc != 0) {
			fsdevperf_errmsg("%s\n", spdk_strerror(-rc));
			return rc;
		}

		TAILQ_FOREACH(fs, &g_app.filesystems, tailq) {
			fsdev = spdk_fsdev_desc_get_fsdev(fs->fsdev_desc);
			if (strcmp(name, spdk_fsdev_get_name(fsdev)) == 0) {
				break;
			}
		}

		if (fs == NULL) {
			fs = fsdevperf_filesystem_alloc(name);
			if (fs == NULL) {
				return -ENODEV;
			}

			TAILQ_INSERT_TAIL(&g_app.filesystems, fs, tailq);
		}
	}

	return 0;
}

static int
fsdevperf_init_threads(void)
{
	struct fsdevperf_thread *thread;
	struct spdk_cpuset cpuset;
	char name[32];
	uint32_t i, count = 0, core;

	assert(g_app.num_threads_per_core > 0);
	SPDK_ENV_FOREACH_CORE(core) {
		for (i = 0; i < g_app.num_threads_per_core; i++) {
			thread = calloc(1, sizeof(*thread));
			if (thread == NULL) {
				fsdevperf_errmsg("%s", spdk_strerror(ENOMEM));
				return -ENOMEM;
			}

			spdk_cpuset_zero(&cpuset);
			spdk_cpuset_set_cpu(&cpuset, core, true);
			snprintf(name, sizeof(name), "fsdevperf%u-%u", core, i);

			TAILQ_INIT(&thread->tasks);
			thread->core = core;
			thread->id = 1000000ull * count;
			if (core == spdk_env_get_main_core() && i == 0) {
				thread->thread = spdk_thread_get_app_thread();
				assert(spdk_get_thread() == spdk_thread_get_app_thread());
			} else {
				thread->thread = spdk_thread_create(name, &cpuset);
			}
			if (thread->thread == NULL) {
				fsdevperf_errmsg("%s", spdk_strerror(ENOMEM));
				free(thread);
				return -ENOMEM;
			}

			TAILQ_INSERT_TAIL(&g_app.threads, thread, tailq);
			count++;
		}
	}

	return 0;
}

static void
fsdevperf_task_free(struct fsdevperf_task *task)
{
	struct fsdevperf_job *job = task->job;
	struct fsdevperf_domain *domain;
	size_t i;

	if (!(job->flags & FSDEVPERF_JOB_SINGLE_BUFFER)) {
		spdk_free(task->buf);
	}
	if (task->requests_buf != NULL) {
		for (i = 0; i < task->io_depth; i++) {
			free(fsdevperf_task_request(task, i)->iovs);
		}
		free(task->requests_buf);
	}
	while (!STAILQ_EMPTY(&task->domains)) {
		domain = STAILQ_FIRST(&task->domains);
		STAILQ_REMOVE_HEAD(&task->domains, stailq);
#ifdef SPDK_CONFIG_RDMA
		spdk_rdma_utils_free_mem_map(&domain->map);
#endif
		free(domain);
	}
	free(task);
}

static struct fsdevperf_task *
fsdevperf_task_alloc(struct fsdevperf_job *job, struct fsdevperf_file *file,
		     struct fsdevperf_thread *thread)
{
	struct fsdevperf_task *task;
	struct fsdevperf_request *request;
	size_t i, j, len, curlen, iovcnt, io_segment_size;
	char *buf;

	task = calloc(1, FSDEVPERF_TASK_SIZE(file->fs));
	if (task == NULL) {
		return NULL;
	}

	STAILQ_INIT(&task->domains);
	task->job = job;
	task->thread = thread;
	task->file = file;
	task->fs = file->fs;
	task->source_id = thread->core;
	task->io_size = job->io_size;
	task->io_depth = job->io_depth;
	task->io_pattern = job->io_pattern;
	task->unique_data = (job->flags & FSDEVPERF_JOB_UNIQUE_DATA) != 0;
	task->requests_buf = calloc(task->io_depth, FSDEVPERF_REQUEST_SIZE(task));
	if (task->requests_buf == NULL) {
		goto error;
	}

	if (job->flags & FSDEVPERF_JOB_SINGLE_BUFFER) {
		task->buf = job->buf;
	} else {
		task->buf = spdk_zmalloc(task->io_depth * task->io_size, 4096, NULL,
					 SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
		if (task->buf == NULL) {
			goto error;
		}
	}

	io_segment_size = job->io_segment_size ? job->io_segment_size : task->io_size;
	iovcnt = spdk_divide_round_up(task->io_size, io_segment_size);
	for (i = 0; i < task->io_depth; i++) {
		request = fsdevperf_task_request(task, i);
		request->iovcnt = iovcnt;
		request->task = task;
		request->iovs = calloc(iovcnt, sizeof(*request->iovs));
		if (request->iovs == NULL) {
			goto error;
		}

		buf = (char *)task->buf + i * task->io_size;
		len = task->io_size;
		for (j = 0; j < iovcnt; j++) {
			curlen = spdk_min(io_segment_size, len);
			request->iovs[j].iov_base = buf;
			request->iovs[j].iov_len = curlen;
			buf += curlen;
			len -= curlen;
		}
	}

	return task;
error:
	fsdevperf_task_free(task);
	return NULL;
}

static void
fsdevperf_file_free(struct fsdevperf_file *file)
{
	free(file->name);
	free(file);
}

static struct fsdevperf_file *
fsdevperf_file_alloc(const char *fsname, const char *filename, size_t size)
{
	struct fsdevperf_file *file;
	struct fsdevperf_filesystem *fs;

	file = calloc(1, sizeof(*file));
	if (file == NULL) {
		return NULL;
	}

	TAILQ_FOREACH(fs, &g_app.filesystems, tailq) {
		if (strcmp(spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
			   fsname) == 0) {
			break;
		}
	}

	if (fs == NULL) {
		fsdevperf_file_free(file);
		return NULL;
	}

	file->fs = fs;
	file->size = size;
	file->name = strdup(filename);
	if (file->name == NULL) {
		fsdevperf_file_free(file);
		return NULL;
	}

	return file;
}

static struct fsdevperf_file *
fsdevperf_file_get(const char *fsname, const char *filename, size_t size)
{
	struct fsdevperf_file *file;

	TAILQ_FOREACH(file, &g_app.files, tailq) {
		if (strcmp(filename, file->name) == 0) {
			/* Make sure the file is large enough for all jobs */
			file->size = spdk_max(file->size, size);
			return file;
		}
	}

	file = fsdevperf_file_alloc(fsname, filename, size);
	if (file == NULL) {
		return NULL;
	}

	TAILQ_INSERT_TAIL(&g_app.files, file, tailq);

	return file;
}

static void
fsdevperf_job_free(struct fsdevperf_job *job)
{
	spdk_free(job->buf);
	free(job->name);
	free(job->path);
	free(job);
}

static struct fsdevperf_job *
fsdevperf_job_alloc(const char *name, const struct fsdevperf_job_ops *ops, uint32_t flags)
{
	struct fsdevperf_job *job;

	job = calloc(1, sizeof(*job));
	if (job == NULL) {
		return NULL;
	}

	job->name = strdup(name);
	if (job->name == NULL) {
		free(job);
		return NULL;
	}

	job->io_size = 4096;
	job->io_depth = 1;
	job->io_pattern = -1;
	job->flags = flags;
	job->num_files = 1;
	job->ops = *ops;

	TAILQ_INIT(&job->tasks);
	TAILQ_INIT(&job->children);

	return job;
}

static void
fsdevperf_job_cleanup(struct fsdevperf_job *job)
{
	struct fsdevperf_task *task;
	struct fsdevperf_thread *thread;

	while ((task = TAILQ_FIRST(&job->tasks))) {
		thread = task->thread;
		TAILQ_REMOVE(&thread->tasks, task, tailq.thread);
		TAILQ_REMOVE(&job->tasks, task, tailq.job);
		fsdevperf_task_free(task);
	}
}

static int
fsdevperf_job_init(struct fsdevperf_job *job)
{
	struct fsdevperf_thread *thread;
	struct fsdevperf_task *task;
	struct fsdevperf_file *file = NULL;
	char fsname[PATH_MAX], namebuf[PATH_MAX];
	const char *filename;
	size_t i;
	int rc;

	rc = fsdevperf_get_fsdev_name(job->path, fsname, sizeof(fsname));
	if (rc != 0) {
		fsdevperf_errmsg("%s\n", spdk_strerror(-rc));
		return rc;
	}

	filename = fsdevperf_get_filename(job->path);
	if (filename != NULL) {
		file = fsdevperf_file_get(fsname, filename, job->filesize);
		if (file == NULL) {
			fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
			return -ENOMEM;
		}
	}

	TAILQ_FOREACH(thread, &g_app.threads, tailq) {
		for (i = 0; i < job->num_files; i++) {
			/* If the user didn't specify a filename, we need to generate a file
			 * for each core */
			if (filename == NULL) {
				rc = snprintf(namebuf, sizeof(namebuf), "%s.%02u.%0*zu", job->name,
					      thread->core, (int)log10(job->num_files) + 1, i);
				if (rc < 0 || rc >= (int)sizeof(namebuf)) {
					fsdevperf_errmsg("%s: /%s: %s\n", job->name, fsname,
							 spdk_strerror(ENAMETOOLONG));
					return -ENAMETOOLONG;
				}

				file = fsdevperf_file_get(fsname, namebuf, job->filesize);
				if (file == NULL) {
					fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
					return -ENOMEM;
				}
			}

			task = fsdevperf_task_alloc(job, file, thread);
			if (task == NULL) {
				return -ENOMEM;
			}

			TAILQ_INSERT_TAIL(&thread->tasks, task, tailq.thread);
			TAILQ_INSERT_TAIL(&job->tasks, task, tailq.job);
			job->num_tasks++;
		}
	}

	if (job->flags & FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN) {
		assert(file != NULL);
		if (!fsdevperf_filesystem_supports_opcode(file->fs, FUSE_READ) ||
		    !fsdevperf_filesystem_supports_opcode(file->fs, FUSE_WRITE)) {
			fsdevperf_errmsg("%s: memory domains are only supported with FUSE "
					 "passthrough\n", job->name);
			return -EINVAL;
		}
	}

	return 0;
}

static int
fsdevperf_init_jobs(void)
{
	struct fsdevperf_job *job;
	int rc;

	fsdevperf_foreach_leaf_job(job) {
		rc = fsdevperf_job_init(job);
		if (rc != 0) {
			return rc;
		}
	}

	return 0;
}

static void
fsdevperf_dump_stats(void)
{
	struct fsdevperf_job *job;
	struct fsdevperf_task *task;
	struct fsdevperf_filesystem *fs;
	double task_iops, job_iops, total_iops;
	double task_mbps, job_mbps, total_mbps;
	double runtime;
	char path[PATH_MAX];
	size_t num_jobs = 0;

	total_iops = 0;
	total_mbps = 0;

	fsdevperf_foreach_leaf_job(job) {
		job_iops = 0;
		job_mbps = 0;

		printf("%s (pattern=%s, iosize=%zu, iodepth=%zu, nrfiles=%zu):\n",
		       job->name, fsdevperf_job_get_io_pattern_name(job), job->io_size,
		       job->io_depth, job->num_files);
		printf("  %30s %4s %10s %10s %10s\n", "filename", "core", "runtime", "IOPS", "MiB/s");
		TAILQ_FOREACH(task, &job->tasks, tailq.job) {
			fs = task->fs;
			snprintf(path, sizeof(path), "/%s/%s",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 task->file->name);
			runtime = (double)(task->tsc_finish - task->tsc_start) / spdk_get_ticks_hz();
			task_iops = (double)task->stats.num_ios / runtime;
			task_mbps = (double)task->stats.num_bytes / (1024 * 1024 * runtime);
			printf("  %30s %4u %10.2f %10.2f %10.2f\n", path, task->thread->core,
			       runtime, task_iops, task_mbps);

			job_iops += task_iops;
			job_mbps += task_mbps;
		}

		if (job->num_tasks > 1) {
			printf("  %30s %4s %10s %10.2f %10.2f\n", "", "", "",
			       job_iops, job_mbps);
		}

		total_iops += job_iops;
		total_mbps += job_mbps;
		num_jobs++;
	}

	if (num_jobs > 1) {
		printf("total\n");
		printf("  %30s %4s %10s %10.2f %10.2f\n", "", "", "", total_iops, total_mbps);
	}
}

static void
fsdevperf_rpc_done(void)
{
	struct spdk_jsonrpc_request *request = g_app.rpc.request;
	struct spdk_json_write_ctx *w;
	struct fsdevperf_job *job;
	struct fsdevperf_task *task;
	struct fsdevperf_filesystem *fs;
	char path[PATH_MAX];
	uint64_t runtime;

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_object_begin(w);
	spdk_json_write_named_int32(w, "status", g_app.status);
	spdk_json_write_named_array_begin(w, "jobs");
	fsdevperf_foreach_leaf_job(job) {
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "name", job->name);
		spdk_json_write_named_string(w, "pattern",
					     fsdevperf_job_get_io_pattern_name(job));
		spdk_json_write_named_uint64(w, "iosize", job->io_size);
		spdk_json_write_named_uint64(w, "iodepth", job->io_depth);
		spdk_json_write_named_array_begin(w, "tasks");
		TAILQ_FOREACH(task, &job->tasks, tailq.job) {
			fs = task->fs;
			snprintf(path, sizeof(path), "/%s/%s",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 task->file->name);
			runtime = (task->tsc_finish - task->tsc_start) * SPDK_SEC_TO_USEC /
				  spdk_get_ticks_hz();
			spdk_json_write_object_begin(w);
			spdk_json_write_named_string(w, "filename", path);
			spdk_json_write_named_uint32(w, "core", task->thread->core);
			spdk_json_write_named_uint64(w, "runtime", runtime);
			spdk_json_write_named_uint64(w, "num_ios", task->stats.num_ios);
			spdk_json_write_named_uint64(w, "num_bytes", task->stats.num_bytes);
			spdk_json_write_object_end(w);
		}
		spdk_json_write_array_end(w);
		spdk_json_write_object_end(w);
	}
	spdk_json_write_array_end(w);
	spdk_json_write_object_end(w);
	spdk_jsonrpc_end_result(request, w);
	g_app.rpc.request = NULL;
}

static void fsdevperf_run(void);

static void
fsdevperf_rpc_perform_tests(struct spdk_jsonrpc_request *request,
			    const struct spdk_json_val *params)
{
	if (!g_app.rpc.enabled) {
		spdk_jsonrpc_send_error_response(request, -ENOTSUP, spdk_strerror(ENOTSUP));
		return;
	}
	if (g_app.rpc.request != NULL) {
		spdk_jsonrpc_send_error_response(request, -EINPROGRESS, spdk_strerror(EINPROGRESS));
		return;
	}

	g_app.rpc.request = request;
	fsdevperf_run();
}
SPDK_RPC_REGISTER("perform_tests", fsdevperf_rpc_perform_tests, SPDK_RPC_RUNTIME)

static void
fsdevperf_thread_exit(void *ctx)
{
	spdk_thread_exit(spdk_get_thread());
}

static int fsdevperf_cleanup(void);

static void
fsdevperf_done(void)
{
	struct fsdevperf_job *job;
	struct fsdevperf_thread *thread;
	struct fsdevperf_filesystem *fs;
	struct fsdevperf_file *file;

	/* Make sure we clean up after ourselves */
	if (fsdevperf_cleanup() == -EINPROGRESS) {
		return;
	}

	fsdevperf_dump_stats();
	if (g_app.rpc.request != NULL) {
		fsdevperf_rpc_done();
	}

	while ((job = TAILQ_FIRST(&g_app.jobs))) {
		TAILQ_REMOVE(&g_app.jobs, job, tailq.app);
		fsdevperf_job_cleanup(job);
		fsdevperf_job_free(job);
	}

	while ((file = TAILQ_FIRST(&g_app.files))) {
		TAILQ_REMOVE(&g_app.files, file, tailq);
		fsdevperf_file_free(file);
	}

	while ((fs = TAILQ_FIRST(&g_app.filesystems))) {
		TAILQ_REMOVE(&g_app.filesystems, fs, tailq);
		fsdevperf_filesystem_free(fs);
	}

	TAILQ_FOREACH(thread, &g_app.threads, tailq) {
		if (thread->thread != spdk_thread_get_app_thread()) {
			spdk_thread_send_msg(thread->thread, fsdevperf_thread_exit, NULL);
		}
	}

	spdk_memory_domain_destroy(g_app.domain);
	spdk_poller_unregister(&g_app.poller.poller);
	spdk_app_stop(g_app.status);
}

static uint64_t
fsdevperf_thread_next_id(struct fsdevperf_thread *thread)
{
	return thread->id++;
}

static uint64_t
fsdevperf_task_next_id(struct fsdevperf_task *task)
{
	return fsdevperf_thread_next_id(task->thread);
}

static void
fsdevperf_filesystem_umount_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_filesystem *fs = cb_arg;

	fs->root = NULL;
	fsdevperf_done();
}

static void
fsdevperf_io_init(struct fsdevperf_io *io, struct spdk_fsdev_desc *fsdev_desc,
		  struct spdk_io_channel *ioch, uint32_t opcode, uint64_t id, uint16_t source_id,
		  uint64_t nodeid, uint32_t len, struct iovec *in_iovs, int in_iovcnt,
		  struct iovec *out_iovs, int out_iovcnt, spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	io->fuse_io.in.hdr.opcode = opcode;
	io->fuse_io.in.hdr.unique = id;
	io->fuse_io.in.hdr.len = sizeof(io->fuse_io.in.hdr) + len;
	io->fuse_io.in.hdr.nodeid = nodeid;
	io->fuse_io.in.hdr.uid = g_app.uid;
	io->fuse_io.in.hdr.gid = g_app.gid;
	/* Skip pid */
	spdk_fsdev_io_init(&io->fsdev_io, fsdev_desc, ioch, id, SPDK_FSDEV_IO_FUSE,
			   source_id, id, cb_fn, cb_ctx);
	io->fsdev_io.u_in.fuse.hdr = &io->fuse_io.in.hdr;
	io->fsdev_io.u_in.fuse.op.raw = &io->fuse_io.in.op;
	io->fsdev_io.u_in.fuse.iov = in_iovs;
	io->fsdev_io.u_in.fuse.iovcnt = in_iovcnt;
	io->fsdev_io.u_out.fuse.hdr = &io->fuse_io.out.hdr;
	io->fsdev_io.u_out.fuse.op.raw = &io->fuse_io.out.op;
	io->fsdev_io.u_out.fuse.iov = out_iovs;
	io->fsdev_io.u_out.fuse.iovcnt = out_iovcnt;
}

static void
fsdevperf_filesystem_submit_mount(struct fsdevperf_filesystem *fs,
				  spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct spdk_fsdev_io *fsdev_io = fsdevperf_fs_get_fsdev_io(fs);
	struct fuse_init_in *init = &fs->fuse_io.in.op.init;
	uint64_t id;

	id = fsdevperf_thread_next_id(fsdevperf_get_thread());
	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_INIT)) {
		fsdevperf_io_init(&fs->io, fs->fsdev_desc, fs->ioch, FUSE_INIT, id,
				  spdk_env_get_current_core(), FUSE_ROOT_ID, sizeof(*init),
				  NULL, 0, NULL, 0, cb_fn, cb_ctx);
		/*
		 * We don't really care about any of this, just set the version to avoid tripping up
		 * modules that check it
		 */
		memset(init, 0, sizeof(*init));
		init->major = 7;
		init->minor = 31;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, fs->ioch, id, SPDK_FSDEV_IO_MOUNT,
				   spdk_env_get_current_core(), id, cb_fn, cb_ctx);
		memset(&fsdev_io->u_in.mount.opts, 0, sizeof(fsdev_io->u_in.mount.opts));
		fsdev_io->u_in.mount.opts.opts_size =
			SPDK_SIZEOF(&fsdev_io->u_in.mount.opts, opts_size);
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_filesystem_submit_umount(struct fsdevperf_filesystem *fs,
				   spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct spdk_fsdev_io *fsdev_io = fsdevperf_fs_get_fsdev_io(fs);
	uint64_t id;

	id = fsdevperf_thread_next_id(fsdevperf_get_thread());
	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_DESTROY)) {
		fsdevperf_io_init(&fs->io, fs->fsdev_desc, fs->ioch, FUSE_DESTROY, id,
				  spdk_env_get_current_core(), FUSE_ROOT_ID, 0, NULL, 0, NULL, 0,
				  cb_fn, cb_ctx);
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, fs->ioch, id, SPDK_FSDEV_IO_UMOUNT,
				   spdk_env_get_current_core(), id, cb_fn, cb_ctx);
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_task_submit_release(struct fsdevperf_task *task, uint64_t id,
			      struct spdk_fsdev_file_object *fobject,
			      struct spdk_fsdev_file_handle *fhandle,
			      spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_filesystem *fs = task->fs;
	struct spdk_fsdev_io *fsdev_io = fsdevperf_task_get_fsdev_io(task);
	struct fuse_release_in *release = &task->io.fuse_io.in.op.release;

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_RELEASE)) {
		fsdevperf_io_init(&task->io, fs->fsdev_desc, task->ioch, FUSE_RELEASE, id,
				  task->source_id, (uint64_t)fobject, sizeof(*release),
				  NULL, 0, NULL, 0, cb_fn, cb_ctx);
		memset(release, 0, sizeof(*release));
		release->fh = (uint64_t)fhandle;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id, SPDK_FSDEV_IO_RELEASE,
				   task->source_id, id, cb_fn, cb_ctx);

		fsdev_io->u_in.release.fobject = fobject;
		fsdev_io->u_in.release.fhandle = fhandle;
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_task_submit_forget(struct fsdevperf_task *task, uint64_t id,
			     struct spdk_fsdev_file_object *fobject, uint64_t nlookup,
			     spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_filesystem *fs = task->fs;
	struct spdk_fsdev_io *fsdev_io = fsdevperf_task_get_fsdev_io(task);
	struct fuse_forget_in *forget = &task->io.fuse_io.in.op.forget;

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_FORGET)) {
		fsdevperf_io_init(&task->io, fs->fsdev_desc, task->ioch, FUSE_FORGET, id,
				  task->source_id, (uint64_t)fobject, sizeof(*forget),
				  NULL, 0, NULL, 0, cb_fn, cb_ctx);
		forget->nlookup = nlookup;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id, SPDK_FSDEV_IO_FORGET,
				   task->source_id, id, cb_fn, cb_ctx);

		fsdev_io->u_in.forget.fobject = fobject;
		fsdev_io->u_in.forget.nlookup = nlookup;
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_task_submit_create(struct fsdevperf_task *task, uint64_t id,
			     struct spdk_fsdev_file_object *parent, const char *name,
			     uint32_t flags, uint32_t mode, uint32_t umask,
			     spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_io *io = &task->io;
	struct fsdevperf_fuse_io *fuse_io = &io->fuse_io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	struct fuse_create_in *create = &fuse_io->in.op.create;
	size_t len;

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_CREATE)) {
		len = strlen(name) + 1;
		fsdevperf_io_init(io, fs->fsdev_desc, task->ioch, FUSE_CREATE, id,
				  task->source_id, (uint64_t)parent, sizeof(*create) + len,
				  fuse_io->in.iovs, 1, NULL, 0, cb_fn, cb_ctx);
		create->flags = flags;
		create->mode = mode;
		create->umask = umask;
		create->open_flags = 0;
		fuse_io->in.iovs[0].iov_base = (char *)name;
		fuse_io->in.iovs[0].iov_len = len;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id,
				   SPDK_FSDEV_IO_CREATE, task->source_id, id, cb_fn, cb_ctx);

		fsdev_io->u_in.create.parent_fobject = parent;
		fsdev_io->u_in.create.name = name;
		fsdev_io->u_in.create.flags = flags;
		fsdev_io->u_in.create.mode = mode;
		fsdev_io->u_in.create.umask = umask;
		fsdev_io->u_in.create.euid = geteuid();
		fsdev_io->u_in.create.egid = getegid();
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_task_submit_open(struct fsdevperf_task *task, uint64_t id,
			   struct spdk_fsdev_file_object *fobject, uint32_t flags,
			   spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_filesystem *fs = task->fs;
	struct spdk_fsdev_io *fsdev_io = fsdevperf_task_get_fsdev_io(task);
	struct fuse_open_in *open = &task->io.fuse_io.in.op.open;

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_OPEN)) {
		fsdevperf_io_init(&task->io, fs->fsdev_desc, task->ioch, FUSE_OPEN, id,
				  task->source_id, (uint64_t)fobject, sizeof(*open),
				  NULL, 0, NULL, 0, cb_fn, cb_ctx);
		open->flags = flags;
		open->open_flags = 0;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id,
				   SPDK_FSDEV_IO_OPEN, task->source_id, id, cb_fn, cb_ctx);

		fsdev_io->u_in.open.fobject = fobject;
		fsdev_io->u_in.open.flags = flags;
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_task_submit_lookup(struct fsdevperf_task *task, uint64_t id,
			     struct spdk_fsdev_file_object *parent, const char *name,
			     spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_io *io = &task->io;
	struct fsdevperf_fuse_io *fuse_io = &io->fuse_io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	size_t len;

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_LOOKUP)) {
		len = strlen(name) + 1;
		fsdevperf_io_init(io, fs->fsdev_desc, task->ioch, FUSE_LOOKUP, id,
				  task->source_id, (uint64_t)parent, len, fuse_io->in.iovs, 1,
				  NULL, 0, cb_fn, cb_ctx);
		fuse_io->in.iovs[0].iov_base = (char *)name;
		fuse_io->in.iovs[0].iov_len = len;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id,
				   SPDK_FSDEV_IO_LOOKUP, task->source_id, id, cb_fn, cb_ctx);

		fsdev_io->u_in.lookup.parent_fobject = parent;
		fsdev_io->u_in.lookup.name = name;
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_task_submit_statfs(struct fsdevperf_task *task, uint64_t id,
			     struct spdk_fsdev_file_object *parent,
			     spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_filesystem *fs = task->fs;
	struct spdk_fsdev_io *fsdev_io = fsdevperf_task_get_fsdev_io(task);

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_STATFS)) {
		fsdevperf_io_init(&task->io, fs->fsdev_desc, task->ioch, FUSE_STATFS, id,
				  task->source_id, FUSE_ROOT_ID, 0, NULL, 0, NULL, 0,
				  cb_fn, cb_ctx);
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id,
				   SPDK_FSDEV_IO_STATFS, task->source_id, id, cb_fn, cb_ctx);
		fsdev_io->u_in.statfs.fobject = fs->root;
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_request_submit_read(struct fsdevperf_request *request, uint64_t id,
			      struct spdk_fsdev_file_object *fobject,
			      struct spdk_fsdev_file_handle *fhandle, uint64_t offset,
			      size_t size, struct iovec *iovs, int iovcnt,
			      spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_task *task = request->task;
	struct fsdevperf_job *job = task->job;
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_io *io = &request->io;
	struct fsdevperf_fuse_io *fuse_io = &io->fuse_io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	struct fuse_read_in *read = &fuse_io->in.op.read;

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_READ)) {
		fsdevperf_io_init(&request->io, fs->fsdev_desc, task->ioch, FUSE_READ, id,
				  task->source_id, (uint64_t)fobject, sizeof(*read), NULL, 0,
				  iovs, iovcnt, cb_fn, cb_ctx);
		if (job->flags & FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN) {
			fsdev_io->u_out.fuse.memory_domain = g_app.domain;
			fsdev_io->u_out.fuse.memory_domain_ctx = task;
		}
		read->fh = (uint64_t) fhandle;
		read->offset = offset;
		read->size = size;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id, SPDK_FSDEV_IO_READ,
				   task->source_id, id, cb_fn, cb_ctx);

		fsdev_io->u_in.read.fobject = fobject;
		fsdev_io->u_in.read.fhandle = fhandle;
		fsdev_io->u_in.read.offs = offset;
		fsdev_io->u_in.read.size = size;
		fsdev_io->u_in.read.iov = iovs;
		fsdev_io->u_in.read.iovcnt = iovcnt;
		fsdev_io->u_in.read.flags = 0;
		fsdev_io->u_in.read.opts = NULL;
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_request_submit_write(struct fsdevperf_request *request, uint64_t id,
			       struct spdk_fsdev_file_object *fobject,
			       struct spdk_fsdev_file_handle *fhandle, uint64_t offset,
			       size_t size, struct iovec *iovs, int iovcnt,
			       spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	struct fsdevperf_task *task = request->task;
	struct fsdevperf_job *job = task->job;
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_io *io = &request->io;
	struct fsdevperf_fuse_io *fuse_io = &io->fuse_io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	struct fuse_write_in *write = &fuse_io->in.op.write;

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_WRITE)) {
		fsdevperf_io_init(&request->io, fs->fsdev_desc, task->ioch, FUSE_WRITE, id,
				  task->source_id, (uint64_t)fobject, sizeof(*write) + size,
				  iovs, iovcnt, NULL, 0, cb_fn, cb_ctx);
		if (job->flags & FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN) {
			fsdev_io->u_in.fuse.memory_domain = g_app.domain;
			fsdev_io->u_in.fuse.memory_domain_ctx = task;
		}
		write->fh = (uint64_t)fhandle;
		write->offset = offset;
		write->size = size;
	} else {
		spdk_fsdev_io_init(fsdev_io, fs->fsdev_desc, task->ioch, id, SPDK_FSDEV_IO_WRITE,
				   task->source_id, id, cb_fn, cb_ctx);

		fsdev_io->u_in.write.fobject = fobject;
		fsdev_io->u_in.write.fhandle = fhandle;
		fsdev_io->u_in.write.offs = offset;
		fsdev_io->u_in.write.size = size;
		fsdev_io->u_in.write.iov = iovs;
		fsdev_io->u_in.write.iovcnt = iovcnt;
		fsdev_io->u_in.write.flags = 0;
		fsdev_io->u_in.write.opts = NULL;
	}

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevperf_filesystem_umount(struct fsdevperf_filesystem *fs)
{
	fsdevperf_filesystem_submit_umount(fs, fsdevperf_filesystem_umount_cb, fs);
}

static void fsdevperf_task_cleanup(struct fsdevperf_task *task);

static void
fsdevperf_task_release_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_task *task = cb_arg;
	struct fsdevperf_file *file = task->file;
	struct fsdevperf_filesystem *fs = task->fs;

	if (status != 0) {
		fsdevperf_errmsg("release /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 task->file->name, spdk_strerror(-status));
	}

	file->fh = NULL;
	fsdevperf_task_cleanup(task);
}

static void
fsdevperf_task_forget_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_task *task = cb_arg;
	struct fsdevperf_file *file = task->file;
	struct fsdevperf_filesystem *fs = task->fs;

	if (status != 0) {
		fsdevperf_errmsg("forget /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 file->name, spdk_strerror(-status));
	}

	file->fobj = NULL;
	fsdevperf_task_cleanup(task);
}

static void fsdevperf_task_done(struct fsdevperf_task *task, int status);

static void
fsdevperf_task_cleanup(struct fsdevperf_task *task)
{
	struct fsdevperf_file *file = task->file;
	uint64_t id;

	id = fsdevperf_task_next_id(task);
	if (file->fh != NULL) {
		fsdevperf_task_submit_release(task, id, file->fobj, file->fh,
					      fsdevperf_task_release_cb, task);
		return;
	}

	if (file->fobj != NULL) {
		fsdevperf_task_submit_forget(task, id, file->fobj, 1,
					     fsdevperf_task_forget_cb, task);
		return;
	}

	fsdevperf_task_done(task, 0);
}

static void
fsdevperf_cleanup_job_done(struct fsdevperf_job *job, int status)
{
	g_app.cleanup_job = NULL;
	fsdevperf_job_cleanup(job);
	fsdevperf_job_free(job);
	fsdevperf_done();
}

static void fsdevperf_job_start(struct fsdevperf_job *job);

static int
fsdevperf_cleanup_files(void)
{
	struct fsdevperf_file *file;
	struct fsdevperf_job *job = NULL;
	struct fsdevperf_task *task;
	struct fsdevperf_thread *thread;
	struct fsdevperf_job_ops ops = {
		.start_task = fsdevperf_task_cleanup,
		.job_done = fsdevperf_cleanup_job_done,
	};
	bool do_cleanup;

	do_cleanup = false;
	TAILQ_FOREACH(file, &g_app.files, tailq) {
		if (file->fh != NULL || file->fobj != NULL) {
			do_cleanup = true;
			break;
		}
	}

	assert(g_app.cleanup_job == NULL);
	if (do_cleanup) {
		job = fsdevperf_job_alloc("cleanup", &ops,
					  FSDEVPERF_JOB_SINGLE_BUFFER | FSDEVPERF_JOB_INTERNAL);
		if (job == NULL) {
			fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
			goto out;
		}

		thread = TAILQ_FIRST(&g_app.threads);
		TAILQ_FOREACH(file, &g_app.files, tailq) {
			if (file->fh == NULL && file->fobj == NULL) {
				continue;
			}
			task = fsdevperf_task_alloc(job, file, thread);
			if (task == NULL) {
				fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
				goto out;
			}
			TAILQ_INSERT_TAIL(&thread->tasks, task, tailq.thread);
			TAILQ_INSERT_TAIL(&job->tasks, task, tailq.job);
			job->num_tasks++;
		}

		g_app.cleanup_job = job;
		fsdevperf_job_start(job);

		return -EINPROGRESS;
	}
out:
	if (job != NULL) {
		fsdevperf_job_cleanup(job);
		fsdevperf_job_free(job);
	}

	/* We don't really care about cleanup errors */
	return 0;
}

static int
fsdevperf_cleanup(void)
{
	struct fsdevperf_filesystem *fs;
	int rc;

	/* First close any open files */
	rc = fsdevperf_cleanup_files();
	if (rc == -EINPROGRESS) {
		return rc;
	}

	/* Then unmount all fsdevs */
	TAILQ_FOREACH(fs, &g_app.filesystems, tailq) {
		if (fs->root != NULL) {
			fsdevperf_filesystem_umount(fs);
			return -EINPROGRESS;
		}
	}

	return 0;
}

static void
_fsdevperf_task_done(void *ctx)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;

	fsdevperf_job_set_status(job, task->status);
	if (--job->num_active == 0) {
		job->ops.job_done(job, job->status);
	}
}

static void
fsdevperf_task_done(struct fsdevperf_task *task, int status)
{
	task->status = status;
	if (task->num_outstanding > 0) {
		return;
	}

	task->tsc_finish = spdk_get_ticks();
	spdk_thread_send_msg(spdk_thread_get_app_thread(), _fsdevperf_task_done, task);
	spdk_put_io_channel(task->ioch);
}

static bool
fsdevperf_task_is_done(struct fsdevperf_task *task)
{
	return task->stats.num_bytes >= task->size ||
	       spdk_get_ticks() >= task->tsc_finish ||
	       task->stop;
}

static uint64_t
fsdevperf_task_get_offset(struct fsdevperf_task *task)
{
	struct fsdevperf_job *job = task->job;
	uint64_t offset;

	if (fsdevperf_job_is_random(job)) {
		offset = (((uint64_t)rand_r(&task->seed) * RAND_MAX + rand_r(&task->seed)) %
			  (task->filesize / task->io_size)) * task->io_size;
	} else {
		offset = task->offset;
		task->offset += task->io_size;
		if (task->offset >= task->filesize) {
			task->offset = 0;
		}
	}

	return offset;
}

static void fsdevperf_request_submit(struct fsdevperf_request *request);

static void
fsdevperf_request_complete_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_request *request = cb_arg;
	struct fsdevperf_task *task = request->task;
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_job *job = task->job;
	struct fsdevperf_io *io = &request->io;
	struct spdk_fsdev *fsdev;

	assert(task->num_outstanding > 0);
	task->num_outstanding--;
	task->stats.num_ios++;

	fsdev = spdk_fsdev_desc_get_fsdev(fs->fsdev_desc);
	switch (spdk_fsdev_io_get_type(fsdev_io)) {
	case SPDK_FSDEV_IO_FUSE:
		switch (io->fuse_io.in.hdr.opcode) {
		case FUSE_READ:
			assert(io->fuse_io.out.hdr.len >= sizeof(io->fuse_io.out.hdr));
			task->stats.num_bytes += io->fuse_io.out.hdr.len -
						 sizeof(io->fuse_io.out.hdr);
			break;
		case FUSE_WRITE:
			task->stats.num_bytes += io->fuse_io.out.op.write.size;
			break;
		default:
			fsdevperf_errmsg("%s /%s/%s unexpected FUSE type: %d\n",
					 fsdevperf_job_get_io_pattern_name(job),
					 spdk_fsdev_get_name(fsdev), task->file->name,
					 io->fuse_io.in.hdr.opcode);
			assert(0);
			break;
		}
		break;
	case SPDK_FSDEV_IO_READ:
		task->stats.num_bytes += fsdev_io->u_out.read.data_size;
		break;
	case SPDK_FSDEV_IO_WRITE:
		task->stats.num_bytes += fsdev_io->u_out.write.data_size;
		break;
	default:
		fsdevperf_errmsg("%s /%s/%s unexpected type: %d\n",
				 fsdevperf_job_get_io_pattern_name(job),
				 spdk_fsdev_get_name(fsdev), task->file->name,
				 spdk_fsdev_io_get_type(fsdev_io));
		assert(0);
		break;
	}

	if (spdk_unlikely(status != 0)) {
		fsdevperf_errmsg("%s /%s/%s failed: %s\n",
				 fsdevperf_job_get_io_pattern_name(job),
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 task->file->name, spdk_strerror(-status));
		fsdevperf_task_done(task, status);
		return;
	}

	if (spdk_unlikely(fsdevperf_task_is_done(task))) {
		fsdevperf_task_done(task, task->status);
		return;
	}

	fsdevperf_request_submit(request);
}

static void
fsdevperf_request_generate_data(struct fsdevperf_request *request, uint64_t id)
{
	struct fsdevperf_task *task = request->task;
	uint64_t *p = request->iovs[0].iov_base;
	size_t i;

	if (!task->unique_data) {
		return;
	}

	for (i = 0; i < task->io_size / sizeof(uint64_t); i++) {
		*(p++) = id;
	}
}

static void
fsdevperf_request_submit(struct fsdevperf_request *request)
{
	struct fsdevperf_task *task = request->task;
	uint64_t offset, id;

	offset = fsdevperf_task_get_offset(task);
	id = fsdevperf_task_next_id(task);
	switch (task->io_pattern) {
	case FUSE_READ:
		fsdevperf_request_submit_read(request, id, task->fobj, task->fh, offset,
					      task->io_size, request->iovs, request->iovcnt,
					      fsdevperf_request_complete_cb, request);
		break;
	case FUSE_WRITE:
		fsdevperf_request_generate_data(request, id);
		fsdevperf_request_submit_write(request, id, task->fobj, task->fh, offset,
					       task->io_size, request->iovs, request->iovcnt,
					       fsdevperf_request_complete_cb, request);
		break;
	default:
		assert(0);
		break;
	}

	task->num_outstanding++;
}

static void
fsdevperf_task_run(struct fsdevperf_task *task)
{
	struct fsdevperf_job *job = task->job;
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_file *file = task->file;
	size_t i, min_size;

	min_size = spdk_max(task->io_size * task->io_depth, job->filesize);
	if (file->size < min_size) {
		fsdevperf_errmsg("/%s/%s: %s (minimum size required: %zu)\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 file->name, spdk_strerror(ENOSPC), min_size);
		fsdevperf_task_done(task, -ENOSPC);
		return;
	}

	task->fh = file->fh;
	task->fobj = file->fobj;
	task->filesize = job->filesize ? job->filesize : file->size;
	task->size = job->size ? job->size : file->size;
	task->tsc_start = spdk_get_ticks();
	task->tsc_finish = job->runtime != 0 ? task->tsc_start +
			   (uint64_t)job->runtime * spdk_get_ticks_hz() : UINT64_MAX;
	for (i = 0; i < task->io_depth; i++) {
		fsdevperf_request_submit(fsdevperf_task_request(task, i));
	}
}

static void
fsdevperf_task_setup_file(struct fsdevperf_task *task)
{
	struct fsdevperf_file *file = task->file;

	/* If the file is already large enough we're done, otherwise we'll need to extend it */
	if (file->size >= task->size) {
		fsdevperf_task_done(task, 0);
		return;
	}

	task->io_size = spdk_min(task->io_size, task->size);
	file->size = task->size;
	fsdevperf_task_run(task);
}

static void
fsdevperf_task_open_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_task *task = cb_arg;
	struct fsdevperf_file *file = task->file;
	struct fsdevperf_filesystem *fs = task->fs;
	struct fuse_open_out *open;

	if (status != 0) {
		fsdevperf_errmsg("open /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 file->name, spdk_strerror(-status));
		fsdevperf_task_done(task, status);
		return;
	}

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_OPEN)) {
		open = &task->io.fuse_io.out.op.open;
		file->fh = task->fh = (void *)open->fh;
	} else {
		file->fh = task->fh = fsdev_io->u_out.open.fhandle;
	}

	fsdevperf_task_setup_file(task);
}

static void
fsdevperf_task_create_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_task *task = cb_arg;
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_file *file = task->file;
	struct spdk_fuse_create_out *create;

	if (status != 0) {
		fsdevperf_errmsg("create /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 file->name, spdk_strerror(-status));
		fsdevperf_task_done(task, status);
		return;
	}

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_CREATE)) {
		create = &task->io.fuse_io.out.op.create;
		file->size = create->entry.attr.size;
		file->fobj = (void *)create->entry.nodeid;
		file->fh = task->fh = (void *)create->open.fh;
	} else {
		file->size = fsdev_io->u_out.create.attr.size;
		file->fobj = task->fobj = fsdev_io->u_out.create.fobject;
		file->fh = task->fh = fsdev_io->u_out.create.fhandle;
	}

	fsdevperf_task_setup_file(task);
}

static void
fsdevperf_task_lookup_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_task *task = cb_arg;
	struct fsdevperf_job *job = task->job;
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_file *file = task->file;
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(fs->fsdev_desc);
	struct fuse_entry_out *entry;
	uint32_t flags;
	uint64_t id;

	if (status != 0) {
		if (status == -ENOENT) {
			/* We're only going to create the file if the user specified its size */
			if (task->size == 0) {
				fsdevperf_errmsg("%s: /%s/%s doesn't exist and filesize wasn't "
						 "specified\n", task->job->name,
						 spdk_fsdev_get_name(fsdev), file->name);
				fsdevperf_task_done(task, -EINVAL);
				return;
			}

			id = fsdevperf_task_next_id(task);
			fsdevperf_task_submit_create(task, id, fs->root, file->name, O_RDWR, 0644,
						     g_app.umask, fsdevperf_task_create_cb, task);
			return;
		}
		fsdevperf_errmsg("lookup /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(fsdev), file->name, spdk_strerror(-status));
		fsdevperf_task_done(task, status);
		return;
	}

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_LOOKUP)) {
		entry = &task->io.fuse_io.out.op.entry;
		file->size = entry->attr.size;
		file->fobj = task->fobj = (void *)entry->nodeid;
	} else {
		file->size = fsdev_io->u_out.lookup.attr.size;
		file->fobj = task->fobj = fsdev_io->u_out.lookup.fobject;
	}

	id = fsdevperf_task_next_id(task);
	flags = O_RDWR;
	if (job->flags & FSDEVPERF_JOB_DIRECT) {
		flags |= O_DIRECT;
	}

	fsdevperf_task_submit_open(task, id, file->fobj, flags, fsdevperf_task_open_cb, task);
}

static void
fsdevperf_task_lookup(struct fsdevperf_task *task)
{
	struct fsdevperf_filesystem *fs = task->fs;
	struct fsdevperf_file *file = task->file;
	uint64_t id;

	id = fsdevperf_task_next_id(task);
	fsdevperf_task_submit_lookup(task, id, fs->root, file->name,
				     fsdevperf_task_lookup_cb, task);
}

static void
fsdevperf_task_do_start(void *ctx)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;

	if (task->status != 0) {
		return;
	}

	job->ops.start_task(task);
}

static void
fsdevperf_task_sync_job(void *ctx)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;
	size_t num_ready = 0, num_tasks = 0;

	job->num_ready++;
	fsdevperf_foreach_leaf_job(job) {
		num_ready += job->num_ready;
		num_tasks += job->num_tasks;
	}

	if (num_ready == num_tasks) {
		fsdevperf_foreach_leaf_job(job) {
			TAILQ_FOREACH(task, &job->tasks, tailq.job) {
				spdk_thread_send_msg(task->thread->thread,
						     fsdevperf_task_do_start, task);
			}
		}
	}
}

static void
fsdevperf_task_statfs_done(void *ctx, int status, struct spdk_fsdev_io *fsdev_io)
{
	spdk_thread_send_msg(spdk_thread_get_app_thread(), fsdevperf_task_sync_job, ctx);
}

static void
fsdevperf_task_start(void *ctx)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_filesystem *fs = task->fs;
	struct spdk_fsdev *fsdev = spdk_fsdev_desc_get_fsdev(fs->fsdev_desc);
	uint64_t id;

	task->seed = rand();
	task->ioch = spdk_fsdev_get_io_channel(fs->fsdev_desc);
	if (task->ioch == NULL) {
		fsdevperf_errmsg("failed to get IO channel for %s on core %u\n",
				 spdk_fsdev_get_name(fsdev), spdk_env_get_current_core());
		fsdevperf_task_done(task, -ENOMEM);
		return;
	}

	if (fsdevperf_job_is_internal(task->job)) {
		fsdevperf_task_do_start(task);
	} else {
		id = fsdevperf_task_next_id(task);
		fsdevperf_task_submit_statfs(task, id, fs->root, fsdevperf_task_statfs_done, task);
	}
}

static void
fsdevperf_job_start(struct fsdevperf_job *job)
{
	struct fsdevperf_task *task;

	TAILQ_FOREACH(task, &job->tasks, tailq.job) {
		spdk_thread_send_msg(task->thread->thread, fsdevperf_task_start, task);
		job->num_active++;
	}
}

static void
fsdevperf_user_job_done(struct fsdevperf_job *job, int status)
{
	fsdevperf_set_status(status);
	if (--g_app.num_active == 0) {
		fsdevperf_done();
	}
}

static void
fsdevperf_start_jobs(void)
{
	struct fsdevperf_job *job;

	fsdevperf_foreach_leaf_job(job) {
		fsdevperf_job_start(job);
		g_app.num_active++;
	}
}

static void
fsdevperf_setup_job_done(struct fsdevperf_job *job, int status)
{
	TAILQ_REMOVE(&g_app.jobs, job, tailq.app);
	fsdevperf_job_cleanup(job);
	fsdevperf_job_free(job);

	if (status == 0) {
		fsdevperf_start_jobs();
	} else {
		fsdevperf_set_status(status);
		fsdevperf_done();
	}
}

static void
fsdevperf_setup_files(void)
{
	struct fsdevperf_job *job;
	struct fsdevperf_task *task;
	struct fsdevperf_thread *thread;
	struct fsdevperf_job_ops ops = {
		.start_task = fsdevperf_task_lookup,
		.job_done = fsdevperf_setup_job_done,
	};
	struct fsdevperf_file *file;
	int rc;

	job = fsdevperf_job_alloc("setup", &ops,
				  FSDEVPERF_JOB_SINGLE_BUFFER | FSDEVPERF_JOB_INTERNAL);
	if (job == NULL) {
		fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
		rc = -ENOMEM;
		goto error;
	}

	job->io_pattern = SPDK_FSDEV_IO_WRITE;
	job->io_depth = 1;
	job->io_size = 1024 * 1024;
	TAILQ_INSERT_TAIL(&g_app.jobs, job, tailq.app);

	job->buf = spdk_zmalloc(job->io_depth * job->io_size, 4096, NULL,
				SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
	if (job->buf == NULL) {
		fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
		rc = -ENOMEM;
		goto error;
	}

	thread = TAILQ_FIRST(&g_app.threads);
	TAILQ_FOREACH(file, &g_app.files, tailq) {
		task = fsdevperf_task_alloc(job, file, thread);
		if (task == NULL) {
			fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
			rc = -ENOMEM;
			goto error;
		}

		task->size = task->filesize = file->size;
		TAILQ_INSERT_TAIL(&thread->tasks, task, tailq.thread);
		TAILQ_INSERT_TAIL(&job->tasks, task, tailq.job);
		thread = TAILQ_NEXT(thread, tailq) ? TAILQ_NEXT(thread, tailq) :
			 TAILQ_FIRST(&g_app.threads);
		job->num_tasks++;
	}

	fsdevperf_job_start(job);
	return;
error:
	fsdevperf_set_status(rc);
	fsdevperf_done();
}

static void fsdevperf_filesystem_mount(struct fsdevperf_filesystem *fs);

static void
fsdevperf_filesystem_mount_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevperf_filesystem *next, *fs = cb_arg;

	if (status != 0) {
		fsdevperf_errmsg("failed to mount %s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(fs->fsdev_desc)),
				 spdk_strerror(-status));
		fsdevperf_set_status(status);
		fsdevperf_done();
		return;
	}

	if (fsdevperf_filesystem_supports_opcode(fs, FUSE_INIT)) {
		fs->root = (void *)FUSE_ROOT_ID;
	} else {
		fs->root = fsdev_io->u_out.mount.root_fobject;
	}

	next = TAILQ_NEXT(fs, tailq);
	if (next != NULL) {
		fsdevperf_filesystem_mount(next);
	} else {
		fsdevperf_setup_files();
	}
}

static void
fsdevperf_filesystem_mount(struct fsdevperf_filesystem *fs)
{
	fsdevperf_filesystem_submit_mount(fs, fsdevperf_filesystem_mount_cb, fs);
}

static void
fsdevperf_poller_update_done(void *ctx)
{
	struct fsdevperf_stats *curr = &g_app.poller.current_stats;
	struct fsdevperf_stats *prev = &g_app.poller.prev_stats;
	double iops, mbps;
	static int lastlen;
	int len;

	if (g_app.poller.poller == NULL) {
		return;
	}

	iops = (double)(curr->num_ios - prev->num_ios) / FSDEVPERF_POLLER_PERIOD;
	mbps = (double)(curr->num_bytes - prev->num_bytes) / (1024 * 1024 * FSDEVPERF_POLLER_PERIOD);
	*prev = *curr;

	spdk_poller_resume(g_app.poller.poller);

	len = printf("IOPS: %.2f, %.2fMiB/s", iops, mbps);
	printf("%*s\r", lastlen - spdk_min(len, lastlen), "");
	lastlen = len;
	fflush(stdout);
}

static void
fsdevperf_poller_update(void *ctx)
{
	struct fsdevperf_thread *thread;
	struct fsdevperf_task *task;
	struct fsdevperf_stats *stats = &g_app.poller.current_stats;

	if (g_app.poller.poller == NULL) {
		return;
	}

	thread = fsdevperf_get_thread();
	if (thread == NULL) {
		return;
	}

	TAILQ_FOREACH(task, &thread->tasks, tailq.thread) {
		stats->num_ios += task->stats.num_ios;
		stats->num_bytes += task->stats.num_bytes;
	}
}

static int
fsdevperf_poller(void *ctx)
{
	spdk_poller_pause(g_app.poller.poller);

	memset(&g_app.poller.current_stats, 0, sizeof(g_app.poller.current_stats));
	spdk_for_each_thread(fsdevperf_poller_update, NULL, fsdevperf_poller_update_done);

	return SPDK_POLLER_BUSY;
}

static const struct fsdevperf_job_ops g_default_job_ops = {
	.start_task = fsdevperf_task_run,
	.job_done = fsdevperf_user_job_done,
};

static bool
fsdevperf_multi_job_check_fsdev(struct fsdevperf_job *job, struct spdk_fsdev *fsdev)
{
	char name[PATH_MAX], *tok, *sp = NULL;

	fsdevperf_get_fsdev_name(job->path, name, sizeof(name));
	if (strcmp(name, "*") == 0) {
		return true;
	}

	for (tok = strtok_r(name, ",", &sp);
	     tok != NULL;
	     tok = strtok_r(NULL, ",", &sp)) {
		if (strcmp(tok, spdk_fsdev_get_name(fsdev)) == 0) {
			return true;
		}
	}

	return false;
}

static int
fsdevperf_for_each_fsdev_create_job(void *ctx, struct spdk_fsdev *fsdev)
{
	struct fsdevperf_job *job, *orig_job = ctx;
	const char *filename = fsdevperf_get_filename(orig_job->path);
	char name[256];

	if (!fsdevperf_multi_job_check_fsdev(orig_job, fsdev)) {
		return 0;
	}

	snprintf(name, sizeof(name), "%s-%s", orig_job->name, spdk_fsdev_get_name(fsdev));
	job = fsdevperf_job_alloc(name, &g_default_job_ops, 0);
	if (job == NULL) {
		return -ENOMEM;
	}

	job->path = spdk_sprintf_alloc("/%s%s%s", spdk_fsdev_get_name(fsdev),
				       filename != NULL ? "/" : "",
				       filename != NULL ? filename : "");
	if (job->path == NULL) {
		fsdevperf_job_free(job);
		return -ENOMEM;
	}

	job->io_pattern = orig_job->io_pattern;
	job->io_size = orig_job->io_size;
	job->io_depth = orig_job->io_depth;
	job->io_segment_size = orig_job->io_segment_size;
	job->filesize = orig_job->filesize;
	job->size = orig_job->size;
	job->num_files = orig_job->num_files;
	job->runtime = orig_job->runtime;
	job->flags = orig_job->flags;

	TAILQ_INSERT_TAIL(&g_app.jobs, job, tailq.app);
	TAILQ_INSERT_TAIL(&orig_job->children, job, tailq.child);

	return 0;
}

static int
fsdevperf_create_jobs(void)
{
	struct fsdevperf_job *job;
	int rc;

	TAILQ_FOREACH(job, &g_app.jobs, tailq.app) {
		if (!fsdevperf_job_is_multi(job)) {
			continue;
		}

		rc = spdk_for_each_fsdev(job, fsdevperf_for_each_fsdev_create_job);
		if (rc != 0) {
			return rc;
		}

		if (TAILQ_EMPTY(&job->children)) {
			fsdevperf_errmsg("could not find fsdev(s) for job: %s\n", job->name);
			return -ENODEV;
		}
	}

	if (TAILQ_EMPTY(&g_app.jobs)) {
		fsdevperf_errmsg("no fsdev(s) were found\n");
		return -ENODEV;
	}

	return 0;
}

static int
fsdevperf_pull_data(struct spdk_memory_domain *src_domain, void *src_domain_ctx,
		    struct iovec *src_iovs, uint32_t src_iovcnt, struct iovec *dst_iovs,
		    uint32_t dst_iovcnt, spdk_memory_domain_data_cpl_cb cpl_cb, void *cpl_ctx)
{
	struct fsdevperf_task *task = src_domain_ctx;
	struct fsdevperf_job *job = task->job;

	if (!(job->flags & FSDEVPERF_JOB_SKIP_COPY)) {
		spdk_iovcpy(src_iovs, src_iovcnt, dst_iovs, dst_iovcnt);
	}

	cpl_cb(cpl_ctx, 0);
	return 0;
}

static int
fsdevperf_push_data(struct spdk_memory_domain *dst_domain, void *dst_domain_ctx,
		    struct iovec *dst_iovs, uint32_t dst_iovcnt, struct iovec *src_iovs,
		    uint32_t src_iovcnt, spdk_memory_domain_data_cpl_cb cpl_cb, void *cpl_ctx)
{
	struct fsdevperf_task *task = dst_domain_ctx;
	struct fsdevperf_job *job = task->job;

	if (!(job->flags & FSDEVPERF_JOB_SKIP_COPY)) {
		spdk_iovcpy(src_iovs, src_iovcnt, dst_iovs, dst_iovcnt);
	}

	cpl_cb(cpl_ctx, 0);
	return 0;
}

#ifdef SPDK_CONFIG_RDMA
static struct fsdevperf_domain *
fsdevperf_get_domain(struct fsdevperf_task *task, struct spdk_memory_domain *domain,
		     struct spdk_memory_domain_translation_ctx *ctx)
{
	struct fsdevperf_job *job = task->job;
	struct fsdevperf_domain *fd;
	struct ibv_qp *qp;
	uint64_t flags;

	STAILQ_FOREACH(fd, &task->domains, stailq) {
		if (fd->domain == domain) {
			return fd;
		}
	}

	fd = calloc(1, sizeof(*fd));
	if (fd == NULL) {
		return NULL;
	}

	qp = SPDK_GET_FIELD(ctx, rdma.ibv_qp, NULL);
	flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

	fd->domain = domain;
	fd->map = spdk_rdma_utils_create_mem_map(qp->pd, NULL, flags);
	if (fd->map == NULL) {
		fsdevperf_errmsg("%s: failed to create memory map\n", job->name);
		free(fd);
		return NULL;
	}

	STAILQ_INSERT_TAIL(&task->domains, fd, stailq);
	return fd;
}

static int
fsdevperf_translate_addr(struct spdk_memory_domain *src_domain,
			 void *src_domain_ctx, struct spdk_memory_domain *dst_domain,
			 struct spdk_memory_domain_translation_ctx *dst_domain_ctx,
			 void *addr, size_t len,
			 struct spdk_memory_domain_translation_result *result)
{
	struct fsdevperf_task *task = src_domain_ctx;
	struct fsdevperf_job *job = task->job;
	struct spdk_rdma_utils_memory_translation tr;
	struct fsdevperf_domain *fd;
	int rc;

	assert(spdk_memory_domain_get_dma_device_type(dst_domain) == SPDK_DMA_DEVICE_TYPE_RDMA);
	fd = fsdevperf_get_domain(task, dst_domain, dst_domain_ctx);
	if (spdk_unlikely(fd == NULL)) {
		return -ENOMEM;
	}

	rc = spdk_rdma_utils_get_translation(fd->map, addr, len, &tr);
	if (spdk_unlikely(rc != 0)) {
		fsdevperf_errmsg("%s: failed to translate addr=%p: %s\n", job->name, addr,
				 spdk_strerror(-rc));
		return rc;
	}

	assert(result->size >= SPDK_SIZEOF(result, rdma));
	result->iov_count = 1;
	result->iov.iov_base = addr;
	result->iov.iov_len = len;
	result->dst_domain = dst_domain;
	result->rdma.lkey = spdk_rdma_utils_memory_translation_get_lkey(&tr);
	result->rdma.rkey = spdk_rdma_utils_memory_translation_get_rkey(&tr);

	return 0;
}
#else
static int
fsdevperf_translate_addr(struct spdk_memory_domain *src_domain,
			 void *src_domain_ctx, struct spdk_memory_domain *dst_domain,
			 struct spdk_memory_domain_translation_ctx *dst_domain_ctx,
			 void *addr, size_t len,
			 struct spdk_memory_domain_translation_result *result)
{
	return -ENOTSUP;
}
#endif

static int
fsdevperf_init_memory_domain(void)
{
	int rc;

	rc = spdk_memory_domain_create(&g_app.domain, SPDK_DMA_DEVICE_TYPE_DMA, NULL, "fsdevperf");
	if (rc != 0) {
		fsdevperf_errmsg("failed to create memory domain: %s\n", spdk_strerror(-rc));
		return rc;
	}

	spdk_memory_domain_set_translation(g_app.domain, fsdevperf_translate_addr);
	spdk_memory_domain_set_pull(g_app.domain, fsdevperf_pull_data);
	spdk_memory_domain_set_push(g_app.domain, fsdevperf_push_data);
	return 0;
}

static void
fsdevperf_run(void)
{
	int rc;

	rc = fsdevperf_init_memory_domain();
	if (rc != 0) {
		goto error;
	}

	rc = fsdevperf_create_jobs();
	if (rc != 0) {
		goto error;
	}

	rc = fsdevperf_init_threads();
	if (rc != 0) {
		goto error;
	}

	rc = fsdevperf_init_filesystems();
	if (rc != 0) {
		goto error;
	}

	rc = fsdevperf_init_jobs();
	if (rc != 0) {
		goto error;
	}

	g_app.poller.poller = SPDK_POLLER_REGISTER(fsdevperf_poller, NULL,
			      FSDEVPERF_POLLER_PERIOD * SPDK_SEC_TO_USEC);
	if (g_app.poller.poller == NULL) {
		goto error;
	}

	assert(!TAILQ_EMPTY(&g_app.filesystems));
	fsdevperf_filesystem_mount(TAILQ_FIRST(&g_app.filesystems));
	return;
error:
	fsdevperf_set_status(rc);
	fsdevperf_done();
}

static void
fsdevperf_start_app(void *ctx)
{
	if (g_app.rpc.enabled) {
		return;
	}

	fsdevperf_run();
}

static void
fsdevperf_shutdown_thread(void *ctx)
{
	struct fsdevperf_thread *thread = ctx;
	struct fsdevperf_task *task;

	TAILQ_FOREACH(task, &thread->tasks, tailq.thread) {
		task->stop = true;
	}
}

static void
fsdevperf_shutdown_cb(void)
{
	struct fsdevperf_thread *thread;

	fsdevperf_set_status(-ECANCELED);
	if (g_app.rpc.enabled && g_app.rpc.request == NULL) {
		fsdevperf_done();
	} else {
		TAILQ_FOREACH(thread, &g_app.threads, tailq) {
			spdk_thread_send_msg(thread->thread, fsdevperf_shutdown_thread, thread);
		}
	}
}

static int
fsdevperf_job_check_params(struct fsdevperf_job *job)
{
	if (job->path == NULL) {
		fsdevperf_errmsg("%s: missing argument: path\n", job->name);
		return -EINVAL;
	}
	if (fsdevperf_job_check_path(job)) {
		return -EINVAL;
	}
	if (job->io_size == 0) {
		fsdevperf_errmsg("%s: invalid iosize argument: %zu\n", job->name, job->io_size);
		return -EINVAL;
	}
	if (job->io_depth == 0) {
		fsdevperf_errmsg("%s: invalid iodepth argument: %zu\n", job->name, job->io_depth);
		return -EINVAL;
	}
	if (job->io_pattern < 0) {
		fsdevperf_errmsg("%s: missing argument: pattern\n", job->name);
		return -EINVAL;
	}
	if (job->num_files > 1 && fsdevperf_get_filename(job->path) != NULL) {
		fsdevperf_errmsg("%s: nrfiles argument can only be used with path set to fsdev's"
				 "root\n", job->name);
		return -EINVAL;
	}

	return 0;
}

static struct option g_options[] = {
#define FSDEVPERF_OPT_PATH 'P'
	{ "path", required_argument, NULL, FSDEVPERF_OPT_PATH },
#define FSDEVPERF_OPT_IOSIZE 'o'
	{ "iosize", required_argument, NULL, FSDEVPERF_OPT_IOSIZE },
#define FSDEVPERF_OPT_IODEPTH 'q'
	{ "iodepth", required_argument, NULL, FSDEVPERF_OPT_IODEPTH },
#define FSDEVPERF_OPT_PATTERN 'w'
	{ "pattern", required_argument, NULL, FSDEVPERF_OPT_PATTERN },
#define FSDEVPERF_OPT_RUNTIME 't'
	{ "runtime", required_argument, NULL, FSDEVPERF_OPT_RUNTIME},
#define FSDEVPERF_OPT_JOBS 'j'
	{ "jobs", required_argument, NULL, FSDEVPERF_OPT_JOBS },
#define FSDEVPERF_OPT_WAIT_FOR_START 'z'
	{ "wait-for-start", no_argument, NULL, FSDEVPERF_OPT_WAIT_FOR_START },
#define FSDEVPERF_OPT_FILESIZE 'f'
	{ "filesize", required_argument, NULL, FSDEVPERF_OPT_FILESIZE },
#define FSDEVPERF_OPT_IOSEGMENT_SIZE 'S'
	{ "iosegment-size", required_argument, NULL, FSDEVPERF_OPT_IOSEGMENT_SIZE },
#define FSDEVPERF_OPT_UNIQUE 'U'
	{ "unique", optional_argument, NULL, FSDEVPERF_OPT_UNIQUE },
#define FSDEVPERF_OPT_SIZE 0x1000
	{ "size", required_argument, NULL, FSDEVPERF_OPT_SIZE },
#define FSDEVPERF_OPT_NRFILES 0x1001
	{ "nrfiles", required_argument, NULL, FSDEVPERF_OPT_NRFILES },
#define FSDEVPERF_OPT_NRTHREADS 0x1002
	{ "nrthreads", required_argument, NULL, FSDEVPERF_OPT_NRTHREADS },
#define FSDEVPERF_OPT_DIRECT 0x1003
	{ "direct", optional_argument, NULL, FSDEVPERF_OPT_DIRECT },
#define FSDEVPERF_OPT_UID 0x1004
	{ "uid", required_argument, NULL, FSDEVPERF_OPT_UID },
#define FSDEVPERF_OPT_GID 0x1005
	{ "gid", required_argument, NULL, FSDEVPERF_OPT_GID },
#define FSDEVPERF_OPT_FAKE_MEMORY_DOMAIN 0x1006
	{ "fake-memory-domain", optional_argument, NULL, FSDEVPERF_OPT_FAKE_MEMORY_DOMAIN },
	{},
};

static const char *
fsdevperf_get_option_name(int val)
{
	size_t i;

	for (i = 0; i < SPDK_COUNTOF(g_options); i++) {
		if (g_options[i].val == val) {
			return g_options[i].name;
		}
	}

	return NULL;
}

static int fsdevperf_job_parse_option(struct fsdevperf_job *job, int ch, char *arg);

static int
fsdevperf_load_jobs(const char *filename)
{
	struct spdk_conf *conf;
	struct spdk_conf_section *section;
	struct fsdevperf_job *job = NULL;
	TAILQ_HEAD(, fsdevperf_job) jobs = TAILQ_HEAD_INITIALIZER(jobs);
	int cmdline_options[] = {
		FSDEVPERF_OPT_JOBS, FSDEVPERF_OPT_WAIT_FOR_START, FSDEVPERF_OPT_NRTHREADS,
	};
	size_t i, j;
	char *str;
	int rc;

	conf = spdk_conf_allocate();
	if (conf == NULL) {
		fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
		return -ENOMEM;
	}

	rc = spdk_conf_read(conf, filename);
	if (rc != 0) {
		fsdevperf_errmsg("failed to load job config: %s\n", filename);
		rc = -EINVAL;
		goto error;
	}

	for (section = spdk_conf_first_section(conf); section != NULL;
	     section = spdk_conf_next_section(section)) {
		job = fsdevperf_job_alloc(spdk_conf_section_get_name(section),
					  &g_default_job_ops, 0);
		if (job == NULL) {
			fsdevperf_errmsg("%s\n", spdk_strerror(ENOMEM));
			goto error;
		}

		TAILQ_INSERT_TAIL(&jobs, job, tailq.app);

		for (i = 0; i < SPDK_COUNTOF(g_options); i++) {
			/* Skip the command-line-only options */
			for (j = 0; j < SPDK_COUNTOF(cmdline_options); j++) {
				if (g_options[i].val == cmdline_options[j]) {
					break;
				}
			}
			if (j < SPDK_COUNTOF(cmdline_options)) {
				continue;
			}
			str = spdk_conf_section_get_val(section, g_options[i].name);
			if (str == NULL) {
				continue;
			}
			rc = fsdevperf_job_parse_option(job, g_options[i].val, str);
			if (rc != 0) {
				goto error;
			}
		}

		rc = fsdevperf_job_check_params(job);
		if (rc != 0) {
			goto error;
		}
	}

	while ((job = TAILQ_FIRST(&jobs))) {
		TAILQ_REMOVE(&jobs, job, tailq.app);
		TAILQ_INSERT_TAIL(&g_app.jobs, job, tailq.app);
	}
error:
	while ((job = TAILQ_FIRST(&jobs))) {
		TAILQ_REMOVE(&jobs, job, tailq.app);
		fsdevperf_job_free(job);
	}

	spdk_conf_free(conf);

	return rc;
}

static bool
fsdevperf_parse_bool_option(char *arg)
{
	if (arg == NULL) {
		return true;
	}

	return strcmp(arg, "0") != 0 && strcasecmp(arg, "false") != 0;
}

static int
fsdevperf_job_parse_option(struct fsdevperf_job *job, int ch, char *arg)
{
	uint64_t u64;
	bool random;
	int ival;

	switch (ch) {
	case FSDEVPERF_OPT_PATH:
		if (!TAILQ_EMPTY(&g_app.jobs)) {
			fsdevperf_errmsg("-P, --path and -j, --jobs are mutually exclusive\n");
			return -EINVAL;
		}
		job->path = strdup(arg);
		if (job->path == NULL) {
			return -ENOMEM;
		}
		break;
	case FSDEVPERF_OPT_PATTERN:
		ival = fsdevperf_parse_io_pattern(arg, &random);
		if (ival < 0) {
			fsdevperf_errmsg("%s: invalid pattern argument: %s\n", job->name, arg);
			return -EINVAL;
		}
		job->io_pattern = ival;
		job->flags |= random ? FSDEVPERF_JOB_RANDOM : 0;
		break;
	case FSDEVPERF_OPT_JOBS:
		if (job->path != NULL) {
			fsdevperf_errmsg("-P, --path and -j, --jobs are mutually exclusive\n");
			return -EINVAL;
		}
		if (fsdevperf_load_jobs(arg)) {
			return -EINVAL;
		}
		break;
	case FSDEVPERF_OPT_WAIT_FOR_START:
		g_app.rpc.enabled = true;
		break;
	case FSDEVPERF_OPT_UNIQUE:
		if (fsdevperf_parse_bool_option(arg)) {
			job->flags |= FSDEVPERF_JOB_UNIQUE_DATA;
		}
		break;
	case FSDEVPERF_OPT_DIRECT:
		if (fsdevperf_parse_bool_option(arg)) {
			job->flags |= FSDEVPERF_JOB_DIRECT;
		}
		break;
	case FSDEVPERF_OPT_FAKE_MEMORY_DOMAIN:
		if (arg != NULL) {
			if (!strcmp(arg, "1") || !strcmp(arg, "true")) {
				job->flags |= FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN;
			} else if (!strcmp(arg, "0") || !strcmp(arg, "false")) {
				job->flags &= ~FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN;
			} else if (!strcmp(arg, "nocopy") || !strcmp(arg, "skip")) {
				job->flags |= FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN |
					      FSDEVPERF_JOB_SKIP_COPY;
			} else {
				fsdevperf_errmsg("%s: invalid option --fake-memory-domain=%s\n",
						 job->name, arg);
				return -EINVAL;
			}
		} else {
			job->flags |= FSDEVPERF_JOB_FAKE_MEMORY_DOMAIN;
		}
		break;
	case FSDEVPERF_OPT_IOSIZE:
	case FSDEVPERF_OPT_IODEPTH:
	case FSDEVPERF_OPT_IOSEGMENT_SIZE:
	case FSDEVPERF_OPT_SIZE:
	case FSDEVPERF_OPT_RUNTIME:
	case FSDEVPERF_OPT_FILESIZE:
	case FSDEVPERF_OPT_NRFILES:
	case FSDEVPERF_OPT_NRTHREADS:
	case FSDEVPERF_OPT_UID:
	case FSDEVPERF_OPT_GID:
		if (spdk_parse_capacity(arg, &u64, NULL) != 0) {
			fsdevperf_errmsg("%s: invalid %s argument: %s\n",
					 job->name, fsdevperf_get_option_name(ch), arg);
			return -EINVAL;
		}
		switch (ch) {
		case FSDEVPERF_OPT_IOSIZE:
			job->io_size = (size_t)u64;
			break;
		case FSDEVPERF_OPT_IODEPTH:
			job->io_depth = (size_t)u64;
			break;
		case FSDEVPERF_OPT_IOSEGMENT_SIZE:
			job->io_segment_size = (size_t)u64;
			break;
		case FSDEVPERF_OPT_SIZE:
			job->size = (size_t)u64;
			break;
		case FSDEVPERF_OPT_RUNTIME:
			if (job->size == 0) {
				job->size = SIZE_MAX;
			}
			job->runtime = (uint32_t)u64;
			break;
		case FSDEVPERF_OPT_FILESIZE:
			job->filesize = (uint64_t)u64;
			break;
		case FSDEVPERF_OPT_NRFILES:
			job->num_files = (size_t)u64;
			break;
		case FSDEVPERF_OPT_NRTHREADS:
			g_app.num_threads_per_core = (size_t)u64;
			break;
		case FSDEVPERF_OPT_UID:
			g_app.uid = (uint32_t)u64;
			break;
		case FSDEVPERF_OPT_GID:
			g_app.gid = (uint32_t)u64;
			break;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int
fsdevperf_parse_arg(int ch, char *arg)
{
	return fsdevperf_job_parse_option(g_app.main_job, ch, arg);
}

static void
fsdevperf_usage(void)
{
	printf(" -P, --path=<path>                    path to a file in the form of /<fsdev>[/<file>]\n");
	printf("                                      If <file> is omitted, fsdevperf will create a file\n");
	printf("                                      on each thread.  If <fsdev> is a wildcard (*), I/O\n");
	printf("                                      will be sent to files on all available fsdevs\n");
	printf(" -o, --iosize=<iosize>                I/O size\n");
	printf(" -q, --iodepth=<iodepth>              I/O depth\n");
	printf(" -S, --iosegment-size                 I/O segment size\n");
	printf("     --size=<size>                    total size of I/O to perform on each file/thread\n");
	printf(" -w, --pattern=<pattern>              I/O pattern (read, write, randread, randwrite)\n");
	printf(" -t, --runtime=<runtime>              runtime in seconds\n");
	printf(" -j, --jobs=<file>                    job configuration file\n");
	printf(" -z, --wait-for-start                 don't start the test immediately, wait for the perform_tests\n");
	printf("                                      RPC (see examples/fsdev/fsdevperf/fsdevperf.py)\n");
	printf(" -f, --filesize=<filesize>            maximum size of each file\n");
	printf("     --nrfiles=<nrfiles>              number of files to send I/O to on each thread\n");
	printf(" -U, --unique                         generate unique data for each I/O\n");
	printf("     --nrthreads=<count>              spawn <count> threads on each core\n");
	printf("     --direct                         use direct I/O\n");
	printf("     --uid                            uid to use in the fuse_in_header for FUSE-based fsdev modules (default: 0)\n");
	printf("     --gid                            gid to use in the fuse_in_header for FUSE-based fsdev modules (default: 0)\n");
	printf("     --fake-memory-domain             pass fake memory domain in all I/O requests\n");
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc;

	srand(getpid());
	g_app.name = argv[0];
	g_app.umask = umask(0);
	umask(g_app.umask);

	/* For now, we only support one "main" job */
	g_app.main_job = fsdevperf_job_alloc("main", &g_default_job_ops, 0);
	if (g_app.main_job == NULL) {
		return EXIT_FAILURE;
	}

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "fsdevperf";
	opts.shutdown_cb = fsdevperf_shutdown_cb;
	rc = spdk_app_parse_args(argc, argv, &opts, "f:j:o:P:t:q:Uw:z", g_options,
				 fsdevperf_parse_arg, fsdevperf_usage);
	if (rc != SPDK_APP_PARSE_ARGS_SUCCESS) {
		return rc;
	}

	/* Only add the main job if the path was specified */
	if (g_app.main_job->path != NULL) {
		if (fsdevperf_job_check_params(g_app.main_job)) {
			return EXIT_FAILURE;
		}

		TAILQ_INSERT_TAIL(&g_app.jobs, g_app.main_job, tailq.app);
	} else {
		fsdevperf_job_free(g_app.main_job);
		g_app.main_job = NULL;
	}

	if (TAILQ_EMPTY(&g_app.jobs)) {
		fsdevperf_errmsg("no job(s) were defined\n");
		return EXIT_FAILURE;
	}

	rc = spdk_app_start(&opts, fsdevperf_start_app, NULL);

	spdk_app_fini();

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
