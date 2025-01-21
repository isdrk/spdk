/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/fsdev.h"
#include "spdk/likely.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"

/*
 * fsdevperf_job describes a single job (i.e. pattern, io_size, etc.), spawned across multiple
 * threads, while fsdevperf_task represents part of that job responsible for submitting IOs to a
 * given file on a given thread.
 */
struct fsdevperf_task;

struct fsdevperf_thread {
	struct spdk_thread		*thread;
	uint32_t			core;
	TAILQ_HEAD(, fsdevperf_task)	tasks;
	TAILQ_ENTRY(fsdevperf_thread)	tailq;
};

struct fsdevperf_request {
	struct fsdevperf_task	*task;
	uint64_t		id;
	struct iovec		iov;
};

struct fsdevperf_task {
	struct fsdevperf_job			*job;
	struct fsdevperf_thread			*thread;
	struct spdk_io_channel			*ioch;
	struct spdk_fsdev_file_object		*fobj;
	struct spdk_fsdev_file_handle		*fh;
	uint64_t				offset;
	uint64_t				filesize;
	uint64_t				size;
	uint32_t				num_outstanding;
	bool					stop;
	struct {
		uint64_t			num_ios;
		uint64_t			num_bytes;
	} stats;
	uint64_t				tsc_finish;
	uint64_t				tsc_start;
	char					*filename;
	int					status;
	struct fsdevperf_request		*requests;
	void					*buf;
	struct {
		TAILQ_ENTRY(fsdevperf_task)	job;
		TAILQ_ENTRY(fsdevperf_task)	thread;
	} tailq;
};

struct fsdevperf_job {
	struct spdk_fsdev_desc		*fsdev_desc;
	int				io_pattern;
	size_t				io_size;
	size_t				io_depth;
	size_t				size;
	struct spdk_fsdev_file_object	*root;
	struct spdk_io_channel		*ioch;
	char				*name;
	char				*path;
	TAILQ_HEAD(, fsdevperf_task)	tasks;
	TAILQ_ENTRY(fsdevperf_job)	tailq;
};

struct fsdevperf_app {
	const char			*name;
	struct fsdevperf_job		*main_job;
	size_t				num_active;
	int				status;
	TAILQ_HEAD(, fsdevperf_job)	jobs;
	TAILQ_HEAD(, fsdevperf_thread)	threads;
} g_app = {
	.jobs = TAILQ_HEAD_INITIALIZER(g_app.jobs),
	.threads = TAILQ_HEAD_INITIALIZER(g_app.threads),
};

#define fsdevperf_errmsg(fmt, ...) \
	fprintf(stderr, "%s: " fmt, g_app.name, ## __VA_ARGS__)

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

	/* For now, we require the user to specify a path to a filename */
	path = strstr(path + 1, "/");
	if (path == NULL || strlen(path + 1) == 0) {
		fsdevperf_errmsg("%s: invalid path: '%s', path must point to a file in "
				 "fsdev's root\n", job->name, job->path);
		return -EINVAL;
	}

	/* We don't support files inside subdirectories */
	if (strstr(path + 1, "/") != NULL) {
		fsdevperf_errmsg("%s: invalid path: '%s', path must point to a file in "
				 "fsdev's root, not to a subdirectory\n", job->name, job->path);
		return -EINVAL;
	}

	return 0;
}

static int
fsdevperf_parse_io_pattern(const char *pattern)
{
	const char *name;
	int i;

	for (i = 0; i < __SPDK_FSDEV_IO_LAST; i++) {
		name = spdk_fsdev_io_type_get_name(i);
		if (name != NULL && strcmp(name, pattern) == 0) {
			return i;
		}
	}

	return -EINVAL;
}

static const char *
fsdevperf_get_io_pattern_name(int pattern)
{
	return spdk_fsdev_io_type_get_name(pattern);
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

static int
fsdevperf_open_fsdevs(void)
{
	struct fsdevperf_job *job;
	char name[PATH_MAX];
	int rc;

	TAILQ_FOREACH(job, &g_app.jobs, tailq) {
		rc = fsdevperf_get_fsdev_name(job->path, name, sizeof(name));
		if (rc != 0) {
			fsdevperf_errmsg("%s\n", spdk_strerror(-rc));
			return rc;
		}
		rc = spdk_fsdev_open(name, fsdevperf_event_cb, NULL, &job->fsdev_desc);
		if (rc != 0) {
			fsdevperf_errmsg("couldn't open /%s: %s\n", name, spdk_strerror(-rc));
			return rc;
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
	uint32_t core;

	SPDK_ENV_FOREACH_CORE(core) {
		thread = calloc(1, sizeof(*thread));
		if (thread == NULL) {
			fsdevperf_errmsg("%s", spdk_strerror(ENOMEM));
			return -ENOMEM;
		}

		spdk_cpuset_zero(&cpuset);
		spdk_cpuset_set_cpu(&cpuset, core, true);
		snprintf(name, sizeof(name), "fsdevperf%u", core);

		TAILQ_INIT(&thread->tasks);
		thread->core = core;
		thread->thread = spdk_thread_create(name, &cpuset);
		if (thread->thread == NULL) {
			fsdevperf_errmsg("%s", spdk_strerror(ENOMEM));
			free(thread);
			return -ENOMEM;
		}

		TAILQ_INSERT_TAIL(&g_app.threads, thread, tailq);
	}

	return 0;
}

static void
fsdevperf_task_free(struct fsdevperf_task *task)
{
	spdk_free(task->buf);
	free(task->requests);
	free(task->filename);
	free(task);
}

static struct fsdevperf_task *
fsdevperf_task_alloc(struct fsdevperf_job *job, struct fsdevperf_thread *thread)
{
	struct fsdevperf_task *task;
	struct fsdevperf_request *request;
	char *filename;
	size_t i;

	task = calloc(1, sizeof(*task));
	if (task == NULL) {
		return NULL;
	}

	task->job = job;
	task->thread = thread;

	filename = strstr(job->path + 1, "/");
	if (filename == NULL || strlen(filename + 1) == 0) {
		goto error;
	}
	filename = strdup(filename + 1);
	if (filename == NULL) {
		goto error;
	}
	task->filename = filename;

	task->requests = calloc(job->io_depth, sizeof(*task->requests));
	if (task->requests == NULL) {
		goto error;
	}

	task->buf = spdk_zmalloc(job->io_depth * job->io_size, 4096, NULL,
				 SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
	if (task->buf == NULL) {
		goto error;
	}

	for (i = 0; i < job->io_depth; i++) {
		request = &task->requests[i];
		request->iov.iov_base = (char *)task->buf + i * job->io_size;
		request->iov.iov_len = job->io_size;
		request->task = task;
		request->id = i;
	}

	return task;
error:
	fsdevperf_task_free(task);
	return NULL;
}

static void
fsdevperf_job_free(struct fsdevperf_job *job)
{
	free(job->name);
	free(job->path);
	free(job);
}

static struct fsdevperf_job *
fsdevperf_job_alloc(const char *name)
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

	TAILQ_INIT(&job->tasks);

	return job;
}

static void
fsdevperf_job_cleanup(struct fsdevperf_job *job)
{
	struct fsdevperf_task *task;
	struct fsdevperf_thread *thread;

	assert(spdk_get_thread() == spdk_thread_get_app_thread());
	if (job->ioch != NULL) {
		spdk_put_io_channel(job->ioch);
		job->ioch = NULL;
	}

	if (job->fsdev_desc != NULL) {
		spdk_fsdev_close(job->fsdev_desc);
		job->fsdev_desc = NULL;
	}

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

	job->ioch = spdk_fsdev_get_io_channel(job->fsdev_desc);
	if (job->ioch == NULL) {
		fsdevperf_errmsg("failed to get IO channel for %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)));
		return -ENOMEM;
	}

	TAILQ_FOREACH(thread, &g_app.threads, tailq) {
		task = fsdevperf_task_alloc(job, thread);
		if (task == NULL) {
			return -ENOMEM;
		}

		TAILQ_INSERT_TAIL(&thread->tasks, task, tailq.thread);
		TAILQ_INSERT_TAIL(&job->tasks, task, tailq.job);
	}

	return 0;
}

static int
fsdevperf_init_jobs(void)
{
	struct fsdevperf_job *job;
	int rc;

	TAILQ_FOREACH(job, &g_app.jobs, tailq) {
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
	double task_iops, job_iops, total_iops;
	double task_mbps, job_mbps, total_mbps;
	size_t num_tasks;
	double runtime;
	char path[PATH_MAX];

	total_iops = 0;
	total_mbps = 0;

	TAILQ_FOREACH(job, &g_app.jobs, tailq) {
		job_iops = 0;
		job_mbps = 0;
		num_tasks = 0;

		printf("%s (pattern=%s, iosize=%zu, iodepth=%zu):\n",
		       job->name, fsdevperf_get_io_pattern_name(job->io_pattern), job->io_size,
		       job->io_depth);
		printf("  %30s %4s %10s %10s %10s\n", "filename", "core", "runtime", "IOPS", "MiB/s");
		TAILQ_FOREACH(task, &job->tasks, tailq.job) {
			snprintf(path, sizeof(path), "/%s/%s",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename);
			runtime = (double)(task->tsc_finish - task->tsc_start) / spdk_get_ticks_hz();
			task_iops = (double)task->stats.num_ios / runtime;
			task_mbps = (double)task->stats.num_bytes / (1024 * 1024 * runtime);
			printf("  %30s %4u %10.2f %10.2f %10.2f\n", path, task->thread->core,
			       runtime, task_iops, task_mbps);

			job_iops += task_iops;
			job_mbps += task_mbps;
			num_tasks++;
		}

		if (num_tasks > 1) {
			printf("  %30s %4s %10s %10.2f %10.2f\n", "", "", "",
			       job_iops, job_mbps);
		}

		total_iops += job_iops;
		total_mbps += job_mbps;
	}
}

static void
fsdevperf_thread_exit(void *ctx)
{
	spdk_thread_exit(spdk_get_thread());
}

static void fsdevperf_job_umount(struct fsdevperf_job *job);

static void
fsdevperf_done(void)
{
	struct fsdevperf_job *job;
	struct fsdevperf_thread *thread;

	/* Make sure all fsdevs are umounted */
	TAILQ_FOREACH(job, &g_app.jobs, tailq) {
		if (job->root != NULL) {
			fsdevperf_job_umount(job);
			return;
		}
	}

	fsdevperf_dump_stats();

	while ((job = TAILQ_FIRST(&g_app.jobs))) {
		TAILQ_REMOVE(&g_app.jobs, job, tailq);
		fsdevperf_job_cleanup(job);
		fsdevperf_job_free(job);
	}

	TAILQ_FOREACH(thread, &g_app.threads, tailq) {
		spdk_thread_send_msg(thread->thread, fsdevperf_thread_exit, NULL);
	}

	spdk_app_stop(g_app.status);
}

static void
fsdevperf_job_umount_cb(void *ctx, struct spdk_io_channel *ioch)
{
	struct fsdevperf_job *job = ctx;

	job->root = NULL;
	fsdevperf_done();
}

static void
fsdevperf_job_umount(struct fsdevperf_job *job)
{
	int rc;

	rc = spdk_fsdev_umount(job->fsdev_desc, job->ioch, 0, fsdevperf_job_umount_cb, job);
	if (rc != 0) {
		fsdevperf_errmsg("failed to umount %s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 spdk_strerror(-rc));
		fsdevperf_job_umount_cb(job, job->ioch);
	}
}

static void fsdevperf_task_done(struct fsdevperf_task *task, int status);

static void
fsdevperf_task_release_cb(void *ctx, struct spdk_io_channel *ch, int status)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;

	if (status != 0) {
		fsdevperf_errmsg("release /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-status));
	}

	task->fh = NULL;
	fsdevperf_task_done(task, task->status);
}

static void
fsdevperf_task_forget_cb(void *ctx, struct spdk_io_channel *ch, int status)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;

	if (status != 0) {
		fsdevperf_errmsg("forget /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-status));
	}

	task->fobj = NULL;
	fsdevperf_task_done(task, task->status);
}

static void
_fsdevperf_task_done(void *ctx)
{
	struct fsdevperf_task *task = ctx;

	fsdevperf_set_status(task->status);
	if (--g_app.num_active == 0) {
		fsdevperf_done();
	}
}

static void
fsdevperf_task_done(struct fsdevperf_task *task, int status)
{
	struct fsdevperf_job *job = task->job;
	int rc;

	task->status = status;
	if (task->num_outstanding > 0) {
		return;
	}

	if (task->fh != NULL) {
		rc = spdk_fsdev_release(job->fsdev_desc, task->ioch, 0, task->fobj, task->fh,
					fsdevperf_task_release_cb, task);
		if (rc == 0) {
			return;
		}

		fsdevperf_errmsg("failed to release /%s/%s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-rc));
		task->fh = NULL;
	}

	if (task->fobj != NULL) {
		rc = spdk_fsdev_forget(job->fsdev_desc, task->ioch, 0, task->fobj, 1,
				       fsdevperf_task_forget_cb, task);
		if (rc == 0) {
			return;
		}

		fsdevperf_errmsg("failed to forget /%s/%s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-rc));
		task->fobj = NULL;
	}

	task->tsc_finish = spdk_get_ticks();
	spdk_thread_send_msg(spdk_thread_get_app_thread(), _fsdevperf_task_done, task);
	spdk_put_io_channel(task->ioch);
}

static bool
fsdevperf_task_is_done(struct fsdevperf_task *task)
{
	return task->stats.num_bytes >= task->size || task->stop;
}

static void fsdevperf_request_submit(struct fsdevperf_request *request);

static void
fsdevperf_request_complete_cb(void *ctx, struct spdk_io_channel *ioch, int status, uint32_t size)
{
	struct fsdevperf_request *request = ctx;
	struct fsdevperf_task *task = request->task;
	struct fsdevperf_job *job = task->job;

	assert(task->num_outstanding > 0);
	task->num_outstanding--;
	task->stats.num_ios++;
	task->stats.num_bytes += size;

	if (spdk_unlikely(status != 0)) {
		fsdevperf_errmsg("%s /%s/%s failed: %s\n",
				 fsdevperf_get_io_pattern_name(job->io_pattern),
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-status));
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
fsdevperf_request_submit(struct fsdevperf_request *request)
{
	struct fsdevperf_task *task = request->task;
	struct fsdevperf_job *job = task->job;
	uint64_t offset = task->offset;
	int rc;

	switch (job->io_pattern) {
	case SPDK_FSDEV_IO_READ:
		rc = spdk_fsdev_read(job->fsdev_desc, task->ioch, request->id, task->fobj,
				     task->fh, job->io_size, offset, 0, &request->iov, 1, NULL,
				     fsdevperf_request_complete_cb, request);
		break;
	case SPDK_FSDEV_IO_WRITE:
		rc = spdk_fsdev_write(job->fsdev_desc, task->ioch, request->id, task->fobj,
				      task->fh, job->io_size, offset, 0, &request->iov, 1, NULL,
				      fsdevperf_request_complete_cb, request);
		break;
	default:
		rc = -EINVAL;
		assert(0);
		break;
	}

	if (spdk_unlikely(rc != 0)) {
		fsdevperf_errmsg("failed to %s /%s/%s: %s\n",
				 fsdevperf_get_io_pattern_name(job->io_pattern),
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-rc));
		fsdevperf_task_done(task, rc);
		return;
	}

	task->num_outstanding++;

	task->offset += job->io_size;
	if (task->offset >= task->filesize) {
		task->offset = 0;
	}
}

static void
fsdevperf_task_run(struct fsdevperf_task *task)
{
	struct fsdevperf_job *job = task->job;
	size_t i;

	task->tsc_start = spdk_get_ticks();
	for (i = 0; i < job->io_depth; i++) {
		fsdevperf_request_submit(&task->requests[i]);
	}
}

static void
fsdevperf_task_open_cb(void *ctx, struct spdk_io_channel *ioch, int status,
		       struct spdk_fsdev_file_handle *file)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;

	if (status != 0) {
		fsdevperf_errmsg("open /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-status));
		fsdevperf_task_done(task, status);
		return;
	}

	task->fh = file;
	fsdevperf_task_run(task);
}

static void
fsdevperf_task_lookup_cb(void *ctx, struct spdk_io_channel *ioch, int status,
			 struct spdk_fsdev_file_object *fobj,
			 const struct spdk_fsdev_file_attr *attr)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;
	int rc;

	if (status != 0) {
		fsdevperf_errmsg("lookup /%s/%s failed: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-status));
		fsdevperf_task_done(task, status);
		return;
	}

	if (attr->size < job->io_size * job->io_depth) {
		fsdevperf_errmsg("/%s/%s: %s (minimum size required: %zu)\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(ENOSPC),
				 job->io_size * job->io_depth);
		fsdevperf_task_done(task, -ENOSPC);
		return;
	}

	task->fobj = fobj;
	task->filesize = attr->size;
	task->size = job->size ? job->size : attr->size;
	rc = spdk_fsdev_fopen(job->fsdev_desc, task->ioch, 0, fobj, O_RDWR,
			      fsdevperf_task_open_cb, task);
	if (rc != 0) {
		fsdevperf_errmsg("failed to open /%s/%s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-rc));
		fsdevperf_task_done(task, rc);
	}
}

static void
fsdevperf_task_start(void *ctx)
{
	struct fsdevperf_task *task = ctx;
	struct fsdevperf_job *job = task->job;
	int rc;

	task->ioch = spdk_fsdev_get_io_channel(job->fsdev_desc);
	if (task->ioch == NULL) {
		fsdevperf_errmsg("failed to get IO channel for %s on core %u\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 spdk_env_get_current_core());
		fsdevperf_task_done(task, -ENOMEM);
		return;
	}

	rc = spdk_fsdev_lookup(job->fsdev_desc, task->ioch, 0, job->root, task->filename,
			       fsdevperf_task_lookup_cb, task);
	if (rc != 0) {
		fsdevperf_errmsg("failed to lookup /%s/%s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 task->filename, spdk_strerror(-rc));
		fsdevperf_task_done(task, rc);
	}
}

static void
fsdevperf_start_tasks(void)
{
	struct fsdevperf_job *job;
	struct fsdevperf_task *task;

	TAILQ_FOREACH(job, &g_app.jobs, tailq) {
		TAILQ_FOREACH(task, &job->tasks, tailq.job) {
			spdk_thread_send_msg(task->thread->thread, fsdevperf_task_start, task);
			g_app.num_active++;
		}
	}
}

static void fsdevperf_job_mount(struct fsdevperf_job *job);

static void
fsdevperf_job_mount_cb(void *ctx, struct spdk_io_channel *ioch, int status,
		       const struct spdk_fsdev_mount_opts *opts,
		       struct spdk_fsdev_file_object *root)
{
	struct fsdevperf_job *next, *job = ctx;

	if (status != 0) {
		fsdevperf_errmsg("failed to mount %s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 spdk_strerror(-status));
		fsdevperf_set_status(status);
		fsdevperf_done();
		return;
	}

	job->root = root;
	next = TAILQ_NEXT(job, tailq);
	if (next != NULL) {
		fsdevperf_job_mount(next);
	} else {
		fsdevperf_start_tasks();
	}
}

static void
fsdevperf_job_mount(struct fsdevperf_job *job)
{
	struct spdk_fsdev_mount_opts opts = {};
	int rc;

	opts.opts_size = SPDK_SIZEOF(&opts, opts_size);
	rc = spdk_fsdev_mount(job->fsdev_desc, job->ioch, 0, &opts, fsdevperf_job_mount_cb, job);
	if (rc != 0) {
		fsdevperf_errmsg("failed to mount %s: %s\n",
				 spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(job->fsdev_desc)),
				 spdk_strerror(-rc));
		goto error;
	}
	return;
error:
	fsdevperf_set_status(rc);
	fsdevperf_done();
}

static void
fsdevperf_run(void *ctx)
{
	int rc;

	rc = fsdevperf_init_threads();
	if (rc != 0) {
		goto error;
	}

	rc = fsdevperf_open_fsdevs();
	if (rc != 0) {
		goto error;
	}

	rc = fsdevperf_init_jobs();
	if (rc != 0) {
		goto error;
	}

	assert(!TAILQ_EMPTY(&g_app.jobs));
	fsdevperf_job_mount(TAILQ_FIRST(&g_app.jobs));
	return;
error:
	fsdevperf_set_status(rc);
	fsdevperf_done();
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
	TAILQ_FOREACH(thread, &g_app.threads, tailq) {
		spdk_thread_send_msg(thread->thread, fsdevperf_shutdown_thread, thread);
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
#define FSDEVPERF_OPT_SIZE 0x1000
	{ "size", required_argument, NULL, FSDEVPERF_OPT_SIZE },
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

static int
fsdevperf_job_parse_option(struct fsdevperf_job *job, int ch, char *arg)
{
	uint64_t u64;
	int ival;

	switch (ch) {
	case FSDEVPERF_OPT_PATH:
		job->path = strdup(arg);
		if (job->path == NULL) {
			return -ENOMEM;
		}
		break;
	case FSDEVPERF_OPT_PATTERN:
		ival = fsdevperf_parse_io_pattern(arg);
		if (ival < 0) {
			fsdevperf_errmsg("%s: invalid pattern argument: %s\n", job->name, arg);
			return -EINVAL;
		}
		job->io_pattern = ival;
		break;
	case FSDEVPERF_OPT_IOSIZE:
	case FSDEVPERF_OPT_IODEPTH:
	case FSDEVPERF_OPT_SIZE:
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
		case FSDEVPERF_OPT_SIZE:
			job->size = (size_t)u64;
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
	printf(" -P, --path=<path>                    path to a file in the form of /<fsdev>/<file>\n");
	printf(" -o, --iosize=<iosize>                I/O size\n");
	printf(" -q, --iodepth=<iodepth>              I/O depth\n");
	printf("     --size=<size>                    total size of I/O to perform on each file/thread\n");
	printf(" -w, --pattern=<pattern>              I/O pattern (read, write)\n");
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc;

	g_app.name = argv[0];

	/* For now, we only support one "main" job */
	g_app.main_job = fsdevperf_job_alloc("main");
	if (g_app.main_job == NULL) {
		return EXIT_FAILURE;
	}

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "fsdevperf";
	opts.shutdown_cb = fsdevperf_shutdown_cb;
	rc = spdk_app_parse_args(argc, argv, &opts, "o:P:q:w:", g_options,
				 fsdevperf_parse_arg, fsdevperf_usage);
	if (rc != SPDK_APP_PARSE_ARGS_SUCCESS) {
		return rc;
	}

	if (fsdevperf_job_check_params(g_app.main_job)) {
		return EXIT_FAILURE;
	}

	TAILQ_INSERT_TAIL(&g_app.jobs, g_app.main_job, tailq);

	rc = spdk_app_start(&opts, fsdevperf_run, NULL);

	spdk_app_fini();

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
