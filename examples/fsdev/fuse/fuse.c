/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/fsdev.h"
#include "spdk/fuse.h"
#include "spdk/string.h"
#include "spdk/thread.h"

struct fsdev_fuse_thread {
	struct spdk_thread		*thread;
	struct spdk_poller		*poller;
	struct spdk_fuse_poll_group	*poll_group;
	int				status;
	bool				running;
	TAILQ_ENTRY(fsdev_fuse_thread)	tailq;
};

struct {
	struct spdk_fuse_mount		*mount;
	struct spdk_fuse_mount_opts	mount_opts;
	const char			*name;
	const char			*fsdev_name;
	const char			*mountpoint;
	const char			*extra_libs;
	struct spdk_poller		*fsdev_poller;
	bool				wait;
	bool				daemon;
	int				status;
	size_t				num_active;
	TAILQ_HEAD(, fsdev_fuse_thread)	threads;
} g_app = {
	.threads = TAILQ_HEAD_INITIALIZER(g_app.threads),
};

#define fsdev_fuse_errmsg(fmt, ...) fprintf(stderr, "%s: " fmt, g_app.name, ## __VA_ARGS__)

static void
fsdev_fuse_thread_exit(void *ctx)
{
	struct fsdev_fuse_thread *thread = ctx;

	spdk_thread_exit(thread->thread);
	free(thread);
}

static void
fsdev_fuse_umount_cb(void *ctx)
{
	struct fsdev_fuse_thread *thread;

	while ((thread = TAILQ_FIRST(&g_app.threads))) {
		TAILQ_REMOVE(&g_app.threads, thread, tailq);
		spdk_thread_send_msg(thread->thread, fsdev_fuse_thread_exit, thread);
	}

	spdk_app_stop(g_app.status);
}

static void fsdev_fuse_stop_threads(void);

static void
fsdev_fuse_done(int status)
{
	int rc = 0;

	if (g_app.status == 0) {
		g_app.status = status;
	}

	spdk_poller_unregister(&g_app.fsdev_poller);
	fsdev_fuse_stop_threads();
	if (g_app.num_active > 0) {
		return;
	}

	if (g_app.mount != NULL) {
		rc = spdk_fuse_umount(g_app.mount, fsdev_fuse_umount_cb, NULL);
		if (rc == 0) {
			return;
		}
	}

	fsdev_fuse_umount_cb(NULL);
}

static void
fsdev_fuse_thread_done(void *ctx)
{
	struct fsdev_fuse_thread *thread = ctx;

	assert(g_app.num_active > 0);
	g_app.num_active--;
	fsdev_fuse_done(thread->status);
}

static void
fsdev_fuse_thread_stop(struct fsdev_fuse_thread *thread, int status)
{
	if (!thread->running) {
		return;
	}

	if (thread->poll_group != NULL) {
		spdk_fuse_poll_group_destroy(thread->poll_group);
		thread->poll_group = NULL;
	}

	spdk_poller_unregister(&thread->poller);
	thread->status = status;
	thread->running = false;

	spdk_thread_send_msg(spdk_thread_get_app_thread(), fsdev_fuse_thread_done, thread);
}

static void
fsdev_fuse_poll_error_cb(void *ctx, struct spdk_fuse_mount *mount, int error)
{
	/* If we're running as a daemon, remove the mount but keep running */
	if (g_app.daemon) {
		spdk_fuse_umount(mount, NULL, NULL);
		return;
	}

	fsdev_fuse_thread_stop(ctx, error);
}

static int
fsdev_fuse_thread_poll(void *ctx)
{
	struct fsdev_fuse_thread *thread = ctx;

	return spdk_fuse_poll_group_poll(thread->poll_group, fsdev_fuse_poll_error_cb, thread) > 0 ?
	       SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static void
fsdev_fuse_thread_start(void *ctx)
{
	struct fsdev_fuse_thread *thread = ctx;
	int rc;

	thread->poll_group = spdk_fuse_poll_group_create();
	if (thread->poll_group == NULL) {
		fsdev_fuse_errmsg("%s\n", spdk_strerror(ENOMEM));
		rc = -ENOMEM;
		goto error;
	}

	thread->poller = SPDK_POLLER_REGISTER(fsdev_fuse_thread_poll, thread, 0);
	if (thread->poller == NULL) {
		fsdev_fuse_errmsg("%s\n", spdk_strerror(ENOMEM));
		rc = -ENOMEM;
		goto error;
	}

	return;
error:
	fsdev_fuse_thread_stop(thread, rc);
}

static void
_fsdev_fuse_thread_stop(void *ctx)
{
	struct fsdev_fuse_thread *thread = ctx;

	fsdev_fuse_thread_stop(thread, thread->status);
}

static void
fsdev_fuse_stop_threads(void)
{
	struct fsdev_fuse_thread *thread;

	TAILQ_FOREACH(thread, &g_app.threads, tailq) {
		if (thread->thread == NULL) {
			continue;
		}

		spdk_thread_send_msg(thread->thread, _fsdev_fuse_thread_stop, thread);
	}
}

static void
fsdev_fuse_mount_cb(void *ctx, struct spdk_fuse_mount *mount, int status)
{
	assert(g_app.num_active > 0);
	g_app.num_active--;

	if (status != 0) {
		fsdev_fuse_errmsg("failed to mount %s at %s: %s\n",
				  g_app.fsdev_name, g_app.mountpoint, spdk_strerror(-status));
		fsdev_fuse_done(status);
		return;
	}

	g_app.mount = mount;
}

static int
fsdev_fuse_for_each_fsdev_cb(void *ctx, struct spdk_fsdev *fsdev)
{
	return strcmp(spdk_fsdev_get_name(fsdev), g_app.fsdev_name) == 0;
}

static int
fsdev_fuse_wait_fsdev(void *ctx)
{
	int rc;

	rc = spdk_for_each_fsdev(NULL, fsdev_fuse_for_each_fsdev_cb);
	if (rc != 1) {
		return SPDK_POLLER_BUSY;
	}

	spdk_poller_unregister(&g_app.fsdev_poller);

	g_app.num_active++;
	rc = spdk_fuse_mount(g_app.fsdev_name, g_app.mountpoint, &g_app.mount_opts,
			     fsdev_fuse_mount_cb, NULL);
	if (rc != 0) {
		fsdev_fuse_errmsg("failed to mount %s at %s: %s\n", g_app.fsdev_name,
				  g_app.mountpoint, spdk_strerror(-rc));
		assert(g_app.num_active > 0);
		g_app.num_active--;
		fsdev_fuse_done(rc);
	}

	return SPDK_POLLER_BUSY;
}

static void
fsdev_fuse_sync_threads_done(void *ctx)
{
	int rc;

	if (g_app.daemon) {
		assert(g_app.num_active > 0);
		g_app.num_active--;
		return;
	}

	rc = spdk_fuse_mount(g_app.fsdev_name, g_app.mountpoint, &g_app.mount_opts,
			     fsdev_fuse_mount_cb, NULL);
	if (rc == 0) {
		return;
	}

	assert(g_app.num_active > 0);
	g_app.num_active--;

	if (rc == -ENODEV && g_app.wait) {
		g_app.fsdev_poller = SPDK_POLLER_REGISTER(fsdev_fuse_wait_fsdev, NULL, 100 * 1000);
		if (g_app.fsdev_poller == NULL) {
			fsdev_fuse_errmsg("%s\n", spdk_strerror(ENOMEM));
			fsdev_fuse_done(-ENOMEM);
		}

		return;
	}

	fsdev_fuse_errmsg("failed to mount %s at %s: %s\n", g_app.fsdev_name, g_app.mountpoint,
			  spdk_strerror(-rc));
	fsdev_fuse_done(rc);
}

static void
fsdev_fuse_sync_threads(void *ctx)
{
}

static void
fsdev_fuse_start_app(void *ctx)
{
	struct fsdev_fuse_thread *thread;
	struct spdk_cpuset cpumask;
	char name[32];
	uint32_t core;
	int rc;

	SPDK_ENV_FOREACH_CORE(core) {
		thread = calloc(1, sizeof(*thread));
		if (thread == NULL) {
			fsdev_fuse_errmsg("%s\n", spdk_strerror(ENOMEM));
			rc = -ENOMEM;
			goto error;
		}
		spdk_cpuset_zero(&cpumask);
		spdk_cpuset_set_cpu(&cpumask, core, true);
		snprintf(name, sizeof(name), "fuse%u", core);
		thread->thread = spdk_thread_create(name, &cpumask);
		if (thread->thread == NULL) {
			fsdev_fuse_errmsg("%s\n", spdk_strerror(ENOMEM));
			free(thread);
			rc = -ENOMEM;
			goto error;
		}
		g_app.num_active++;
		thread->running = true;
		TAILQ_INSERT_TAIL(&g_app.threads, thread, tailq);
		spdk_thread_send_msg(thread->thread, fsdev_fuse_thread_start, thread);
	}

	g_app.num_active++;
	spdk_for_each_thread(fsdev_fuse_sync_threads, NULL, fsdev_fuse_sync_threads_done);
	return;
error:
	fsdev_fuse_done(rc);
}

static void
fsdev_fuse_shutdown_cb(void)
{
	fsdev_fuse_done(0);
}

static struct option g_options[] = {
#define FSDEV_FUSE_OPT_MOUNTPOINT 'M'
	{ "mountpoint", required_argument, NULL, FSDEV_FUSE_OPT_MOUNTPOINT },
#define FSDEV_FUSE_OPT_FS 'f'
	{ "fs", required_argument,  NULL, FSDEV_FUSE_OPT_FS },
#define FSDEV_FUSE_OPT_WAIT 'w'
	{ "wait", no_argument,  NULL, FSDEV_FUSE_OPT_WAIT },
#define FSDEV_FUSE_OPT_DAEMON 'D'
	{ "daemon", no_argument,  NULL, FSDEV_FUSE_OPT_DAEMON },
#define FSDEV_FUSE_OPT_MAX_IODEPTH 0x1000
	{ "max-iodepth", required_argument, NULL, FSDEV_FUSE_OPT_MAX_IODEPTH },
#define FSDEV_FUSE_OPT_MAX_XFER 0x1001
	{ "max-xfer", required_argument, NULL, FSDEV_FUSE_OPT_MAX_XFER },
#define FSDEV_FUSE_OPT_NO_CLONE 0x1002
	{ "no-clone", no_argument, NULL, FSDEV_FUSE_OPT_NO_CLONE },
#define FSDEV_FUSE_OPT_FSTYPE 0x1003
	{ "fstype", required_argument, NULL, FSDEV_FUSE_OPT_FSTYPE },
#define FSDEV_FUSE_OPT_EXTERN_LIBS 0x1004
	{ "ext-libs", required_argument, NULL, FSDEV_FUSE_OPT_EXTERN_LIBS },
	{},
};

static const char *
fsdev_fuse_get_option_name(int ch)
{
	size_t i;

	for (i = 0; i < SPDK_COUNTOF(g_options); i++) {
		if (g_options[i].val == ch) {
			return g_options[i].name;
		}
	}

	return NULL;
}

static int
fsdev_fuse_parse_arg(int ch, char *arg)
{
	uint64_t u64;

	switch (ch) {
	case FSDEV_FUSE_OPT_MOUNTPOINT:
		g_app.mountpoint = arg;
		break;
	case FSDEV_FUSE_OPT_FS:
		g_app.fsdev_name = arg;
		break;
	case FSDEV_FUSE_OPT_WAIT:
		g_app.wait = true;
		break;
	case FSDEV_FUSE_OPT_DAEMON:
		g_app.daemon = true;
		break;
	case FSDEV_FUSE_OPT_MAX_IODEPTH:
	case FSDEV_FUSE_OPT_MAX_XFER:
		if (spdk_parse_capacity(arg, &u64, NULL) != 0) {
			fsdev_fuse_errmsg("invalid --%s argument: %s\n",
					  fsdev_fuse_get_option_name(ch), arg);
			return -EINVAL;
		}
		switch (ch) {
		case FSDEV_FUSE_OPT_MAX_IODEPTH:
			g_app.mount_opts.max_io_depth = u64;
			break;
		case FSDEV_FUSE_OPT_MAX_XFER:
			g_app.mount_opts.max_xfer_size = u64;
			break;
		}
		break;
	case FSDEV_FUSE_OPT_NO_CLONE:
		g_app.mount_opts.clone_fd = false;
		break;
	case FSDEV_FUSE_OPT_FSTYPE:
		g_app.mount_opts.fstype = arg;
		break;
	case FSDEV_FUSE_OPT_EXTERN_LIBS:
		g_app.extra_libs = arg;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static bool
fsdev_fuse_check_params(void)
{
	if (!g_app.daemon) {
		if (g_app.fsdev_name == NULL) {
			fsdev_fuse_errmsg("missing argument: -f, --fs\n");
			return false;
		}
		if (g_app.mountpoint == NULL) {
			fsdev_fuse_errmsg("missing argument: -M, --mountpoint\n");
			return false;
		}
	} else {
		if (g_app.fsdev_name != NULL) {
			fsdev_fuse_errmsg("argument -f, --fs cannot be used with -D, --daemon\n");
			return false;
		}
		if (g_app.mountpoint != NULL) {
			fsdev_fuse_errmsg("argument -M, --mountpoint cannot be used with "
					  "-D, --daemon\n");
			return false;
		}
	}

	return true;
}

static bool
fsdev_fuse_load_extra_libs(void)
{
	char **libs;
	int i = 0;

	if (!g_app.extra_libs) {
		return true;
	}

	libs = spdk_strarray_from_string(g_app.extra_libs, ",");
	if (!libs) {
		fsdev_fuse_errmsg("Bad --ext-libs: %s\n", g_app.extra_libs);
		return false;
	}

	for (i = 0; libs[i]; i++) {
		void *lib_handle = dlopen(libs[i], RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
		if (!lib_handle) {
			fsdev_fuse_errmsg("Failed to load extra lib: %s (%s)\n", libs[i], dlerror());
			spdk_strarray_free(libs);
			return false;
		}
	}

	spdk_strarray_free(libs);
	return true;
}

static void
fsdev_fuse_usage(void)
{
	printf(" -f, --fs=<fs>                        name of the fsdev to use\n");
	printf(" -M, --mountpoint=<mountpoint>        where to mount the fsdev\n");
	printf("     --max-iodepth=<iodepth>          maximum I/O depth on each core\n");
	printf("     --max-xfer=<size>                maximum transfer size\n");
	printf("     --no-clone                       use the same /dev/fuse fd on all cores\n");
	printf(" -w, --wait                           wait for the fsdev if it's not available\n");
	printf("     --fstype=<fstype>                use fstype as filesystem type when mounting\n");
	printf(" -D, --daemon                         run as daemon\n");
	printf("     --ext-libs=<name1[,name2[]]>     comma-separated list of external libs to be loaded\n");
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc;

	g_app.name = argv[0];
	spdk_fuse_get_default_mount_opts(&g_app.mount_opts, sizeof(g_app.mount_opts));

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "fuse";
	opts.shutdown_cb = fsdev_fuse_shutdown_cb;
	rc = spdk_app_parse_args(argc, argv, &opts, "Df:M:w", g_options,
				 fsdev_fuse_parse_arg, fsdev_fuse_usage);
	if (rc != SPDK_APP_PARSE_ARGS_SUCCESS) {
		return rc;
	}

	if (!fsdev_fuse_check_params()) {
		fsdev_fuse_usage();
		return EXIT_FAILURE;
	}

	if (!fsdev_fuse_load_extra_libs()) {
		return EXIT_FAILURE;
	}

	rc = spdk_app_start(&opts, fsdev_fuse_start_app, NULL);

	spdk_app_fini();

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
