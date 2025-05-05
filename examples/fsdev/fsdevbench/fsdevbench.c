/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/fsdev.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"


struct fsdevbench_app {
	/* User options */
	const char				*fsdev_name;
	const char				*workload;
	size_t					num_files;

	struct spdk_fsdev_desc			*fsdev_desc;
	struct spdk_io_channel			*ioch;
	struct spdk_fsdev_io			*fsdev_io;
	struct spdk_fsdev_file_object		*root;
	size_t					cur_file_count;

	int					status;
	uint64_t				tsc_start;
	uint64_t				tsc_end;

} g_app = {};

#define fsdevbench_errmsg(fmt, ...) \
	fprintf(stderr, "%s: " fmt, g_app.fsdev_name, ## __VA_ARGS__)

static void
fsdevbench_set_status(int status)
{
	if (g_app.status == 0) {
		g_app.status = status;
	}
}

static void
fsdevbench_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *event_ctx)
{
	fsdevbench_errmsg("unhandled event %d on fsdev %s\n", type, spdk_fsdev_get_name(fsdev));
}

static void
fsdevbench_done(void *ctx)
{
	spdk_app_stop(g_app.status);
}

static void
fsdevbench_thread_exit(void *ctx)
{
	spdk_thread_exit(spdk_get_thread());
}

static void
fsdevbench_fini(void)
{
	free(g_app.fsdev_io);

	spdk_for_each_thread(fsdevbench_thread_exit, NULL, fsdevbench_done);
}

static void
fsdevbench_fini_umount_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	if (status != 0) {
		fsdevbench_errmsg("failed to mount %s: %s\n",
				  spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(g_app.fsdev_desc)),
				  spdk_strerror(-status));
		fsdevbench_set_status(status);
		fsdevbench_fini();
		return;
	}

	spdk_put_io_channel(g_app.ioch);
	spdk_fsdev_close(g_app.fsdev_desc);

	fsdevbench_fini();

}

static void
fsdevbench_fini_umount(void)
{
	struct spdk_fsdev_io *fsdev_io = g_app.fsdev_io;

	spdk_fsdev_io_init(fsdev_io, g_app.fsdev_desc, g_app.ioch, 0, SPDK_FSDEV_IO_UMOUNT,
			   0, 0, fsdevbench_fini_umount_cb, NULL);

	spdk_fsdev_io_submit(fsdev_io);
}


static void fsdevbench_fini_unlink(void);

static void
fsdevbench_fini_unlink_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	free((void *)fsdev_io->u_in.unlink.name);

	if (g_app.cur_file_count > 0) {
		fsdevbench_fini_unlink();
	} else {
		fsdevbench_fini_umount();
	}
}

static void
fsdevbench_fini_unlink(void)
{
	struct spdk_fsdev_io *fsdev_io = g_app.fsdev_io;
	char *file_name;

	g_app.cur_file_count--;

	file_name = spdk_sprintf_alloc("file_%lu", g_app.cur_file_count);
	if (file_name == NULL) {
		fsdevbench_errmsg("failed to allocate file name\n");
		fsdevbench_set_status(-ENOMEM);
		fsdevbench_fini();
		return;
	}

	spdk_fsdev_io_init(fsdev_io, g_app.fsdev_desc, g_app.ioch, 0, SPDK_FSDEV_IO_UNLINK,
			   0, 0, fsdevbench_fini_unlink_cb, NULL);

	fsdev_io->u_in.unlink.parent_fobject = g_app.root;
	fsdev_io->u_in.create.name = file_name;

	spdk_fsdev_io_submit(fsdev_io);
}

/* This section is the readdir benchmark */

static void
fsdevbench_readdir_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	if (status != 0) {
		fsdevbench_errmsg("failed to readdir: %s\n", spdk_strerror(-status));
		fsdevbench_set_status(status);
		fsdevbench_fini_unlink();
		return;
	}

	g_app.tsc_end = spdk_get_ticks();

	printf("Benchmark complete.\n");

	fsdevbench_fini_unlink();

}

static int
fsdevbench_readdir_entry_cb(void *cb_arg, struct spdk_fsdev_io *fsdev_io,
			    const char *name,
			    struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
			    off_t offset, bool *forget)
{
	return 0;
}


static void
fsdevbench_opendir_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct spdk_fsdev_file_handle *fhandle;

	if (status != 0) {
		fsdevbench_errmsg("failed to open dir: %s\n", spdk_strerror(-status));
		fsdevbench_set_status(status);
		fsdevbench_fini_unlink();
		return;
	}

	fhandle = fsdev_io->u_out.opendir.fhandle;

	spdk_fsdev_io_init(fsdev_io, g_app.fsdev_desc, g_app.ioch, 0, SPDK_FSDEV_IO_READDIR,
			   0, 0, fsdevbench_readdir_cb, NULL);

	fsdev_io->u_in.readdir.fhandle = fhandle;
	fsdev_io->u_in.readdir.fobject = g_app.root;
	fsdev_io->u_in.readdir.entry_cb_fn = fsdevbench_readdir_entry_cb;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevbench_opendir(void)
{
	struct spdk_fsdev_io *fsdev_io = g_app.fsdev_io;

	spdk_fsdev_io_init(fsdev_io, g_app.fsdev_desc, g_app.ioch, 0, SPDK_FSDEV_IO_OPENDIR,
			   0, 0, fsdevbench_opendir_cb, NULL);

	fsdev_io->u_in.opendir.fobject = g_app.root;
	fsdev_io->u_in.opendir.flags = 0;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevbench_run(void)
{
	printf("Setup complete. Starting benchmark...\n");
	g_app.tsc_start = spdk_get_ticks();

	assert(strcmp(g_app.workload, "readdir") == 0);

	fsdevbench_opendir();
}

static void fsdevbench_init_create_file(void);

static void
fsdevbench_init_close_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	g_app.cur_file_count++;

	if (g_app.cur_file_count < g_app.num_files) {
		fsdevbench_init_create_file();
	} else {
		fsdevbench_run();
	}
}

static void
fsdevbench_init_create_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct spdk_fsdev_file_object *fobject;
	struct spdk_fsdev_file_handle *fhandle;

	free((void *)fsdev_io->u_in.create.name);

	if (status != 0) {
		fsdevbench_errmsg("failed to mount %s: %s\n",
				  spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(g_app.fsdev_desc)),
				  spdk_strerror(-status));
		fsdevbench_set_status(status);
		fsdevbench_fini();
		return;
	}

	fobject = fsdev_io->u_out.create.fobject;
	fhandle = fsdev_io->u_out.create.fhandle;

	/* Immediately close the file */
	spdk_fsdev_io_init(fsdev_io, g_app.fsdev_desc, g_app.ioch, 0, SPDK_FSDEV_IO_RELEASE,
			   0, 0, fsdevbench_init_close_cb, NULL);

	fsdev_io->u_in.release.fobject = fobject;
	fsdev_io->u_in.release.fhandle = fhandle;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevbench_init_create_file(void)
{
	struct spdk_fsdev_io *fsdev_io = g_app.fsdev_io;
	char *file_name;

	file_name = spdk_sprintf_alloc("file_%lu", g_app.cur_file_count);
	if (file_name == NULL) {
		fsdevbench_errmsg("failed to allocate file name\n");
		fsdevbench_set_status(-ENOMEM);
		fsdevbench_fini();
		return;
	}

	spdk_fsdev_io_init(fsdev_io, g_app.fsdev_desc, g_app.ioch, 0, SPDK_FSDEV_IO_CREATE,
			   0, 0, fsdevbench_init_create_cb, NULL);

	fsdev_io->u_in.create.parent_fobject = g_app.root;
	fsdev_io->u_in.create.name = file_name;
	fsdev_io->u_in.create.mode = 0644;
	fsdev_io->u_in.create.euid = geteuid();
	fsdev_io->u_in.create.egid = getegid();
	fsdev_io->u_in.create.flags = O_RDWR;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevbench_init_mount_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	if (status != 0) {
		fsdevbench_errmsg("failed to mount %s: %s\n",
				  spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(g_app.fsdev_desc)),
				  spdk_strerror(-status));
		fsdevbench_set_status(status);
		fsdevbench_fini();
		return;
	}

	g_app.root = fsdev_io->u_out.mount.root_fobject;

	fsdevbench_init_create_file();

}

static void
fsdevbench_init_mount(void)
{
	struct spdk_fsdev_io *fsdev_io = g_app.fsdev_io;

	spdk_fsdev_io_init(fsdev_io, g_app.fsdev_desc, g_app.ioch, 0, SPDK_FSDEV_IO_MOUNT,
			   0, 0, fsdevbench_init_mount_cb, NULL);

	memset(&fsdev_io->u_in.mount.opts, 0, sizeof(fsdev_io->u_in.mount.opts));
	fsdev_io->u_in.mount.opts.opts_size = SPDK_SIZEOF(&fsdev_io->u_in.mount.opts, opts_size);

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevbench_start_app(void *ctx)
{
	int rc;
	int sz;

	rc = spdk_fsdev_open(g_app.fsdev_name, fsdevbench_event_cb, NULL, &g_app.fsdev_desc);
	if (rc != 0) {
		fsdevbench_errmsg("couldn't open /%s: %s\n", g_app.fsdev_name, spdk_strerror(-rc));
		goto error;
	}

	g_app.ioch = spdk_fsdev_get_io_channel(g_app.fsdev_desc);
	if (g_app.ioch == NULL) {
		fsdevbench_errmsg("failed to get IO channel for /%s\n",
				  spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(g_app.fsdev_desc)));
		goto error;
	}

	sz = spdk_fsdev_get_io_ctx_size();
	g_app.fsdev_io = calloc(1, sz);
	if (g_app.fsdev_io == NULL) {
		fsdevbench_errmsg("failed to allocate %d bytes for fsdev_io\n", sz);
		goto error;
	}

	fsdevbench_init_mount();
	return;

error:
	fsdevbench_set_status(rc);
	fsdevbench_fini();
}

static void
fsdevbench_shutdown_cb(void)
{
	fsdevbench_set_status(-ECANCELED);
}

static struct option g_options[] = {
#define FSDEVBENCH_OPT_FSDEV 'f'
	{ "fsdev", required_argument, NULL, FSDEVBENCH_OPT_FSDEV },
#define FSDEVBENCH_OPT_WORKLOAD 'w'
	{ "workload", required_argument, NULL, FSDEVBENCH_OPT_WORKLOAD },
#define FSDEVBENCH_OPT_NRFILES 0x1001
	{ "nrfiles", required_argument, NULL, FSDEVBENCH_OPT_NRFILES },
	{},
};

static int
fsdevbench_parse_arg(int ch, char *arg)
{
	uint64_t u64;

	switch (ch) {
	case FSDEVBENCH_OPT_FSDEV:
		g_app.fsdev_name = arg;
		break;
	case FSDEVBENCH_OPT_WORKLOAD:
		g_app.workload = arg;
		break;
	case FSDEVBENCH_OPT_NRFILES:
		if (spdk_parse_capacity(arg, &u64, NULL) != 0) {
			return -EINVAL;
		}

		g_app.num_files = (size_t)u64;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void
fsdevbench_usage(void)
{
	printf(" -f, --fsdev=<fsdev>                  fsdev to use\n");
	printf(" -w, --workload=<workload>            workload (benchmark) to run\n");
	printf("     --nrfiles=<nrfiles>              For readdir workload, number of files in the directory\n");
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc;

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "fsdevbench";
	opts.shutdown_cb = fsdevbench_shutdown_cb;
	rc = spdk_app_parse_args(argc, argv, &opts, "f:w:", g_options,
				 fsdevbench_parse_arg, fsdevbench_usage);
	if (rc != SPDK_APP_PARSE_ARGS_SUCCESS) {
		return rc;
	}

	rc = spdk_app_start(&opts, fsdevbench_start_app, NULL);

	spdk_app_fini();

	printf("Operation completed in %lf seconds\n",
	       (double)(g_app.tsc_end - g_app.tsc_start) / spdk_get_ticks_hz());

	return rc != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
