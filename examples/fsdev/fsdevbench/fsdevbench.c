/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/fsdev.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include "spdk/thread.h"

struct fsdevbench_fuse_io {
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
		struct iovec			iovs[1];
	} out;

	uint64_t unique;
};
struct fsdevbench_io {
	struct fsdevbench_fuse_io fuse_io;
	struct spdk_fsdev_io fsdev_io;
};
SPDK_STATIC_ASSERT(offsetof(struct fsdevbench_io, fsdev_io) % 8 == 0, "misalignment");

struct fsdevbench_app {
	/* User options */
	const char				*fsdev_name;
	const char				*workload;
	size_t					num_files;

	struct spdk_fsdev_desc			*fsdev_desc;
	struct spdk_io_channel			*ioch;
	struct fsdevbench_io			*io;
	size_t					cur_file_count;

	int					status;
	uint64_t				tsc_start;
	uint64_t				tsc_end;

	char					readdir_buf[4096];
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
	free(g_app.io);

	spdk_for_each_thread(fsdevbench_thread_exit, NULL, fsdevbench_done);
}

static void
fsdevbench_io_init(struct fsdevbench_io *io, struct spdk_fsdev_desc *fsdev_desc,
		   struct spdk_io_channel *ioch, uint32_t opcode,
		   uint64_t nodeid, uint32_t len, struct iovec *in_iovs, int in_iovcnt,
		   struct iovec *out_iovs, int out_iovcnt, spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	io->fuse_io.in.hdr.opcode = opcode;
	io->fuse_io.in.hdr.unique = io->fuse_io.unique;
	io->fuse_io.in.hdr.len = sizeof(io->fuse_io.in.hdr) + len;
	io->fuse_io.in.hdr.nodeid = nodeid;
	io->fuse_io.in.hdr.uid = geteuid();
	io->fuse_io.in.hdr.gid = getegid();
	spdk_fsdev_io_init(&io->fsdev_io, fsdev_desc, ioch, io->fuse_io.unique,
			   0, io->fuse_io.unique, cb_fn, cb_ctx);
	io->fsdev_io.u_in.fuse.hdr = &io->fuse_io.in.hdr;
	io->fsdev_io.u_in.fuse.op.raw = &io->fuse_io.in.op;
	io->fsdev_io.u_in.fuse.iov = in_iovs;
	io->fsdev_io.u_in.fuse.iovcnt = in_iovcnt;
	io->fsdev_io.u_out.fuse.hdr = &io->fuse_io.out.hdr;
	io->fsdev_io.u_out.fuse.op.raw = &io->fuse_io.out.op;
	io->fsdev_io.u_out.fuse.iov = out_iovs;
	io->fsdev_io.u_out.fuse.iovcnt = out_iovcnt;

	io->fuse_io.unique++;
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
	struct fsdevbench_io *io = g_app.io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;

	fsdevbench_io_init(io, g_app.fsdev_desc, g_app.ioch, FUSE_DESTROY,
			   0, 0, NULL, 0, NULL, 0, fsdevbench_fini_umount_cb, NULL);

	spdk_fsdev_io_submit(fsdev_io);
}


static void fsdevbench_fini_unlink(void);

static void
fsdevbench_fini_unlink_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevbench_io *io = g_app.io;

	free((void *)io->fuse_io.in.iovs[0].iov_base);

	if (g_app.cur_file_count > 0) {
		fsdevbench_fini_unlink();
	} else {
		fsdevbench_fini_umount();
	}
}

static void
fsdevbench_fini_unlink(void)
{
	struct fsdevbench_io *io = g_app.io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	struct fsdevbench_fuse_io *fuse_io = &io->fuse_io;
	char *file_name;

	g_app.cur_file_count--;

	file_name = spdk_sprintf_alloc("file_%lu", g_app.cur_file_count);
	if (file_name == NULL) {
		fsdevbench_errmsg("failed to allocate file name\n");
		fsdevbench_set_status(-ENOMEM);
		fsdevbench_fini();
		return;
	}

	fsdevbench_io_init(io, g_app.fsdev_desc, g_app.ioch, FUSE_UNLINK,
			   FUSE_ROOT_ID, strlen(file_name) + 1, fuse_io->in.iovs, 1, NULL, 0, fsdevbench_fini_unlink_cb, NULL);

	fuse_io->in.iovs[0].iov_base = (char *)file_name;
	fuse_io->in.iovs[0].iov_len = strlen(file_name) + 1;

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

static void
fsdevbench_opendir_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct fsdevbench_io *io = g_app.io;
	struct fuse_open_out *open = &io->fuse_io.out.op.open;
	struct fuse_read_in *read_in = io->fsdev_io.u_in.fuse.op.read;

	if (status != 0) {
		fsdevbench_errmsg("failed to open dir: %s\n", spdk_strerror(-status));
		fsdevbench_set_status(status);
		fsdevbench_fini_unlink();
		return;
	}

	fsdevbench_io_init(io, g_app.fsdev_desc, g_app.ioch, FUSE_READDIR,
			   FUSE_ROOT_ID, sizeof(*read_in), NULL, 0, io->fuse_io.out.iovs, 1, fsdevbench_readdir_cb, NULL);

	memset(read_in, 0, sizeof(*read_in));
	read_in->fh = open->fh;
	io->fuse_io.out.iovs[0].iov_base = g_app.readdir_buf;
	io->fuse_io.out.iovs[0].iov_len = sizeof(g_app.readdir_buf);

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevbench_opendir(void)
{
	struct fsdevbench_io *io = g_app.io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	struct fuse_open_in *open = &io->fuse_io.in.op.open;

	fsdevbench_io_init(io, g_app.fsdev_desc, g_app.ioch, FUSE_OPENDIR,
			   FUSE_ROOT_ID, 0, NULL, 0, NULL, 0, fsdevbench_opendir_cb, NULL);


	open->flags = 0;

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
	struct fsdevbench_io *io = g_app.io;
	struct spdk_fuse_create_out *create = &io->fuse_io.out.op.create;
	struct fuse_release_in *release = &io->fuse_io.in.op.release;

	free((void *)io->fuse_io.in.iovs[0].iov_base);

	if (status != 0) {
		fsdevbench_errmsg("failed to create file %s: %s\n",
				  spdk_fsdev_get_name(spdk_fsdev_desc_get_fsdev(g_app.fsdev_desc)),
				  spdk_strerror(-status));
		fsdevbench_set_status(status);
		fsdevbench_fini();
		return;
	}

	/* Immediately close the file */
	fsdevbench_io_init(io, g_app.fsdev_desc, g_app.ioch, FUSE_RELEASE, create->entry.nodeid,
			   sizeof(*release), NULL, 0, NULL, 0, fsdevbench_init_close_cb, NULL);

	release->fh = create->open.fh;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fsdevbench_init_create_file(void)
{
	struct fsdevbench_io *io = g_app.io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	struct fsdevbench_fuse_io *fuse_io = &io->fuse_io;
	struct fuse_create_in *create = &io->fuse_io.in.op.create;
	char *file_name;
	size_t len;

	file_name = spdk_sprintf_alloc("file_%lu", g_app.cur_file_count);
	if (file_name == NULL) {
		fsdevbench_errmsg("failed to allocate file name\n");
		fsdevbench_set_status(-ENOMEM);
		fsdevbench_fini();
		return;
	}

	len = strlen(file_name) + 1;
	fsdevbench_io_init(io, g_app.fsdev_desc, g_app.ioch, FUSE_CREATE,
			   FUSE_ROOT_ID, sizeof(*create) + len, fuse_io->in.iovs, 1, NULL, 0, fsdevbench_init_create_cb, NULL);

	create->mode = 0644;
	create->flags = O_RDWR;
	fuse_io->in.iovs[0].iov_base = (char *)file_name;
	fuse_io->in.iovs[0].iov_len = len;

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

	fsdevbench_init_create_file();
}

static void
fsdevbench_init_mount(void)
{
	struct fsdevbench_io *io = g_app.io;
	struct spdk_fsdev_io *fsdev_io = &io->fsdev_io;
	struct fuse_init_in *init = &io->fuse_io.in.op.init;

	fsdevbench_io_init(io, g_app.fsdev_desc, g_app.ioch, FUSE_INIT,
			   0, 0, NULL, 0, NULL, 0, fsdevbench_init_mount_cb, NULL);

	memset(init, 0, sizeof(*init));
	init->major = 7;
	init->minor = 31;

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
	g_app.io = calloc(1, sizeof(struct fsdevbench_io) + sz);
	if (g_app.io == NULL) {
		fsdevbench_errmsg("failed to allocate %zu bytes for fsdev_io\n",
				  sizeof(struct fsdevbench_io) + (size_t)sz);
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
