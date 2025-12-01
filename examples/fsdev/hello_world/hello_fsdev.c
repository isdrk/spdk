/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/fsdev.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"

#define TEST_FILENAME "hello_file"
#define DATA_SIZE 512
#define ROOT_NODEID 1

static char *g_fsdev_name = "Fs0";
int g_result = 0;

struct hello_fuse_io {
	struct {
		struct fuse_in_header		hdr;
		union {
			struct fuse_init_in	init;
			struct fuse_open_in	open;
			struct fuse_mknod_in	mknod;
			struct fuse_release_in	release;
			struct fuse_forget_in	forget;
			struct fuse_read_in	read;
			struct fuse_write_in	write;
			struct fuse_getattr_in  getattr;
			struct fuse_setattr_in	setattr;
		} op;
		struct iovec			iovs[1];
	} in;
	struct {
		struct fuse_out_header			hdr;
		union {
			struct fuse_init_out		init;
			struct fuse_entry_out		entry;
			struct fuse_open_out		open;
			struct fuse_write_out		write;
		} op;
	} out;
};

/*
 * We'll use this struct to gather housekeeping hello_context to pass between
 * our events and callbacks.
 */
struct hello_context_t {
	struct spdk_thread *app_thread;
	struct spdk_fsdev_desc *fsdev_desc;
	struct spdk_io_channel *fsdev_io_channel;
	char *fsdev_name;
	int thread_count;
	struct hello_fuse_io fuse_io;
};

#define ALIGNED_CONTEXT_SIZE SPDK_ALIGN_CEIL(sizeof(struct hello_context_t), 8)

static inline struct spdk_fsdev_io *
hello_context_get_fsdev_io(struct hello_context_t *hello_context)
{
	return (struct spdk_fsdev_io *)(((char *)hello_context) + ALIGNED_CONTEXT_SIZE);
}

struct hello_thread_t {
	struct hello_context_t *hello_context;
	struct spdk_thread *thread;
	struct spdk_io_channel *fsdev_io_channel;
	uint64_t unique;
	uint8_t *buf;
	char *file_name;
	uint64_t nodeid;
	uint64_t fh;
	struct fuse_attr attr;
	struct hello_fuse_io fuse_io;
	struct iovec iov[2];
};

#define ALIGNED_THREAD_SIZE SPDK_ALIGN_CEIL(sizeof(struct hello_thread_t), 8)

static inline struct spdk_fsdev_io *
hello_thread_get_fsdev_io(struct hello_thread_t *hello_thread)
{
	return (struct spdk_fsdev_io *)(((char *)hello_thread) + ALIGNED_THREAD_SIZE);
}

/*
 * Usage function for printing parameters that are specific to this application
 */
static void
hello_fsdev_usage(void)
{
	printf(" -f <fs>                 name of the fsdev to use\n");
}

/*
 * This function is called to parse the parameters that are specific to this application
 */
static int
hello_fsdev_parse_arg(int ch, char *arg)
{
	switch (ch) {
	case 'f':
		g_fsdev_name = arg;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void
fsdev_io_init_fuse(struct hello_fuse_io *fuse_io, struct spdk_fsdev_io *fsdev_io,
		   struct spdk_fsdev_desc *fsdev_desc, struct spdk_io_channel *ioch, uint32_t opcode, uint64_t unique,
		   uint16_t source_id, uint64_t nodeid, uint32_t len, struct iovec *in_iovs, int in_iovcnt,
		   struct iovec *out_iovs, int out_iovcnt, spdk_fsdev_cpl_cb cb_fn, void *cb_ctx)
{
	fuse_io->in.hdr.opcode = opcode;
	fuse_io->in.hdr.unique = unique;
	fuse_io->in.hdr.len = sizeof(fuse_io->in.hdr) + len;
	fuse_io->in.hdr.nodeid = nodeid;
	fuse_io->in.hdr.uid = 0;
	fuse_io->in.hdr.gid = 0;

	spdk_fsdev_io_init(fsdev_io, fsdev_desc, ioch, unique, source_id, unique, cb_fn, cb_ctx);

	fsdev_io->u_in.fuse.hdr = &fuse_io->in.hdr;
	fsdev_io->u_in.fuse.op.raw = &fuse_io->in.op;
	fsdev_io->u_in.fuse.iov = in_iovs;
	fsdev_io->u_in.fuse.iovcnt = in_iovcnt;
	fsdev_io->u_out.fuse.hdr = &fuse_io->out.hdr;
	fsdev_io->u_out.fuse.op.raw = &fuse_io->out.op;
	fsdev_io->u_out.fuse.iov = out_iovs;
	fsdev_io->u_out.fuse.iovcnt = out_iovcnt;
}

static void
hello_app_done(struct hello_context_t *hello_context, int rc)
{
	spdk_put_io_channel(hello_context->fsdev_io_channel);
	spdk_fsdev_close(hello_context->fsdev_desc);
	SPDK_NOTICELOG("Stopping app: rc %d\n", rc);
	spdk_app_stop(rc);
}

static void
umount_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_context_t *hello_context = cb_arg;

	SPDK_NOTICELOG("Unmount complete (status=%d)\n", status);
	hello_app_done(hello_context, g_result);
}

static void
hello_umount(struct hello_context_t *hello_context)
{
	struct spdk_fsdev_io *fsdev_io = hello_context_get_fsdev_io(hello_context);
	struct hello_fuse_io *fuse_io = &hello_context->fuse_io;

	SPDK_NOTICELOG("Unmount\n");

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_context->fsdev_io_channel,
			   FUSE_DESTROY, 0, 0, FUSE_ROOT_ID, 0,
			   NULL, 0, NULL, 0, umount_complete, hello_context);


	spdk_fsdev_io_submit(fsdev_io);
}

static void
hello_app_notify_thread_done(void *ctx)
{
	struct hello_context_t *hello_context = (struct hello_context_t *)ctx;

	assert(hello_context->thread_count > 0);
	hello_context->thread_count--;
	if (hello_context->thread_count == 0) {
		hello_umount(hello_context);
	}
}

static void
hello_thread_done(struct hello_thread_t *hello_thread, int rc)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;

	spdk_put_io_channel(hello_thread->fsdev_io_channel);
	free(hello_thread->buf);
	free(hello_thread->file_name);
	SPDK_NOTICELOG("Thread %s done: rc %d\n",
		       spdk_thread_get_name(hello_thread->thread), rc);
	spdk_thread_exit(hello_thread->thread);
	free(hello_thread);
	if (rc) {
		g_result = rc;
	}

	spdk_thread_send_msg(hello_context->app_thread, hello_app_notify_thread_done, hello_context);
}

static bool
hello_check_complete(struct hello_thread_t *hello_thread, int status, const char *op)
{
	hello_thread->unique++;
	if (status) {
		SPDK_ERRLOG("%s failed with %d\n", op, status);
		hello_thread_done(hello_thread, EIO);
		return false;
	}

	return true;
}

static void
unlink_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;

	SPDK_NOTICELOG("Unlink complete (status=%d)\n", status);
	if (!hello_check_complete(hello_thread, status, "unlink")) {
		return;
	}

	hello_thread->nodeid = 0;
	hello_thread_done(hello_thread, 0);
}

static void
hello_unlink(struct hello_thread_t *hello_thread)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	uint32_t len = strlen(hello_thread->file_name) + 1;

	SPDK_NOTICELOG("Unlink file %s\n", hello_thread->file_name);

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_UNLINK, 0, 0, FUSE_ROOT_ID, len,
			   fuse_io->in.iovs, 1, NULL, 0, unlink_complete, hello_thread);

	fuse_io->in.iovs[0].iov_base = (char *)hello_thread->file_name;
	fuse_io->in.iovs[0].iov_len = len;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
setattr_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;
	struct fuse_attr_out *attr_out = fsdev_io->u_out.fuse.op.attr;

	SPDK_NOTICELOG("Setattr complete (status=%d)\n", status);
	if (!hello_check_complete(hello_thread, status, "setattr")) {
		return;
	}

	hello_thread->attr = attr_out->attr;
	hello_unlink(hello_thread);
}

static void
hello_setattr(struct hello_thread_t *hello_thread)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	struct fuse_setattr_in *setattr = &fuse_io->in.op.setattr;

	SPDK_NOTICELOG("Setattr file %s\n", hello_thread->file_name);

	hello_thread->attr.mode &= ~S_IRWXO;

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_SETATTR, 0, 0, hello_thread->nodeid, sizeof(*setattr),
			   NULL, 0, NULL, 0, setattr_complete, hello_thread);

	memset(setattr, 0, sizeof(*setattr));
	setattr->fh = hello_thread->fh;
	setattr->valid = FATTR_MODE;
	setattr->mode = hello_thread->attr.mode;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
getattr_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;

	SPDK_NOTICELOG("Getattr complete (status=%d)\n", status);
	if (!hello_check_complete(hello_thread, status, "getattr")) {
		return;
	}

	hello_thread->attr = fsdev_io->u_out.fuse.op.attr->attr;
	hello_setattr(hello_thread);
}

static void
hello_getattr(struct hello_thread_t *hello_thread)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	struct fuse_getattr_in *getattr = &fuse_io->in.op.getattr;

	SPDK_NOTICELOG("Getattr file %s\n", hello_thread->file_name);

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_GETATTR, 0, 0, hello_thread->nodeid, sizeof(*getattr),
			   NULL, 0, NULL, 0, getattr_complete, hello_thread);

	getattr->fh = hello_thread->fh;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
release_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;

	SPDK_NOTICELOG("Release complete (status=%d)\n", status);
	if (!hello_check_complete(hello_thread, status, "release")) {
		return;
	}

	hello_thread->fh = 0;
	hello_getattr(hello_thread);
}

static void
hello_release(struct hello_thread_t *hello_thread)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	struct fuse_release_in *release = &fuse_io->in.op.release;


	SPDK_NOTICELOG("Release file handle 0x%" PRIx64 "\n", hello_thread->fh);

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_RELEASE, 0, 0, hello_thread->nodeid, sizeof(*release),
			   NULL, 0, NULL, 0, release_complete, hello_thread);

	release->fh = hello_thread->fh;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
read_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;
	uint8_t data = spdk_env_get_current_core();
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	uint32_t data_size = fuse_io->out.hdr.len - sizeof(fuse_io->out.hdr);
	uint32_t i;

	SPDK_NOTICELOG("Read complete (status=%d, %" PRIu32 " bytes read)\n", status, data_size);

	if (!hello_check_complete(hello_thread, status, "read")) {
		return;
	}

	assert(data_size == DATA_SIZE);

	for (i = 0; i < DATA_SIZE; ++i) {
		if (hello_thread->buf[i] != data) {
			SPDK_NOTICELOG("Bad read data at offset %d, 0x%02X != 0x%02X\n",
				       i, hello_thread->buf[i], data);
			break;
		}
	}

	hello_release(hello_thread);
}

static void
hello_read(struct hello_thread_t *hello_thread)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	struct fuse_read_in *read = &fuse_io->in.op.read;

	SPDK_NOTICELOG("Read from file handle 0x%" PRIx64 "\n", hello_thread->fh);

	memset(hello_thread->buf, 0xFF, DATA_SIZE);

	hello_thread->iov[0].iov_base = hello_thread->buf;
	hello_thread->iov[0].iov_len = DATA_SIZE / 4;
	hello_thread->iov[1].iov_base = hello_thread->buf + hello_thread->iov[0].iov_len;
	hello_thread->iov[1].iov_len = DATA_SIZE - hello_thread->iov[0].iov_len;

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_READ, 0, 0, hello_thread->nodeid, sizeof(*read) + DATA_SIZE,
			   NULL, 0, hello_thread->iov, 2, read_complete, hello_thread);

	read->fh = hello_thread->fh;
	read->size = DATA_SIZE;
	read->offset = 0;
	read->flags = 0;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
write_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;
	struct fuse_write_out *write = fsdev_io->u_out.fuse.op.write;

	SPDK_NOTICELOG("Write complete (status=%d, %" PRIu32 " bytes written)\n", status,
		       write->size);
	if (!hello_check_complete(hello_thread, status, "write")) {
		return;
	}

	assert(write->size == DATA_SIZE);
	hello_read(hello_thread);
}

static void
hello_write(struct hello_thread_t *hello_thread)
{
	uint8_t data = spdk_env_get_current_core();
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	struct fuse_write_in *write = &fuse_io->in.op.write;

	SPDK_NOTICELOG("Write to file handle 0x%" PRIx64 "\n", hello_thread->fh);

	memset(hello_thread->buf, data, DATA_SIZE);

	hello_thread->iov[0].iov_base = hello_thread->buf;
	hello_thread->iov[0].iov_len = DATA_SIZE / 2;
	hello_thread->iov[1].iov_base = hello_thread->buf + hello_thread->iov[0].iov_len;
	hello_thread->iov[1].iov_len = DATA_SIZE - hello_thread->iov[0].iov_len;

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_WRITE, 0, 0, hello_thread->nodeid, sizeof(*write) + DATA_SIZE,
			   hello_thread->iov, 2, NULL, 0, write_complete, hello_thread);

	write->fh = hello_thread->fh;
	write->size = DATA_SIZE;
	write->offset = 0;
	write->flags = 0;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
fopen_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;
	struct fuse_open_out *open = fsdev_io->u_out.fuse.op.open;

	SPDK_NOTICELOG("Open complete (status=%d)\n", status);
	if (!hello_check_complete(hello_thread, status, "open")) {
		return;
	}

	hello_thread->fh = open->fh;
	hello_write(hello_thread);
}

static void
hello_open(struct hello_thread_t *hello_thread)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	struct fuse_open_in *open = &fuse_io->in.op.open;

	SPDK_NOTICELOG("Open file 0x%" PRIx64 "\n", hello_thread->nodeid);

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_OPEN, 0, 0, hello_thread->nodeid, sizeof(*open),
			   fuse_io->in.iovs, 1, NULL, 0, fopen_complete, hello_thread);

	memset(open, 0, sizeof(*open));
	open->flags = O_RDWR;
	open->open_flags = 0;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
lookup_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;
	struct fuse_entry_out *entry_out = fsdev_io->u_out.fuse.op.entry;

	SPDK_NOTICELOG("Lookup complete (status=%d)\n", status);
	if (!hello_check_complete(hello_thread, status, "lookup")) {
		return;
	}

	SPDK_UNUSED(entry_out);
	assert(hello_thread->nodeid == entry_out->nodeid);
	hello_open(hello_thread);
}

static void
hello_lookup(struct hello_thread_t *hello_thread)
{
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	uint32_t len = strlen(hello_thread->file_name) + 1;

	SPDK_NOTICELOG("Lookup file %s\n", hello_thread->file_name);

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_LOOKUP, 0, 0, FUSE_ROOT_ID, len,
			   fuse_io->in.iovs, 1, NULL, 0, lookup_complete, hello_thread);

	fuse_io->in.iovs[0].iov_base = (char *)hello_thread->file_name;
	fuse_io->in.iovs[0].iov_len = len;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
mknod_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_thread_t *hello_thread = cb_arg;
	struct fuse_entry_out *entry_out = fsdev_io->u_out.fuse.op.entry;

	SPDK_NOTICELOG("Mknod complete (status=%d)\n", status);
	if (!hello_check_complete(hello_thread, status, "mknod")) {
		return;
	}

	hello_thread->nodeid = entry_out->nodeid;
	hello_lookup(hello_thread);
}

static void
hello_mknod(void *ctx)
{
	struct hello_thread_t *hello_thread = (struct hello_thread_t *)ctx;
	struct hello_context_t *hello_context = hello_thread->hello_context;
	struct spdk_fsdev_io *fsdev_io = hello_thread_get_fsdev_io(hello_thread);
	struct hello_fuse_io *fuse_io = &hello_thread->fuse_io;
	struct fuse_mknod_in *mknod = &hello_thread->fuse_io.in.op.mknod;
	uint32_t len  = strlen(hello_thread->file_name) + 1;

	SPDK_NOTICELOG("Mknod file %s\n", hello_thread->file_name);

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_thread->fsdev_io_channel,
			   FUSE_MKNOD, 0, 0, FUSE_ROOT_ID, sizeof(*mknod) + len,
			   fuse_io->in.iovs, 1, NULL, 0, mknod_complete, hello_thread);

	memset(mknod, 0, sizeof(*mknod));
	mknod->mode = S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO;
	mknod->umask = 0022;
	mknod->rdev = 0;

	fuse_io->in.iovs[0].iov_base = hello_thread->file_name;
	fuse_io->in.iovs[0].iov_len = len;

	spdk_fsdev_io_submit(fsdev_io);
}

static void
hello_start_thread(void *ctx)
{
	struct hello_context_t *hello_context = (struct hello_context_t *)ctx;
	struct hello_thread_t *hello_thread;
	/* File name size assumes that core number will fit into 3 characters */
	const int filename_size = strlen(TEST_FILENAME) + 5;

	hello_thread = calloc(1, ALIGNED_THREAD_SIZE + spdk_fsdev_get_io_ctx_size());
	if (!hello_thread) {
		SPDK_ERRLOG("Failed to allocate thread context\n");
		spdk_thread_send_msg(hello_context->app_thread, hello_app_notify_thread_done, hello_context);
		return;
	}

	hello_thread->hello_context = hello_context;
	hello_thread->thread = spdk_get_thread();
	hello_thread->unique = 1;
	hello_thread->buf = (char *)malloc(DATA_SIZE);
	if (!hello_thread->buf) {
		SPDK_ERRLOG("Could not allocate data buffer\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	hello_thread->file_name = (char *)malloc(filename_size);
	if (!hello_thread->file_name) {
		SPDK_ERRLOG("Could not allocate file name buffer\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	if (snprintf(hello_thread->file_name, filename_size, "%s_%u",
		     TEST_FILENAME, spdk_env_get_current_core()) >= filename_size) {
		SPDK_ERRLOG("File name size doesn't fit into buffer\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	hello_thread->fsdev_io_channel = spdk_fsdev_get_io_channel(hello_thread->hello_context->fsdev_desc);
	if (!hello_thread->fsdev_io_channel) {
		SPDK_ERRLOG("Could not create fsdev I/O channel!\n");
		hello_thread_done(hello_thread, ENOMEM);
		return;
	}

	SPDK_NOTICELOG("Started thread %s on core %u\n",
		       spdk_thread_get_name(hello_thread->thread),
		       spdk_env_get_current_core());
	spdk_thread_send_msg(hello_thread->thread, hello_mknod, hello_thread);
}

static void
hello_create_threads(struct hello_context_t *hello_context)
{
	uint32_t cpu;
	char thread_name[32];
	struct spdk_cpuset mask = {};
	struct spdk_thread *thread;

	SPDK_ENV_FOREACH_CORE(cpu) {
		snprintf(thread_name, sizeof(thread_name), "hello_fsdev_%u", cpu);
		spdk_cpuset_zero(&mask);
		spdk_cpuset_set_cpu(&mask, cpu, true);
		thread = spdk_thread_create(thread_name, &mask);
		assert(thread != NULL);
		hello_context->thread_count++;
		spdk_thread_send_msg(thread, hello_start_thread, hello_context);
	}
}

static void
mount_complete(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	struct hello_context_t *hello_context = cb_arg;

	SPDK_NOTICELOG("Mount complete (status=%d)\n", status);
	if (status) {
		SPDK_ERRLOG("Mount failed: error %d\n", status);
		hello_app_done(hello_context, status);
		return;
	}

	hello_create_threads(hello_context);
}

static void
hello_submit_mount(struct hello_context_t *hello_context)
{
	struct spdk_fsdev_io *fsdev_io;
	struct fuse_init_in *init = &hello_context->fuse_io.in.op.init;
	struct hello_fuse_io *fuse_io = &hello_context->fuse_io;

	fsdev_io = hello_context_get_fsdev_io(hello_context);

	memset(init, 0, sizeof(*init));
	init->major = 7;
	init->minor = 31;

	fsdev_io_init_fuse(fuse_io, fsdev_io, hello_context->fsdev_desc, hello_context->fsdev_io_channel,
			   FUSE_INIT, 0, 0, 0, 0, NULL, 0, NULL, 0, mount_complete, hello_context);

	spdk_fsdev_io_submit(fsdev_io);
}

static void
hello_fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev, void *event_ctx)
{
	SPDK_NOTICELOG("Unsupported fsdev event: type %d\n", type);
}

/*
 * Our initial event that kicks off everything from main().
 */
static void
hello_start(void *arg1)
{
	struct hello_context_t *hello_context = arg1;
	int rc = 0;
	hello_context->fsdev_desc = NULL;

	SPDK_NOTICELOG("Successfully started the application\n");

	hello_context->app_thread = spdk_get_thread();

	/*
	 * There can be many fsdevs configured, but this application will only use
	 * the one input by the user at runtime.
	 *
	 * Open the fs by calling spdk_fsdev_open() with its name.
	 * The function will return a descriptor
	 */
	SPDK_NOTICELOG("Opening the fsdev %s\n", hello_context->fsdev_name);
	rc = spdk_fsdev_open(hello_context->fsdev_name,
			     hello_fsdev_event_cb, NULL,
			     &hello_context->fsdev_desc);
	if (rc) {
		SPDK_ERRLOG("Could not open fsdev: %s\n", hello_context->fsdev_name);
		spdk_app_stop(-1);
		return;
	}

	SPDK_NOTICELOG("Opening io channel\n");
	/* Open I/O channel */
	hello_context->fsdev_io_channel = spdk_fsdev_get_io_channel(hello_context->fsdev_desc);
	if (!hello_context->fsdev_io_channel) {
		SPDK_ERRLOG("Could not create fsdev I/O channel!\n");
		spdk_fsdev_close(hello_context->fsdev_desc);
		spdk_app_stop(-1);
		return;
	}

	SPDK_NOTICELOG("Mount\n");

	hello_submit_mount(hello_context);
}

int
main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc = 0;
	struct hello_context_t *hello_context;

	hello_context = calloc(1, ALIGNED_CONTEXT_SIZE + spdk_fsdev_get_io_ctx_size());
	if (!hello_context) {
		SPDK_ERRLOG("Could not allocate hello context\n");
		return -1;
	}

	/* Set default values in opts structure. */
	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "hello_fsdev";

	/*
	 * Parse built-in SPDK command line parameters as well
	 * as our custom one(s).
	 */
	if ((rc = spdk_app_parse_args(argc, argv, &opts, "f:", NULL, hello_fsdev_parse_arg,
				      hello_fsdev_usage)) != SPDK_APP_PARSE_ARGS_SUCCESS) {
		exit(rc);
	}
	hello_context->fsdev_name = g_fsdev_name;

	/*
	 * spdk_app_start() will initialize the SPDK framework, call hello_start(),
	 * and then block until spdk_app_stop() is called (or if an initialization
	 * error occurs, spdk_app_start() will return with rc even without calling
	 * hello_start().
	 */
	rc = spdk_app_start(&opts, hello_start, hello_context);
	if (rc) {
		SPDK_ERRLOG("ERROR starting application\n");
	}

	/* At this point either spdk_app_stop() was called, or spdk_app_start()
	 * failed because of internal error.
	 */

	/* Gracefully close out all of the SPDK subsystems. */
	spdk_app_fini();

	free(hello_context);
	return rc;
}
