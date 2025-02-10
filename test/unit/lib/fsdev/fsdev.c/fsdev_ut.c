/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk_internal/cunit.h"

#include "common/lib/ut_multithread.c"
#define UT_NUM_THREADS 3
#include "common/lib/ut_call.c"
#include "unit/lib/json_mock.c"

#include "spdk/config.h"

#include "spdk/log.h"
#include "spdk/fsdev.h"
#include "spdk/fsdev_module.h"

#define UT_UNIQUE 0xBEADBEAD
#define UT_FOBJECT ((struct spdk_fsdev_file_object *)0xDEADDEAD)
#define UT_FHANDLE ((struct spdk_fsdev_file_handle *)0xBEABBEAB)
#define UT_FNAME "ut_test.file"
#define UT_LNAME "ut_test.file.link"
#define UT_ANAME "xattr1.name"
#define UT_AVALUE "xattr1.val"
#define UT_NUM_LOOKUPS 11
#define UT_DATA_SIZE 22
#define UT_NOTIFY_MAX_DATA_SIZE 4096

#define UT_SUBMIT_IO_NUM_COMMON_PARAMS 4

/* No-op ioctl */
#define UT_IOCTL_CMD 42
#define UT_IOCTL_ARG ((uint64_t)0xBEEFDEAF)

#define UT_IOCTL_IN_IOVCNT 2
#define UT_IOCTL_OUT_IOVCNT 4

struct iovec ut_ioctl_in_iov[UT_IOCTL_IN_IOVCNT];
struct iovec ut_ioctl_out_iov[UT_IOCTL_OUT_IOVCNT];

#define UT_IOCTL_IN_IOV (&ut_ioctl_in_iov[0])
#define UT_IOCTL_OUT_IOV (&ut_ioctl_out_iov[0])

struct ut_fsdev {
	struct spdk_fsdev fsdev;
	int desired_io_status;
};

struct ut_io_channel {
	int reserved;
};

struct spdk_fsdev_file_object {
	int reserved;
};

struct spdk_fsdev_file_handle {
	int reserved;
};

static inline struct ut_fsdev *
fsdev_to_ut_fsdev(struct spdk_fsdev *fsdev)
{
	return SPDK_CONTAINEROF(fsdev, struct ut_fsdev, fsdev);
}

static struct ut_io_channel *g_ut_io_channel = NULL;

static int
ut_fsdev_io_channel_create_cb(void *io_device, void *ctx_buf)
{
	struct ut_io_channel *ch = ctx_buf;

	g_ut_io_channel = ch;

	ut_call_record_simple_param_ptr(ut_fsdev_io_channel_create_cb, ctx_buf);

	return 0;
}

static void
ut_fsdev_io_channel_destroy_cb(void *io_device, void *ctx_buf)
{
	g_ut_io_channel = NULL;

	ut_call_record_simple_param_ptr(ut_fsdev_io_channel_destroy_cb, ctx_buf);
}

static int
ut_fsdev_initialize(void)
{
	spdk_io_device_register(&g_call_list,
				ut_fsdev_io_channel_create_cb, ut_fsdev_io_channel_destroy_cb,
				sizeof(struct ut_io_channel), "ut_fsdev");

	return 0;
}

static void
ut_fsdev_io_device_unregister_done(void *io_device)
{
	SPDK_NOTICELOG("ut_fsdev_io_device unregistred\n");
}

static void
ut_fsdev_finish(void)
{
	spdk_io_device_unregister(&g_call_list, ut_fsdev_io_device_unregister_done);
}

static int
ut_fsdev_get_ctx_size(void)
{
	return 0;
}

static struct spdk_fsdev_module ut_fsdev_module = {
	.name = "ut_fsdev",
	.module_init = ut_fsdev_initialize,
	.module_fini = ut_fsdev_finish,
	.get_ctx_size = ut_fsdev_get_ctx_size,
};

SPDK_FSDEV_MODULE_REGISTER(ut_fsdev, &ut_fsdev_module);

static int
ut_fsdev_destruct(void *ctx)
{
	ut_call_record_simple_param_ptr(ut_fsdev_destruct, ctx);

	return 0;
}

static struct spdk_fsdev_file_attr ut_fsdev_attr;
static struct spdk_fsdev_file_object ut_fsdev_fobject;
static struct iovec ut_iov[5];
static struct spdk_fsdev_file_statfs ut_statfs;
static char ut_buff[1024];
static bool ut_listxattr_size_only;
static uint64_t ut_readdir_offset;
static uint64_t ut_readdir_num_entries;
static uint64_t ut_readdir_num_entry_cb_calls;
static int ut_reset_desired_err;
static bool ut_reset_leak_io;
static bool ut_complete_next_request = true;
static struct spdk_fsdev_io *ut_oustanding_io = NULL;
static struct spdk_fsdev_file_lock ut_fsdev_lock;
static struct spdk_fsdev_mount_opts ut_mount_opts;

static void
ut_fsdev_submit_request(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	enum spdk_fsdev_io_type type = spdk_fsdev_io_get_type(fsdev_io);
	struct ut_fsdev *utfsdev = fsdev_to_ut_fsdev(fsdev_io->fsdev);
	struct ut_io_channel *ch = spdk_io_channel_get_ctx(_ch);
	uint64_t unique = spdk_fsdev_io_get_unique(fsdev_io);
	int res, i = 0;

	CU_ASSERT(type >= 0 && type < __SPDK_FSDEV_IO_LAST);

	ut_call_record_begin(ut_fsdev_submit_request);

	/* Common params */
	ut_call_record_param_int(type);
	/* There's no unique for abort so we just add UT_UNIQUE to pass the test */
	ut_call_record_param_int((type != SPDK_FSDEV_IO_ABORT) ? unique : UT_UNIQUE);
	ut_call_record_param_ptr(ch);
	ut_call_record_param_ptr(utfsdev);

	CU_ASSERT(ut_call_record_get_current_param_count() == UT_SUBMIT_IO_NUM_COMMON_PARAMS);

	switch (type) {
	case SPDK_FSDEV_IO_MOUNT:
		ut_call_record_param_hash(&fsdev_io->u_in.mount.opts, sizeof(fsdev_io->u_in.mount.opts));
		fsdev_io->u_out.mount.root_fobject = UT_FOBJECT;
		fsdev_io->u_out.mount.opts.opts_size = fsdev_io->u_in.mount.opts.opts_size;
		fsdev_io->u_out.mount.opts.max_xfer_size = fsdev_io->u_in.mount.opts.max_xfer_size / 2;
		fsdev_io->u_out.mount.opts.flags = fsdev_io->u_in.mount.opts.flags;
		fsdev_io->u_out.mount.opts.flags &= ~SPDK_FSDEV_MOUNT_WRITEBACK_CACHE;
		break;
	case SPDK_FSDEV_IO_LOOKUP:
		ut_call_record_param_str(fsdev_io->u_in.lookup.name);
		ut_call_record_param_ptr(fsdev_io->u_in.lookup.parent_fobject);
		fsdev_io->u_out.lookup.fobject = &ut_fsdev_fobject;
		fsdev_io->u_out.lookup.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_FORGET:
		ut_call_record_param_ptr(fsdev_io->u_in.forget.fobject);
		ut_call_record_param_int(fsdev_io->u_in.forget.nlookup);
		break;
	case SPDK_FSDEV_IO_GETATTR:
		ut_call_record_param_ptr(fsdev_io->u_in.getattr.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.getattr.fhandle);
		fsdev_io->u_out.getattr.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_SETATTR:
		ut_call_record_param_ptr(fsdev_io->u_in.setattr.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.setattr.fhandle);
		ut_call_record_param_hash(&fsdev_io->u_in.setattr.attr, sizeof(fsdev_io->u_in.setattr.attr));
		ut_call_record_param_int(fsdev_io->u_in.setattr.to_set);
		fsdev_io->u_out.getattr.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_READLINK:
		ut_call_record_param_ptr(fsdev_io->u_in.readlink.fobject);
		fsdev_io->u_out.readlink.linkname = strdup(UT_FNAME);
		SPDK_CU_ASSERT_FATAL(fsdev_io->u_out.readlink.linkname != NULL);
		break;
	case SPDK_FSDEV_IO_SYMLINK:
		ut_call_record_param_ptr(fsdev_io->u_in.symlink.parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.symlink.target);
		ut_call_record_param_str(fsdev_io->u_in.symlink.linkpath);
		ut_call_record_param_int(fsdev_io->u_in.symlink.euid);
		ut_call_record_param_int(fsdev_io->u_in.symlink.egid);
		fsdev_io->u_out.symlink.fobject = UT_FOBJECT + 1;
		fsdev_io->u_out.symlink.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_MKNOD:
		ut_call_record_param_ptr(fsdev_io->u_in.mknod.parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.mknod.name);
		ut_call_record_param_int(fsdev_io->u_in.mknod.mode);
		ut_call_record_param_int(fsdev_io->u_in.mknod.rdev);
		ut_call_record_param_int(fsdev_io->u_in.mknod.umask);
		ut_call_record_param_int(fsdev_io->u_in.mknod.euid);
		ut_call_record_param_int(fsdev_io->u_in.mknod.egid);
		fsdev_io->u_out.mknod.fobject = UT_FOBJECT + 1;
		fsdev_io->u_out.mknod.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_MKDIR:
		ut_call_record_param_ptr(fsdev_io->u_in.mkdir.parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.mkdir.name);
		ut_call_record_param_int(fsdev_io->u_in.mkdir.mode);
		ut_call_record_param_int(fsdev_io->u_in.mkdir.umask);
		ut_call_record_param_int(fsdev_io->u_in.mkdir.euid);
		ut_call_record_param_int(fsdev_io->u_in.mkdir.egid);
		fsdev_io->u_out.mkdir.fobject = UT_FOBJECT + 1;
		fsdev_io->u_out.mkdir.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_UNLINK:
		ut_call_record_param_ptr(fsdev_io->u_in.unlink.parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.unlink.name);
		break;
	case SPDK_FSDEV_IO_RMDIR:
		ut_call_record_param_ptr(fsdev_io->u_in.rmdir.parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.rmdir.name);
		break;
	case SPDK_FSDEV_IO_RENAME:
		ut_call_record_param_ptr(fsdev_io->u_in.rename.parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.rename.name);
		ut_call_record_param_ptr(fsdev_io->u_in.rename.new_parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.rename.new_name);
		ut_call_record_param_int(fsdev_io->u_in.rename.flags);
		break;
	case SPDK_FSDEV_IO_LINK:
		ut_call_record_param_ptr(fsdev_io->u_in.link.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.link.new_parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.link.name);
		fsdev_io->u_out.link.fobject = UT_FOBJECT + 1;
		fsdev_io->u_out.link.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_OPEN:
		ut_call_record_param_ptr(fsdev_io->u_in.open.fobject);
		ut_call_record_param_int(fsdev_io->u_in.open.flags);
		fsdev_io->u_out.open.fhandle = UT_FHANDLE;
		break;
	case SPDK_FSDEV_IO_READ:
		ut_call_record_param_ptr(fsdev_io->u_in.read.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.read.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.read.size);
		ut_call_record_param_int(fsdev_io->u_in.read.offs);
		ut_call_record_param_int(fsdev_io->u_in.read.flags);
		ut_call_record_param_hash(fsdev_io->u_in.read.iov,
					  fsdev_io->u_in.read.iovcnt * sizeof(fsdev_io->u_in.read.iov[0]));
		ut_call_record_param_int(fsdev_io->u_in.read.iovcnt);
		ut_call_record_param_ptr(fsdev_io->u_in.read.opts);
		fsdev_io->u_out.read.data_size = UT_DATA_SIZE;
		break;
	case SPDK_FSDEV_IO_WRITE:
		ut_call_record_param_ptr(fsdev_io->u_in.write.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.write.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.write.size);
		ut_call_record_param_int(fsdev_io->u_in.write.offs);
		ut_call_record_param_int(fsdev_io->u_in.write.flags);
		ut_call_record_param_hash(fsdev_io->u_in.write.iov,
					  fsdev_io->u_in.write.iovcnt * sizeof(fsdev_io->u_in.write.iov[0]));
		ut_call_record_param_int(fsdev_io->u_in.write.iovcnt);
		ut_call_record_param_ptr(fsdev_io->u_in.write.opts);
		fsdev_io->u_out.write.data_size = UT_DATA_SIZE;
		break;
	case SPDK_FSDEV_IO_STATFS:
		ut_call_record_param_ptr(fsdev_io->u_in.statfs.fobject);
		fsdev_io->u_out.statfs.statfs = ut_statfs;
		break;
	case SPDK_FSDEV_IO_RELEASE:
		ut_call_record_param_ptr(fsdev_io->u_in.release.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.release.fhandle);
		break;
	case SPDK_FSDEV_IO_FSYNC:
		ut_call_record_param_ptr(fsdev_io->u_in.fsync.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.fsync.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.fsync.datasync);
		break;
	case SPDK_FSDEV_IO_SETXATTR:
		ut_call_record_param_ptr(fsdev_io->u_in.setxattr.fobject);
		ut_call_record_param_str(fsdev_io->u_in.setxattr.name);
		ut_call_record_param_str(fsdev_io->u_in.setxattr.value);
		ut_call_record_param_int(fsdev_io->u_in.setxattr.size);
		ut_call_record_param_int(fsdev_io->u_in.setxattr.flags);
		break;
	case SPDK_FSDEV_IO_GETXATTR:
		ut_call_record_param_ptr(fsdev_io->u_in.getxattr.fobject);
		ut_call_record_param_str(fsdev_io->u_in.getxattr.name);
		ut_call_record_param_ptr(fsdev_io->u_in.getxattr.buffer);
		ut_call_record_param_int(fsdev_io->u_in.getxattr.size);
		spdk_strcpy_pad(fsdev_io->u_in.getxattr.buffer, UT_AVALUE,
				fsdev_io->u_in.getxattr.size - 1, 0);
		fsdev_io->u_out.getxattr.value_size = sizeof(UT_AVALUE);
		break;
	case SPDK_FSDEV_IO_LISTXATTR:
		ut_call_record_param_ptr(fsdev_io->u_in.listxattr.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.listxattr.buffer);
		ut_call_record_param_int(fsdev_io->u_in.listxattr.size);

		fsdev_io->u_out.listxattr.size_only = fsdev_io->u_in.listxattr.buffer == NULL;
		fsdev_io->u_out.listxattr.data_size = (sizeof(ut_buff) / sizeof(UT_ANAME)) * sizeof(UT_ANAME);

		if (!fsdev_io->u_out.listxattr.size_only) {
			size_t size = fsdev_io->u_in.listxattr.size;
			char *p = fsdev_io->u_in.listxattr.buffer;

			while (size >= sizeof(UT_ANAME)) {
				memcpy(p, UT_ANAME, sizeof(UT_ANAME));
				p += sizeof(UT_ANAME);
				size -= sizeof(UT_ANAME);
			}
		}
		break;
	case SPDK_FSDEV_IO_REMOVEXATTR:
		ut_call_record_param_ptr(fsdev_io->u_in.removexattr.fobject);
		ut_call_record_param_str(fsdev_io->u_in.removexattr.name);
		break;
	case SPDK_FSDEV_IO_FLUSH:
		ut_call_record_param_ptr(fsdev_io->u_in.flush.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.flush.fhandle);
		break;
	case SPDK_FSDEV_IO_OPENDIR:
		ut_call_record_param_ptr(fsdev_io->u_in.opendir.fobject);
		ut_call_record_param_int(fsdev_io->u_in.opendir.flags);
		fsdev_io->u_out.opendir.fhandle = UT_FHANDLE;
		break;
	case SPDK_FSDEV_IO_READDIR:
		ut_call_record_param_ptr(fsdev_io->u_in.readdir.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.readdir.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.readdir.offset);
		ut_call_record_param_ptr(fsdev_io->u_in.readdir.usr_entry_cb_fn);

		do {
			bool forget = false;
			fsdev_io->u_out.readdir.fobject = UT_FOBJECT + i;
			fsdev_io->u_out.readdir.attr = ut_fsdev_attr;
			fsdev_io->u_out.readdir.name = UT_FNAME;
			fsdev_io->u_out.readdir.offset = ut_readdir_offset + i;
			res = fsdev_io->u_in.readdir.entry_cb_fn(fsdev_io, fsdev_io->internal.cb_arg, &forget);
			i++;
		} while (!res);

		break;
	case SPDK_FSDEV_IO_RELEASEDIR:
		ut_call_record_param_ptr(fsdev_io->u_in.releasedir.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.releasedir.fhandle);
		break;
	case SPDK_FSDEV_IO_FSYNCDIR:
		ut_call_record_param_ptr(fsdev_io->u_in.fsyncdir.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.fsyncdir.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.fsyncdir.datasync);
		break;
	case SPDK_FSDEV_IO_FLOCK:
		ut_call_record_param_ptr(fsdev_io->u_in.flock.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.flock.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.flock.operation);
		break;
	case SPDK_FSDEV_IO_CREATE:
		ut_call_record_param_ptr(fsdev_io->u_in.create.parent_fobject);
		ut_call_record_param_str(fsdev_io->u_in.create.name);
		ut_call_record_param_int(fsdev_io->u_in.create.mode);
		ut_call_record_param_int(fsdev_io->u_in.create.flags);
		ut_call_record_param_int(fsdev_io->u_in.create.umask);
		ut_call_record_param_int(fsdev_io->u_in.create.euid);
		ut_call_record_param_int(fsdev_io->u_in.create.egid);
		fsdev_io->u_out.create.fobject = UT_FOBJECT + 1;
		fsdev_io->u_out.create.fhandle = UT_FHANDLE;
		fsdev_io->u_out.create.attr = ut_fsdev_attr;
		break;
	case SPDK_FSDEV_IO_ABORT:
		ut_call_record_param_int(fsdev_io->u_in.abort.unique_to_abort);
		break;
	case SPDK_FSDEV_IO_FALLOCATE:
		ut_call_record_param_ptr(fsdev_io->u_in.fallocate.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.fallocate.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.fallocate.mode);
		ut_call_record_param_int(fsdev_io->u_in.fallocate.offset);
		ut_call_record_param_int(fsdev_io->u_in.fallocate.length);
		break;
	case SPDK_FSDEV_IO_COPY_FILE_RANGE:
		ut_call_record_param_ptr(fsdev_io->u_in.copy_file_range.fobject_in);
		ut_call_record_param_ptr(fsdev_io->u_in.copy_file_range.fhandle_in);
		ut_call_record_param_int(fsdev_io->u_in.copy_file_range.off_in);
		ut_call_record_param_ptr(fsdev_io->u_in.copy_file_range.fobject_out);
		ut_call_record_param_ptr(fsdev_io->u_in.copy_file_range.fhandle_out);
		ut_call_record_param_int(fsdev_io->u_in.copy_file_range.off_out);
		ut_call_record_param_int(fsdev_io->u_in.copy_file_range.len);
		ut_call_record_param_int(fsdev_io->u_in.copy_file_range.flags);
		fsdev_io->u_out.copy_file_range.data_size = UT_DATA_SIZE;
		break;
	case SPDK_FSDEV_IO_SYNCFS:
		ut_call_record_param_ptr(fsdev_io->u_in.syncfs.fobject);
		break;
	case SPDK_FSDEV_IO_ACCESS:
		ut_call_record_param_ptr(fsdev_io->u_in.access.fobject);
		ut_call_record_param_int(fsdev_io->u_in.access.mask);
		ut_call_record_param_int(fsdev_io->u_in.access.uid);
		ut_call_record_param_int(fsdev_io->u_in.access.gid);
		break;
	case SPDK_FSDEV_IO_LSEEK:
		ut_call_record_param_ptr(fsdev_io->u_in.lseek.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.lseek.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.lseek.offset);
		ut_call_record_param_int(fsdev_io->u_in.lseek.whence);
		break;
	case SPDK_FSDEV_IO_POLL:
		ut_call_record_param_ptr(fsdev_io->u_in.poll.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.poll.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.poll.events);
		ut_call_record_param_int(fsdev_io->u_in.poll.wait);
		break;
	case SPDK_FSDEV_IO_IOCTL:
		ut_call_record_param_ptr(fsdev_io->u_in.ioctl.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.ioctl.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.ioctl.request);
		ut_call_record_param_int(fsdev_io->u_in.ioctl.arg);
		ut_call_record_param_ptr(fsdev_io->u_in.ioctl.in_iov);
		ut_call_record_param_int(fsdev_io->u_in.ioctl.in_iovcnt);
		ut_call_record_param_ptr(fsdev_io->u_in.ioctl.out_iov);
		ut_call_record_param_int(fsdev_io->u_in.ioctl.out_iovcnt);
		break;
	case SPDK_FSDEV_IO_GETLK:
		ut_call_record_param_ptr(fsdev_io->u_in.getlk.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.getlk.fhandle);
		ut_call_record_param_hash(&fsdev_io->u_in.getlk.lock,
					  sizeof(fsdev_io->u_in.getlk.lock));
		fsdev_io->u_out.getlk.lock = ut_fsdev_lock;
		ut_call_record_param_int(fsdev_io->u_in.getlk.owner);
		break;
	case SPDK_FSDEV_IO_SETLK:
		ut_call_record_param_ptr(fsdev_io->u_in.setlk.fobject);
		ut_call_record_param_ptr(fsdev_io->u_in.setlk.fhandle);
		ut_call_record_param_int(fsdev_io->u_in.setlk.owner);
		ut_call_record_param_int(fsdev_io->u_in.setlk.wait);
		break;
	case __SPDK_FSDEV_IO_LAST:
	default:
		break;
	}

	ut_call_record_end();

	if (ut_complete_next_request) {
		spdk_fsdev_io_complete(fsdev_io, utfsdev->desired_io_status);
	} else {
		ut_oustanding_io = fsdev_io;
		ut_complete_next_request = true;
	}
}

static struct spdk_io_channel *
ut_fsdev_get_io_channel(void *ctx)
{
	ut_call_record_simple_param_ptr(ut_fsdev_get_io_channel, ctx);

	return spdk_get_io_channel(&g_call_list);
}

static void
ut_fsdev_write_config_json(struct spdk_fsdev *fsdev, struct spdk_json_write_ctx *w)
{

}

static int
ut_fsdev_get_memory_domains(void *ctx, struct spdk_memory_domain **domains,
			    int array_size)
{
	return 0;
}

static int
ut_fsdev_reset(void *ctx, spdk_fsdev_reset_done_cb cb, void *cb_arg)
{
	ut_call_record_simple_param_ptr(ut_fsdev_reset, ctx);

	if (!ut_reset_leak_io) {
		spdk_fsdev_io_complete(ut_oustanding_io, -ESTALE);
		ut_oustanding_io = NULL;
	}

	if (!ut_reset_desired_err) {
		/* The callback should only be called in case of success */
		cb(cb_arg, ut_reset_desired_err);
	}

	return ut_reset_desired_err;
}

static int
ut_fsdev_set_notifications(void *ctx, bool enabled)
{
	ut_call_record_begin(ut_fsdev_set_notifications);
	ut_call_record_param_ptr(ctx);
	ut_call_record_param_int(enabled);
	ut_call_record_end();
	return 0;
}

static const struct spdk_fsdev_fn_table ut_fdev_fn_table = {
	.destruct		= ut_fsdev_destruct,
	.submit_request		= ut_fsdev_submit_request,
	.get_io_channel		= ut_fsdev_get_io_channel,
	.write_config_json	= ut_fsdev_write_config_json,
	.get_memory_domains	= ut_fsdev_get_memory_domains,
	.reset			= ut_fsdev_reset,
	.set_notifications	= ut_fsdev_set_notifications,
};

static void
ut_fsdev_free(struct ut_fsdev *ufsdev)
{
	free(ufsdev->fsdev.name);
	free(ufsdev);
}

static void
ut_fsdev_unregister_done(void *cb_arg, int rc)
{
	struct ut_fsdev *ufsdev = cb_arg;

	ut_call_record_simple_param_ptr(ut_fsdev_unregister_done, cb_arg);

	ut_fsdev_free(ufsdev);
}

static void
ut_fsdev_destroy(struct ut_fsdev *utfsdev)
{
	ut_calls_reset();
	spdk_fsdev_unregister(&utfsdev->fsdev, ut_fsdev_unregister_done, utfsdev);
	poll_thread(0);

	CU_ASSERT(ut_calls_get_call_count() == 2);

	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_destruct);
	CU_ASSERT(ut_calls_get_param_count(0) == 1);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == utfsdev);

	CU_ASSERT(ut_calls_get_func(1) == ut_fsdev_unregister_done);
	CU_ASSERT(ut_calls_get_param_count(1) == 1);
	CU_ASSERT(ut_calls_param_get_ptr(1, 0) == utfsdev);
}

static struct ut_fsdev *
ut_fsdev_create(const char *name)
{
	struct ut_fsdev *ufsdev;
	int rc;

	ufsdev = calloc(1, sizeof(*ufsdev));
	if (!ufsdev) {
		SPDK_ERRLOG("Could not allocate ut_fsdev\n");
		return NULL;
	}

	ufsdev->fsdev.name = strdup(name);
	if (!ufsdev->fsdev.name) {
		SPDK_ERRLOG("Could not strdup name %s\n", name);
		free(ufsdev);
		return NULL;
	}

	ufsdev->fsdev.ctxt = ufsdev;
	ufsdev->fsdev.fn_table = &ut_fdev_fn_table;
	ufsdev->fsdev.module = &ut_fsdev_module;
	ufsdev->fsdev.notify_max_data_size = UT_NOTIFY_MAX_DATA_SIZE;

	rc = spdk_fsdev_register(&ufsdev->fsdev);
	if (rc) {
		ut_fsdev_free(ufsdev);
		return NULL;
	}

	return ufsdev;
}

static void
ut_fsdev_initialize_complete(void *cb_arg, int rc)
{
	bool *completed  = cb_arg;

	*completed = true;
}

static int
ut_fsdev_setup(void)
{
	bool completed = false;

	spdk_fsdev_initialize(ut_fsdev_initialize_complete, &completed);

	poll_thread(0);

	if (!completed) {
		SPDK_ERRLOG("No spdk_fsdev_initialize callback arrived\n");
		return EINVAL;
	}

	return 0;
}

static void
ut_fsdev_teardown_complete(void *cb_arg)
{
	bool *completed  = cb_arg;

	*completed = true;
}

static int
ut_fsdev_teardown(void)
{
	bool completed = false;
	spdk_fsdev_finish(ut_fsdev_teardown_complete, &completed);

	poll_thread(0);

	if (!completed) {
		SPDK_ERRLOG("No spdk_fsdev_finish callback arrived\n");
		return EINVAL;
	}

	return 0;
}

static void
fsdev_event_cb(enum spdk_fsdev_event_type type, struct spdk_fsdev *fsdev,
	       void *event_ctx)
{
	SPDK_NOTICELOG("Unsupported bdev event: type %d\n", type);
}

static void
ut_fsdev_test_open_close(void)
{
	struct ut_fsdev *utfsdev;
	struct spdk_fsdev_desc *fsdev_desc;
	int rc;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	CU_ASSERT(!strcmp(spdk_fsdev_get_module_name(&utfsdev->fsdev), ut_fsdev_module.name));
	CU_ASSERT(!strcmp(spdk_fsdev_get_name(&utfsdev->fsdev), "utfsdev0"));

	ut_calls_reset();
	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);
	CU_ASSERT(spdk_fsdev_desc_get_fsdev(fsdev_desc) == &utfsdev->fsdev);

	if (fsdev_desc) {
		spdk_fsdev_close(fsdev_desc);
	}

	ut_fsdev_destroy(utfsdev);
}

static void
ut_fsdev_test_set_opts(void)
{
	struct spdk_fsdev_opts old_opts;
	struct spdk_fsdev_opts new_opts;
	int rc;

	rc = spdk_fsdev_set_opts(NULL);
	CU_ASSERT(rc == -EINVAL);

	new_opts.opts_size = 0;
	rc = spdk_fsdev_set_opts(&new_opts);
	CU_ASSERT(rc == -EINVAL);

	old_opts.opts_size = sizeof(old_opts);
	rc = spdk_fsdev_get_opts(&old_opts, sizeof(old_opts));
	CU_ASSERT(rc == 0);

	new_opts.opts_size = sizeof(new_opts);
	new_opts.fsdev_io_pool_size = old_opts.fsdev_io_pool_size * 2;
	new_opts.fsdev_io_cache_size = old_opts.fsdev_io_cache_size * 2;
	rc = spdk_fsdev_set_opts(&new_opts);
	CU_ASSERT(rc == 0);

	rc = spdk_fsdev_get_opts(&new_opts, sizeof(new_opts));
	CU_ASSERT(rc == 0);
	CU_ASSERT(old_opts.fsdev_io_pool_size * 2 == new_opts.fsdev_io_pool_size);
	CU_ASSERT(old_opts.fsdev_io_cache_size * 2 == new_opts.fsdev_io_cache_size);
}

static void
ut_fsdev_test_get_io_channel(void)
{
	struct ut_fsdev *utfsdev;
	struct spdk_io_channel *ch;
	struct spdk_fsdev_desc *fsdev_desc;
	struct ut_io_channel *ut_ch;
	int rc;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);
	CU_ASSERT(spdk_fsdev_desc_get_fsdev(fsdev_desc) == &utfsdev->fsdev);

	ut_calls_reset();
	ch = spdk_fsdev_get_io_channel(fsdev_desc);
	CU_ASSERT(ch != NULL);
	CU_ASSERT(ut_calls_get_call_count() == 2);

	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_get_io_channel);
	CU_ASSERT(ut_calls_get_param_count(0) == 1);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == utfsdev);

	CU_ASSERT(ut_calls_get_func(1) == ut_fsdev_io_channel_create_cb);
	CU_ASSERT(ut_calls_get_param_count(1) == 1);
	ut_ch = (struct ut_io_channel *)ut_calls_param_get_ptr(1, 0);

	ut_calls_reset();
	spdk_put_io_channel(ch);
	poll_thread(0);
	CU_ASSERT(ut_calls_get_call_count() == 1);

	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_io_channel_destroy_cb);
	CU_ASSERT(ut_calls_get_param_count(0) == 1);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == ut_ch);

	spdk_fsdev_close(fsdev_desc);

	ut_fsdev_destroy(utfsdev);
}

static void
ut_fsdev_for_each_msg_cb(struct spdk_fsdev_channel_iter *i,
			 struct spdk_fsdev *fsdev, struct spdk_io_channel *ch, void *ctx)
{
	uint64_t *desired_res = ctx;

	ut_call_record_begin(ut_fsdev_for_each_msg_cb);

	ut_call_record_param_ptr(fsdev);
	ut_call_record_param_ptr(ch);
	ut_call_record_param_ptr(ctx);

	ut_call_record_end();

	spdk_fsdev_for_each_channel_continue(i, (int)*desired_res);
}

static void
ut_fsdev_for_each_done_cb(struct spdk_fsdev *fsdev, void *ctx, int status)
{
	ut_call_record_begin(ut_fsdev_for_each_done_cb);

	ut_call_record_param_ptr(fsdev);
	ut_call_record_param_ptr(ctx);
	ut_call_record_param_int(status);

	ut_call_record_end();
}

static void
ut_fsdev_test_for_each_channel(uint64_t desired_res)
{
	struct ut_fsdev *utfsdev;
	struct spdk_io_channel *ch[UT_NUM_THREADS];
	struct ut_io_channel *ut_ch[UT_NUM_THREADS];
	struct spdk_fsdev_desc *fsdev_desc;
	int rc, i;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);
	CU_ASSERT(spdk_fsdev_desc_get_fsdev(fsdev_desc) == &utfsdev->fsdev);

	ut_calls_reset();
	for (i = 0; i < UT_NUM_THREADS; i++) {
		set_thread(i);

		ch[i] = spdk_fsdev_get_io_channel(fsdev_desc);
		CU_ASSERT(ch[i] != NULL);
	}

	CU_ASSERT(ut_calls_get_call_count() == UT_NUM_THREADS * 2);

	for (i = 0; i < UT_NUM_THREADS; i++) {
		int j = i * 2;
		CU_ASSERT(ut_calls_get_func(j) == ut_fsdev_get_io_channel);
		CU_ASSERT(ut_calls_get_param_count(j) == 1);
		CU_ASSERT(ut_calls_param_get_ptr(j, 0) == utfsdev);

		CU_ASSERT(ut_calls_get_func(j + 1) == ut_fsdev_io_channel_create_cb);
		CU_ASSERT(ut_calls_get_param_count(j + 1) == 1);
		ut_ch[i] = (struct ut_io_channel *)ut_calls_param_get_ptr(j + 1, 0);
	}

	set_thread(0);
	ut_calls_reset();
	spdk_fsdev_for_each_channel(&utfsdev->fsdev, ut_fsdev_for_each_msg_cb, &desired_res,
				    ut_fsdev_for_each_done_cb);
	poll_threads();
	set_thread(0);
	poll_thread(0);

	if (!desired_res) {
		CU_ASSERT(ut_calls_get_call_count() == UT_NUM_THREADS + 1);

		for (i = 0; i < UT_NUM_THREADS; i++) {
			CU_ASSERT(ut_calls_get_func(i) == ut_fsdev_for_each_msg_cb);
			CU_ASSERT(ut_calls_get_param_count(i) == 3);
			CU_ASSERT(ut_calls_param_get_ptr(i, 0) == &utfsdev->fsdev);
			CU_ASSERT(ut_calls_param_get_ptr(i, 1) != NULL);
			CU_ASSERT(ut_calls_param_get_ptr(i, 2) == &desired_res);
		}
	} else {
		/* we failed the 1st ut_fsdev_for_each_msg_cb, so it should be called only once */

		CU_ASSERT(ut_calls_get_call_count() == 2);

		i = 0;
		CU_ASSERT(ut_calls_get_func(i) == ut_fsdev_for_each_msg_cb);
		CU_ASSERT(ut_calls_get_param_count(i) == 3);
		CU_ASSERT(ut_calls_param_get_ptr(i, 0) == &utfsdev->fsdev);
		CU_ASSERT(ut_calls_param_get_ptr(i, 1) != NULL);
		CU_ASSERT(ut_calls_param_get_ptr(i, 2) == &desired_res);

		i = 1;
	}

	CU_ASSERT(ut_calls_get_func(i) == ut_fsdev_for_each_done_cb);
	CU_ASSERT(ut_calls_get_param_count(i) == 3);
	CU_ASSERT(ut_calls_param_get_ptr(i, 0) == &utfsdev->fsdev);
	CU_ASSERT(ut_calls_param_get_ptr(i, 1) == &desired_res);
	CU_ASSERT(ut_calls_param_get_int(i, 2) == desired_res);

	ut_calls_reset();
	for (i = 0; i < UT_NUM_THREADS; i++) {
		set_thread(i);
		spdk_put_io_channel(ch[i]);
	}

	poll_threads();
	set_thread(0);

	CU_ASSERT(ut_calls_get_call_count() == UT_NUM_THREADS);

	for (i = 0; i < UT_NUM_THREADS; i++) {
		CU_ASSERT(ut_calls_get_func(i) == ut_fsdev_io_channel_destroy_cb);
		CU_ASSERT(ut_calls_get_param_count(i) == 1);
		CU_ASSERT(ut_calls_param_get_ptr(i, 0) == ut_ch[i]);
	}

	set_thread(0);
	spdk_fsdev_close(fsdev_desc);

	ut_fsdev_destroy(utfsdev);
}


static void
ut_fsdev_test_for_each_channel_ok(void)
{
	ut_fsdev_test_for_each_channel(0);
}

static void
ut_fsdev_test_for_each_channel_err(void)
{
	ut_fsdev_test_for_each_channel(ENOSR);
}

static void
ut_fsdev_reset_flush_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	ut_call_record_begin(ut_fsdev_reset_flush_cpl_cb);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_param_int(status);
	ut_call_record_end();

}

static void
ut_fsdev_reset_cpl_cb(struct spdk_fsdev_desc *desc, bool success, void *cb_arg)
{
	ut_call_record_begin(ut_fsdev_reset_cpl_cb);
	ut_call_record_param_ptr(desc);
	ut_call_record_param_int(success);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_end();
}

static void
ut_fsdev_do_test_reset(bool fail_module_reset, bool leak_io)
{
	struct ut_fsdev *utfsdev;
	struct spdk_io_channel *ch;
	struct spdk_fsdev_desc *fsdev_desc;
	int rc;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);
	CU_ASSERT(spdk_fsdev_desc_get_fsdev(fsdev_desc) == &utfsdev->fsdev);

	ch = spdk_fsdev_get_io_channel(fsdev_desc);
	CU_ASSERT(ch != NULL);

	ut_calls_reset();
	ut_complete_next_request = false; /* Make sure the flush IO won't be completed */
	rc =  spdk_fsdev_flush(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
			       ut_fsdev_reset_flush_cpl_cb, utfsdev);
	CU_ASSERT(rc == 0);

	poll_thread(0);

	ut_reset_desired_err = fail_module_reset ? EINVAL : 0;
	ut_reset_leak_io = leak_io;

	ut_calls_reset();

	rc = spdk_fsdev_reset(fsdev_desc, ut_fsdev_reset_cpl_cb, utfsdev);
	CU_ASSERT(rc == 0);

	poll_thread(0);

	/* IO must be completed either by the module (if it doesn't leak IOs) or by the fsdev core (if it does) */
	CU_ASSERT(ut_calls_get_call_count() == fail_module_reset ? 2 : 3);
	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_reset);
	CU_ASSERT(ut_calls_get_param_count(0) == 1);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == utfsdev);
	CU_ASSERT(ut_calls_get_func(1) == ut_fsdev_reset_flush_cpl_cb);
	CU_ASSERT(ut_calls_get_param_count(1) == 2);
	CU_ASSERT(ut_calls_param_get_ptr(1, 0) == utfsdev);
	/* fsdev core completes with ECANCELED while ut_fsdev_reset completes with ESTALE */
	CU_ASSERT(ut_calls_param_get_int(1, 1) == leak_io ? ECANCELED : ESTALE);

	if (!fail_module_reset) {
		/* The reset completion callback is only called if the module's reset suceeds */
		CU_ASSERT(ut_calls_get_func(2) == ut_fsdev_reset_cpl_cb);
		CU_ASSERT(ut_calls_get_param_count(2) == 3);
		CU_ASSERT(ut_calls_param_get_ptr(2, 0) == fsdev_desc);
		CU_ASSERT(ut_calls_param_get_int(2, 1) == !ut_reset_desired_err);
		CU_ASSERT(ut_calls_param_get_ptr(2, 2) == utfsdev);
	}

	ut_calls_reset();
	spdk_put_io_channel(ch);
	poll_thread(0);

	spdk_fsdev_close(fsdev_desc);

	ut_fsdev_destroy(utfsdev);
}

static void
ut_fsdev_test_reset_module_reset_succeeds(void)
{
	/* Test with a module that succeeds to reset and doesn't leak the IO (i.e. confirms it) */
	ut_fsdev_do_test_reset(false, false);
}

static void
ut_fsdev_test_reset_module_reset_leaks_io(void)
{
	/* Test with a module that succeeds to reset and leaks the IO (i.e. doesn't confirm it, so fsdev should) */
	ut_fsdev_do_test_reset(false, true);
}

static void
ut_fsdev_test_reset_module_reset_fails(void)
{
	/* Test with a module that fails to reset */
	ut_fsdev_do_test_reset(true, false);
}

static void
ut_fsdev_notify_cb(struct spdk_fsdev *fsdev,
		   void *ctx,
		   const struct spdk_fsdev_notify_data *notify_data,
		   spdk_fsdev_notify_reply_cb_t reply_cb,
		   void *reply_ctx)
{
	ut_call_record_begin(ut_fsdev_notify_cb);
	ut_call_record_param_ptr(fsdev);
	ut_call_record_param_ptr(ctx);
	ut_call_record_param_int(notify_data->type);
	switch (notify_data->type) {
	case SPDK_FSDEV_NOTIFY_INVAL_DATA:
		ut_call_record_param_hash(&notify_data->inval_data, sizeof(notify_data->inval_data));
		break;
	case SPDK_FSDEV_NOTIFY_INVAL_ENTRY:
		ut_call_record_param_hash(&notify_data->inval_entry, sizeof(notify_data->inval_entry));
		break;
	default:
		CU_ASSERT(false);
		break;
	}
	ut_call_record_param_ptr(reply_cb);
	ut_call_record_param_ptr(reply_ctx);
	ut_call_record_end();
}

static void
ut_fsdev_notify_reply_cb(const struct spdk_fsdev_notify_reply_data *notify_reply_data,
			 void *reply_ctx)
{
}

static void
ut_fsdev_device_stat_cb(struct spdk_fsdev *fsdev, struct spdk_fsdev_io_stat *stat, void *cb_arg,
			int rc)
{
}

static void
ut_fsdev_test_notifications(void)
{
	struct ut_fsdev *utfsdev;
	struct spdk_fsdev_desc *fsdev_desc;
	struct spdk_fsdev *fsdev;
	int notify_ctx;
	int reply_ctx;
	int file_object;
	int parent_file_object;
	const char *filename = "test_file.txt";
	struct spdk_fsdev_notify_data notify_data;
	struct spdk_fsdev_io_stat stat;
	int rc;

	utfsdev = ut_fsdev_create("utfsdev0");
	SPDK_CU_ASSERT_FATAL(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	SPDK_CU_ASSERT_FATAL(rc == 0);
	SPDK_CU_ASSERT_FATAL(fsdev_desc != NULL);
	fsdev = spdk_fsdev_desc_get_fsdev(fsdev_desc);
	SPDK_CU_ASSERT_FATAL(fsdev != NULL);

	CU_ASSERT(spdk_fsdev_get_notify_max_data_size(spdk_fsdev_desc_get_fsdev(fsdev_desc)) ==
		  UT_NOTIFY_MAX_DATA_SIZE);

	/* No subscriber */
	ut_calls_reset();
	rc = spdk_fsdev_notify_inval_data(&utfsdev->fsdev, (struct spdk_fsdev_file_object *)&file_object,
					  4096, 8192, NULL, NULL);
	CU_ASSERT(rc == -ENODEV);

	/* Enable notifications */
	ut_calls_reset();
	rc = spdk_fsdev_enable_notifications(fsdev_desc, ut_fsdev_notify_cb, &notify_ctx);
	CU_ASSERT(rc == 0);
	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_set_notifications);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == utfsdev);
	CU_ASSERT(ut_calls_param_get_int(0, 1) == true);

	/* Enable notifications twice should fail */
	rc = spdk_fsdev_enable_notifications(fsdev_desc, ut_fsdev_notify_cb, &notify_ctx);
	CU_ASSERT(rc == -EALREADY);

	/* SPDK_FSDEV_EVENT_NOTIFY_INVAL_DATA */
	ut_calls_reset();
	rc = spdk_fsdev_notify_inval_data(&utfsdev->fsdev, (struct spdk_fsdev_file_object *)&file_object,
					  4096, 8192, ut_fsdev_notify_reply_cb, &reply_ctx);
	CU_ASSERT(rc == 0);

	memset(&notify_data, 0, sizeof(notify_data));
	notify_data.inval_data.fobject = (struct spdk_fsdev_file_object *)&file_object;
	notify_data.inval_data.offset = 4096;
	notify_data.inval_data.size = 8192;
	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_notify_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == fsdev);
	CU_ASSERT(ut_calls_param_get_ptr(0, 1) == &notify_ctx);
	CU_ASSERT(ut_calls_param_get_int(0, 2) == SPDK_FSDEV_NOTIFY_INVAL_DATA);
	CU_ASSERT(ut_calls_param_get_hash(0, 3) == ut_hash(&notify_data.inval_data,
			sizeof(notify_data.inval_data)));
	CU_ASSERT(ut_calls_param_get_ptr(0, 4) == ut_fsdev_notify_reply_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 5) == &reply_ctx);

	/* SPDK_FSDEV_EVENT_NOTIFY_INVAL_ENTRY */
	ut_calls_reset();
	rc = spdk_fsdev_notify_inval_entry(&utfsdev->fsdev,
					   (struct spdk_fsdev_file_object *)&parent_file_object,
					   filename, ut_fsdev_notify_reply_cb, &reply_ctx);
	CU_ASSERT(rc == 0);

	memset(&notify_data, 0, sizeof(notify_data));
	notify_data.inval_entry.parent_fobject = (struct spdk_fsdev_file_object *)&parent_file_object;
	notify_data.inval_entry.name = filename;
	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_notify_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == fsdev);
	CU_ASSERT(ut_calls_param_get_ptr(0, 1) == &notify_ctx);
	CU_ASSERT(ut_calls_param_get_int(0, 2) == SPDK_FSDEV_NOTIFY_INVAL_ENTRY);
	CU_ASSERT(ut_calls_param_get_hash(0, 3) == ut_hash(&notify_data.inval_entry,
			sizeof(notify_data.inval_entry)));
	CU_ASSERT(ut_calls_param_get_ptr(0, 4) == ut_fsdev_notify_reply_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 5) == &reply_ctx);

	memset(&stat, 0, sizeof(stat));
	spdk_fsdev_get_device_stat(&utfsdev->fsdev, &stat, ut_fsdev_device_stat_cb, NULL);
	poll_threads();
	CU_ASSERT(stat.num_notifies[SPDK_FSDEV_NOTIFY_INVAL_DATA] == 1);
	CU_ASSERT(stat.num_notifies[SPDK_FSDEV_NOTIFY_INVAL_ENTRY] == 1);

	/* Disable notifications */
	ut_calls_reset();
	rc = spdk_fsdev_disable_notifications(fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_set_notifications);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == utfsdev);
	CU_ASSERT(ut_calls_param_get_int(0, 1) == false);

	/* Disable notifications twice should fail */
	rc = spdk_fsdev_disable_notifications(fsdev_desc);
	CU_ASSERT(rc == -EALREADY);

	spdk_fsdev_close(fsdev_desc);
	ut_fsdev_destroy(utfsdev);
}

typedef int (*execute_clb)(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status);
typedef void (*check_clb)(void);

static void
ut_fsdev_test_io(enum spdk_fsdev_io_type type, int desired_io_status, size_t num_priv_params,
		 execute_clb execute_cb, check_clb check_cb)
{
	struct ut_fsdev *utfsdev;
	struct spdk_io_channel *ch;
	struct spdk_fsdev_desc *fsdev_desc;
	int rc;
	int status = -1;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);

	ch = spdk_fsdev_get_io_channel(fsdev_desc);
	CU_ASSERT(ch != NULL);

	ut_calls_reset();
	utfsdev->desired_io_status = desired_io_status;
	rc = execute_cb(utfsdev, ch, fsdev_desc, &status);
	CU_ASSERT(rc == 0);

	poll_thread(0);
	CU_ASSERT(status == desired_io_status);
	CU_ASSERT(ut_calls_get_call_count() == 1);
	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_submit_request);
	CU_ASSERT(ut_calls_get_param_count(0) == UT_SUBMIT_IO_NUM_COMMON_PARAMS + num_priv_params);

	/* Common params */
	CU_ASSERT(ut_calls_param_get_int(0, 0) == type);
	CU_ASSERT(ut_calls_param_get_int(0, 1) == UT_UNIQUE);
	CU_ASSERT(ut_calls_param_get_ptr(0, 2) == g_ut_io_channel);
	CU_ASSERT(ut_calls_param_get_ptr(0, 3) == utfsdev);

	SPDK_CU_ASSERT_FATAL(UT_SUBMIT_IO_NUM_COMMON_PARAMS == 4);

	/* Op-specific params */
	check_cb();

	ut_calls_reset();
	spdk_put_io_channel(ch);
	poll_thread(0);

	spdk_fsdev_close(fsdev_desc);

	ut_fsdev_destroy(utfsdev);
}

static void
ut_fsdev_mount_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      const struct spdk_fsdev_mount_opts *opts, struct spdk_fsdev_file_object *root_fobject)

{
	int *clb_status = cb_arg;
	bool has_writeback_cache;
	bool ut_writeback_cache;
	*clb_status = status;
	if (!status) {
		CU_ASSERT(root_fobject == UT_FOBJECT);
		CU_ASSERT(opts != NULL);
		CU_ASSERT(opts->opts_size == ut_mount_opts.opts_size);
		CU_ASSERT(opts->max_xfer_size == ut_mount_opts.max_xfer_size / 2);
		has_writeback_cache = !!(opts->flags && SPDK_FSDEV_MOUNT_WRITEBACK_CACHE);
		ut_writeback_cache = !!(ut_mount_opts.flags && SPDK_FSDEV_MOUNT_WRITEBACK_CACHE);
		CU_ASSERT(has_writeback_cache == !ut_writeback_cache);
	}
}

static int
ut_fsdev_mount_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_mount_opts, 0, sizeof(ut_mount_opts));
	ut_mount_opts.opts_size = sizeof(ut_mount_opts);
	ut_mount_opts.max_xfer_size = UINT32_MAX;
	ut_mount_opts.flags = SPDK_FSDEV_MOUNT_WRITEBACK_CACHE;

	return spdk_fsdev_mount(fsdev_desc, ch, UT_UNIQUE, &ut_mount_opts, ut_fsdev_mount_cpl_cb, status);
}

static void
ut_fsdev_mount_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_hash(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) ==
		  ut_hash(&ut_mount_opts, sizeof(ut_mount_opts)));
}

static void
ut_fsdev_test_mount_ok(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_MOUNT, 0, 1, ut_fsdev_mount_execute_clb,
			 ut_fsdev_mount_check_clb);
}

static void
ut_fsdev_test_mount_err(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_MOUNT, -EINVAL, 1, ut_fsdev_mount_execute_clb,
			 ut_fsdev_mount_check_clb);
}

static void
ut_fsdev_umount_cpl_cb(void *cb_arg, struct spdk_io_channel *ch)
{
	int *clb_status = cb_arg;
	*clb_status = 0; /* the callback doesn't get status, so we just zero it here */
}

static int
ut_fsdev_umount_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_umount(fsdev_desc, ch, UT_UNIQUE, ut_fsdev_umount_cpl_cb, status);
}

static void
ut_fsdev_umount_check_clb(void)
{
	/* Nothing to check here */
}

static void
ut_fsdev_test_umount(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_UMOUNT, 0, 0, ut_fsdev_umount_execute_clb,
			 ut_fsdev_umount_check_clb);
}

static void
ut_fsdev_lookup_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		       struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	int *clb_status = cb_arg;
	*clb_status = status;
	if (!status) {
		CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
		CU_ASSERT(&ut_fsdev_fobject == fobject);
	}
}

static int
ut_fsdev_lookup_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_lookup(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FNAME,
				 ut_fsdev_lookup_cpl_cb,
				 status);
}

static void
ut_fsdev_lookup_check_clb(void)
{
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS), UT_FNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FOBJECT);
}

static void
ut_fsdev_test_lookup_ok(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_LOOKUP, 0, 2, ut_fsdev_lookup_execute_clb,
			 ut_fsdev_lookup_check_clb);
}

static void
ut_fsdev_test_lookup_err(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_LOOKUP, -EBUSY, 2, ut_fsdev_lookup_execute_clb,
			 ut_fsdev_lookup_check_clb);
}

static void
ut_fsdev_forget_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_forget_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_forget(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_NUM_LOOKUPS,
				 ut_fsdev_forget_cpl_cb, status);
}

static void
ut_fsdev_forget_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_NUM_LOOKUPS);
}

static void
ut_fsdev_test_forget(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_FORGET, 0, 2, ut_fsdev_forget_execute_clb,
			 ut_fsdev_forget_check_clb);
}

static void
ut_fsdev_getattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			const struct spdk_fsdev_file_attr *attr)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_getattr_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_getattr(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				  ut_fsdev_getattr_cpl_cb, status);
}

static void
ut_fsdev_getattr_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
}

static void
ut_fsdev_test_getattr(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_GETATTR, 0, 2, ut_fsdev_getattr_execute_clb,
			 ut_fsdev_getattr_check_clb);
}

static void
ut_fsdev_setattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			const struct spdk_fsdev_file_attr *attr)
{
	int *clb_status = cb_arg;
	CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
	*clb_status = status;
}

static int
ut_fsdev_setattr_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_fsdev_attr, rand(), sizeof(ut_fsdev_attr));
	return spdk_fsdev_setattr(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				  &ut_fsdev_attr, 0x11111111, ut_fsdev_setattr_cpl_cb, status);
}

static void
ut_fsdev_setattr_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_hash(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) ==
		  ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 0x11111111);
}

static void
ut_fsdev_test_setattr(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_SETATTR, 0, 4, ut_fsdev_setattr_execute_clb,
			 ut_fsdev_setattr_check_clb);
}

static void
ut_fsdev_readlink_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			 const char *linkname)
{
	int *clb_status = cb_arg;
	CU_ASSERT(!strcmp(linkname, UT_FNAME));
	*clb_status = status;
}

static int
ut_fsdev_readlink_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			      struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_readlink(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, ut_fsdev_readlink_cpl_cb,
				   status);
}

static void
ut_fsdev_readlink_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
}

static void
ut_fsdev_test_readlink(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_READLINK, 0, 1, ut_fsdev_readlink_execute_clb,
			 ut_fsdev_readlink_check_clb);
}

static void
ut_fsdev_symlink_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	int *clb_status = cb_arg;
	CU_ASSERT(fobject == UT_FOBJECT + 1);
	CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
	*clb_status = status;
}

static int
ut_fsdev_symlink_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_fsdev_attr, rand(), sizeof(ut_fsdev_attr));
	return spdk_fsdev_symlink(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FNAME, UT_LNAME, 100, 200,
				  ut_fsdev_symlink_cpl_cb, status);
}

static void
ut_fsdev_symlink_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_FNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2), UT_LNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 100);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 200);
}

static void
ut_fsdev_test_symlink(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_SYMLINK, 0, 5, ut_fsdev_symlink_execute_clb,
			 ut_fsdev_symlink_check_clb);
}

static void
ut_fsdev_mknod_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	int *clb_status = cb_arg;
	CU_ASSERT(fobject == UT_FOBJECT + 1);
	CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
	*clb_status = status;
}

static int
ut_fsdev_mknod_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_fsdev_attr, rand(), sizeof(ut_fsdev_attr));
	return spdk_fsdev_mknod(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FNAME, 0x1111, 50,
				0022, 100, 200, ut_fsdev_mknod_cpl_cb, status);
}

static void
ut_fsdev_mknod_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_FNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 0x1111);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 50);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 0022);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 5) == 100);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 6) == 200);
}

static void
ut_fsdev_test_mknod(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_MKNOD, 0, 7, ut_fsdev_mknod_execute_clb,
			 ut_fsdev_mknod_check_clb);
}

static void
ut_fsdev_mkdir_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	int *clb_status = cb_arg;
	CU_ASSERT(fobject == UT_FOBJECT + 1);
	CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
	*clb_status = status;
}

static int
ut_fsdev_mkdir_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_fsdev_attr, rand(), sizeof(ut_fsdev_attr));
	return spdk_fsdev_mkdir(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FNAME, 0x1111,
				0022, 100, 200, ut_fsdev_mkdir_cpl_cb, status);
}

static void
ut_fsdev_mkdir_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_FNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 0x1111);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 0022);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 100);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 5) == 200);
}

static void
ut_fsdev_test_mkdir(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_MKDIR, 0, 6, ut_fsdev_mkdir_execute_clb,
			 ut_fsdev_mkdir_check_clb);
}

static void
ut_fsdev_unlink_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_unlink_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_unlink(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FNAME,
				 ut_fsdev_unlink_cpl_cb, status);
}

static void
ut_fsdev_unlink_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_FNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
}

static void
ut_fsdev_test_unlink(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_UNLINK, 0, 2, ut_fsdev_unlink_execute_clb,
			 ut_fsdev_unlink_check_clb);
}

static void
ut_fsdev_rmdir_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_rmdir_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_rmdir(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FNAME,
				ut_fsdev_rmdir_cpl_cb, status);
}

static void
ut_fsdev_rmdir_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_FNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
}

static void
ut_fsdev_test_rmdir(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_RMDIR, 0, 2, ut_fsdev_rmdir_execute_clb,
			 ut_fsdev_rmdir_check_clb);
}

static void
ut_fsdev_rename_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_rename_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_rename(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FNAME, UT_FOBJECT + 2,
				 UT_LNAME, 0xFFFF, ut_fsdev_rename_cpl_cb, status);
}

static void
ut_fsdev_rename_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_FNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == UT_FOBJECT + 2);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3), UT_LNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 0xFFFF);
}

static void
ut_fsdev_test_rename(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_RENAME, 0, 5, ut_fsdev_rename_execute_clb,
			 ut_fsdev_rename_check_clb);
}

static void
ut_fsdev_link_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		     struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr)
{
	int *clb_status = cb_arg;
	CU_ASSERT(fobject == UT_FOBJECT + 1);
	CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
	*clb_status = status;
}

static int
ut_fsdev_link_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			  struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_link(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FOBJECT + 2, UT_LNAME,
			       ut_fsdev_link_cpl_cb, status);
}

static void
ut_fsdev_link_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FOBJECT + 2);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2), UT_LNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
}

static void
ut_fsdev_test_link(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_LINK, 0, 3, ut_fsdev_link_execute_clb,
			 ut_fsdev_link_check_clb);
}

static void
ut_fsdev_fopen_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      struct spdk_fsdev_file_handle *fhandle)
{
	int *clb_status = cb_arg;
	CU_ASSERT(fhandle == UT_FHANDLE);
	*clb_status = status;
}

static int
ut_fsdev_fopen_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_fopen(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, 0xFEAD,
				ut_fsdev_fopen_cpl_cb, status);
}

static void
ut_fsdev_fopen_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == 0xFEAD);
}

static void
ut_fsdev_test_fopen(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_OPEN, 0, 2, ut_fsdev_fopen_execute_clb,
			 ut_fsdev_fopen_check_clb);
}

static void
ut_fsdev_read_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		     uint32_t data_size)
{
	int *clb_status = cb_arg;
	CU_ASSERT(data_size == UT_DATA_SIZE);
	*clb_status = status;
}

static int
ut_fsdev_read_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			  struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_iov, rand(), sizeof(ut_iov));
	return spdk_fsdev_read(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, 100, 200, 0x1111,
			       ut_iov, SPDK_COUNTOF(ut_iov), (struct spdk_fsdev_io_opts *)0xAAAAAAAA,
			       ut_fsdev_read_cpl_cb, status);
}

static void
ut_fsdev_read_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 100);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 200);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 0x1111);
	CU_ASSERT(ut_calls_param_get_hash(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 5) == ut_hash(ut_iov,
			sizeof(ut_iov)));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 6) == SPDK_COUNTOF(ut_iov));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 7) == 0xAAAAAAAA);
}

static void
ut_fsdev_test_read(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_READ, 0, 8, ut_fsdev_read_execute_clb,
			 ut_fsdev_read_check_clb);
}

static void
ut_fsdev_write_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      uint32_t data_size)
{
	int *clb_status = cb_arg;
	CU_ASSERT(data_size == UT_DATA_SIZE);
	*clb_status = status;
}

static int
ut_fsdev_write_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_iov, rand(), sizeof(ut_iov));
	return spdk_fsdev_write(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, 100, 200, 0x1111,
				ut_iov, SPDK_COUNTOF(ut_iov), (struct spdk_fsdev_io_opts *)0xAAAAAAAA,
				ut_fsdev_write_cpl_cb, status);
}

static void
ut_fsdev_write_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 100);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 200);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 0x1111);
	CU_ASSERT(ut_calls_param_get_hash(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 5) ==
		  ut_hash(ut_iov, sizeof(ut_iov)));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 6) == SPDK_COUNTOF(ut_iov));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 7) == 0xAAAAAAAA);
}

static void
ut_fsdev_test_write(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_WRITE, 0, 8, ut_fsdev_write_execute_clb,
			 ut_fsdev_write_check_clb);
}

static void
ut_fsdev_statfs_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		       const struct spdk_fsdev_file_statfs *statfs)
{
	int *clb_status = cb_arg;
	CU_ASSERT(ut_hash(&ut_statfs, sizeof(ut_statfs)) == ut_hash(statfs, sizeof(*statfs)));
	*clb_status = status;
}

static int
ut_fsdev_statfs_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_statfs, rand(), sizeof(ut_statfs));
	return spdk_fsdev_statfs(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT,
				 ut_fsdev_statfs_cpl_cb, status);
}

static void
ut_fsdev_statfs_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
}

static void
ut_fsdev_test_statfs(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_STATFS, 0, 1, ut_fsdev_statfs_execute_clb,
			 ut_fsdev_statfs_check_clb);
}

static void
ut_fsdev_release_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_release_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_release(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				  ut_fsdev_release_cpl_cb, status);
}

static void
ut_fsdev_release_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
}

static void
ut_fsdev_test_release(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_RELEASE, 0, 2, ut_fsdev_release_execute_clb,
			 ut_fsdev_release_check_clb);
}

static void
ut_fsdev_fsync_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_fsync_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_fsync(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, false,
				ut_fsdev_fsync_cpl_cb, status);
}

static void
ut_fsdev_fsync_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == false);
}

static void
ut_fsdev_test_fsync(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_FSYNC, 0, 3, ut_fsdev_fsync_execute_clb,
			 ut_fsdev_fsync_check_clb);
}

static void
ut_fsdev_getxattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			 size_t value_size)
{
	int *clb_status = cb_arg;
	CU_ASSERT(value_size == sizeof(UT_AVALUE));
	CU_ASSERT(!strcmp(ut_buff, UT_AVALUE));
	*clb_status = status;
}

static int
ut_fsdev_getxattr_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			      struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(ut_buff, 0, sizeof(ut_buff));
	return spdk_fsdev_getxattr(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_ANAME, ut_buff,
				   sizeof(ut_buff), ut_fsdev_getxattr_cpl_cb, status);
}

static void
ut_fsdev_getxattr_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_ANAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == ut_buff);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == sizeof(ut_buff));
}

static void
ut_fsdev_test_getxattr(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_GETXATTR, 0, 4, ut_fsdev_getxattr_execute_clb,
			 ut_fsdev_getxattr_check_clb);
}

static void
ut_fsdev_setxattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_setxattr_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			      struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_setxattr(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_ANAME, UT_AVALUE,
				   sizeof(UT_AVALUE), 0xFF, ut_fsdev_setxattr_cpl_cb, status);
}

static void
ut_fsdev_setxattr_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_ANAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2), UT_AVALUE,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == sizeof(UT_AVALUE));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 0xFF);
}

static void
ut_fsdev_test_setxattr(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_SETXATTR, 0, 5, ut_fsdev_setxattr_execute_clb,
			 ut_fsdev_setxattr_check_clb);
}

static void
ut_fsdev_listxattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status, size_t size,
			  bool size_only)
{
	int *clb_status = cb_arg;
	if (ut_listxattr_size_only) {
		CU_ASSERT(size_only);
		CU_ASSERT(size == (sizeof(ut_buff) / sizeof(UT_ANAME)) * sizeof(UT_ANAME));
	} else {
		char *p = ut_buff;

		CU_ASSERT(!size_only);
		CU_ASSERT(size != 0);

		for (; p + sizeof(UT_ANAME) <= ut_buff + size; p += sizeof(UT_ANAME)) {
			CU_ASSERT(!strcmp(p, UT_ANAME));
		}

		CU_ASSERT(size + sizeof(UT_ANAME) > sizeof(ut_buff));
	}
	*clb_status = status;
}

static int
ut_fsdev_listxattr_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			       struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_listxattr(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT,
				    ut_listxattr_size_only ? NULL : ut_buff, ut_listxattr_size_only ? 0 : sizeof(ut_buff),
				    ut_fsdev_listxattr_cpl_cb, status);
}

static void
ut_fsdev_listxattr_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	if (ut_listxattr_size_only) {
		CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == NULL);
		CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 0);
	} else {
		CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == ut_buff);
		CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == sizeof(ut_buff));
	}
}

static void
ut_fsdev_test_listxattr(void)
{
	ut_listxattr_size_only = false;
	ut_fsdev_test_io(SPDK_FSDEV_IO_LISTXATTR, 0, 3, ut_fsdev_listxattr_execute_clb,
			 ut_fsdev_listxattr_check_clb);
}

static void
ut_fsdev_test_listxattr_get_size(void)
{
	ut_listxattr_size_only = true;
	ut_fsdev_test_io(SPDK_FSDEV_IO_LISTXATTR, 0, 3, ut_fsdev_listxattr_execute_clb,
			 ut_fsdev_listxattr_check_clb);
}

static void
ut_fsdev_removexattr_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_removexattr_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
				 struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_removexattr(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_ANAME,
				      ut_fsdev_removexattr_cpl_cb, status);
}

static void
ut_fsdev_removexattr_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_ANAME,
			   UT_CALL_REC_MAX_STR_SIZE));
}

static void
ut_fsdev_test_removexattr(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_REMOVEXATTR, 0, 2, ut_fsdev_removexattr_execute_clb,
			 ut_fsdev_removexattr_check_clb);
}

static void
ut_fsdev_flush_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_flush_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_flush(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				ut_fsdev_flush_cpl_cb, status);
}

static void
ut_fsdev_flush_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
}

static void
ut_fsdev_test_flush(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_FLUSH, 0, 2, ut_fsdev_flush_execute_clb,
			 ut_fsdev_flush_check_clb);
}

static void
ut_fsdev_opendir_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
			struct spdk_fsdev_file_handle *fhandle)
{
	int *clb_status = cb_arg;
	CU_ASSERT(fhandle == UT_FHANDLE);
	*clb_status = status;
}

static int
ut_fsdev_opendir_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_opendir(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, 0x1111,
				  ut_fsdev_opendir_cpl_cb, status);
}

static void
ut_fsdev_opendir_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == 0x1111);
}

static void
ut_fsdev_test_opendir(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_OPENDIR, 0, 2, ut_fsdev_opendir_execute_clb,
			 ut_fsdev_opendir_check_clb);
}

static int
ut_fsdev_readdir_entry_cb(void *cb_arg, struct spdk_io_channel *ch, const char *name,
			  struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
			  off_t offset, bool *forget)
{
	CU_ASSERT(!strcmp(name, UT_FNAME));
	CU_ASSERT(fobject == UT_FOBJECT + ut_readdir_num_entry_cb_calls);
	CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
	CU_ASSERT(offset == (off_t)(ut_readdir_offset + ut_readdir_num_entry_cb_calls));
	CU_ASSERT(forget != NULL);
	CU_ASSERT(*forget == false);

	ut_readdir_num_entry_cb_calls++;
	return (ut_readdir_num_entry_cb_calls == ut_readdir_num_entries) ? -1 : 0;
}

static void
ut_fsdev_readdir_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_readdir_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	ut_readdir_num_entries = 20;
	ut_readdir_num_entry_cb_calls = 0;
	ut_readdir_offset = (uint64_t)rand();
	memset(&ut_fsdev_attr, rand(), sizeof(ut_fsdev_attr));
	return spdk_fsdev_readdir(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, 10000,
				  ut_fsdev_readdir_entry_cb, ut_fsdev_readdir_cpl_cb, status);
}

static void
ut_fsdev_readdir_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 10000);
	CU_ASSERT(ut_calls_param_get_ptr(0,
					 UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == ut_fsdev_readdir_entry_cb);
	CU_ASSERT(ut_readdir_num_entry_cb_calls == ut_readdir_num_entries);
}

static void
ut_fsdev_test_readdir(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_READDIR, 0, 4, ut_fsdev_readdir_execute_clb,
			 ut_fsdev_readdir_check_clb);
}

static void
ut_fsdev_releasedir_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_releasedir_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
				struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_releasedir(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				     ut_fsdev_releasedir_cpl_cb, status);
}

static void
ut_fsdev_releasedir_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
}

static void
ut_fsdev_test_releasedir(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_RELEASEDIR, 0, 2, ut_fsdev_releasedir_execute_clb,
			 ut_fsdev_releasedir_check_clb);
}

static void
ut_fsdev_fsyncdir_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_fsyncdir_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			      struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_fsyncdir(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, true,
				   ut_fsdev_fsyncdir_cpl_cb, status);
}

static void
ut_fsdev_fsyncdir_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == true);
}

static void
ut_fsdev_test_fsyncdir(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_FSYNCDIR, 0, 3, ut_fsdev_fsyncdir_execute_clb,
			 ut_fsdev_fsyncdir_check_clb);
}

static void
ut_fsdev_syncfs_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_syncfs_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_syncfs(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT,
				 ut_fsdev_syncfs_cpl_cb, status);
}

static void
ut_fsdev_syncfs_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 0) == UT_FOBJECT);
}

static void
ut_fsdev_test_syncfs(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_SYNCFS, 0, 1, ut_fsdev_syncfs_execute_clb,
			 ut_fsdev_syncfs_check_clb);
}

static void
ut_fsdev_access_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		       uint32_t mask, uid_t uid, uid_t gid)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_access_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_access(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT,
				 F_OK | R_OK, 42, 43, ut_fsdev_access_cpl_cb, status);
}

static void
ut_fsdev_access_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 0) == UT_FOBJECT);
	int mask = (int)ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1);
	CU_ASSERT(mask >= F_OK && mask <= (F_OK | R_OK | W_OK | X_OK));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 42);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 43);
}

static void
ut_fsdev_test_access(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_ACCESS, 0, 4, ut_fsdev_access_execute_clb,
			 ut_fsdev_access_check_clb);
}

static void
ut_fsdev_lseek_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      off_t offset, enum spdk_fsdev_seek_whence whence)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_lseek_execute_op_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			      struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_lseek(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				4096, SPDK_FSDEV_SEEK_SET, ut_fsdev_lseek_cpl_cb, status);
}

static void
ut_fsdev_lseek_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 0) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	off_t offset = (off_t)ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2);
	enum spdk_fsdev_seek_whence whence = ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3);
	CU_ASSERT(offset >= 0 && offset != (off_t) -1);
	CU_ASSERT(whence >= SPDK_FSDEV_SEEK_SET && whence <= SPDK_FSDEV_SEEK_DATA);
}

static void
ut_fsdev_test_lseek(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_LSEEK, 0, 4, ut_fsdev_lseek_execute_op_clb,
			 ut_fsdev_lseek_check_clb);
}

static void
ut_fsdev_poll_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		     uint32_t reevents)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_poll_execute_op_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_poll(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
			       SPDK_FSDEV_POLLIN, false, ut_fsdev_poll_cpl_cb, status);
}

static void
ut_fsdev_poll_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 0) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == SPDK_FSDEV_POLLIN);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == false);
}

static void
ut_fsdev_test_poll(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_POLL, 0, 4, ut_fsdev_poll_execute_op_clb,
			 ut_fsdev_poll_check_clb);
}

static void
ut_fsdev_ioctl_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      int32_t result, struct iovec *in_iov, uint32_t in_iovcnt,
		      struct iovec *out_iov, uint32_t out_iovcnt)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_ioctl_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_ioctl(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				UT_IOCTL_CMD, UT_IOCTL_ARG,
				UT_IOCTL_IN_IOV, UT_IOCTL_IN_IOVCNT,
				UT_IOCTL_OUT_IOV, UT_IOCTL_OUT_IOVCNT,
				ut_fsdev_ioctl_cpl_cb, status);
}

static void
ut_fsdev_ioctl_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 0) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == UT_IOCTL_CMD);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == UT_IOCTL_ARG);

	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == UT_IOCTL_IN_IOV);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 5) == UT_IOCTL_IN_IOVCNT);

	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 6) == UT_IOCTL_OUT_IOV);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 7) == UT_IOCTL_OUT_IOVCNT);
}

static void
ut_fsdev_test_ioctl(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_IOCTL, 0, 8, ut_fsdev_ioctl_execute_clb,
			 ut_fsdev_ioctl_check_clb);
}

static void
ut_fsdev_flock_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_flock_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_flock(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, 111,
				ut_fsdev_flock_cpl_cb, status);
}

static void
ut_fsdev_flock_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 111);
}

static void
ut_fsdev_test_flock(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_FLOCK, 0, 3, ut_fsdev_flock_execute_clb,
			 ut_fsdev_flock_check_clb);
}

static void
ut_fsdev_create_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		       struct spdk_fsdev_file_object *fobject, const struct spdk_fsdev_file_attr *attr,
		       struct spdk_fsdev_file_handle *fhandle)
{
	int *clb_status = cb_arg;
	CU_ASSERT(fobject == UT_FOBJECT + 1);
	CU_ASSERT(fhandle == UT_FHANDLE);
	CU_ASSERT(ut_hash(&ut_fsdev_attr, sizeof(ut_fsdev_attr)) == ut_hash(attr, sizeof(*attr)));
	*clb_status = status;
}

static int
ut_fsdev_create_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			    struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	memset(&ut_fsdev_attr, rand(), sizeof(ut_fsdev_attr));
	return spdk_fsdev_create(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_LNAME, 100, 0x2222, 0x666,
				 200, 300, ut_fsdev_create_cpl_cb, status);
}

static void
ut_fsdev_create_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1), UT_LNAME,
			   UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 100);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 0x2222);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 0x666);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 5) == 200);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 6) == 300);
}

static void
ut_fsdev_test_create(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_CREATE, 0, 7, ut_fsdev_create_execute_clb,
			 ut_fsdev_create_check_clb);
}

static void
ut_fsdev_abort_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_abort_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_abort(fsdev_desc, ch, UT_UNIQUE,
				ut_fsdev_abort_cpl_cb, status);
}

static void
ut_fsdev_abort_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_UNIQUE);
}

static void
ut_fsdev_test_abort(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_ABORT, 0, 1, ut_fsdev_abort_execute_clb,
			 ut_fsdev_abort_check_clb);
}

static void
ut_fsdev_fallocate_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_fallocate_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			       struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_fallocate(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, 0x1111, 2000,
				    1002, ut_fsdev_fallocate_cpl_cb, status);
}

static void
ut_fsdev_fallocate_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 0x1111);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 2000);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == 1002);
}

static void
ut_fsdev_test_fallocate(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_FALLOCATE, 0, 5, ut_fsdev_fallocate_execute_clb,
			 ut_fsdev_fallocate_check_clb);
}

static void
ut_fsdev_copy_file_range_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
				uint32_t data_size)
{
	int *clb_status = cb_arg;
	CU_ASSERT(data_size == UT_DATA_SIZE);
	*clb_status = status;
}

static int
ut_fsdev_copy_file_range_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
				     struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_copy_file_range(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE, 1000,
					  UT_FOBJECT + 2, UT_FHANDLE + 2, 3000, 50000, 0x77777777,
					  ut_fsdev_copy_file_range_cpl_cb, status);
}

static void
ut_fsdev_copy_file_range_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 1000);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == UT_FOBJECT + 2);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 4) == UT_FHANDLE + 2);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 5) == 3000);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 6) == 50000);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 7) == 0x77777777);
}

static void
ut_fsdev_test_copy_file_range(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_COPY_FILE_RANGE, 0, 8, ut_fsdev_copy_file_range_execute_clb,
			 ut_fsdev_copy_file_range_check_clb);
}

static void
ut_fsdev_getlk_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status,
		      const struct spdk_fsdev_file_lock *lock)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_getlk_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_getlk(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				&ut_fsdev_lock, 42, ut_fsdev_getlk_cpl_cb, status);
}

static void
ut_fsdev_getlk_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 0) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_hash(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) ==
		  ut_hash(&ut_fsdev_lock, sizeof(ut_fsdev_lock)));
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == 42);
}

static void
ut_fsdev_test_getlk(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_GETLK, 0, 4, ut_fsdev_getlk_execute_clb,
			 ut_fsdev_getlk_check_clb);
}

static void
ut_fsdev_setlk_cpl_cb(void *cb_arg, struct spdk_io_channel *ch, int status)
{
	int *clb_status = cb_arg;
	*clb_status = status;
}

static int
ut_fsdev_setlk_execute_clb(struct ut_fsdev *utfsdev, struct spdk_io_channel *ch,
			   struct spdk_fsdev_desc *fsdev_desc, int *status)
{
	return spdk_fsdev_setlk(fsdev_desc, ch, UT_UNIQUE, UT_FOBJECT, UT_FHANDLE,
				&ut_fsdev_lock, 42, true, ut_fsdev_setlk_cpl_cb, status);
}

static void
ut_fsdev_setlk_check_clb(void)
{
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 0) == UT_FOBJECT);
	CU_ASSERT(ut_calls_param_get_ptr(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 1) == UT_FHANDLE);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 2) == 42);
	CU_ASSERT(ut_calls_param_get_int(0, UT_SUBMIT_IO_NUM_COMMON_PARAMS + 3) == true);
}

static void
ut_fsdev_test_setlk(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_SETLK, 0, 4, ut_fsdev_setlk_execute_clb,
			 ut_fsdev_setlk_check_clb);
}

static int
fsdev_ut(int argc, char **argv)
{
	CU_pSuite		suite = NULL;
	unsigned int		num_failures;

	suite = CU_add_suite("fsdev", ut_fsdev_setup, ut_fsdev_teardown);

	CU_ADD_TEST(suite, ut_fsdev_test_open_close);
	CU_ADD_TEST(suite, ut_fsdev_test_set_opts);
	CU_ADD_TEST(suite, ut_fsdev_test_get_io_channel);
	CU_ADD_TEST(suite, ut_fsdev_test_reset_module_reset_succeeds);
	CU_ADD_TEST(suite, ut_fsdev_test_reset_module_reset_leaks_io);
	CU_ADD_TEST(suite, ut_fsdev_test_reset_module_reset_fails);
	CU_ADD_TEST(suite, ut_fsdev_test_notifications);
	CU_ADD_TEST(suite, ut_fsdev_test_mount_ok);
	CU_ADD_TEST(suite, ut_fsdev_test_mount_err);
	CU_ADD_TEST(suite, ut_fsdev_test_umount);
	CU_ADD_TEST(suite, ut_fsdev_test_lookup_ok);
	CU_ADD_TEST(suite, ut_fsdev_test_lookup_err);
	CU_ADD_TEST(suite, ut_fsdev_test_forget);
	CU_ADD_TEST(suite, ut_fsdev_test_getattr);
	CU_ADD_TEST(suite, ut_fsdev_test_setattr);
	CU_ADD_TEST(suite, ut_fsdev_test_readlink);
	CU_ADD_TEST(suite, ut_fsdev_test_symlink);
	CU_ADD_TEST(suite, ut_fsdev_test_mknod);
	CU_ADD_TEST(suite, ut_fsdev_test_mkdir);
	CU_ADD_TEST(suite, ut_fsdev_test_unlink);
	CU_ADD_TEST(suite, ut_fsdev_test_rmdir);
	CU_ADD_TEST(suite, ut_fsdev_test_rename);
	CU_ADD_TEST(suite, ut_fsdev_test_link);
	CU_ADD_TEST(suite, ut_fsdev_test_fopen);
	CU_ADD_TEST(suite, ut_fsdev_test_read);
	CU_ADD_TEST(suite, ut_fsdev_test_write);
	CU_ADD_TEST(suite, ut_fsdev_test_statfs);
	CU_ADD_TEST(suite, ut_fsdev_test_release);
	CU_ADD_TEST(suite, ut_fsdev_test_fsync);
	CU_ADD_TEST(suite, ut_fsdev_test_getxattr);
	CU_ADD_TEST(suite, ut_fsdev_test_setxattr);
	CU_ADD_TEST(suite, ut_fsdev_test_listxattr);
	CU_ADD_TEST(suite, ut_fsdev_test_listxattr_get_size);
	CU_ADD_TEST(suite, ut_fsdev_test_removexattr);
	CU_ADD_TEST(suite, ut_fsdev_test_flush);
	CU_ADD_TEST(suite, ut_fsdev_test_opendir);
	CU_ADD_TEST(suite, ut_fsdev_test_readdir);
	CU_ADD_TEST(suite, ut_fsdev_test_releasedir);
	CU_ADD_TEST(suite, ut_fsdev_test_fsyncdir);
	CU_ADD_TEST(suite, ut_fsdev_test_flock);
	CU_ADD_TEST(suite, ut_fsdev_test_create);
	CU_ADD_TEST(suite, ut_fsdev_test_abort);
	CU_ADD_TEST(suite, ut_fsdev_test_fallocate);
	CU_ADD_TEST(suite, ut_fsdev_test_copy_file_range);
	CU_ADD_TEST(suite, ut_fsdev_test_syncfs);
	CU_ADD_TEST(suite, ut_fsdev_test_access);
	CU_ADD_TEST(suite, ut_fsdev_test_lseek);
	CU_ADD_TEST(suite, ut_fsdev_test_poll);
	CU_ADD_TEST(suite, ut_fsdev_test_ioctl);
	CU_ADD_TEST(suite, ut_fsdev_test_getlk);
	CU_ADD_TEST(suite, ut_fsdev_test_setlk);

	allocate_cores(1);
	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	poll_thread(0);

	free_threads();
	free_cores();

	return num_failures;
}

static int
fsdev_mt_ut(int argc, char **argv)
{
	CU_pSuite		suite = NULL;
	unsigned int		num_failures;

	suite = CU_add_suite("fsdev_mt", ut_fsdev_setup, ut_fsdev_teardown);

	CU_ADD_TEST(suite, ut_fsdev_test_for_each_channel_ok);
	CU_ADD_TEST(suite, ut_fsdev_test_for_each_channel_err);

	allocate_cores(UT_NUM_THREADS);
	allocate_threads(UT_NUM_THREADS);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	poll_threads();

	free_threads();
	free_cores();

	return num_failures;
}

int
main(int argc, char **argv)
{
	unsigned int		num_failures;

	CU_initialize_registry();

	num_failures = fsdev_ut(argc, argv) + fsdev_mt_ut(argc, argv);

	CU_cleanup_registry();
	return num_failures;
}
