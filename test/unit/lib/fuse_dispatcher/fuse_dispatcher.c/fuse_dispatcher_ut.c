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
#include "spdk/fuse_dispatcher.h"
#include "spdk/rmem.h"
#include "linux/fuse_kernel.h"

#define UT_UNIQUE 0xBEADBEAD
#define UT_FSDEV_NAME "utfsdev0"
#define UT_FOBJECT ((struct spdk_fsdev_file_object *)0xDEADDEAD)
#define UT_FHANDLE ((struct spdk_fsdev_file_handle *)0xBEABBEAB)
#define UT_FNAME "ut_test.file"

DEFINE_STUB_V(spdk_fsdev_close, (struct spdk_fsdev_desc *desc));
DEFINE_STUB(spdk_fsdev_desc_get_fsdev, struct spdk_fsdev *, (struct spdk_fsdev_desc *desc), NULL);
DEFINE_STUB(spdk_fsdev_get_opts, int, (struct spdk_fsdev_opts *opts, size_t opts_size), 0);
DEFINE_STUB(spdk_fsdev_reset, int, (struct spdk_fsdev_desc *desc, spdk_fsdev_reset_completion_cb cb,
				    void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_reset_supported, bool, (struct spdk_fsdev *fsdev), true);
DEFINE_STUB(spdk_fsdev_syncfs, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique, struct spdk_fsdev_file_object *fobject,
				     spdk_fsdev_syncfs_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_lookup, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique,
				     struct spdk_fsdev_file_object *parent_fobject, const char *name,
				     spdk_fsdev_lookup_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_access, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique, struct spdk_fsdev_file_object *fobject,
				     uint32_t mask, uid_t uid, uid_t gid, spdk_fsdev_access_cpl_cb cb_fn,
				     void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_forget, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique,
				     struct spdk_fsdev_file_object *fobject, uint64_t nlookup,
				     spdk_fsdev_forget_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_lseek, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique, struct spdk_fsdev_file_object *fobject,
				    struct spdk_fsdev_file_handle *fhandle, off_t offset,
				    enum spdk_fsdev_seek_whence whence, spdk_fsdev_lseek_cpl_cb cb_fn,
				    void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_poll, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				   uint64_t unique, struct spdk_fsdev_file_object *fobject,
				   struct spdk_fsdev_file_handle *fhandle, uint32_t events,
				   bool wait, spdk_fsdev_poll_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_readlink, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				       uint64_t unique, struct spdk_fsdev_file_object *fobject,
				       spdk_fsdev_readlink_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_ioctl, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique, struct spdk_fsdev_file_object *fobject,
				    struct spdk_fsdev_file_handle *fhandle, uint32_t request,
				    uint64_t arg, struct iovec *in_iov, uint32_t in_iovcnt,
				    struct iovec *out_iov, uint32_t out_iovcnt,
				    spdk_fsdev_ioctl_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_getlk, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique, struct spdk_fsdev_file_object *fobject,
				    struct spdk_fsdev_file_handle *fhandle,
				    const struct spdk_fsdev_file_lock *lock_to_check,
				    uint64_t owner, spdk_fsdev_getlk_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_setlk, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique, struct spdk_fsdev_file_object *fobject,
				    struct spdk_fsdev_file_handle *fhandle,
				    const struct spdk_fsdev_file_lock *lock_to_acquire,
				    uint64_t owner, bool wait, spdk_fsdev_setlk_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_symlink, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				      uint64_t unique,
				      struct spdk_fsdev_file_object *parent_fobject, const char *target,
				      const char *linkpath, uid_t euid, gid_t egid,
				      spdk_fsdev_symlink_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_mknod, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode, dev_t rdev,
				    uint32_t umask, uid_t euid, gid_t egid, spdk_fsdev_mknod_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_mkdir, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode,
				    uint32_t umask, uid_t euid, gid_t egid, spdk_fsdev_mkdir_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_unlink, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique,
				     struct spdk_fsdev_file_object *parent_fobject, const char *name,
				     spdk_fsdev_unlink_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_rmdir, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *parent_fobject, const char *name,
				    spdk_fsdev_rmdir_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_rename, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique,
				     struct spdk_fsdev_file_object *parent_fobject, const char *name,
				     struct spdk_fsdev_file_object *new_parent_fobject, const char *new_name,
				     uint32_t flags, spdk_fsdev_rename_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_link, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				   uint64_t unique,
				   struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_object *new_parent_fobject,
				   const char *name, spdk_fsdev_link_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_statfs, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique,
				     struct spdk_fsdev_file_object *fobject, spdk_fsdev_statfs_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_setxattr, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				       uint64_t unique, struct spdk_fsdev_file_object *fobject, const char *name, const char *value,
				       size_t size, uint64_t flags, spdk_fsdev_setxattr_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_getxattr, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				       uint64_t unique, struct spdk_fsdev_file_object *fobject, const char *name, void *buffer,
				       size_t size, spdk_fsdev_getxattr_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_listxattr, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
					uint64_t unique, struct spdk_fsdev_file_object *fobject, char *buffer, size_t size,
					spdk_fsdev_listxattr_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_removexattr, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		uint64_t unique, struct spdk_fsdev_file_object *fobject, const char *name,
		spdk_fsdev_removexattr_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_fopen, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *fobject, uint32_t flags, spdk_fsdev_fopen_cpl_cb cb_fn,
				    void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_create, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique,
				     struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode, uint32_t flags,
				     mode_t umask, uid_t euid, gid_t egid,
				     spdk_fsdev_create_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_release, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				      uint64_t unique,
				      struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				      spdk_fsdev_release_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_getattr, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				      uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				      spdk_fsdev_getattr_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_setattr, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				      uint64_t unique,
				      struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				      const struct spdk_fsdev_file_attr *attr, uint32_t to_set,
				      spdk_fsdev_setattr_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_read, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				   uint64_t unique,
				   struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				   size_t size, uint64_t offs, uint32_t flags,
				   struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_io_opts *opts,
				   spdk_fsdev_read_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_write, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle, size_t size,
				    uint64_t offs, uint64_t flags,
				    const struct iovec *iov, uint32_t iovcnt, struct spdk_fsdev_io_opts *opts,
				    spdk_fsdev_write_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_fsync, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle, bool datasync,
				    spdk_fsdev_fsync_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_flush, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				    spdk_fsdev_flush_cpl_cb cb_fn,
				    void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_opendir, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				      uint64_t unique, struct spdk_fsdev_file_object *fobject, uint32_t flags,
				      spdk_fsdev_opendir_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_readdir, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				      uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				      uint64_t offset,
				      spdk_fsdev_readdir_entry_cb entry_cb_fn, spdk_fsdev_readdir_cpl_cb cpl_cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_releasedir, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
		spdk_fsdev_releasedir_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_fsyncdir, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				       uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				       bool datasync,
				       spdk_fsdev_fsyncdir_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_flock, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
				    enum spdk_fsdev_file_lock_op operation, spdk_fsdev_flock_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_fallocate, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
					uint64_t unique, struct spdk_fsdev_file_object *fobject, struct spdk_fsdev_file_handle *fhandle,
					int mode, off_t offset, off_t length,
					spdk_fsdev_fallocate_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_copy_file_range, int, (struct spdk_fsdev_desc *desc,
		struct spdk_io_channel *ch,
		uint64_t unique,
		struct spdk_fsdev_file_object *fobject_in, struct spdk_fsdev_file_handle *fhandle_in, off_t off_in,
		struct spdk_fsdev_file_object *fobject_out, struct spdk_fsdev_file_handle *fhandle_out,
		off_t off_out, size_t len, uint32_t flags,
		spdk_fsdev_copy_file_range_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_abort, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique_to_abort, spdk_fsdev_abort_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_get_name, const char *, (const struct spdk_fsdev *fsdev), NULL);

DEFINE_STUB(spdk_rmem_is_enabled, bool, (void), false);
DEFINE_STUB(spdk_rmem_pool_create, struct spdk_rmem_pool *, (const char *name, uint32_t entry_size,
		uint32_t num_entries, uint32_t ext_num_entries), NULL);
DEFINE_STUB(spdk_rmem_pool_restore, struct spdk_rmem_pool *, (const char *name, uint32_t entry_size,
		spdk_rmem_pool_restore_entry_cb clb, void *ctx), NULL);
DEFINE_STUB(spdk_rmem_pool_get, struct spdk_rmem_entry *, (struct spdk_rmem_pool *pool), NULL);
DEFINE_STUB_V(spdk_rmem_entry_write, (struct spdk_rmem_entry *entry, const void *buf));
DEFINE_STUB(spdk_rmem_entry_read, bool, (struct spdk_rmem_entry *entry, void *buf), false);
DEFINE_STUB_V(spdk_rmem_entry_release, (struct spdk_rmem_entry *entry));
DEFINE_STUB_V(spdk_rmem_pool_destroy, (struct spdk_rmem_pool *pool));

static struct spdk_fsdev_desc *g_ut_fsdev_desc = (struct spdk_fsdev_desc *)0xBEADFEAD;

int
spdk_fsdev_mount(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		 uint64_t unique, const struct spdk_fsdev_mount_opts *opts,
		 spdk_fsdev_mount_cpl_cb cb_fn, void *cb_arg)
{
	ut_call_record_begin(spdk_fsdev_mount);
	ut_call_record_param_ptr(desc);
	ut_call_record_param_ptr(ch);
	ut_call_record_param_int(unique);
	ut_call_record_param_hash(opts, sizeof(*opts));
	ut_call_record_param_ptr(cb_fn);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_end();

	return 0;
}

int
spdk_fsdev_umount(struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
		  uint64_t unique, spdk_fsdev_umount_cpl_cb cb_fn, void *cb_arg)
{
	ut_call_record_begin(spdk_fsdev_umount);
	ut_call_record_param_ptr(desc);
	ut_call_record_param_ptr(ch);
	ut_call_record_param_int(unique);
	ut_call_record_param_ptr(cb_fn);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_end();

	return 0;
}

static void
request_cb(void *cb_arg, int error)
{
	ut_call_record_begin(request_cb);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_param_int(error);
	ut_call_record_end();
}

static void
ut_fuse_disp_test_create_delete(void)
{
	struct spdk_fuse_dispatcher *disp;

	disp = spdk_fuse_dispatcher_create(g_ut_fsdev_desc, false);
	CU_ASSERT(disp != NULL);

	spdk_fuse_dispatcher_delete(disp);
}

struct fuse_in {
	struct fuse_in_header hdr;
	union {
		struct fuse_init_in init;
	};
};

struct fuse_out {
	struct fuse_out_header hdr;
	union {
		struct fuse_init_out init;
	};
};

static void
ut_fuse_disp_test_init_destroy(void)
{
	struct spdk_fuse_dispatcher *disp;
	const size_t io_ctx_size = spdk_fuse_dispatcher_get_io_ctx_size();
	uint8_t io_ctx[io_ctx_size];
	struct spdk_io_channel *io_channel = (struct spdk_io_channel *)0x12345678;
	int request_cb_arg;
	struct fuse_in init_in;
	struct iovec in_iov = { .iov_base = &init_in };
	struct fuse_out init_out;
	struct iovec out_iov = { .iov_base = &init_out };
	struct spdk_fsdev_mount_opts opts = {};
	spdk_fsdev_mount_cpl_cb *mount_cb_fn;
	spdk_fsdev_umount_cpl_cb *umount_cb_fn;
	void *cb_arg;
	int rc;

	ut_calls_reset();
	disp = spdk_fuse_dispatcher_create(g_ut_fsdev_desc, false);
	CU_ASSERT(disp != NULL);

	/* FUSE_INIT 7.34 */
	ut_calls_reset();
	memset(&init_in, 0, sizeof(init_in));
	init_in.hdr.len = sizeof(init_in.hdr) + sizeof(init_in.init);
	init_in.hdr.opcode = FUSE_INIT;
	init_in.hdr.unique = 1;
	init_in.init.major = 7;
	init_in.init.minor = 34;
	init_in.init.max_readahead = 16384;
	init_in.init.flags = FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_MAX_PAGES |
			     FUSE_EXPORT_SUPPORT | FUSE_AUTO_INVAL_DATA | FUSE_WRITEBACK_CACHE | FUSE_POSIX_ACL;
	in_iov.iov_len = init_in.hdr.len;
	out_iov.iov_len = sizeof(init_out.hdr) + sizeof(init_out.init);
	rc = spdk_fuse_dispatcher_submit_request(disp, io_channel, &in_iov, 1, &out_iov, 1, io_ctx,
			request_cb, &request_cb_arg);
	CU_ASSERT(rc == 0);
	CU_ASSERT(ut_calls_get_func(0) == spdk_fsdev_mount);
	CU_ASSERT(ut_calls_param_get_ptr(0, 1) == io_channel);
	CU_ASSERT(ut_calls_param_get_int(0, 2) == 1);
	opts.opts_size = sizeof(opts);
	opts.max_xfer_size = 0;
	opts.max_readahead = 16384;
	opts.flags = SPDK_FSDEV_MOUNT_DOT_PATH_LOOKUP | SPDK_FSDEV_MOUNT_AUTO_INVAL_DATA |
		     SPDK_FSDEV_MOUNT_WRITEBACK_CACHE | SPDK_FSDEV_MOUNT_POSIX_ACL;
	CU_ASSERT(ut_calls_param_get_hash(0, 3) == ut_hash(&opts, sizeof(opts)));
	mount_cb_fn = ut_calls_param_get_ptr(0, 4);
	cb_arg = ut_calls_param_get_ptr(0, 5);

	ut_calls_reset();
	opts.max_readahead = 4096;
	opts.max_xfer_size = 131072;
	/* POSIX_ACL is not supported by fsdev */
	opts.flags &= ~SPDK_FSDEV_MOUNT_POSIX_ACL;
	mount_cb_fn(cb_arg, io_channel, 0, &opts, UT_FOBJECT);
	CU_ASSERT(ut_calls_get_func(0) == request_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == &request_cb_arg);
	CU_ASSERT(ut_calls_param_get_int(0, 1) == 0);
	CU_ASSERT(init_out.hdr.len == sizeof(init_out.hdr) + sizeof(init_out.init));
	CU_ASSERT(init_out.hdr.error == 0);
	CU_ASSERT(init_out.hdr.unique == 1);
	CU_ASSERT(init_out.init.major == 7);
	CU_ASSERT(init_out.init.minor == 34);
	CU_ASSERT(init_out.init.max_readahead == 4096);
	CU_ASSERT(init_out.init.flags == (FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_MAX_PAGES |
					  FUSE_EXPORT_SUPPORT | FUSE_AUTO_INVAL_DATA |
					  FUSE_WRITEBACK_CACHE));
	CU_ASSERT(init_out.init.max_background == 0xFFFF);
	CU_ASSERT(init_out.init.congestion_threshold == 0xFFFF);
	CU_ASSERT(init_out.init.max_write == 131072);
	CU_ASSERT(init_out.init.time_gran == 1);
	CU_ASSERT(init_out.init.max_pages == 131072 / 4096);
	CU_ASSERT(init_out.init.map_alignment == 0);

	/* FUSE_DESTROY */
	ut_calls_reset();
	memset(&init_in, 0, sizeof(init_in));
	init_in.hdr.len = sizeof(init_in.hdr);
	init_in.hdr.opcode = FUSE_DESTROY;
	init_in.hdr.unique = 2;
	in_iov.iov_len = init_in.hdr.len;
	out_iov.iov_len = sizeof(init_out.hdr);
	rc = spdk_fuse_dispatcher_submit_request(disp, io_channel, &in_iov, 1, &out_iov, 1, io_ctx,
			request_cb, &request_cb_arg);
	CU_ASSERT(rc == 0);
	CU_ASSERT(ut_calls_get_func(0) == spdk_fsdev_umount);
	CU_ASSERT(ut_calls_param_get_ptr(0, 1) == io_channel);
	CU_ASSERT(ut_calls_param_get_int(0, 2) == 2);
	umount_cb_fn = ut_calls_param_get_ptr(0, 3);
	cb_arg = ut_calls_param_get_ptr(0, 4);

	ut_calls_reset();
	umount_cb_fn(cb_arg, io_channel);
	CU_ASSERT(ut_calls_get_func(0) == request_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == &request_cb_arg);
	CU_ASSERT(ut_calls_param_get_int(0, 1) == 0);
	CU_ASSERT(init_out.hdr.len == sizeof(init_out.hdr));
	CU_ASSERT(init_out.hdr.error == 0);
	CU_ASSERT(init_out.hdr.unique == 2);

	spdk_fuse_dispatcher_delete(disp);
}

static int
fuse_disp_ut(int argc, char **argv)
{
	CU_pSuite		suite = NULL;
	unsigned int		num_failures;

	suite = CU_add_suite("fuse_dispatcher", NULL, NULL);

	CU_ADD_TEST(suite, ut_fuse_disp_test_create_delete);
	CU_ADD_TEST(suite, ut_fuse_disp_test_init_destroy);

	allocate_cores(1);
	allocate_threads(1);
	set_thread(0);

	num_failures = spdk_ut_run_tests(argc, argv, NULL);

	poll_thread(0);

	free_threads();
	free_cores();

	return num_failures;
}

int
main(int argc, char **argv)
{
	unsigned int num_failures;

	CU_initialize_registry();

	num_failures = fuse_disp_ut(argc, argv);

	CU_cleanup_registry();
	return num_failures;
}
