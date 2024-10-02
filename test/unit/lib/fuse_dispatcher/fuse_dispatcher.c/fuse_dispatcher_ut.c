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

#define UT_UNIQUE 0xBEADBEAD
#define UT_FOBJECT ((struct spdk_fsdev_file_object *)0xDEADDEAD)
#define UT_FHANDLE ((struct spdk_fsdev_file_handle *)0xBEABBEAB)
#define UT_FNAME "ut_test.file"

DEFINE_STUB_V(spdk_fsdev_close, (struct spdk_fsdev_desc *desc));
DEFINE_STUB(spdk_fsdev_get_io_channel, struct spdk_io_channel *, (struct spdk_fsdev_desc *desc),
	    NULL);
DEFINE_STUB(spdk_fsdev_desc_get_fsdev, struct spdk_fsdev *, (struct spdk_fsdev_desc *desc), NULL);
DEFINE_STUB(spdk_fsdev_get_opts, int, (struct spdk_fsdev_opts *opts, size_t opts_size), 0);
DEFINE_STUB(spdk_fsdev_reset, int, (struct spdk_fsdev_desc *desc, spdk_fsdev_reset_completion_cb cb,
				    void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_reset_supported, bool, (struct spdk_fsdev *fsdev), true);
DEFINE_STUB(spdk_fsdev_mount, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique, const struct spdk_fsdev_mount_opts *opts,
				    spdk_fsdev_mount_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_umount, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				     uint64_t unique, spdk_fsdev_umount_cpl_cb cb_fn, void *cb_arg), 0);
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
				   spdk_fsdev_poll_cpl_cb cb_fn, void *cb_arg), 0);
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
				    uint64_t owner, spdk_fsdev_setlk_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_symlink, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				      uint64_t unique,
				      struct spdk_fsdev_file_object *parent_fobject, const char *target,
				      const char *linkpath, uid_t euid, gid_t egid,
				      spdk_fsdev_symlink_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_mknod, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode, dev_t rdev,
				    uid_t euid, gid_t egid, spdk_fsdev_mknod_cpl_cb cb_fn, void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_mkdir, int, (struct spdk_fsdev_desc *desc, struct spdk_io_channel *ch,
				    uint64_t unique,
				    struct spdk_fsdev_file_object *parent_fobject, const char *name, mode_t mode,
				    uid_t euid, gid_t egid, spdk_fsdev_mkdir_cpl_cb cb_fn, void *cb_arg), 0);
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

static int g_ut_fsdev_desc;

int
spdk_fsdev_open(const char *fsdev_name, spdk_fsdev_event_cb_t event_cb,
		void *event_ctx, struct spdk_fsdev_desc **desc)
{
	*desc = (struct spdk_fsdev_desc *)&g_ut_fsdev_desc;
	ut_call_record_begin(spdk_fsdev_open);
	ut_call_record_param_str(fsdev_name);
	ut_call_record_param_ptr(event_cb);
	ut_call_record_param_ptr(event_ctx);
	ut_call_record_param_ptr(desc);
	ut_call_record_end();

	return 0;
}

static void
fuse_disp_create_cb(void *cb_arg, struct spdk_fuse_dispatcher *disp)
{
	ut_call_record_begin(fuse_disp_create_cb);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_param_ptr(disp);
	ut_call_record_end();
}

static void
fuse_disp_delete_cb(void *cb_arg, int error)
{
	ut_call_record_begin(fuse_disp_delete_cb);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_param_int(error);
	ut_call_record_end();
}

static void
fuse_disp_event_cb(enum spdk_fuse_dispatcher_event_type type,
		   struct spdk_fuse_dispatcher *disp,
		   void *event_ctx)
{
	ut_call_record_begin(fuse_disp_event_cb);
	ut_call_record_param_int(type);
	ut_call_record_param_ptr(disp);
	ut_call_record_param_ptr(event_ctx);
	ut_call_record_end();
}

static void
ut_fuse_disp_test_create_delete(void)
{
	struct spdk_fuse_dispatcher *disp;
	int create_cb_arg;
	int delete_cb_arg;
	int rc;

	ut_calls_reset();
	rc = spdk_fuse_dispatcher_create("utfsdev0", fuse_disp_event_cb, NULL, fuse_disp_create_cb,
					 &create_cb_arg);
	CU_ASSERT(rc == 0);
	poll_thread(0);
	CU_ASSERT(ut_calls_get_func(0) == spdk_fsdev_open);
	CU_ASSERT(!strncmp(ut_calls_param_get_str(0, 0), "utfsdev0", UT_CALL_REC_MAX_STR_SIZE));
	CU_ASSERT(ut_calls_get_func(1) == fuse_disp_create_cb);
	CU_ASSERT(ut_calls_param_get_ptr(1, 0) == &create_cb_arg);
	disp = (struct spdk_fuse_dispatcher *)ut_calls_param_get_ptr(1, 1);

	ut_calls_reset();
	rc = spdk_fuse_dispatcher_delete(disp, fuse_disp_delete_cb, &delete_cb_arg);
	CU_ASSERT(rc == 0);
	poll_thread(0);
	CU_ASSERT(ut_calls_get_func(0) == fuse_disp_delete_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == &delete_cb_arg);
}

static int
fuse_disp_ut(int argc, char **argv)
{
	CU_pSuite		suite = NULL;
	unsigned int		num_failures;

	suite = CU_add_suite("fuse_dispatcher", NULL, NULL);

	CU_ADD_TEST(suite, ut_fuse_disp_test_create_delete);

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
