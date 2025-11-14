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
#include "spdk/linux/fuse.h"

#include "lib/fuse_dispatcher/fuse_dispatcher.c"

#define UT_UNIQUE 0xBEADBEAD
#define UT_FSDEV_NAME "utfsdev0"
#define UT_FNAME "ut_test.file"
#define UT_IO_BUFF_SIZE 111

#define UT_RMEM_POOL ((struct spdk_rmem_pool *)0xBEADBEAD)
#define UT_RMEM_POOL_ENTRY ((struct spdk_rmem_entry *)0xDEABDEAB)

DEFINE_STUB_V(spdk_fsdev_close, (struct spdk_fsdev_desc *desc));
DEFINE_STUB(spdk_fsdev_get_supported_fuse_opcodes, uint64_t, (struct spdk_fsdev *fsdev), 0);
DEFINE_STUB(spdk_fsdev_desc_get_fsdev, struct spdk_fsdev *, (struct spdk_fsdev_desc *desc), NULL);
DEFINE_STUB(spdk_fsdev_get_opts, int, (struct spdk_fsdev_opts *opts, size_t opts_size), 0);
DEFINE_STUB(spdk_fsdev_reset, int, (struct spdk_fsdev_desc *desc, spdk_fsdev_reset_completion_cb cb,
				    void *cb_arg), 0);
DEFINE_STUB(spdk_fsdev_reset_supported, bool, (struct spdk_fsdev *fsdev), true);
DEFINE_STUB(spdk_fsdev_get_notify_max_data_size, uint32_t, (const struct spdk_fsdev *fsdev), 0);
DEFINE_STUB(spdk_fsdev_get_name, const char *, (const struct spdk_fsdev *fsdev), NULL);
DEFINE_STUB(spdk_fsdev_is_recovered, bool, (struct spdk_fsdev *fsdev), false);
DEFINE_STUB(spdk_rmem_get_backend_dir, const char *, (void), NULL);
DEFINE_STUB(spdk_rmem_set_backend_dir, int, (const char *backend_dir_name), 0);
DEFINE_STUB(spdk_rmem_pool_create, struct spdk_rmem_pool *, (const char *name, uint32_t entry_size,
		uint32_t num_entries, uint32_t ext_num_entries), UT_RMEM_POOL);
DEFINE_STUB(spdk_rmem_pool_restore, struct spdk_rmem_pool *, (const char *name, uint32_t entry_size,
		spdk_rmem_pool_restore_entry_cb clb, void *ctx), NULL);
DEFINE_STUB(spdk_rmem_pool_get, struct spdk_rmem_entry *, (struct spdk_rmem_pool *pool),
	    UT_RMEM_POOL_ENTRY);
DEFINE_STUB_V(spdk_rmem_entry_write, (struct spdk_rmem_entry *entry, const void *buf));
DEFINE_STUB(spdk_rmem_entry_read, int, (struct spdk_rmem_entry *entry, void *buf), 0);
DEFINE_STUB_V(spdk_rmem_entry_release, (struct spdk_rmem_entry *entry));
DEFINE_STUB_V(spdk_rmem_pool_destroy, (struct spdk_rmem_pool *pool));

static struct spdk_fsdev_desc *g_ut_fsdev_desc = (struct spdk_fsdev_desc *)0xBEADFEAD;

void
spdk_fsdev_io_init(struct spdk_fsdev_io *fsdev_io, struct spdk_fsdev_desc *desc,
		   struct spdk_io_channel *ch,
		   uint64_t unique, enum spdk_fsdev_io_type type,
		   uint16_t source_id, uint64_t source_unique,
		   spdk_fsdev_cpl_cb *cb_fn, void *cb_arg)
{
	ut_call_record_begin(spdk_fsdev_io_init);
	ut_call_record_param_ptr(fsdev_io);
	ut_call_record_param_ptr(desc);
	ut_call_record_param_ptr(ch);
	ut_call_record_param_int(unique);
	ut_call_record_param_int(type);
	ut_call_record_param_int(source_id);
	ut_call_record_param_int(source_unique);
	ut_call_record_param_ptr(cb_fn);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_end();
}

void
spdk_fsdev_io_submit(struct spdk_fsdev_io *fsdev_io)
{
	ut_call_record_begin(spdk_fsdev_io_submit);
	ut_call_record_param_ptr(fsdev_io);
	ut_call_record_end();
}

int
spdk_fsdev_get_io_ctx_size(void)
{
	ut_call_record_begin(spdk_fsdev_get_io_ctx_size);
	ut_call_record_end();
	return sizeof(struct spdk_fsdev_io) +  UT_IO_BUFF_SIZE;
}

static void
notify_reply_cb(void *cb_arg,
		const struct spdk_fsdev_notify_reply_data *notify_reply_data,
		uint64_t unique_id)
{
	ut_call_record_begin(notify_reply_cb);
	ut_call_record_param_ptr(cb_arg);
	ut_call_record_param_hash(notify_reply_data, sizeof(*notify_reply_data));
	ut_call_record_param_int(unique_id);
	ut_call_record_end();
}

static void
ut_fuse_disp_test_create_delete(void)
{
	struct spdk_fuse_dispatcher *disp;

	disp = spdk_fuse_dispatcher_create(g_ut_fsdev_desc, notify_reply_cb, NULL);
	CU_ASSERT(disp != NULL);

	spdk_fuse_dispatcher_delete(disp);
}

struct fuse_in {
	struct fuse_in_header hdr;
	union {
		struct fuse_init_in init;
		struct fuse_notify_reply_in notify_reply;
	};
};

struct fuse_out {
	struct fuse_out_header hdr;
	union {
		struct fuse_init_out init;
		struct fuse_notify_poll_wakeup_out poll;
		struct fuse_notify_inval_inode_out inval_inode;
		struct {
			struct fuse_notify_inval_entry_out fuse;
			char name[UT_CALL_REC_MAX_STR_SIZE];
		} inval_entry;
		struct fuse_notify_delete_out delete;
		struct fuse_notify_store_out store;
		struct fuse_notify_retrieve_out retrieve;
	};
};

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
