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
#define UT_FOBJECT ((uint64_t)0xDEADDEAD)
#define UT_FHANDLE ((uint64_t)0xBEABBEAB)
#define UT_FNAME "ut_test.file"
#define UT_LNAME "ut_test.file.link"
#define UT_ANAME "xattr1.name"
#define UT_AVALUE "xattr1.val"
#define UT_NUM_LOOKUPS 11
#define UT_DATA_SIZE 22
#define UT_NOTIFY_MAX_DATA_SIZE 4096

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

static int ut_reset_desired_err;
static bool ut_reset_leak_io;
static bool ut_complete_next_request = true;
static struct spdk_fsdev_io *ut_oustanding_io = NULL;

static void
ut_fsdev_submit_request(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	struct ut_fsdev *utfsdev = fsdev_to_ut_fsdev(fsdev_io->fsdev);

	struct fuse_in_header *in_hdr = fsdev_io->u_in.fuse.hdr;
	struct fuse_out_header *out_hdr = fsdev_io->u_out.fuse.hdr;

	assert(spdk_fsdev_io_get_type(fsdev_io) == SPDK_FSDEV_IO_FUSE);

	ut_call_record_begin(ut_fsdev_submit_request);
	ut_call_record_param_ptr(_ch);
	ut_call_record_param_ptr(fsdev_io);
	ut_call_record_param_hash(&fsdev_io->u_in.fuse.hdr, sizeof(fsdev_io->u_in.fuse));

	switch (in_hdr->opcode) {
	case FUSE_INIT: {
		struct fuse_init_out *init = fsdev_io->u_out.fuse.op.init;
		init->major = 7;
		init->minor = 31;
		init->flags = FUSE_WRITEBACK_CACHE;
		init->max_readahead = UINT32_MAX / 2;
		init->max_write = UINT32_MAX;

		out_hdr->len = sizeof(*init);
		out_hdr->error = utfsdev->desired_io_status;
		out_hdr->unique = in_hdr->unique;
	}
	break;
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
ut_fsdev_get_memory_domain_types(void *ctx, enum spdk_dma_device_type *types, int array_size)
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
	.get_memory_domain_types = ut_fsdev_get_memory_domain_types,
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

	old_opts.opts_size = SPDK_SIZEOF(&old_opts, recovery_enabled);
	rc = spdk_fsdev_get_opts(&old_opts, sizeof(old_opts));
	CU_ASSERT(rc == 0);

	new_opts.opts_size = SPDK_SIZEOF(&new_opts, recovery_enabled);
	new_opts.max_source_id = old_opts.max_source_id / 2;
	rc = spdk_fsdev_set_opts(&new_opts);
	CU_ASSERT(rc == 0);

	rc = spdk_fsdev_get_opts(&new_opts, sizeof(new_opts));
	CU_ASSERT(rc == 0);
	CU_ASSERT(old_opts.max_source_id / 2 == new_opts.max_source_id);
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
	CU_ASSERT(ut_calls_param_get_ptr(1, 0) == g_ut_io_channel);

	ut_ch = g_ut_io_channel;

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
ut_fsdev_reset_flush_cpl_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
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
	struct spdk_fsdev_io *fsdev_io;
	struct fuse_in_header in_hdr = {};
	struct fuse_out_header out_hdr = {};
	struct fuse_flush_in flush_in = {};
	int rc;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);
	CU_ASSERT(spdk_fsdev_desc_get_fsdev(fsdev_desc) == &utfsdev->fsdev);

	ch = spdk_fsdev_get_io_channel(fsdev_desc);
	CU_ASSERT(ch != NULL);

	fsdev_io = calloc(1, sizeof(*fsdev_io) + spdk_fsdev_get_io_ctx_size());
	CU_ASSERT(fsdev_io != NULL);

	in_hdr.opcode = FUSE_FLUSH;
	in_hdr.unique = UT_UNIQUE;
	in_hdr.len = sizeof(in_hdr) + sizeof(flush_in);
	in_hdr.nodeid = UT_FOBJECT;
	in_hdr.uid = geteuid();
	in_hdr.gid = getegid();
	fsdev_io->u_in.fuse.hdr = &in_hdr;

	flush_in.fh = UT_FHANDLE;
	fsdev_io->u_in.fuse.op.flush = &flush_in;

	fsdev_io->u_out.fuse.hdr = &out_hdr;
	fsdev_io->u_out.fuse.op.raw = NULL;

	ut_calls_reset();
	ut_complete_next_request = false; /* Make sure the flush IO won't be completed */

	spdk_fsdev_io_init(fsdev_io, fsdev_desc, ch, UT_UNIQUE, SPDK_FSDEV_IO_FUSE,
			   0, 0, ut_fsdev_reset_flush_cpl_cb, utfsdev);

	spdk_fsdev_io_submit(fsdev_io);

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

	free(fsdev_io);

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

static spdk_fsdev_notify_reply_cb_t ut_notify_reply_cb = NULL;
static void *ut_notify_reply_ctx = NULL;

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
	ut_call_record_param_hash(notify_data->fuse, offsetof(struct spdk_fuse_notify_request, internal));
	ut_call_record_param_hash(notify_data->fuse->iovs[0].iov_base,
				  (uint32_t)notify_data->fuse->iovs[0].iov_len);
	ut_call_record_end();

	ut_notify_reply_cb = reply_cb;
	ut_notify_reply_ctx = reply_ctx;
}

static void
ut_fsdev_notify_reply_cb(struct spdk_fuse_notify_request *req, int status)
{
	ut_call_record_begin(ut_fsdev_notify_reply_cb);
	ut_call_record_param_ptr(req);
	ut_call_record_param_int(status);
	ut_call_record_end();
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
	const char *filename = "test_file.txt";
	struct spdk_fsdev_io_stat stat;
	struct spdk_fuse_notify_request req;
	struct {
		struct fuse_out_header hdr;
		struct fuse_notify_inval_entry_out entry;
		uint8_t data[256];
	} out = {};
	struct iovec iov = {};
	struct spdk_fsdev_notify_reply_data notify_reply_data = {};
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

	out.hdr.error = FUSE_NOTIFY_INVAL_ENTRY;
	out.hdr.unique = 0;
	out.entry.parent = FUSE_ROOT_ID;
	out.entry.namelen = strlen(filename);
	out.hdr.len = sizeof(out) + out.entry.namelen + 1;

	memcpy(out.data, filename, out.entry.namelen + 1);

	iov.iov_base = &out;
	iov.iov_len = sizeof(out) + out.entry.namelen + 1;

	req.iovcnt = 1;
	req.iovs = &iov;
	req.fsdev = &utfsdev->fsdev;
	req.cb_fn = ut_fsdev_notify_reply_cb;

	/* No subscriber */
	ut_calls_reset();
	rc = spdk_fsdev_notify_fuse(&req);
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
	rc = spdk_fsdev_notify_fuse(&req);
	CU_ASSERT(rc == 0);

	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_notify_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == fsdev);
	CU_ASSERT(ut_calls_param_get_ptr(0, 1) == &notify_ctx);
	CU_ASSERT(ut_calls_param_get_hash(0, 2) ==
		  ut_hash(&req, offsetof(struct spdk_fuse_notify_request, internal)));
	CU_ASSERT(ut_calls_param_get_hash(0, 3) == ut_hash(&out, sizeof(out) + out.entry.namelen + 1));

	CU_ASSERT(ut_notify_reply_cb != NULL);
	CU_ASSERT(ut_notify_reply_ctx != NULL);

	/* Check device stat */
	memset(&stat, 0, sizeof(stat));
	spdk_fsdev_get_device_stat(&utfsdev->fsdev, &stat, ut_fsdev_device_stat_cb, NULL);
	poll_threads();
	CU_ASSERT(stat.notify[FUSE_NOTIFY_INVAL_ENTRY].count == 1);
	CU_ASSERT(stat.notify[FUSE_NOTIFY_INVAL_ENTRY].replies == 0);

	/* Check reply path */
	ut_calls_reset();
	notify_reply_data.status = 100;
	ut_notify_reply_cb(&notify_reply_data, ut_notify_reply_ctx);

	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_notify_reply_cb);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == &req);
	CU_ASSERT(ut_calls_param_get_int(0, 1) == 100);

	/* Check device stat - now with reply */
	memset(&stat, 0, sizeof(stat));
	spdk_fsdev_get_device_stat(&utfsdev->fsdev, &stat, ut_fsdev_device_stat_cb, NULL);
	poll_threads();
	CU_ASSERT(stat.notify[FUSE_NOTIFY_INVAL_ENTRY].count == 1);
	CU_ASSERT(stat.notify[FUSE_NOTIFY_INVAL_ENTRY].replies == 1);

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

typedef void (*check_clb)(struct spdk_fsdev_io *fsdev_io);

static void
ut_fsdev_test_io_cpl_cb(void *cb_arg, int status, struct spdk_fsdev_io *fsdev_io)
{
	CU_ASSERT(cb_arg == (void *)UT_UNIQUE);

	ut_call_record_begin(ut_fsdev_test_io_cpl_cb);
	ut_call_record_param_int(status);
	ut_call_record_param_ptr(fsdev_io);
	ut_call_record_end();
}

static void
ut_fsdev_test_io(uint32_t opcode, void *extra_buf_in, uint32_t extra_len_in, void *extra_buf_out,
		 uint32_t extra_len_out, int desired_io_status, uint64_t unique)
{
	struct ut_fsdev *utfsdev;
	struct spdk_io_channel *ch;
	struct spdk_fsdev_desc *fsdev_desc;
	struct spdk_fsdev_io *fsdev_io;
	struct fuse_in_header in_hdr = {};
	struct fuse_out_header out_hdr = {};
	int rc;
	size_t io_hash;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);

	ch = spdk_fsdev_get_io_channel(fsdev_desc);
	CU_ASSERT(ch != NULL);

	fsdev_io = calloc(1,  sizeof(*fsdev_io) + spdk_fsdev_get_io_ctx_size());
	CU_ASSERT(fsdev_io != NULL);

	in_hdr.opcode = opcode;
	in_hdr.unique = unique;
	in_hdr.len = sizeof(in_hdr) + extra_len_in;
	in_hdr.nodeid = UT_FOBJECT;
	in_hdr.uid = geteuid();
	in_hdr.gid = getegid();
	fsdev_io->u_in.fuse.hdr = &in_hdr;

	spdk_fsdev_io_init(fsdev_io, fsdev_desc, ch, unique, SPDK_FSDEV_IO_FUSE, 0, 0,
			   ut_fsdev_test_io_cpl_cb,
			   (void *)UT_UNIQUE);
	fsdev_io->u_in.fuse.op.raw = extra_buf_in;

	fsdev_io->u_out.fuse.hdr = &out_hdr;
	fsdev_io->u_out.fuse.op.raw = extra_buf_out;

	ut_calls_reset();
	utfsdev->desired_io_status = desired_io_status;

	io_hash = ut_hash(&fsdev_io->u_in.fuse, sizeof(fsdev_io->u_in.fuse));

	spdk_fsdev_io_submit(fsdev_io);

	poll_thread(0);

	CU_ASSERT(ut_calls_get_call_count() == 2);

	CU_ASSERT(ut_calls_get_func(0) == ut_fsdev_submit_request);
	CU_ASSERT(ut_calls_get_param_count(0) == 3);
	CU_ASSERT(ut_calls_param_get_ptr(0, 0) == spdk_io_channel_from_ctx(g_ut_io_channel));
	CU_ASSERT(ut_calls_param_get_ptr(0, 1) == fsdev_io);
	CU_ASSERT(ut_calls_param_get_hash(0, 2) == io_hash);

	CU_ASSERT(ut_calls_get_func(1) == ut_fsdev_test_io_cpl_cb);
	CU_ASSERT(ut_calls_param_get_int(1, 0) == (uint64_t)desired_io_status);
	CU_ASSERT(ut_calls_param_get_ptr(1, 1) == fsdev_io);

	free(fsdev_io);

	ut_calls_reset();
	spdk_put_io_channel(ch);
	poll_thread(0);

	spdk_fsdev_close(fsdev_desc);

	ut_fsdev_destroy(utfsdev);
}


static void
ut_fsdev_do_test_mount_test(int desired_io_status)
{
	struct fuse_init_in init_in = {};
	struct fuse_init_out init_out = {};

	init_in.major = 7;
	init_in.minor = 34;

	init_in.flags = FUSE_WRITEBACK_CACHE | FUSE_DO_READDIRPLUS;
	init_in.max_readahead = UINT32_MAX;

	ut_fsdev_test_io(FUSE_INIT, &init_in, sizeof(init_in), &init_out, sizeof(init_out),
			 desired_io_status, UT_UNIQUE);


	CU_ASSERT(init_out.major == 7);
	CU_ASSERT(init_out.minor == 31);
	CU_ASSERT(init_out.flags == FUSE_WRITEBACK_CACHE);
	CU_ASSERT(init_out.max_readahead == UINT32_MAX / 2);
	CU_ASSERT(init_out.max_write == UINT32_MAX);
}

static void
ut_fsdev_test_mount_ok(void)
{
	ut_fsdev_do_test_mount_test(0);
}

static void
ut_fsdev_test_mount_err(void)
{
	ut_fsdev_do_test_mount_test(-EINVAL);
}

static void
ut_fsdev_test_umount(void)
{
	ut_fsdev_test_io(FUSE_DESTROY, NULL, 0, NULL, 0, 0, UT_UNIQUE);
	/* Nothing to check here */
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
