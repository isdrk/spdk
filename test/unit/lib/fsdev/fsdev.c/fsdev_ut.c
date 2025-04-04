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

static int ut_reset_desired_err;
static bool ut_reset_leak_io;
static bool ut_complete_next_request = true;
static struct spdk_fsdev_io *ut_oustanding_io = NULL;

static void
ut_fsdev_submit_request(struct spdk_io_channel *_ch, struct spdk_fsdev_io *fsdev_io)
{
	enum spdk_fsdev_io_type type = spdk_fsdev_io_get_type(fsdev_io);
	struct ut_fsdev *utfsdev = fsdev_to_ut_fsdev(fsdev_io->fsdev);

	CU_ASSERT(type >= 0 && type < __SPDK_FSDEV_IO_LAST);

	ut_call_record_begin(ut_fsdev_submit_request);
	ut_call_record_param_ptr(_ch);
	ut_call_record_param_ptr(fsdev_io);
	ut_call_record_param_hash(&fsdev_io->u_in, sizeof(fsdev_io->u_in));

	switch (type) {
	case SPDK_FSDEV_IO_MOUNT:
		fsdev_io->u_out.mount.root_fobject = UT_FOBJECT;
		fsdev_io->u_out.mount.opts.opts_size = fsdev_io->u_in.mount.opts.opts_size;
		fsdev_io->u_out.mount.opts.max_xfer_size = fsdev_io->u_in.mount.opts.max_xfer_size / 2;
		fsdev_io->u_out.mount.opts.flags = fsdev_io->u_in.mount.opts.flags;
		fsdev_io->u_out.mount.opts.flags &= ~SPDK_FSDEV_MOUNT_WRITEBACK_CACHE;
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
	new_opts.max_num_sources = old_opts.max_num_sources / 2;
	rc = spdk_fsdev_set_opts(&new_opts);
	CU_ASSERT(rc == 0);

	rc = spdk_fsdev_get_opts(&new_opts, sizeof(new_opts));
	CU_ASSERT(rc == 0);
	CU_ASSERT(old_opts.max_num_sources / 2 == new_opts.max_num_sources);
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
	int rc;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);
	CU_ASSERT(spdk_fsdev_desc_get_fsdev(fsdev_desc) == &utfsdev->fsdev);

	ch = spdk_fsdev_get_io_channel(fsdev_desc);
	CU_ASSERT(ch != NULL);

	fsdev_io = calloc(1, spdk_fsdev_get_io_ctx_size());
	CU_ASSERT(fsdev_io != NULL);

	ut_calls_reset();
	ut_complete_next_request = false; /* Make sure the flush IO won't be completed */

	spdk_fsdev_io_init(fsdev_io, fsdev_desc, ch, UT_UNIQUE, SPDK_FSDEV_IO_FLUSH,
			   ut_fsdev_reset_flush_cpl_cb, utfsdev);

	fsdev_io->u_in.flush.fobject = UT_FOBJECT;
	fsdev_io->u_in.flush.fhandle = UT_FHANDLE;

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
	CU_ASSERT(stat.notify[SPDK_FSDEV_NOTIFY_INVAL_DATA].count == 1);
	CU_ASSERT(stat.notify[SPDK_FSDEV_NOTIFY_INVAL_ENTRY].count == 1);
	CU_ASSERT(stat.notify[SPDK_FSDEV_NOTIFY_INVAL_DATA].replies == 0);
	CU_ASSERT(stat.notify[SPDK_FSDEV_NOTIFY_INVAL_ENTRY].replies == 0);

	spdk_fsdev_notify_reply_add_stat(&utfsdev->fsdev, SPDK_FSDEV_NOTIFY_INVAL_DATA);
	spdk_fsdev_get_device_stat(&utfsdev->fsdev, &stat, ut_fsdev_device_stat_cb, NULL);
	poll_threads();
	CU_ASSERT(stat.notify[SPDK_FSDEV_NOTIFY_INVAL_DATA].replies == 1);
	CU_ASSERT(stat.notify[SPDK_FSDEV_NOTIFY_INVAL_ENTRY].replies == 0);

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

typedef void (*fill_clb)(struct spdk_fsdev_io *fsdev_io);
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
ut_fsdev_test_io(enum spdk_fsdev_io_type type, int desired_io_status, uint64_t unique,
		 fill_clb fill_cb, check_clb check_cb)
{
	struct ut_fsdev *utfsdev;
	struct spdk_io_channel *ch;
	struct spdk_fsdev_desc *fsdev_desc;
	struct spdk_fsdev_io *fsdev_io;
	int rc;
	size_t io_hash;

	utfsdev = ut_fsdev_create("utfsdev0");
	CU_ASSERT(utfsdev != NULL);

	rc = spdk_fsdev_open("utfsdev0", fsdev_event_cb, NULL, &fsdev_desc);
	CU_ASSERT(rc == 0);
	CU_ASSERT(fsdev_desc != NULL);

	ch = spdk_fsdev_get_io_channel(fsdev_desc);
	CU_ASSERT(ch != NULL);

	fsdev_io = calloc(1, spdk_fsdev_get_io_ctx_size());
	CU_ASSERT(fsdev_io != NULL);

	spdk_fsdev_io_init(fsdev_io, fsdev_desc, ch, unique, type, ut_fsdev_test_io_cpl_cb,
			   (void *)UT_UNIQUE);

	ut_calls_reset();
	utfsdev->desired_io_status = desired_io_status;
	fill_cb(fsdev_io);

	io_hash = ut_hash(&fsdev_io->u_in, sizeof(fsdev_io->u_in));

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

	/* Op-specific params */
	check_cb(fsdev_io);

	free(fsdev_io);

	ut_calls_reset();
	spdk_put_io_channel(ch);
	poll_thread(0);

	spdk_fsdev_close(fsdev_desc);

	ut_fsdev_destroy(utfsdev);
}

static void
ut_fsdev_mount_fill_clb(struct spdk_fsdev_io *fsdev_io)
{
	memset(&fsdev_io->u_in.mount.opts, 0, sizeof(fsdev_io->u_in.mount.opts));
	fsdev_io->u_in.mount.opts.opts_size = sizeof(fsdev_io->u_in.mount.opts);
	fsdev_io->u_in.mount.opts.max_xfer_size = UINT32_MAX;
	fsdev_io->u_in.mount.opts.flags = SPDK_FSDEV_MOUNT_WRITEBACK_CACHE;
}

static void
ut_fsdev_mount_check_clb(struct spdk_fsdev_io *fsdev_io)
{
	CU_ASSERT(fsdev_io->u_out.mount.root_fobject == UT_FOBJECT);
	CU_ASSERT(fsdev_io->u_out.mount.opts.opts_size == sizeof(fsdev_io->u_in.mount.opts));
	CU_ASSERT(fsdev_io->u_out.mount.opts.max_xfer_size == UINT32_MAX / 2);
	CU_ASSERT((fsdev_io->u_out.mount.opts.flags & SPDK_FSDEV_MOUNT_WRITEBACK_CACHE) == 0);
}

static void
ut_fsdev_test_mount_ok(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_MOUNT, 0, 1, ut_fsdev_mount_fill_clb,
			 ut_fsdev_mount_check_clb);
}

static void
ut_fsdev_test_mount_err(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_MOUNT, -EINVAL, 1, ut_fsdev_mount_fill_clb,
			 ut_fsdev_mount_check_clb);
}

static void
ut_fsdev_umount_fill_clb(struct spdk_fsdev_io *fsdev_io)
{
	/* Nothing to check here */
}

static void
ut_fsdev_umount_check_clb(struct spdk_fsdev_io *fsdev_io)
{
	/* Nothing to check here */
}

static void
ut_fsdev_test_umount(void)
{
	ut_fsdev_test_io(SPDK_FSDEV_IO_UMOUNT, 0, 0, ut_fsdev_umount_fill_clb,
			 ut_fsdev_umount_check_clb);
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
