/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2020 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/conf.h"
#include "spdk/event.h"
#include "spdk/vhost.h"
#include "spdk/json.h"
#include "spdk/jsonrpc.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/scheduler.h"

#include "spdk_internal/event.h"

struct interrupt_tgt_poller {
	struct spdk_thread *thread;
	struct spdk_poller *busy;
	struct spdk_poller *timer;
	TAILQ_ENTRY(interrupt_tgt_poller) link;
};

static struct interrupt_tgt_ctx {
	TAILQ_HEAD(, interrupt_tgt_poller) pollers;
	int rc;
} g_tgt_ctx = {
	.pollers = TAILQ_HEAD_INITIALIZER(g_tgt_ctx.pollers)
};

struct rpc_reactor_set_interrupt_mode {
	int32_t lcore;
	bool disable_interrupt;
	int rc;
	struct spdk_thread *rpc_thread;
	struct spdk_jsonrpc_request *request;
};

enum interrupt_tgt_op_on_thread {
	INTERRUPT_TGT_OP_CREATE,
	INTERRUPT_TGT_OP_DELETE,
	INTERRUPT_TGT_OP_PAUSE,
	INTERRUPT_TGT_OP_RESUME,
};

struct interrupt_tgt_op_on_thread_ctx {
	enum interrupt_tgt_op_on_thread op;
	int rc;
	struct interrupt_tgt_ctx *tgt_ctx;
	struct spdk_jsonrpc_request *request;
};

static void interrupt_tgt_op_on_thread(void *ctx);

static void
rpc_op_done(void *ctx)
{
	struct interrupt_tgt_op_on_thread_ctx *op_ctx = ctx;

	SPDK_NOTICELOG("%s pollers done\n", op_ctx->op == INTERRUPT_TGT_OP_RESUME ? "resume" : "pause");
	spdk_jsonrpc_send_bool_response(op_ctx->request, true);
	free(op_ctx);
}

static void
rpc_exec_op_on_threads(struct spdk_jsonrpc_request *request, enum interrupt_tgt_op_on_thread op)
{
	struct interrupt_tgt_op_on_thread_ctx *op_ctx;

	op_ctx = calloc(1, sizeof * op_ctx);
	if (!op_ctx) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "No memory");
		return;
	}
	op_ctx->tgt_ctx = &g_tgt_ctx;
	op_ctx->op = op;
	op_ctx->request = request;

	spdk_for_each_thread(interrupt_tgt_op_on_thread, op_ctx, rpc_op_done);
}

static void
rpc_pause_pollers(struct spdk_jsonrpc_request *request,
		  const struct spdk_json_val *params)
{
	rpc_exec_op_on_threads(request, INTERRUPT_TGT_OP_PAUSE);
}
SPDK_RPC_REGISTER("pause_pollers", rpc_pause_pollers, SPDK_RPC_RUNTIME)

static void
rpc_resume_pollers(struct spdk_jsonrpc_request *request,
		   const struct spdk_json_val *params)
{
	rpc_exec_op_on_threads(request, INTERRUPT_TGT_OP_RESUME);
}
SPDK_RPC_REGISTER("resume_pollers", rpc_resume_pollers, SPDK_RPC_RUNTIME)

static const struct spdk_json_object_decoder rpc_reactor_set_interrupt_mode_decoders[] = {
	{"lcore", offsetof(struct rpc_reactor_set_interrupt_mode, lcore), spdk_json_decode_int32},
	{"disable_interrupt", offsetof(struct rpc_reactor_set_interrupt_mode, disable_interrupt), spdk_json_decode_bool},
};

static void
rpc_reactor_set_interrupt_mode_cb(void *cb_arg)
{
	struct rpc_reactor_set_interrupt_mode *req = cb_arg;

	SPDK_NOTICELOG("complete reactor switch\n");

	spdk_jsonrpc_send_bool_response(req->request, true);
	free(req);
}

static void
set_interrupt_mode_cb(void *arg1, void *arg2)
{
	struct rpc_reactor_set_interrupt_mode *req = arg1;

	spdk_thread_send_msg(req->rpc_thread, rpc_reactor_set_interrupt_mode_cb, req);
}

static void
set_interrupt_mode(void *arg1, void *arg2)
{
	struct rpc_reactor_set_interrupt_mode *req = arg1;
	int rc;

	rc = spdk_reactor_set_interrupt_mode(req->lcore, !req->disable_interrupt,
					     set_interrupt_mode_cb, req);
	if (rc)	{
		req->rc = rc;
		set_interrupt_mode_cb(req, NULL);
	}
}

static void
rpc_reactor_set_interrupt_mode(struct spdk_jsonrpc_request *request,
			       const struct spdk_json_val *params)
{
	struct rpc_reactor_set_interrupt_mode *req;

	req = calloc(1, sizeof(*req));
	if (req == NULL) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "Out of memory");
		return;
	}

	req->request = request;
	req->rpc_thread = spdk_get_thread();

	if (spdk_json_decode_object(params, rpc_reactor_set_interrupt_mode_decoders,
				    SPDK_COUNTOF(rpc_reactor_set_interrupt_mode_decoders),
				    req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		free(req);
		return;
	}

	if (!spdk_interrupt_mode_is_enabled()) {
		SPDK_ERRLOG("Interrupt mode is not set when staring the application\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "spdk_json_decode_object failed");
		free(req);
		return;
	}


	SPDK_NOTICELOG("RPC Start to %s interrupt mode on reactor %d.\n",
		       req->disable_interrupt ? "disable" : "enable", req->lcore);
	if (req->lcore >= (int64_t)spdk_env_get_first_core() &&
	    req->lcore <= (int64_t)spdk_env_get_last_core()) {
		struct spdk_event *e;

		e = spdk_event_allocate(spdk_scheduler_get_scheduling_lcore(),
					set_interrupt_mode, req, NULL);
		spdk_event_call(e);
	} else {
		free(req);
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 "Invalid parameters");
	}
}
/* private */ SPDK_RPC_REGISTER("reactor_set_interrupt_mode", rpc_reactor_set_interrupt_mode,
				SPDK_RPC_RUNTIME)

static void
interrupt_tgt_usage(void)
{
	printf(" -E                        Set interrupt mode\n");
	printf(" -S <path>                 directory where to create vhost sockets (default: pwd)\n");
}

static int
interrupt_tgt_parse_arg(int ch, char *arg)
{
	switch (ch) {
	case 'S':
		spdk_vhost_set_socket_path(arg);
		break;
	case 'E':
		spdk_interrupt_mode_enable();
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void
interrupt_stop_done(void *ctx)
{
	struct interrupt_tgt_op_on_thread_ctx *op_ctx = ctx;
	struct interrupt_tgt_ctx *tgt_ctx = op_ctx->tgt_ctx;
	struct interrupt_tgt_poller *poller, *tmp;

	free(op_ctx);
	TAILQ_FOREACH_SAFE(poller, &tgt_ctx->pollers, link, tmp) {
		TAILQ_REMOVE(&tgt_ctx->pollers, poller, link);
		free(poller);
	}

	spdk_app_stop(tgt_ctx->rc);
}

static int
poller_noop(void *ctx)
{
	return SPDK_POLLER_BUSY;
}

static int
timer_noop(void *ctx)
{
	return SPDK_POLLER_BUSY;
}

static void
interrupt_tgt_op_on_thread(void *ctx)
{
	struct interrupt_tgt_op_on_thread_ctx *op_ctx = ctx;
	struct interrupt_tgt_ctx *tgt_ctx = op_ctx->tgt_ctx;
	struct interrupt_tgt_poller *poller, *tmp;
	struct spdk_thread *this_thread = spdk_get_thread();

	if (op_ctx->rc) {
		return;
	}

	TAILQ_FOREACH_SAFE(poller, &tgt_ctx->pollers, link, tmp) {
		if (poller->thread != this_thread) {
			continue;
		}
		switch (op_ctx->op) {
		case INTERRUPT_TGT_OP_CREATE:
			poller->busy = SPDK_POLLER_REGISTER(poller_noop, poller, 0);
			if (!poller->busy) {
				free(poller);
				op_ctx->rc = -ENOMEM;
				return;
			}
			poller->timer = SPDK_POLLER_REGISTER(timer_noop, poller, 1000);
			if (!poller->timer) {
				spdk_poller_unregister(&poller->busy);
				op_ctx->rc = -ENOMEM;
				return;
			}
			break;
		case INTERRUPT_TGT_OP_DELETE:
			spdk_poller_unregister(&poller->busy);
			spdk_poller_unregister(&poller->timer);
			spdk_thread_exit(poller->thread);
			break;
		case INTERRUPT_TGT_OP_PAUSE:
			spdk_poller_pause(poller->busy);
			spdk_poller_pause(poller->timer);
			break;
		case INTERRUPT_TGT_OP_RESUME:
			spdk_poller_resume(poller->busy);
			spdk_poller_resume(poller->timer);
			break;
		default:
			abort();
		}
		return;
	}
}

static void
interrupt_tgt_stop(int rc)
{
	struct interrupt_tgt_op_on_thread_ctx *op_ctx;

	if (rc) {
		if (g_tgt_ctx.rc == 0) {
			g_tgt_ctx.rc = rc;
		} else {
			SPDK_WARNLOG("prev rc %d, new rc %d\n", g_tgt_ctx.rc, rc);
		}
	}
	op_ctx = calloc(1, sizeof * op_ctx);
	if (!op_ctx) {
		SPDK_ERRLOG("can't allocate memory for op context, skip cleanup\n");
		spdk_app_stop(rc ? rc : -ENOMEM);
		return;
	}
	op_ctx->tgt_ctx = &g_tgt_ctx;
	op_ctx->op = INTERRUPT_TGT_OP_DELETE;

	spdk_for_each_thread(interrupt_tgt_op_on_thread, op_ctx, interrupt_stop_done);
}

static void
interrupt_tgt_shutdown(void)
{
	interrupt_tgt_stop(0);
}

static void
create_done(void *ctx)
{
	struct interrupt_tgt_op_on_thread_ctx *op_ctx = ctx;

	if (op_ctx->rc) {
		SPDK_ERRLOG("foreach thread failed, stopping app\n");
		interrupt_tgt_stop(op_ctx->rc);
	}
	free(op_ctx);
}

static void
interrupt_tgt_started(void *arg1)
{
	char thread_name[32];
	struct spdk_cpuset cpu_set;
	struct interrupt_tgt_poller *poller;
	struct interrupt_tgt_op_on_thread_ctx *op_ctx;
	struct interrupt_tgt_ctx *tgt_ctx = arg1;
	uint32_t i;

	SPDK_ENV_FOREACH_CORE(i) {
		poller = calloc(1, sizeof * poller);
		if (!poller) {
			interrupt_tgt_stop(-ENOMEM);
			return;
		}
		snprintf(thread_name, 32, "intr_thr_%u", i);
		spdk_cpuset_zero(&cpu_set);
		spdk_cpuset_set_cpu(&cpu_set, i, true);
		poller->thread = spdk_thread_create(thread_name, &cpu_set);
		if (!poller->thread) {
			SPDK_ERRLOG("Failed to create SPDK thread, core %u\n", i);
			free(poller);
			interrupt_tgt_stop(-ENOMEM);
			return;
		}
		TAILQ_INSERT_TAIL(&tgt_ctx->pollers, poller, link);
	}
	op_ctx = calloc(1, sizeof * op_ctx);
	if (!op_ctx) {
		interrupt_tgt_stop(-ENOMEM);
		return;
	}
	op_ctx->op = INTERRUPT_TGT_OP_CREATE;
	op_ctx->tgt_ctx = tgt_ctx;

	spdk_for_each_thread(interrupt_tgt_op_on_thread, op_ctx, create_done);
}

int
main(int argc, char *argv[])
{
	struct spdk_app_opts opts = {};
	int rc;

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "interrupt_tgt";
	opts.shutdown_cb = interrupt_tgt_shutdown;

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "S:E", NULL,
				      interrupt_tgt_parse_arg, interrupt_tgt_usage)) !=
	    SPDK_APP_PARSE_ARGS_SUCCESS) {
		exit(rc);
	}

	/* Blocks until the application is exiting */
	rc = spdk_app_start(&opts, interrupt_tgt_started, &g_tgt_ctx);

	spdk_app_fini();

	return rc;
}
