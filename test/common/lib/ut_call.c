/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk_internal/cunit.h"

#ifndef UT_NUM_THREADS
#error "UT_NUM_THREADS is not defined"
#endif

#define UT_CALL_REC_MAX_CALLS (UT_NUM_THREADS * 5)
#define UT_CALL_REC_MAX_PARAMS 15
#define UT_CALL_REC_MAX_STR_SIZE 255

static uint64_t
ut_hash(const void *buf, size_t size)
{
	uint64_t hash = 5381;
	const char *p = buf;
	size_t i;

	for (i = 0; i < size; i++) {
		hash = ((hash << 5) + hash) + (*p); /* hash * 33 + c */
		p++;
	}

	return hash;
}

struct ut_call_record {
	struct {
		void *func;
		union {
			uint64_t integer;
			void *ptr;
			char str[UT_CALL_REC_MAX_STR_SIZE + 1];
			uint64_t hash;
		} params[UT_CALL_REC_MAX_PARAMS];
		size_t param_count;
	} call[UT_CALL_REC_MAX_CALLS];
	size_t count;
};

static struct ut_call_record g_call_list;

static inline void
ut_calls_reset(void)
{
	memset(&g_call_list, 0, sizeof(g_call_list));
}

static inline void
ut_call_record_begin(void *pfunc)
{
	SPDK_CU_ASSERT_FATAL(g_call_list.count < UT_CALL_REC_MAX_CALLS);
	g_call_list.call[g_call_list.count].func = pfunc;
	g_call_list.call[g_call_list.count].param_count = 0;
}

static inline void
ut_call_record_param_int(uint64_t val)
{
	SPDK_CU_ASSERT_FATAL(g_call_list.call[g_call_list.count].param_count < UT_CALL_REC_MAX_PARAMS);
	g_call_list.call[g_call_list.count].params[g_call_list.call[g_call_list.count].param_count].integer
		= val;
	g_call_list.call[g_call_list.count].param_count++;
}

static inline void
ut_call_record_param_ptr(void *ptr)
{
	SPDK_CU_ASSERT_FATAL(g_call_list.call[g_call_list.count].param_count < UT_CALL_REC_MAX_PARAMS);
	g_call_list.call[g_call_list.count].params[g_call_list.call[g_call_list.count].param_count].ptr =
		ptr;
	g_call_list.call[g_call_list.count].param_count++;
}

static inline void
ut_call_record_param_str(const char *str)
{
	SPDK_CU_ASSERT_FATAL(g_call_list.call[g_call_list.count].param_count < UT_CALL_REC_MAX_PARAMS);
	spdk_strcpy_pad(
		g_call_list.call[g_call_list.count].params[g_call_list.call[g_call_list.count].param_count].str,
		str, UT_CALL_REC_MAX_STR_SIZE, 0);
	g_call_list.call[g_call_list.count].params[g_call_list.call[g_call_list.count].param_count].str[UT_CALL_REC_MAX_STR_SIZE]
		= 0;
	g_call_list.call[g_call_list.count].param_count++;
}

static inline void
ut_call_record_param_hash(const void *buf, size_t size)
{
	SPDK_CU_ASSERT_FATAL(g_call_list.call[g_call_list.count].param_count < UT_CALL_REC_MAX_PARAMS);
	g_call_list.call[g_call_list.count].params[g_call_list.call[g_call_list.count].param_count].hash =
		ut_hash(buf, size);
	g_call_list.call[g_call_list.count].param_count++;
}

static inline size_t
ut_call_record_get_current_param_count(void)
{
	return g_call_list.call[g_call_list.count].param_count;
}
static inline void
ut_call_record_end(void)
{
	g_call_list.count++;
}

static inline void
ut_call_record_simple_param_ptr(void *pfunc, void *ptr)
{
	ut_call_record_begin(pfunc);
	ut_call_record_param_ptr(ptr);
	ut_call_record_end();
}

static inline size_t
ut_calls_get_call_count(void)
{
	return g_call_list.count;
}

static inline size_t
ut_calls_get_param_count(size_t call_idx)
{
	SPDK_CU_ASSERT_FATAL(call_idx < g_call_list.count);
	return g_call_list.call[call_idx].param_count;
}

static inline void *
ut_calls_get_func(size_t call_idx)
{
	SPDK_CU_ASSERT_FATAL(call_idx < g_call_list.count);
	return g_call_list.call[call_idx].func;
}

static inline uint64_t
ut_calls_param_get_int(size_t call_idx, size_t param_idx)
{
	SPDK_CU_ASSERT_FATAL(call_idx < g_call_list.count);
	SPDK_CU_ASSERT_FATAL(param_idx < g_call_list.call[call_idx].param_count);
	return g_call_list.call[call_idx].params[param_idx].integer;
}

static inline void *
ut_calls_param_get_ptr(size_t call_idx, size_t param_idx)
{
	SPDK_CU_ASSERT_FATAL(call_idx < g_call_list.count);
	SPDK_CU_ASSERT_FATAL(param_idx < g_call_list.call[call_idx].param_count);
	return g_call_list.call[call_idx].params[param_idx].ptr;
}

static inline const char *
ut_calls_param_get_str(size_t call_idx, size_t param_idx)
{
	SPDK_CU_ASSERT_FATAL(call_idx < g_call_list.count);
	SPDK_CU_ASSERT_FATAL(param_idx < g_call_list.call[call_idx].param_count);
	return g_call_list.call[call_idx].params[param_idx].str;
}

static inline uint64_t
ut_calls_param_get_hash(size_t call_idx, size_t param_idx)
{
	SPDK_CU_ASSERT_FATAL(call_idx < g_call_list.count);
	SPDK_CU_ASSERT_FATAL(param_idx < g_call_list.call[call_idx].param_count);
	return g_call_list.call[call_idx].params[param_idx].hash;
}
