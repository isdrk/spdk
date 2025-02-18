/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/assert.h"
#include "spdk/util.h"
#include "spdk/lut.h"

/* SPDK_LUT_MAX_KEY_BITS must be < 64 to share the same uint64_t with the 'valid' field */
SPDK_STATIC_ASSERT(SPDK_LUT_MAX_KEY_BITS == 63, "Incorrect number of bits");

#define SPDK_LUT_MAX_SIZE ((((uint64_t)1) << SPDK_LUT_MAX_KEY_BITS) - 1)

struct spdk_lut_node {
	uint64_t valid : 1;
	/* unfortunately, uint64_t lut_key : SPDK_LUT_MAX_KEY_BITS keeps being re-formatted by astyle */
	uint64_t key : 63;
	/* NOTE: the current implementation never uses both link and ptr simultaneously.
	 * The link is only used while a node is in the free_nodes list, while the ptr is only used on insert, after
	 * we remove it from the free_nodes list and mark as valid.
	 * We utilize this understanding here, putting both the ptr and the link data members under the same union
	 * that allows us to make the node as small as 16 bytes and therefore improve the cache utilization.
	 */
	union {
		void *ptr;
		STAILQ_ENTRY(spdk_lut_node) link;
		uint64_t pad;  /* To make sure that size of this structure is a multiply of 8 */
	} u;
};

/* The sizeof(struct spdk_lut_node) must be a multiple of 8 to ensure proper alignment  */
SPDK_STATIC_ASSERT(sizeof(struct spdk_lut_node) == 16, "Incorrect size");

struct spdk_lut {
	struct spdk_lut_node *nodes;
	uint64_t num_nodes;
	uint64_t growth_step;
	uint64_t max_size;
	STAILQ_HEAD(, spdk_lut_node) free_nodes;
};

static inline size_t
lut_node_size(struct spdk_lut *lut)
{
	return sizeof(struct spdk_lut_node);
}

static inline struct spdk_lut_node *
lut_get_node(struct spdk_lut *lut, uint64_t key)
{
	return &lut->nodes[key];
}

static bool
lut_extend_unsafe(struct spdk_lut *lut, uint64_t delta)
{
	void *new_nodes;
	struct spdk_lut_node *node;
	uint64_t num_nodes = lut->num_nodes + delta;
	uint64_t i;

	if (num_nodes > lut->max_size) {
		SPDK_ERRLOG("The map size will exceed the max: %" PRIu64 " > %" PRIu64 "nodes\n",
			    num_nodes, lut->max_size);
		return false;
	}

	new_nodes = realloc(lut->nodes, num_nodes * lut_node_size(lut));
	if (!new_nodes) {
		SPDK_ERRLOG("Cannot alloc array of %" PRIu64 "nodes\n", num_nodes);
		return false;
	}

	i = lut->num_nodes;

	lut->nodes = new_nodes;
	lut->num_nodes = num_nodes;

	for (; i < num_nodes; i++) {
		node = lut_get_node(lut, i);
		node->valid = 0;
		node->key = i;
		STAILQ_INSERT_TAIL(&lut->free_nodes, node, u.link);
	}

	return true;
}

static struct spdk_lut_node *
lut_insert_unsafe(struct spdk_lut *lut, void *value)
{
	struct spdk_lut_node *node;

	if (STAILQ_EMPTY(&lut->free_nodes) && !lut_extend_unsafe(lut, lut->growth_step)) {
		return NULL;
	}

	node = STAILQ_FIRST(&lut->free_nodes);
	STAILQ_REMOVE_HEAD(&lut->free_nodes, u.link);
	node->valid = 1;
	node->u.ptr = value;

	return node;
}

struct spdk_lut *
spdk_lut_create(uint64_t init_size, uint64_t growth_step, uint64_t max_size)
{
	struct spdk_lut *lut;

	if (max_size < init_size || max_size > SPDK_LUT_MAX_SIZE) {
		SPDK_ERRLOG("Invalid sizes: init=%" PRIu64 " max=%" PRIu64 "\n", init_size, max_size);
		return NULL;
	}

	lut = calloc(1, sizeof(*lut));
	if (!lut) {
		SPDK_ERRLOG("Cannot alloc array object\n");
		return NULL;
	}

	STAILQ_INIT(&lut->free_nodes);
	lut->max_size = max_size;

	if (!lut_extend_unsafe(lut, init_size)) {
		SPDK_ERRLOG("Cannot create array of %" PRIu64 "objects\n", init_size);
		free(lut);
		return NULL;
	}

	lut->growth_step = growth_step;

	return lut;
}

uint64_t
spdk_lut_insert(struct spdk_lut *lut, void *value)
{
	struct spdk_lut_node *node;
	uint64_t key = SPDK_LUT_INVALID_KEY;

	node = lut_insert_unsafe(lut, value);
	if (node) {
		key = node->key;
	}

	return key;
}

int
spdk_lut_insert_at(struct spdk_lut *lut, void *value, uint64_t key)
{
	struct spdk_lut_node *node;

	assert(key < lut->max_size);

	if (key > lut->num_nodes) {
		if (!lut_extend_unsafe(lut, spdk_divide_round_up(key, lut->growth_step) - lut->num_nodes)) {
			return -ENOMEM;
		}
	}

	node = lut_get_node(lut, key);
	if (node->valid) {
		return -EALREADY;
	}

	STAILQ_REMOVE(&lut->free_nodes, node, spdk_lut_node, u.link);

	node->valid = 1;
	node->u.ptr = value;

	return 0;
}


void *
spdk_lut_get(struct spdk_lut *lut, uint64_t key)
{
	struct spdk_lut_node *node;
	void *value = SPDK_LUT_INVALID_VALUE;

	if (key < lut->num_nodes) {
		node = lut_get_node(lut, key);
		if (node->valid) {
			value = node->u.ptr;
		}
	}

	return value;
}

int
spdk_lut_foreach(struct spdk_lut *lut, spdk_lut_foreach_cb cb_fn, void *cb_arg)
{
	struct spdk_lut_node *node;
	uint64_t key;
	int rc = 0;

	for (key = 0; key < lut->num_nodes ; key++) {
		node = lut_get_node(lut, key);

		if (!node->valid) {
			continue;
		}

		rc = cb_fn(cb_arg, key, node->u.ptr);
		if (rc) {
			break;
		}
	}

	return rc;
}

int
spdk_lut_remove(struct spdk_lut *lut, uint64_t key)
{
	struct spdk_lut_node *node;
	bool rc = -ENOENT;

	if (key < lut->num_nodes) {
		node = lut_get_node(lut, key);
		if (node->valid) {
			node->valid = 0;
			STAILQ_INSERT_TAIL(&lut->free_nodes, node, u.link);
			rc = 0;
		}
	}

	return rc;
}

void
spdk_lut_free(struct spdk_lut *lut)
{
	free(lut->nodes);
	free(lut);
}
