/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"
#include "spdk/barrier.h"
#include "spdk/log.h"
#include "spdk/assert.h"
#include "spdk/util.h"
#include "spdk/lut.h"

/* SPDK_LUT_MAX_KEY_BITS must be < 64 to share the same uint64_t with the 'valid' field */
SPDK_STATIC_ASSERT(SPDK_LUT_MAX_KEY_BITS == 63, "Incorrect number of bits");

#define SPDK_LUT_MAX_SIZE ((((uint64_t)1) << SPDK_LUT_MAX_KEY_BITS) - 1)

#define SPDK_LUT_SET_SIZE 1024

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

struct spdk_lut_node_set {
	struct spdk_lut_node nodes[SPDK_LUT_SET_SIZE];
	struct spdk_lut_node_set *next;
};

struct spdk_lut {
	struct spdk_lut_node_set node_set;
	uint64_t num_nodes;
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
	struct spdk_lut_node_set *set;
	uint64_t remainder = key;

	set = &lut->node_set;
	while (remainder >= SPDK_LUT_SET_SIZE) {
		set = set->next;
		if (set == NULL) {
			return NULL;
		}
		remainder -= SPDK_LUT_SET_SIZE;
	}

	return &set->nodes[remainder];
}

static bool
lut_extend_unsafe(struct spdk_lut *lut)
{
	struct spdk_lut_node_set *set, *new_set;
	struct spdk_lut_node *node;
	uint64_t i;

	if (lut->num_nodes + SPDK_LUT_SET_SIZE > lut->max_size) {
		SPDK_ERRLOG("The map size will exceed the max: %" PRIu64 " > %" PRIu64 "nodes\n",
			    lut->num_nodes + SPDK_LUT_SET_SIZE, lut->max_size);
		return false;
	}

	set = &lut->node_set;
	while (set->next != NULL) {
		set = set->next;
	}

	new_set = calloc(1, sizeof(*new_set));
	if (!new_set) {
		SPDK_ERRLOG("Cannot alloc new node set\n");
		return false;
	}

	for (i = 0; i < SPDK_LUT_SET_SIZE; i++) {
		node = &new_set->nodes[i];
		node->valid = 0;
		node->key = lut->num_nodes + i;
		STAILQ_INSERT_TAIL(&lut->free_nodes, node, u.link);
	}

	lut->num_nodes += SPDK_LUT_SET_SIZE;

	/* Barrier here so that next isn't shown as non-NULL before
	 * all of the above stuff has completed. */
	spdk_wmb();

	set->next = new_set;

	return true;
}

static struct spdk_lut_node *
lut_insert_unsafe(struct spdk_lut *lut, void *value)
{
	struct spdk_lut_node *node;

	if (STAILQ_EMPTY(&lut->free_nodes) && !lut_extend_unsafe(lut)) {
		return NULL;
	}

	node = STAILQ_FIRST(&lut->free_nodes);
	STAILQ_REMOVE_HEAD(&lut->free_nodes, u.link);
	node->u.ptr = value;

	/* Barrier here so that 'valid' isn't shown as 1 before
	 * all of the above stuff has completed. */
	spdk_wmb();

	node->valid = 1;

	return node;
}

struct spdk_lut *
spdk_lut_create(uint64_t init_size, uint64_t growth_step, uint64_t max_size)
{
	struct spdk_lut *lut;
	struct spdk_lut_node_set *set;
	struct spdk_lut_node *node;
	uint64_t i;

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

	set = &lut->node_set;
	for (i = 0; i < SPDK_LUT_SET_SIZE; i++) {
		node = &set->nodes[i];
		node->valid = 0;
		node->key = i;
		STAILQ_INSERT_TAIL(&lut->free_nodes, node, u.link);
	}

	lut->num_nodes = SPDK_LUT_SET_SIZE;

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

void *
spdk_lut_get(struct spdk_lut *lut, uint64_t key)
{
	struct spdk_lut_node *node;
	void *value = SPDK_LUT_INVALID_VALUE;

	if (key < lut->num_nodes) {
		node = lut_get_node(lut, key);
		if (node->valid) {

			/* Barrier here so that our read of 'ptr' never reorders with our
			 * read of 'valid'. This probably is not necessary because
			 * most architectures strictly order reads and the writes
			 * have been ordered by other barriers, but it'll just be
			 * a no-op in that case. */
			spdk_rmb();

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

		/* Barrier here so that our read of 'ptr' never reorders with our
		 * read of 'valid'. This probably is not necessary because
		 * most architectures strictly order reads and the writes
		 * have been ordered by other barriers, but it'll just be
		 * a no-op in that case. */
		spdk_rmb();

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
	struct spdk_lut_node_set *set, *next;

	set = &lut->node_set;

	set = set->next;
	while (set) {
		next = set->next;
		free(set);
		set = next;
	}

	free(lut);
}
