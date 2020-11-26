/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2020 Mellanox Technologies LTD. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spdk/config.h"
#include "io_pacer.h"
#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/likely.h"
#include "spdk_internal/assert.h"
#include "spdk_internal/log.h"

#define IO_PACER_DEFAULT_MAX_QUEUES 32

#ifdef SPDK_CONFIG_VTUNE
#include <ittnotify.h>
extern __itt_string_handle *io_pacer_poll_task;
extern __itt_domain *io_pacer_domain;
#endif /* SPDK_CONFIG_VTUNE */


#define MAX_DRIVES_STATS 256
static rte_spinlock_t drives_stats_create_lock = RTE_SPINLOCK_INITIALIZER;
struct spdk_io_pacer_drives_stats drives_stats = {0};


static struct io_pacer_queue *
io_pacer_get_queue(struct spdk_io_pacer_shared *pacer, uint64_t key)
{
	uint32_t i;
	for (i = 0; i < pacer->num_queues.cnt; ++i) {
		if (pacer->queues[i].key.cnt == key) {
			return &pacer->queues[i];
		}
	}

	/* @todo: Creating queue on demand due to limitations in rdma transport.
	 * To be removed.
	 */
	if (0 != spdk_io_pacer_create_queue(pacer, key)) {
		return NULL;
	}

	return io_pacer_get_queue(pacer, key);
}

struct spdk_io_pacer *
spdk_io_pacer_create(spdk_io_pacer_shared *pacer_shared, uint32_t period_ns,
		     uint32_t credit,
		     uint32_t disk_credit,
		     spdk_io_pacer_pop_cb pop_cb)
{
	struct spdk_io_pacer *pacer;
    uint32_t i, j;

	assert(pop_cb != NULL);
	assert(pacer_shared != NULL);

	pacer = (struct spdk_io_pacer *)calloc(1, sizeof(struct spdk_io_pacer));
	if (!pacer) {
		SPDK_ERRLOG("Failed to allocate IO pacer\n");
		return NULL;
	}

	/* @todo: may overflow? */
	pacer->period_ticks = (period_ns * spdk_get_ticks_hz()) / SPDK_SEC_TO_NSEC;
	pacer->credit = credit;
	pacer->disk_credit = disk_credit;
	pacer->pop_cb = pop_cb;
	pacer->first_tick = spdk_get_ticks();
	pacer->last_tick = spdk_get_ticks();
    
    /* Required for slow disc algo. */
    //pacer->start_pacer_at_startup = 1;
    pacer->pacer_iteration_number = 1;
    pacer->disk_start_index = 0;
    pacer->take_average_after_count = MAX_ITERATION_TO_COMPUTE_AVERAGE;
    //pacer->max_allowed_mem = BF2_CACHE_SIZE;

    if ( ! pacer_shared->slow_disk_var_initialization.cnt) {
        rte_spinlock_lock(&pacer_shared->lock_for_pacer_initialization);
            pacer_shared->slow_disk_var_initialization.cnt = 1;
            pacer_shared->max_queues.cnt = 64000 * 96;
            pacer_shared->num_queues.cnt = 0;
            pacer_shared->next_queue.cnt = 0;
            //pacer_shared->current_lock_priority = 0;
            //rte_spinlock_init(&pacer_shared->lock_for_priority);
            pacer_shared->total_allocated_mem.cnt = 0;
            pacer->last_scheduling_disk_index = 0;
            pacer_shared->max_number_of_supported_disks.cnt = MAX_SUPPORTED_DISKS;
            pacer_shared->number_of_inserted_disks.cnt = MAX_SUPPORTED_DISKS;
            rte_spinlock_init(&pacer_shared->lock_for_total_allocated_mem);
            pacer_shared->current_data_and_time_index.cnt = 0;
            //for (i = 0; i < MAX_SUPPORTED_DISKS; i++) {
            for (i = 0; i < pacer_shared->max_number_of_supported_disks.cnt; i++) {
                rte_spinlock_init(&pacer_shared->lock_per_disk[i]);
                rte_spinlock_init(&pacer_shared->lock_per_queue[i]);
                pacer_shared->per_disk_used_buffer[i].cnt = 0;
                pacer_shared->disk_speeds[i].cnt = AVG_5GbPS_DISK_SPEED; //Take from bdev. ~Ankit
                pacer_shared->per_disk_max_buffer[i].cnt = MAX_ALLOCATION_SIZE_PER_DISK; //Check how to find inserted disks. Can be equal to max_nsid. ~Ankit
                //if(pacer->num_queues.cnt < (MAX_SUPPORTED_DISKS / 2)) {
                if(pacer_shared->number_of_inserted_disks.cnt < (MAX_SUPPORTED_DISKS / 2)) {
                    pacer_shared->per_disk_max_buffer[i].cnt = 2 * BF2_CACHE_SIZE / (MAX_SUPPORTED_DISKS / 2); //Check how to find inserted disks. Can be equal to max_nsid ~Ankit
                }
                for (j = 0; j < pacer->take_average_after_count; j++) {
                    pacer_shared->per_disk_data_transfered[i][j].cnt = 0;
                    pacer_shared->per_disk_time_taken_to_transfer[i][j].cnt = 0;
                }
                SPDK_NOTICELOG("Created IO pacer %p: max_queues.cnt %u, core %u, pacer_shared->per_disk_used_buffer.cnt[i]: %d, pacer_shared->per_disk_max_buffer[i].cnt: %d\n",
                                pacer, pacer_shared->max_queues.cnt, spdk_env_get_current_core(),
                                pacer_shared->per_disk_used_buffer[i].cnt, pacer_shared->per_disk_max_buffer[i].cnt);
            }
        rte_spinlock_unlock(&pacer_shared->lock_for_pacer_initialization);
    }


	SPDK_NOTICELOG("Created IO pacer %p: period_ns %u, period_ticks %lu, max_queues.cnt %u, core %u, BF2_CACHE_SIZE: %d, MAX_SUPPORTED_DISKS: %d\n",
                   pacer, period_ns, pacer->period_ticks, pacer_shared->max_queues.cnt,
                   spdk_env_get_current_core(), BF2_CACHE_SIZE, MAX_SUPPORTED_DISKS);

	return pacer;
}

void
spdk_io_pacer_destroy(struct spdk_io_pacer_shared *pacer)
{
	uint32_t i;

	assert(pacer != NULL);

	/* Check if we have something in the queues */
	for (i = 0; i < pacer->num_queues.cnt; ++i) {
		if (!STAILQ_EMPTY(&pacer->queues[i].queue)) {
			SPDK_WARNLOG("IO pacer queue is not empty on pacer destroy: pacer %p, key.cnt %016lx\n",
				     pacer, pacer->queues[i].key.cnt);
		}
	}

	free(pacer->queues);
	free(pacer);
	SPDK_NOTICELOG("Destroyed IO pacer %p\n", pacer);
}

void spdk_io_pacer_drive_stats_setup(struct spdk_io_pacer_drives_stats *stats, int32_t entries)
{
	struct rte_hash_parameters hash_params = {
		.name = "DRIVE_STATS",
		.entries = entries,
		.key_len = sizeof(uint64_t),
		.socket_id = rte_socket_id(),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
	};
	struct rte_hash *h = NULL;

	if (stats->h != NULL) {
		return;
	}

	rte_spinlock_lock(&drives_stats_create_lock);
	if (stats->h != NULL) {
		goto exit;
	}

	h = rte_hash_create(&hash_params);
	if (h == NULL) {
		SPDK_ERRLOG("IO pacer can't create drive statistics dict\n");
	}

	stats->h = h;
	rte_spinlock_init(&stats->lock);
	SPDK_NOTICELOG("Drives stats setup done\n");

 exit:
	rte_spinlock_unlock(&drives_stats_create_lock);
}

int
spdk_io_pacer_create_queue(struct spdk_io_pacer_shared *pacer, uint64_t key)
{
	assert(pacer != NULL);

	if (pacer->num_queues.cnt <= 0 || pacer->num_queues.cnt >= pacer->max_queues.cnt) {
		const uint64_t new_max_queues = pacer->max_queues.cnt ?
			2 * pacer->max_queues.cnt : IO_PACER_DEFAULT_MAX_QUEUES;
		struct io_pacer_queue *new_queues =
			(struct io_pacer_queue *)realloc(pacer->queues,
							 new_max_queues * sizeof(*pacer->queues));
		if (!new_queues) {
			SPDK_NOTICELOG("Failed to allocate more queues for IO pacer %p: max_queues %u\n",
				       pacer, new_max_queues);
			return -1;
		}

		pacer->queues = new_queues;
        // Will pointer initialization be good for atomic64_set or I need to take lock? ~Ankit
		// rte_atomic64_set(&pacer->queues, new_queues);
		rte_atomic64_set(&pacer->max_queues, new_max_queues);
		SPDK_NOTICELOG("Allocated more queues for IO pacer %p: max_queues.cnt %u\n",
			       pacer, pacer->max_queues.cnt);
	}

	rte_atomic64_set(&pacer->queues[pacer->num_queues.cnt].key, key);
	STAILQ_INIT(&pacer->queues[pacer->num_queues.cnt].queue);
	spdk_io_pacer_drive_stats_setup(&drives_stats, MAX_DRIVES_STATS);
    uint64_t disk_stats = spdk_io_pacer_drive_stats_get(&drives_stats, key); // Currently not using. ~Ankit
	rte_atomic64_set(&pacer->num_queues, pacer->num_queues.cnt + 1);
	SPDK_NOTICELOG("Created IO pacer queue: pacer %p, key %016lx\n",
		       pacer, key);

	return 0;
}

int
spdk_io_pacer_destroy_queue(struct spdk_io_pacer_shared *pacer, uint64_t key)
{
	uint32_t i;

	assert(pacer != NULL);

	for (i = 0; i < pacer->num_queues.cnt; ++i) {
		if (pacer->queues[i].key.cnt == key) {
			if (!STAILQ_EMPTY(&pacer->queues[i].queue)) {
				SPDK_WARNLOG("Destroying non empty IO pacer queue: key %016lx\n", key);
			}

			memmove(&pacer->queues[i], &pacer->queues[i + 1],
				(pacer->num_queues.cnt - i - 1) * sizeof(struct io_pacer_queue));
			pacer->num_queues.cnt--;
			SPDK_NOTICELOG("Destroyed IO pacer queue: pacer %p, key %016lx\n",
				       pacer, key);
			return 0;
		}
	}

	SPDK_ERRLOG("IO pacer queue not found: key %016lx\n", key);
	return -1;
}

int
spdk_io_pacer_push(struct spdk_io_pacer_shared *pacer, uint64_t key, struct io_pacer_queue_entry *entry)
{
	struct io_pacer_queue *queue;

	assert(pacer != NULL);
	assert(entry != NULL);

	queue = io_pacer_get_queue(pacer, key);
	if (spdk_unlikely(queue == NULL)) {
		SPDK_ERRLOG("IO pacer queue not found: key %016lx\n", key);
		return -1;
	}

	STAILQ_INSERT_TAIL(&queue->queue, entry, link);
	return 0;
}

void
spdk_io_pacer_get_stat(const struct spdk_io_pacer *pacer,
		       struct spdk_nvmf_transport_poll_group_stat *stat)
{
	if (pacer && stat) {
		stat->io_pacer.total_ticks = pacer->stat.total_ticks;
		stat->io_pacer.polls = pacer->stat.polls;
		stat->io_pacer.ios = pacer->stat.ios;
		stat->io_pacer.bytes = pacer->stat.bytes;
		stat->io_pacer.calls = pacer->stat.calls;
		stat->io_pacer.no_ios = pacer->stat.no_ios;
		stat->io_pacer.period_ticks = pacer->period_ticks;
	}
}

