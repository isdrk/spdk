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
//#include "rdma.h"
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
            SPDK_NOTICELOG("Ankit: \n");
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

/*
static int
io_pacer_poll(void *arg)
{
	struct spdk_io_pacer *pacer = arg;
	struct io_pacer_queue_entry *entry;
	uint32_t next_queue = pacer->next_queue;
	int rc = 0;
	uint32_t ops_in_flight = 0;

	const uint64_t cur_tick = spdk_get_ticks();
	const uint64_t ticks_diff = cur_tick - pacer->last_tick;

	uint32_t attempts_cnt = 0;

#ifdef SPDK_CONFIG_VTUNE
	static __thread uint64_t poll_cnt;
	poll_cnt++;
	if (poll_cnt % 100 == 0)
		__itt_task_begin(io_pacer_domain, __itt_null, __itt_null, io_pacer_poll_task);
#endif

	pacer->stat.calls++;
	if (ticks_diff < pacer->period_ticks) {
		return 0;
	}
	pacer->stat.total_ticks = cur_tick - pacer->first_tick;
	pacer->last_tick = cur_tick - ticks_diff % pacer->period_ticks;
	pacer->stat.polls++;

	pacer->remaining_credit = spdk_min(pacer->remaining_credit + pacer->credit,
					   pacer->credit);

	if (pacer->num_ios == 0) {
		pacer->stat.no_ios++;
	}

	while ((pacer->num_ios > 0) &&
	       (pacer->remaining_credit > 0) &&
	       (attempts_cnt < pacer->num_queues)) {
		next_queue %= pacer->num_queues;
		attempts_cnt++;

		if (pacer->disk_credit) {
			ops_in_flight = rte_atomic32_read(&pacer->queues[next_queue].stats->ops_in_flight);
			if (ops_in_flight > pacer->disk_credit) {
				next_queue++;
				continue;
			}
		}
		entry = STAILQ_FIRST(&pacer->queues[next_queue].queue);
		next_queue++;
		if (entry != NULL) {
			STAILQ_REMOVE_HEAD(&pacer->queues[next_queue - 1].queue, link);
			pacer->num_ios--;
			pacer->next_queue = next_queue;
			pacer->remaining_credit -= entry->size;
			pacer->stat.ios++;
			pacer->stat.bytes += entry->size;
			rte_atomic32_add(&pacer->queues[next_queue - 1].stats->ops_in_flight, 1);
			pacer->pop_cb(entry);
			rc++;
			attempts_cnt = 0;
		}
	}

#ifdef  SPDK_CONFIG_VTUNE
	if (poll_cnt % 100 == 0)
		__itt_task_end(io_pacer_domain);
#endif

	return rc;
}
//*/

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
	//pacer->poller = SPDK_POLLER_REGISTER(io_pacer_poll, (void *)pacer, 0);
    
    /* Required for slow disc algo. */
    //pacer->start_pacer_at_startup = 1;
    pacer->pacer_iteration_number = 1;
    pacer->disk_start_index = 0;
    pacer->take_average_after_count = MAX_ITERATION_TO_COMPUTE_AVERAGE;
    pacer->max_allowed_mem = BF2_CACHE_SIZE;
    ////rte_spinlock_init(&pacer->lock_for_starting_pacer);
    ////
    ////if (custom_max_iteration_to_compute_average < MAX_ITERATION_TO_COMPUTE_AVERAGE) {
    ////    pacer->average_after_count = custom_max_iteration_to_compute_average;
    ////}

    /* How can I globally initalize slow_disk_var_initialization?
     * One thought is to control via config files. ~Ankit */
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

	//spdk_poller_unregister(&pacer->poller);
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
            SPDK_NOTICELOG("Ankit: \n");
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
        // Wil pointer initialization be good for atomic64_set or I need to take lock? ~Ankit
		// rte_atomic64_set(&pacer->queues, new_queues);
		rte_atomic64_set(&pacer->max_queues, new_max_queues);
		SPDK_NOTICELOG("Allocated more queues for IO pacer %p: max_queues.cnt %u\n",
			       pacer, pacer->max_queues.cnt);
	}

	rte_atomic64_set(&pacer->queues[pacer->num_queues.cnt].key, key);
	STAILQ_INIT(&pacer->queues[pacer->num_queues.cnt].queue);
	spdk_io_pacer_drive_stats_setup(&drives_stats, MAX_DRIVES_STATS);
    uint64_t disk_stats = spdk_io_pacer_drive_stats_get(&drives_stats, key);
	//rte_atomic64_set(&pacer->queues[pacer->num_queues.cnt].stats, disk_stats);
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

            SPDK_NOTICELOG("Ankit: \n");
	assert(pacer != NULL);
	assert(entry != NULL);

	queue = io_pacer_get_queue(pacer, key);
	if (spdk_unlikely(queue == NULL)) {
		SPDK_ERRLOG("IO pacer queue not found: key %016lx\n", key);
		return -1;
	}

            SPDK_NOTICELOG("Ankit: \n");
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

/*
static int
io_pacer_tune(void *arg)
{
	struct spdk_io_pacer_tuner *tuner = arg;
	struct spdk_io_pacer *pacer = tuner->pacer;
	const uint64_t ticks_hz = spdk_get_ticks_hz();
	const uint64_t bytes = pacer->stat.bytes - tuner->last_bytes;
	// * We do calculations in terms of credit sized IO * /
	const uint64_t io_period_ns = tuner->period_ns / ((bytes != 0) ? (bytes / pacer->credit) : 1);

	const uint64_t cur_period_ns = (pacer->period_ticks * SPDK_SEC_TO_NSEC) / ticks_hz;
	// * We always want to set pacer period one step shorter than measured IO period.
	// * But we limit changes to one step at a time in any direction.
	// * /
	uint64_t new_period_ns = io_period_ns - tuner->step_ns;
	if (new_period_ns > cur_period_ns + tuner->step_ns) {
		new_period_ns = cur_period_ns + tuner->step_ns;
	} else if (new_period_ns < cur_period_ns - tuner->step_ns) {
		new_period_ns = cur_period_ns - tuner->step_ns;
	}

	uint64_t new_period_ticks = (new_period_ns * ticks_hz) / SPDK_SEC_TO_NSEC;
	new_period_ticks = spdk_max(spdk_min(new_period_ticks, tuner->max_pacer_period_ticks),
				    tuner->min_pacer_period_ticks);

	static __thread uint32_t log_counter = 0;
	// * Try to log once per second * /
	if (log_counter % (SPDK_SEC_TO_NSEC / tuner->period_ns) == 0) {
		SPDK_NOTICELOG("IO pacer tuner %p: pacer %p, bytes %lu, io period %lu ns, new period %lu ns, new period %lu ticks, min %lu, max %lu\n",
			       tuner,
			       pacer,
			       pacer->stat.bytes - tuner->last_bytes,
			       io_period_ns,
			       new_period_ns,
			       new_period_ticks,
			       tuner->min_pacer_period_ticks,
			       tuner->max_pacer_period_ticks);
	}
	log_counter++;

	pacer->period_ticks = new_period_ticks;
	tuner->last_bytes = pacer->stat.bytes;

	return 1;
}
//*/

/*
struct spdk_io_pacer_tuner *
spdk_io_pacer_tuner_create(struct spdk_io_pacer *pacer,
			   uint32_t period_us,
			   uint32_t step_ns)
{
	struct spdk_io_pacer_tuner *tuner;

	assert(pacer != NULL);

	tuner = (struct spdk_io_pacer_tuner *)calloc(1, sizeof(struct spdk_io_pacer_tuner));
	if (!tuner) {
		SPDK_ERRLOG("Failed to allocate IO pacer tuner\n");
		return NULL;
	}

	tuner->pacer = pacer;
	tuner->period_ns = 1000ULL * period_us;
	tuner->step_ns = step_ns;
	tuner->min_pacer_period_ticks = pacer->period_ticks;
	tuner->max_pacer_period_ticks = 2 * tuner->min_pacer_period_ticks;

	if (0 != period_us) {
		tuner->poller = SPDK_POLLER_REGISTER(io_pacer_tune, (void *)tuner, period_us);
		if (!tuner->poller) {
			SPDK_ERRLOG("Failed to create tuner poller for IO pacer\n");
			spdk_io_pacer_tuner_destroy(tuner);
			return NULL;
		}
	}

	SPDK_NOTICELOG("Created IO pacer tuner %p: pacer %p, period_ns %lu, step_ns %lu, min_pacer_period_ticks %lu, max_pacer_period_ticks %lu\n",
		       tuner,
		       pacer,
		       tuner->period_ns,
		       tuner->step_ns,
		       tuner->min_pacer_period_ticks,
		       tuner->max_pacer_period_ticks);

	return tuner;
}
//*/

/*
void
spdk_io_pacer_tuner_destroy(struct spdk_io_pacer_tuner *tuner)
{
	assert(tuner != NULL);

	spdk_poller_unregister(&tuner->poller);
	free(tuner);
	SPDK_NOTICELOG("Destroyed IO pacer tuner %p\n", tuner);
}
//*/

/*
struct spdk_io_pacer_tuner2 {
	struct spdk_io_pacer *pacer;
	uint64_t period_ns;
	uint32_t value;
	uint32_t min_threshold;
	uint64_t factor;
	uint64_t min_pacer_period_ticks;
	uint64_t max_pacer_period_ticks;
	struct spdk_poller *poller;
};
//*/

/*
static int
io_pacer_tune2(void *arg)
{
	struct spdk_io_pacer_tuner2 *tuner = arg;
	struct spdk_io_pacer *pacer = tuner->pacer;
	uint32_t v = tuner->value;

	uint64_t new_period_ticks = (v <= tuner->min_threshold) ?
		tuner->min_pacer_period_ticks :
		(v - tuner->min_threshold) * tuner->factor / 1000 + tuner->min_pacer_period_ticks;
	new_period_ticks = spdk_min(new_period_ticks, tuner->max_pacer_period_ticks);

	static __thread uint32_t log_counter = 0;
	// * Try to log once per second * /
	if (log_counter % (SPDK_SEC_TO_NSEC / tuner->period_ns) == 0) {
		SPDK_NOTICELOG("IO pacer tuner %p: pacer %p, value %u, new period %lu ticks, min %lu, polls %u. ios %u\n",
			       tuner,
			       pacer,
			       v,
			       new_period_ticks,
			       tuner->min_pacer_period_ticks,
			       pacer->stat.polls,
			       pacer->stat.ios);
	}
	log_counter++;

	pacer->period_ticks = new_period_ticks;

	return 1;
}
//*/

/*
struct spdk_io_pacer_tuner2 *
spdk_io_pacer_tuner2_create(struct spdk_io_pacer *pacer,
			    uint32_t period_us,
			    uint32_t min_threshold,
			    uint64_t factor)
{
	struct spdk_io_pacer_tuner2 *tuner;

	assert(pacer != NULL);

	tuner = (struct spdk_io_pacer_tuner2 *)calloc(1, sizeof(struct spdk_io_pacer_tuner2));
	if (!tuner) {
		SPDK_ERRLOG("Failed to allocate IO pacer tuner\n");
		return NULL;
	}

	tuner->pacer = pacer;
	tuner->period_ns = 1000ULL * period_us;
	tuner->value = 0;
	tuner->min_threshold = min_threshold;
	tuner->factor = factor;
	tuner->min_pacer_period_ticks = pacer->period_ticks;
	tuner->max_pacer_period_ticks = 4 * tuner->min_pacer_period_ticks;

	if (0 != period_us) {
		tuner->poller = SPDK_POLLER_REGISTER(io_pacer_tune2, (void *)tuner, period_us);
		if (!tuner->poller) {
			SPDK_ERRLOG("Failed to create tuner poller for IO pacer\n");
			spdk_io_pacer_tuner2_destroy(tuner);
			return NULL;
		}
	}

	SPDK_NOTICELOG("Created IO pacer tuner %p: pacer %p, period_ns %lu, threshold %u, factor %lu\n",
		       tuner,
		       pacer,
		       tuner->period_ns,
		       tuner->min_threshold,
		       tuner->factor);

	return tuner;
}
//*/

/*
void
spdk_io_pacer_tuner2_destroy(struct spdk_io_pacer_tuner2 *tuner)
{
	assert(tuner != NULL);

	spdk_poller_unregister(&tuner->poller);
	free(tuner);
	SPDK_NOTICELOG("Destroyed IO pacer tuner %p\n", tuner);
}
//*/

/*
void
spdk_io_pacer_tuner2_add(struct spdk_io_pacer_tuner2 *tuner, uint32_t value)
{
	assert(tuner != NULL);
	tuner->value += value;
}
//*/

/*
void
spdk_io_pacer_tuner2_sub(struct spdk_io_pacer_tuner2 *tuner, uint32_t value)
{
	assert(tuner != NULL);
	tuner->value -= value;
}
//*/
