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
#ifndef IO_PACER_H
#define IO_PACER_H

#include <stdint.h>
#include <rte_config.h>
#include <rte_hash.h>
#include <rte_spinlock.h>
#include <rte_atomic.h>
#include <rte_jhash.h>
#include "spdk/stdinc.h"
#include "spdk_internal/log.h"
#include "spdk/nvmf.h"


#define MAX_SUPPORTED_DISKS 96
#define KB 1024
#define MB (KB * KB)
#define BF2_CACHE_SIZE (12 * MB)
#define MAX_PACKET_SIZE (128 * KB)
#define MAX_ALLOCATION_SIZE_PER_DISK (128 * MAX_PACKET_SIZE) 
#define MAX_ITERATION_TO_COMPUTE_AVERAGE 96000
#define AVG_5GbPS_DISK_SPEED 5

struct spdk_io_pacer;
struct spdk_io_pacer_tuner;
struct spdk_io_pacer_tuner2;
typedef void (*spdk_io_pacer_pop_cb)(void *io);
typedef struct io_pacer_queue_entry {
	uint64_t size;
    struct spdk_nvmf_ns *ns;
	STAILQ_ENTRY(io_pacer_queue_entry) link;
} io_pacer_queue_entry;


struct spdk_io_pacer_drives_stats {
	struct rte_hash *h;
	rte_spinlock_t lock;
};

extern struct spdk_io_pacer_drives_stats drives_stats;

struct drive_stats {
	rte_atomic32_t ops_in_flight;
};

typedef struct io_pacer_queue {
	rte_atomic64_t key;
	struct drive_stats *stats;
	STAILQ_HEAD(io_pacer_queue_struct, io_pacer_queue_entry) queue;
} io_pacer_queue;

// Rename below one to spdk_io_pacer_for_disks. ~Ankit 
typedef struct spdk_io_pacer {
	uint64_t period_ticks;
	int64_t credit;
	int64_t remaining_credit;
	uint64_t num_ios;
	spdk_io_pacer_pop_cb pop_cb;
	uint64_t first_tick;
	uint64_t last_tick;
	struct spdk_nvmf_io_pacer_stat stat;
	struct spdk_poller *poller;
	uint32_t disk_credit;
	
    /* Required for slow disc algo. */
    uint32_t pacer_iteration_number;
    uint32_t take_average_after_count;
    uint32_t max_allowed_mem;
    //uint32_t start_pacer_at_startup;
    //rte_spinlock_t lock_for_starting_pacer;
    uint32_t disk_start_index;
    uint32_t last_scheduling_disk_index;
} spdk_io_pacer;

// Rename below one to spdk_shared_io_pacer_for_disks. ~Ankit 
typedef struct spdk_io_pacer_shared {
    /* Required for slow disc algo. */
    rte_spinlock_t lock_for_pacer_initialization;
    rte_atomic64_t slow_disk_var_initialization;
    rte_atomic64_t total_allocated_mem;
    rte_atomic64_t number_of_inserted_disks;
    rte_atomic64_t max_number_of_supported_disks;
    //rte_spinlock_t lock_for_priority;
    //volatile uint32_t current_lock_priority;
    rte_spinlock_t lock_for_total_allocated_mem;
    rte_spinlock_t lock_per_disk[MAX_SUPPORTED_DISKS];
    rte_atomic64_t per_disk_max_buffer[MAX_SUPPORTED_DISKS];
    rte_atomic64_t per_disk_used_buffer[MAX_SUPPORTED_DISKS];
    rte_atomic64_t current_data_and_time_index;
    rte_atomic64_t per_disk_data_transfered[MAX_SUPPORTED_DISKS][MAX_ITERATION_TO_COMPUTE_AVERAGE];
    //per_disk_time_taken_to_transfer transfer_time[MAX_SUPPORTED_DISKS];
    rte_atomic64_t per_disk_time_taken_to_transfer[MAX_SUPPORTED_DISKS][MAX_ITERATION_TO_COMPUTE_AVERAGE];
    rte_atomic64_t disk_speeds[MAX_SUPPORTED_DISKS];

    rte_atomic64_t max_queues;
	rte_atomic64_t num_queues;
	rte_atomic64_t next_queue;
	struct io_pacer_queue *queues;
    rte_spinlock_t lock_per_queue[MAX_SUPPORTED_DISKS];
} spdk_io_pacer_shared;

extern spdk_io_pacer_shared pacer_shared;

typedef void (*spdk_io_pacer_pop_cb)(void *io);

struct spdk_io_pacer *spdk_io_pacer_create(spdk_io_pacer_shared *pacer_shared,
                       uint32_t period_ns,
					   uint32_t credit,
					   uint32_t disk_credit,
					   spdk_io_pacer_pop_cb pop_cb);
void spdk_io_pacer_destroy(struct spdk_io_pacer_shared *pacer);
int spdk_io_pacer_create_queue(struct spdk_io_pacer_shared *pacer, uint64_t key);
int spdk_io_pacer_destroy_queue(struct spdk_io_pacer_shared *pacer, uint64_t key);
int spdk_io_pacer_push(struct spdk_io_pacer_shared *pacer,
		       uint64_t key,
		       struct io_pacer_queue_entry *entry);
void spdk_io_pacer_get_stat(const struct spdk_io_pacer *pacer,
			    struct spdk_nvmf_transport_poll_group_stat *stat);
//int io_pacer_schedule_request(struct spdk_nvmf_rdma_transport *rtransport, struct spdk_nvmf_rdma_request *rdma_req, spdk_io_pacer_shared *pacer_shared, spdk_io_pacer *pacer);
struct spdk_io_pacer_tuner *spdk_io_pacer_tuner_create(struct spdk_io_pacer *pacer,
						       uint32_t tuner_period_us,
						       uint32_t tuner_step_ns);
void spdk_io_pacer_tuner_destroy(struct spdk_io_pacer_tuner *tuner);
struct spdk_io_pacer_tuner2 *spdk_io_pacer_tuner2_create(struct spdk_io_pacer *pacer,
							 uint32_t period_us,
							 uint32_t min_threshold,
							 uint64_t factor);
void spdk_io_pacer_tuner2_destroy(struct spdk_io_pacer_tuner2 *tuner);
void spdk_io_pacer_tuner2_add(struct spdk_io_pacer_tuner2 *tuner, uint32_t value);
void spdk_io_pacer_tuner2_sub(struct spdk_io_pacer_tuner2 *tuner, uint32_t value);

static inline void drive_stats_lock(struct spdk_io_pacer_drives_stats *stats) {
	rte_spinlock_lock(&stats->lock);
}

static inline void drive_stats_unlock(struct spdk_io_pacer_drives_stats *stats) {
	rte_spinlock_unlock(&stats->lock);
}

static inline struct drive_stats* spdk_io_pacer_drive_stats_create(struct spdk_io_pacer_drives_stats *stats,
								   uint64_t key)
{
	int32_t ret = 0;
	struct drive_stats *data = NULL;
	struct rte_hash *h = stats->h;

	ret = rte_hash_lookup(h, &key);
	if (ret != -ENOENT)
		return 0;

	drive_stats_lock(stats);
	data = calloc(1, sizeof(struct drive_stats));
	rte_atomic32_init(&data->ops_in_flight);
	ret = rte_hash_add_key_data(h, (void *) &key, data);
	if (ret < 0) {
		SPDK_ERRLOG("Can't add key to drive statistics dict: %" PRIx64 "\n", key);
		goto err;
	}
	goto exit;
err:
	free(data);
	data = NULL;
exit:
	drive_stats_unlock(stats);
	return data;
}

static inline struct drive_stats * spdk_io_pacer_drive_stats_get(struct spdk_io_pacer_drives_stats *stats,
								 uint64_t key)
{
	return 0;

	struct drive_stats *data = NULL;
	int ret = 0;
	ret = rte_hash_lookup_data(stats->h, (void*) &key, (void**) &data);
	if (ret == -EINVAL) {
		SPDK_ERRLOG("Drive statistics seems broken\n");
	} else if (unlikely(ret == -ENOENT)) {
		SPDK_NOTICELOG("Creating drive stats for key: %" PRIx64 "\n", key);
		data = spdk_io_pacer_drive_stats_create(stats, key);
	}
	return data;
}

static inline void spdk_io_pacer_drive_stats_add(struct spdk_io_pacer_drives_stats *stats,
						 uint64_t key,
						 uint32_t val)
{
	struct drive_stats *drive_stats = spdk_io_pacer_drive_stats_get(stats, key);
	rte_atomic32_add(&drive_stats->ops_in_flight, val);
}

static inline void spdk_io_pacer_drive_stats_sub(struct spdk_io_pacer_drives_stats *stats,
						 uint64_t key,
						 uint32_t val)
{
	struct drive_stats *drive_stats = spdk_io_pacer_drive_stats_get(stats, key);
	rte_atomic32_sub(&drive_stats->ops_in_flight, val);
}

void spdk_io_pacer_drive_stats_setup(struct spdk_io_pacer_drives_stats *stats, int32_t entries);

#endif /* IO_PACER_H */
