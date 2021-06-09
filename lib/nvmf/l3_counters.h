#include "spdk_internal/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CACHE_LINE 64
#define KB 1000
#define ZERO "0"
#define ONE "1"

/*
  Counter ids
*/
#define CYCLES "0x01"
#define L3_HITS_BANK0 "0x17"
#define L3_HITS_BANK1 "0x18"
#define L3_MISSES_BANK0 "0x19"
#define L3_MISSES_BANK1 "0x1a"

#define L3_ALLOCATIONS_BANK0 "0x1b"
#define L3_ALLOCATIONS_BANK1 "0x1c"
#define L3_EVICTIONS_BANK0 "0x1d"
#define L3_EVICTIONS_BANK1 "0x1e"

#define NUM_COUNTERS 5

enum l3_type {EN, EVENT, COUNTER};

char *get_type(int l3cache, int half, int idx, enum l3_type event_type)
{
    char *buf = malloc(128);
    switch (event_type)
    {
        case EN:
            snprintf(buf, 128, "/sys/class/hwmon/hwmon0/l3cache%dhalf%d/enable", l3cache, half);
            break;
        case EVENT:
            snprintf(buf, 128, "/sys/class/hwmon/hwmon0/l3cache%dhalf%d/event%d", l3cache, half, idx);
            break;
        case COUNTER:
            snprintf(buf, 128, "/sys/class/hwmon/hwmon0/l3cache%dhalf%d/counter%d", l3cache, half, idx);
            break;
    }
    return buf;
}

void set_l3_event()
{
    char counters[NUM_COUNTERS][5] = {CYCLES, L3_HITS_BANK0, L3_HITS_BANK1,
                        L3_MISSES_BANK0, L3_MISSES_BANK1};
    // char counters[NUM_COUNTERS][5] = {CYCLES, L3_ALLOCATIONS_BANK0, L3_ALLOCATIONS_BANK1,
    //                     L3_EVICTIONS_BANK0, L3_EVICTIONS_BANK1};
    int l3_num = 2;
    int bank_num = 2 ;
    int l3cache, half, idx;

    FILE *ptr;
    for (l3cache = 0; l3cache < l3_num; l3cache++)
    {
        for (half = 0; half < bank_num; half++)
        {
            for (idx = 0; idx < NUM_COUNTERS; idx++)
            {
                char *event = get_type(l3cache, half, idx, EVENT);

                ptr = fopen(event, "w");
                fprintf(ptr, ZERO);
                fclose(ptr);
                ptr = fopen(event, "w");
                fprintf(ptr, counters[idx]);
                fclose(ptr);
                free(event);
            }
            char *enable = get_type(l3cache, half, idx, EN);
			ptr = fopen(enable, "w");
            fprintf(ptr, ONE);
            fclose(ptr);
            free(enable);
        }
    }
}


float get_l3_event()
{
    int l3_num = 2;
    int bank_num = 2 ;
    int l3cache, half, idx;

    int hit_sum = 0;
    int miss_sum = 0;
    FILE *ptr;
    for (l3cache = 0; l3cache < l3_num; l3cache++)
    {
        for (half = 0; half < bank_num; half++)
        {
            for (idx = 0; idx < NUM_COUNTERS; idx++)
            {
                char event_line[1000];
                char counter_line[1000];

                char *event = get_type(l3cache, half, idx, EVENT);
                ptr = fopen(event, "r");
                fscanf(ptr, "%[^\n]", event_line);
                fclose(ptr);
                free(event);

                char *event_name_tmp = strtok(event_line, ":");
                event_name_tmp = strtok(NULL, ":");

                char *event_name = strtok(event_name_tmp, " ");

                char *counter = get_type(l3cache, half, idx, COUNTER);
                ptr = fopen(counter, "r");
                fscanf(ptr, "%[^\n]", counter_line);
                fclose(ptr);
                free(counter);

                int value = (int)strtol(counter_line, NULL, 0);

                char *found = strstr(event_name, "MISS");
                // char *found = strstr(event_name, "ALLOCATION");
                if(found)
                    miss_sum += value;
                found = strstr(event_name, "HIT");
                // found = strstr(event_name, "EVICTION");
                if(found)
                    hit_sum += value;

            }
        }
    }
    float hit_rate = (float)hit_sum / (float)(hit_sum + miss_sum);
    for (l3cache = 0; l3cache < l3_num; l3cache++)
    {
        for (half = 0; half < bank_num; half++)
        {
            for (idx = 0; idx < NUM_COUNTERS; idx++)
            {
                char *event = get_type(l3cache, half, idx, EVENT);
                ptr = fopen(event, "w");
                fprintf(ptr, ZERO);
                fclose(ptr);
                free(event);
            }
        }
    }
    return hit_rate;
}

