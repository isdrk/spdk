#include <stdlib.h> // For random(), RAND_MAX
#include <time.h>
#include <stdint.h>

#define MAX_VALUE 1500
#define KEEP_DECISION_PROBABILITY 0.85
#define STAY_THE_SAME_PROBABILITY 0.6
#define BUFFERS_THERSHOLD 12.5

int activated = 0;
unsigned int prev_decision = 0;

uint shift_condition = 0;

void random_seed()
{
    if (activated == 0)
    {
        srand(time(NULL));
        activated = 1;
    }
}

double RandomDouble(double min, double max){
   return ((max - min) * ((double)rand() / RAND_MAX)) + min;
}

long random_at_most(long max) {
  unsigned long
    // max <= RAND_MAX < ULONG_MAX, so this is okay.
    num_bins = (unsigned long) max + 1,
    num_rand = (unsigned long) RAND_MAX + 1,
    bin_size = num_rand / num_bins,
    defect   = num_rand % num_bins;

  long x;
  do {
   x = random();
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned long)x);

  // Truncated division is intentional
  return x/bin_size;
}

uint64_t get_period(uint64_t current_period, unsigned int decision)
{
    // decision - {0: decrease, 1: stay the same, 2: increase }
    double value = RandomDouble(0.0, (double)MAX_VALUE);
    switch (decision)
    {
        case 0: // decrease
            return (uint64_t)round((double)current_period - value);
        case 1: // no change
            return current_period;
        case 2: // increase
            return (uint64_t)round((double)current_period + value);
    }
    return current_period;
}
uint64_t get_new_random_period(double current_period)
{
    if (activated == 0)
        random_seed();

    unsigned int decision;
    uint64_t new_period;

    double prob = RandomDouble(0.0, 1.0);
    if (prob <= KEEP_DECISION_PROBABILITY)
        decision = prev_decision;
    else
        decision = random_at_most(2);

    new_period = get_period(current_period, decision);
    prev_decision = decision;
    return new_period;
}


uint64_t get_smart_random_period(double current_period, double buffers_in_flight)
{
    if (activated == 0)
        random_seed();

    uint64_t new_period = (uint64_t)round(current_period);

    double prob = RandomDouble(0.0, 1.0);
    if (prob <= STAY_THE_SAME_PROBABILITY)
        return new_period;

    prob = RandomDouble(0.0, 1.0);
    if (buffers_in_flight > BUFFERS_THERSHOLD && prob <= KEEP_DECISION_PROBABILITY)
        return get_period(current_period, 2);
    else if (buffers_in_flight > BUFFERS_THERSHOLD && prob > KEEP_DECISION_PROBABILITY)
        return get_period(current_period, 0);
    else if (buffers_in_flight <= BUFFERS_THERSHOLD && prob <= KEEP_DECISION_PROBABILITY)
        return get_period(current_period, 0);
    else
        return get_period(current_period, 2);
}