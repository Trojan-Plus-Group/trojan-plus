#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static int64_t nanoseconds(struct timespec value) {
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}

int main(void) {
    const clockid_t clocks[] = {CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_MONOTONIC_RAW};
    const char *names[] = {"CLOCK_MONOTONIC", "CLOCK_BOOTTIME", "CLOCK_MONOTONIC_RAW"};
    const unsigned calls = 5000000;
    for (unsigned clock = 0; clock < sizeof(clocks) / sizeof(clocks[0]); ++clock) {
        struct timespec start, end, value;
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
            perror("clock_gettime start");
            return 1;
        }
        for (unsigned call = 0; call < calls; ++call) {
            if (clock_gettime(clocks[clock], &value) != 0) {
                perror(names[clock]);
                return 1;
            }
        }
        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
            perror("clock_gettime end");
            return 1;
        }
        printf("%s calls=%u ns/call=%.3f\n", names[clock], calls,
               (double)(nanoseconds(end) - nanoseconds(start)) / calls);
    }
    return 0;
}
