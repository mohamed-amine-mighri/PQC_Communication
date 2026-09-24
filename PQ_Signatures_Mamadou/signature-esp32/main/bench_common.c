#include "bench_common.h"

#include <stdio.h>
#include <inttypes.h>

#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

int64_t bench_now_us(void) {
    return (int64_t)esp_timer_get_time();
}

int64_t bench_heap_free_bytes(void) {
    return (int64_t)heap_caps_get_free_size(MALLOC_CAP_8BIT);
}

int64_t bench_heap_min_free_bytes(void) {
    // global minimum since boot (not “per op”)
    return (int64_t)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
}

int64_t bench_heap_largest_free_block_bytes(void) {
    return (int64_t)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
}

uint32_t bench_stack_highwater_words(void) {
    return (uint32_t)uxTaskGetStackHighWaterMark(NULL);
}

int64_t bench_heap_free_now(void) {
    return (int64_t)heap_caps_get_free_size(MALLOC_CAP_8BIT);
}

int64_t bench_largest_free_now(void) {
    return (int64_t)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
}

void emit_jsonl(const char *platform_id,
                const char *mode,
                const char *alg,
                const char *op,
                int iter_idx,
                int msg_len_bytes,
                int64_t time_us,
                int64_t heap_before,
                int64_t heap_after,
                int64_t heap_min_free_global,
                int64_t heap_min_during_bytes,
                int64_t largest_before_bytes,
                int64_t largest_min_during_bytes,
                int64_t useful_heap_bytes,
                int64_t extra_heap_bytes,
                int64_t static_stack_used_bytes,
                int64_t total_mem_bytes,
                int pk_len_bytes,
                int sk_len_bytes,
                int sig_len_bytes,
                int ok)
{
    int64_t heap_delta = heap_after - heap_before;

    printf("{"
           "\"platform_id\":\"%s\","
           "\"mode\":\"%s\","
           "\"pqc_sig_alg\":\"%s\","
           "\"bench_op\":\"%s\","
           "\"iter_idx\":%d,"
           "\"msg_len_bytes\":%d,"
           "\"time_us\":%" PRId64 ","

           "\"heap_before\":%" PRId64 ","
           "\"heap_after\":%" PRId64 ","
           "\"heap_delta_bytes\":%" PRId64 ","
           "\"heap_min_free_global_bytes\":%" PRId64 ","

           "\"heap_min_during_bytes\":%" PRId64 ","
           "\"largest_before_bytes\":%" PRId64 ","
           "\"largest_min_during_bytes\":%" PRId64 ","

           "\"useful_heap_bytes\":%" PRId64 ","
           "\"extra_heap_bytes\":%" PRId64 ","
           "\"static_stack_used_bytes\":%" PRId64 ","
           "\"total_mem_bytes\":%" PRId64 ","

           "\"pk_len_bytes\":%d,"
           "\"sk_len_bytes\":%d,"
           "\"sig_len_bytes\":%d,"
           "\"ok\":%d"
           "}\n",
           platform_id, mode, alg, op,
           iter_idx, msg_len_bytes,
           time_us,

           heap_before, heap_after, heap_delta, heap_min_free_global,

           heap_min_during_bytes,
           largest_before_bytes,
           largest_min_during_bytes,

           useful_heap_bytes,
           extra_heap_bytes,
           static_stack_used_bytes,
           total_mem_bytes,

           pk_len_bytes, sk_len_bytes, sig_len_bytes,
           ok);

    fflush(stdout);
}