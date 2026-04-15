#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Time
int64_t bench_now_us(void);

// Heap (8-bit capable heap)
int64_t bench_heap_free_bytes(void);
int64_t bench_heap_min_free_bytes(void);              // global min since boot
int64_t bench_heap_largest_free_block_bytes(void);

// Stack (for current task)
uint32_t bench_stack_highwater_words(void);

/*
 * JSONL emitter
 * Adds fields needed for your colleague-style table:
 * - heap_min_during_bytes
 * - largest_before_bytes / largest_min_during_bytes
 * - useful_heap_bytes / extra_heap_bytes
 * - static_stack_used_bytes / total_mem_bytes
 */
void emit_jsonl(const char *platform_id,
                const char *mode,
                const char *alg,
                const char *op,
                int iter_idx,
                int msg_len_bytes,
                int64_t time_us,

                // heap snapshots (classic)
                int64_t heap_before,
                int64_t heap_after,
                int64_t heap_min_free_global,

                // local min during this op (peak tracking)
                int64_t heap_min_during_bytes,
                int64_t largest_before_bytes,
                int64_t largest_min_during_bytes,

                // derived memory metrics
                int64_t useful_heap_bytes,
                int64_t extra_heap_bytes,
                int64_t static_stack_used_bytes,
                int64_t total_mem_bytes,

                // sizes & status
                int pk_len_bytes,
                int sk_len_bytes,
                int sig_len_bytes,
                int ok);

#ifdef __cplusplus
}
#endif

void bench_local_run(void);
void app_interop_run(void);