#pragma once

#include <stdint.h>

#define MAX_BENCHMARK_ITERATIONS 20

#ifdef __cplusplus
extern "C" {
#endif

void run_ml_kem_benchmark(void);
void run_multiple_benchmarks(int iterations);

#ifdef __cplusplus
}
#endif
