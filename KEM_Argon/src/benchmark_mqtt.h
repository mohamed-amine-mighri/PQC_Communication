#pragma once

#include <stdint.h>

#define MAX_MQTT_BENCHMARK_ITERATIONS 20

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Run ML-KEM benchmark over MQTT communication.
 * Measures end-to-end key exchange including network overhead.
 *
 * @param role       "server" or "client"
 * @param iterations Number of measured iterations (+ 1 warmup)
 */
void run_mqtt_benchmark(const char *role, int iterations);

#ifdef __cplusplus
}
#endif
