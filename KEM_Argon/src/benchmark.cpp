/*
 * ML-KEM Benchmark for Particle Argon (nRF52840 / ARM Cortex-M4F)
 *
 * Memory measurement: pqm4 stack watermark technique
 *   Reference: https://github.com/mupq/pqm4
 *   This is the standard approach used in NIST Post-Quantum Cryptography
 *   benchmarking on ARM Cortex-M microcontrollers.
 *
 * How it works:
 *   1. Read current SP (ARM stack pointer register via inline asm)
 *   2. Paint 20 KB below SP with 0xDEADBEEF canary words
 *   3. Call the ML-KEM function (its local polyvec arrays overwrite canaries)
 *   4. After return, scan from bottom up to find deepest overwritten canary
 *   5. stack_used = (total painted words - intact canaries) * 4  bytes
 *
 * Timing: micros() — hardware microsecond counter on nRF52840.
 *
 * Heap: System.freeMemory() before/after buffer malloc.
 *   Note: ML-KEM itself uses only stack (local arrays), never malloc.
 *   heap_bytes reflects the I/O buffer allocations (pk, sk, ct, ss).
 */

#include "benchmark.h"
#include "mlkem.h"
#include "Particle.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

// ── Variant name ─────────────────────────────────────────────────────────
#if defined(PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME)
  static const char *VARIANT = "ML-KEM-512";
#elif defined(PQCLEAN_MLKEM768_CLEAN_CRYPTO_ALGNAME)
  static const char *VARIANT = "ML-KEM-768";
#elif defined(PQCLEAN_MLKEM1024_CLEAN_CRYPTO_ALGNAME)
  static const char *VARIANT = "ML-KEM-1024";
#else
  static const char *VARIANT = "UNKNOWN";
#endif

// ═══════════════════════════════════════════════════════════════════════
// Stack Watermark (pqm4 methodology)
// ═══════════════════════════════════════════════════════════════════════

// Paint 20 KB below current SP.  Our benchmark thread has 32 KB stack,
// so 20 KB is safe.  ML-KEM-1024 peak stack is ~12 KB.
#define PAINT_BYTES  (20u * 1024u)
#define PAINT_WORDS  (PAINT_BYTES / 4u)
#define CANARY_WORD  0xDEADBEEFu

// Read the ARM Cortex-M4 stack pointer register.
static inline __attribute__((always_inline)) uint32_t read_sp(void) {
    uint32_t sp;
    __asm volatile ("mov %0, sp" : "=r"(sp));
    return sp;
}

// Paint canaries into the unused portion of the thread stack (below SP).
// Returns the base address of the painted region (lowest address).
static volatile uint32_t *paint_canaries(void) {
    uint32_t sp = read_sp();
    volatile uint32_t *base = (volatile uint32_t *)(sp - PAINT_BYTES);
    for (uint32_t i = 0; i < PAINT_WORDS; i++) {
        base[i] = CANARY_WORD;
    }
    __asm volatile ("dsb" ::: "memory");   // ensure all writes complete
    return base;
}

// Scan from base upward.  Intact canaries = stack the function never reached.
// Returns peak stack usage in bytes.
static uint32_t measure_watermark(volatile uint32_t *base) {
    uint32_t intact = 0;
    for (uint32_t i = 0; i < PAINT_WORDS; i++) {
        if (base[i] != CANARY_WORD) break;
        intact++;
    }
    return (PAINT_WORDS - intact) * 4u;
}

// ═══════════════════════════════════════════════════════════════════════
// Per-iteration data
// ═══════════════════════════════════════════════════════════════════════

struct iter_data {
    // Timing
    float keygen_ms;
    float encaps_ms;
    float decaps_ms;
    float total_ms;
    // Stack (pqm4 watermark) per operation
    uint32_t stack_keygen;
    uint32_t stack_encaps;
    uint32_t stack_decaps;
    // Heap (System.freeMemory delta from malloc) per operation
    uint32_t heap_keygen;
    uint32_t heap_encaps;
    uint32_t heap_decaps;
    uint32_t heap_peak;
    // Context
    uint32_t free_heap_before;
    uint32_t free_heap_after;
    bool     ss_match;
};

static struct iter_data s_iters[MAX_BENCHMARK_ITERATIONS];

// ── Statistics helpers ───────────────────────────────────────────────────
static float stddev_f(const float *v, int n, float mean) {
    if (n < 2) return 0.0f;
    float s = 0;
    for (int i = 0; i < n; i++) { float d = v[i] - mean; s += d * d; }
    return sqrtf(s / (float)(n - 1));
}

static float stddev_u(const uint32_t *v, int n, float mean) {
    if (n < 2) return 0.0f;
    float s = 0;
    for (int i = 0; i < n; i++) { float d = (float)v[i] - mean; s += d * d; }
    return sqrtf(s / (float)(n - 1));
}

// ═══════════════════════════════════════════════════════════════════════
// Run one iteration
// ═══════════════════════════════════════════════════════════════════════
static void run_iteration(int idx)
{
    struct iter_data *it = &s_iters[idx];
    memset(it, 0, sizeof(*it));

    it->free_heap_before = System.freeMemory();

    // Allocate I/O buffers on HEAP so they don't interfere with stack
    // watermark measurement.
    uint32_t h0, h1;

    h0 = System.freeMemory();
    uint8_t *pk  = (uint8_t *)malloc(MLKEM_PUBLICKEYBYTES);
    uint8_t *sk  = (uint8_t *)malloc(MLKEM_SECRETKEYBYTES);
    h1 = System.freeMemory();
    it->heap_keygen = h0 - h1;

    h0 = h1;
    uint8_t *ct  = (uint8_t *)malloc(MLKEM_CIPHERTEXTBYTES);
    uint8_t *ss  = (uint8_t *)malloc(MLKEM_SHAREDSECRETBYTES);
    h1 = System.freeMemory();
    it->heap_encaps = h0 - h1;

    h0 = h1;
    uint8_t *ss2 = (uint8_t *)malloc(MLKEM_SHAREDSECRETBYTES);
    h1 = System.freeMemory();
    it->heap_decaps = h0 - h1;

    it->heap_peak = it->free_heap_before - System.freeMemory();

    // ── KEY GENERATION ───────────────────────────────────────────────
    volatile uint32_t *base;
    uint32_t t0, t1;

    base = paint_canaries();
    t0 = micros();
    mlkem_keypair(pk, sk);
    t1 = micros();
    it->keygen_ms    = (float)(t1 - t0) / 1000.0f;
    it->stack_keygen = measure_watermark(base);

    // ── ENCAPSULATION ────────────────────────────────────────────────
    base = paint_canaries();
    t0 = micros();
    mlkem_enc(ct, ss, pk);
    t1 = micros();
    it->encaps_ms    = (float)(t1 - t0) / 1000.0f;
    it->stack_encaps = measure_watermark(base);

    // ── DECAPSULATION ────────────────────────────────────────────────
    base = paint_canaries();
    t0 = micros();
    mlkem_dec(ss2, ct, sk);
    t1 = micros();
    it->decaps_ms    = (float)(t1 - t0) / 1000.0f;
    it->stack_decaps = measure_watermark(base);

    // ── Totals & validation ──────────────────────────────────────────
    it->total_ms = it->keygen_ms + it->encaps_ms + it->decaps_ms;
    it->ss_match = (memcmp(ss, ss2, MLKEM_SHAREDSECRETBYTES) == 0);

    free(ss2); free(ss); free(ct); free(sk); free(pk);
    it->free_heap_after = System.freeMemory();
}

// ═══════════════════════════════════════════════════════════════════════
// JSON report
// ═══════════════════════════════════════════════════════════════════════
static void emit_json(int n, uint32_t heap_start)
{
    float a_kg_t[MAX_BENCHMARK_ITERATIONS], a_en_t[MAX_BENCHMARK_ITERATIONS];
    float a_de_t[MAX_BENCHMARK_ITERATIONS], a_tot_t[MAX_BENCHMARK_ITERATIONS];
    uint32_t a_kg_s[MAX_BENCHMARK_ITERATIONS], a_en_s[MAX_BENCHMARK_ITERATIONS];
    uint32_t a_de_s[MAX_BENCHMARK_ITERATIONS];

    float s_kg_t=0,s_en_t=0,s_de_t=0,s_tot_t=0;
    float mn_kg=1e9,mn_en=1e9,mn_de=1e9,mn_tot=1e9;
    float mx_kg=0,mx_en=0,mx_de=0,mx_tot=0;
    float s_kg_s=0,s_en_s=0,s_de_s=0;

    for (int i = 0; i < n; i++) {
        a_kg_t[i]  = s_iters[i].keygen_ms;
        a_en_t[i]  = s_iters[i].encaps_ms;
        a_de_t[i]  = s_iters[i].decaps_ms;
        a_tot_t[i] = s_iters[i].total_ms;
        a_kg_s[i]  = s_iters[i].stack_keygen;
        a_en_s[i]  = s_iters[i].stack_encaps;
        a_de_s[i]  = s_iters[i].stack_decaps;

        s_kg_t += a_kg_t[i]; s_en_t += a_en_t[i];
        s_de_t += a_de_t[i]; s_tot_t += a_tot_t[i];
        s_kg_s += a_kg_s[i]; s_en_s += a_en_s[i]; s_de_s += a_de_s[i];

        if (a_kg_t[i]  < mn_kg)  mn_kg  = a_kg_t[i];
        if (a_kg_t[i]  > mx_kg)  mx_kg  = a_kg_t[i];
        if (a_en_t[i]  < mn_en)  mn_en  = a_en_t[i];
        if (a_en_t[i]  > mx_en)  mx_en  = a_en_t[i];
        if (a_de_t[i]  < mn_de)  mn_de  = a_de_t[i];
        if (a_de_t[i]  > mx_de)  mx_de  = a_de_t[i];
        if (a_tot_t[i] < mn_tot) mn_tot = a_tot_t[i];
        if (a_tot_t[i] > mx_tot) mx_tot = a_tot_t[i];
    }

    float avg_kg  = s_kg_t/n,  avg_en  = s_en_t/n;
    float avg_de  = s_de_t/n,  avg_tot = s_tot_t/n;
    float avg_skg = s_kg_s/n,  avg_sen = s_en_s/n,  avg_sde = s_de_s/n;

    Serial.println("===JSON_START===");
    Serial.println("{");
    Serial.printlnf("  \"variant\": \"%s\",", VARIANT);
    Serial.println( "  \"device\": \"Particle Argon (nRF52840)\",");
    Serial.println( "  \"cpu_mhz\": 64,");
    Serial.println( "  \"total_ram_bytes\": 262144,");
    Serial.printlnf("  \"free_heap_at_start_bytes\": %lu,", (unsigned long)heap_start);
    Serial.printlnf("  \"num_iterations\": %d,", n);
    Serial.println( "  \"methodology\": {");
    Serial.println( "    \"timing\": \"micros() — nRF52840 hardware timer, 1 us resolution\",");
    Serial.println( "    \"stack\": \"pqm4 stack watermark (0xDEADBEEF canary painting below SP)\",");
    Serial.println( "    \"heap\": \"System.freeMemory() delta around malloc calls\"");
    Serial.println( "  },");

    Serial.println("  \"buffer_sizes\": {");
    Serial.printlnf("    \"public_key_bytes\": %d,", MLKEM_PUBLICKEYBYTES);
    Serial.printlnf("    \"secret_key_bytes\": %d,", MLKEM_SECRETKEYBYTES);
    Serial.printlnf("    \"ciphertext_bytes\": %d,", MLKEM_CIPHERTEXTBYTES);
    Serial.printlnf("    \"shared_secret_bytes\": %d", MLKEM_SHAREDSECRETBYTES);
    Serial.println("  },");

    // ── Per-iteration ────────────────────────────────────────────────
    Serial.println("  \"iterations\": [");
    for (int i = 0; i < n; i++) {
        Serial.println("    {");
        Serial.printlnf("      \"iteration\": %d,", i + 1);

        Serial.println( "      \"key_generation\": {");
        Serial.printlnf("        \"time_ms\": %.3f,", (double)s_iters[i].keygen_ms);
        Serial.printlnf("        \"stack_bytes\": %lu,", (unsigned long)s_iters[i].stack_keygen);
        Serial.printlnf("        \"heap_bytes\": %lu", (unsigned long)s_iters[i].heap_keygen);
        Serial.println( "      },");

        Serial.println( "      \"encapsulation\": {");
        Serial.printlnf("        \"time_ms\": %.3f,", (double)s_iters[i].encaps_ms);
        Serial.printlnf("        \"stack_bytes\": %lu,", (unsigned long)s_iters[i].stack_encaps);
        Serial.printlnf("        \"heap_bytes\": %lu", (unsigned long)s_iters[i].heap_encaps);
        Serial.println( "      },");

        Serial.println( "      \"decapsulation\": {");
        Serial.printlnf("        \"time_ms\": %.3f,", (double)s_iters[i].decaps_ms);
        Serial.printlnf("        \"stack_bytes\": %lu,", (unsigned long)s_iters[i].stack_decaps);
        Serial.printlnf("        \"heap_bytes\": %lu", (unsigned long)s_iters[i].heap_decaps);
        Serial.println( "      },");

        Serial.printlnf("      \"total_time_ms\": %.3f,", (double)s_iters[i].total_ms);
        Serial.printlnf("      \"peak_heap_bytes\": %lu,", (unsigned long)s_iters[i].heap_peak);
        Serial.printlnf("      \"free_heap_before\": %lu,", (unsigned long)s_iters[i].free_heap_before);
        Serial.printlnf("      \"free_heap_after\": %lu,", (unsigned long)s_iters[i].free_heap_after);
        Serial.printlnf("      \"shared_secret_match\": %s", s_iters[i].ss_match ? "true" : "false");
        Serial.printlnf("    }%s", (i < n - 1) ? "," : "");
    }
    Serial.println("  ],");

    // ── Summary ──────────────────────────────────────────────────────
    Serial.println("  \"summary\": {");

    Serial.println("    \"key_generation\": {");
    Serial.printlnf("      \"avg_time_ms\": %.3f,", (double)avg_kg);
    Serial.printlnf("      \"min_time_ms\": %.3f,", (double)mn_kg);
    Serial.printlnf("      \"max_time_ms\": %.3f,", (double)mx_kg);
    Serial.printlnf("      \"stddev_time_ms\": %.3f,", (double)stddev_f(a_kg_t, n, avg_kg));
    Serial.printlnf("      \"avg_stack_bytes\": %.0f,", (double)avg_skg);
    Serial.printlnf("      \"stddev_stack_bytes\": %.0f", (double)stddev_u(a_kg_s, n, avg_skg));
    Serial.println("    },");

    Serial.println("    \"encapsulation\": {");
    Serial.printlnf("      \"avg_time_ms\": %.3f,", (double)avg_en);
    Serial.printlnf("      \"min_time_ms\": %.3f,", (double)mn_en);
    Serial.printlnf("      \"max_time_ms\": %.3f,", (double)mx_en);
    Serial.printlnf("      \"stddev_time_ms\": %.3f,", (double)stddev_f(a_en_t, n, avg_en));
    Serial.printlnf("      \"avg_stack_bytes\": %.0f,", (double)avg_sen);
    Serial.printlnf("      \"stddev_stack_bytes\": %.0f", (double)stddev_u(a_en_s, n, avg_sen));
    Serial.println("    },");

    Serial.println("    \"decapsulation\": {");
    Serial.printlnf("      \"avg_time_ms\": %.3f,", (double)avg_de);
    Serial.printlnf("      \"min_time_ms\": %.3f,", (double)mn_de);
    Serial.printlnf("      \"max_time_ms\": %.3f,", (double)mx_de);
    Serial.printlnf("      \"stddev_time_ms\": %.3f,", (double)stddev_f(a_de_t, n, avg_de));
    Serial.printlnf("      \"avg_stack_bytes\": %.0f,", (double)avg_sde);
    Serial.printlnf("      \"stddev_stack_bytes\": %.0f", (double)stddev_u(a_de_s, n, avg_sde));
    Serial.println("    },");

    Serial.println("    \"total\": {");
    Serial.printlnf("      \"avg_time_ms\": %.3f,", (double)avg_tot);
    Serial.printlnf("      \"min_time_ms\": %.3f,", (double)mn_tot);
    Serial.printlnf("      \"max_time_ms\": %.3f,", (double)mx_tot);
    Serial.printlnf("      \"stddev_time_ms\": %.3f", (double)stddev_f(a_tot_t, n, avg_tot));
    Serial.println("    }");

    Serial.println("  }");
    Serial.println("}");
    Serial.println("===JSON_END===");
}

// ═══════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════

void run_ml_kem_benchmark(void) {
    run_multiple_benchmarks(1);
}

void run_multiple_benchmarks(int iterations) {
    if (iterations < 1)  iterations = 1;
    if (iterations > MAX_BENCHMARK_ITERATIONS) iterations = MAX_BENCHMARK_ITERATIONS;

    uint32_t heap_start = System.freeMemory();

    Serial.println("\n========================================");
    Serial.printlnf("[BENCHMARK] Variant    : %s", VARIANT);
    Serial.printlnf("[BENCHMARK] Iterations : %d", iterations);
    Serial.printlnf("[BENCHMARK] Free heap  : %lu bytes", (unsigned long)heap_start);
    Serial.printlnf("[BENCHMARK] Buffers    : PK=%d  SK=%d  CT=%d  SS=%d",
        MLKEM_PUBLICKEYBYTES, MLKEM_SECRETKEYBYTES,
        MLKEM_CIPHERTEXTBYTES, MLKEM_SHAREDSECRETBYTES);
    Serial.println("[BENCHMARK] Stack meas : pqm4 watermark (0xDEADBEEF)");
    Serial.println("[BENCHMARK] Timer      : micros() (nRF52840 HW, 1us)");
    Serial.println("========================================\n");

    // ── Warmup (result discarded) ────────────────────────────────────
    Serial.println("[BENCHMARK] Warmup...");
    run_iteration(0);
    Serial.printlnf("[BENCHMARK] Warmup: KG=%.3f ms (%lu B)  EN=%.3f ms (%lu B)  DE=%.3f ms (%lu B)",
        (double)s_iters[0].keygen_ms,  (unsigned long)s_iters[0].stack_keygen,
        (double)s_iters[0].encaps_ms,  (unsigned long)s_iters[0].stack_encaps,
        (double)s_iters[0].decaps_ms,  (unsigned long)s_iters[0].stack_decaps);
    Serial.println("[BENCHMARK] Warmup done (discarded).\n");
    delay(500);

    // ── Measured iterations ──────────────────────────────────────────
    for (int i = 0; i < iterations; i++) {
        run_iteration(i);

        Serial.printlnf("  Iter %2d | KG: %7.3f ms (%5lu B)  EN: %7.3f ms (%5lu B)  DE: %7.3f ms (%5lu B)  Tot: %7.3f ms | %s",
            i + 1,
            (double)s_iters[i].keygen_ms,  (unsigned long)s_iters[i].stack_keygen,
            (double)s_iters[i].encaps_ms,  (unsigned long)s_iters[i].stack_encaps,
            (double)s_iters[i].decaps_ms,  (unsigned long)s_iters[i].stack_decaps,
            (double)s_iters[i].total_ms,
            s_iters[i].ss_match ? "OK" : "FAIL");

        if (i < iterations - 1) delay(100);
    }

    // ── Print averages ───────────────────────────────────────────────
    float avg_kg=0, avg_en=0, avg_de=0, avg_tot=0;
    float avg_skg=0, avg_sen=0, avg_sde=0;
    for (int i = 0; i < iterations; i++) {
        avg_kg  += s_iters[i].keygen_ms;
        avg_en  += s_iters[i].encaps_ms;
        avg_de  += s_iters[i].decaps_ms;
        avg_tot += s_iters[i].total_ms;
        avg_skg += s_iters[i].stack_keygen;
        avg_sen += s_iters[i].stack_encaps;
        avg_sde += s_iters[i].stack_decaps;
    }
    avg_kg /= iterations; avg_en /= iterations;
    avg_de /= iterations; avg_tot /= iterations;
    avg_skg /= iterations; avg_sen /= iterations; avg_sde /= iterations;

    Serial.println("\n===== AVERAGES =====");
    Serial.printlnf("  Key Generation : %7.3f ms  |  Stack: %5.0f bytes", (double)avg_kg, (double)avg_skg);
    Serial.printlnf("  Encapsulation  : %7.3f ms  |  Stack: %5.0f bytes", (double)avg_en, (double)avg_sen);
    Serial.printlnf("  Decapsulation  : %7.3f ms  |  Stack: %5.0f bytes", (double)avg_de, (double)avg_sde);
    Serial.printlnf("  Total          : %7.3f ms", (double)avg_tot);
    Serial.println("====================\n");

    emit_json(iterations, heap_start);
    Serial.println("\n[BENCHMARK] Complete.");
}
