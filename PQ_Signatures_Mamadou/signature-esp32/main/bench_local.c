// bench_local.c — op par op (keypair / sign / verify / whole) + diagnostics + JSONL
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"

#include "dsa.h"
#include "bench_common.h"

// ---------- Paramètres ----------
#ifndef KEYPAIR_ITERS
#define KEYPAIR_ITERS 1
#endif

#ifndef SV_ITERS
#define SV_ITERS 5
#endif

#ifndef WHOLE_ITERS
#define WHOLE_ITERS 1
#endif

#ifndef WARMUP
#define WARMUP 0
#endif

#ifndef MSG_LEN
#define MSG_LEN 32
#endif

#ifndef YIELD_MS
#define YIELD_MS 10
#endif

#ifndef BENCH_OP
#define BENCH_OP "keypair"
#endif

#ifndef BENCH_ALG
#define BENCH_ALG "ML_DSA_44"
#endif

// IMPORTANT: bench_task() stack = 64 KB chez toi
#ifndef BENCH_STACK_BYTES
#define BENCH_STACK_BYTES (64 * 1024)
#endif

// ---------- Diagnostics helpers ----------
static void diag_stack_heap(const char *where)
{
    UBaseType_t hw = uxTaskGetStackHighWaterMark(NULL);
    int heap_ok = heap_caps_check_integrity_all(true);
    printf("[ESP32-LOCAL] diag %s stack_hw=%u words heap_ok=%d\n",
           where, (unsigned)hw, heap_ok ? 1 : 0);
}

#if (WARMUP > 0)
static void warmup_safe(void)
{
    for (int w = 0; w < WARMUP; w++) vTaskDelay(pdMS_TO_TICKS(50));
}
#endif

// ---------- Choix algos (ROBUSTE) ----------
static enum DSA_ALGO bench_alg_from_str(const char *s)
{
    if (!s || s[0] == '\0') {
        printf("[ESP32-LOCAL] WARN: BENCH_ALG is empty -> default ML_DSA_44\n");
        return ML_DSA_44;
    }

    /* ========= Falcon ========= */
    if (strcmp(s, "FALCON_512") == 0)          return FALCON_512;
    if (strcmp(s, "FALCON_1024") == 0)         return FALCON_1024;
    if (strcmp(s, "FALCON_PADDED_512") == 0)   return FALCON_PADDED_512;
    if (strcmp(s, "FALCON_PADDED_1024") == 0)  return FALCON_PADDED_1024;

    /* ========= ML-DSA ========= */
    if (strcmp(s, "ML_DSA_44") == 0)           return ML_DSA_44;
    if (strcmp(s, "ML_DSA_65") == 0)           return ML_DSA_65;
    if (strcmp(s, "ML_DSA_87") == 0)           return ML_DSA_87;

    /* ========= SPHINCS+ SHA2 ========= */
    if (strcmp(s, "SPHINCS_SHA2_128F") == 0)   return SPHINCS_SHA2_128F;
    if (strcmp(s, "SPHINCS_SHA2_128S") == 0)   return SPHINCS_SHA2_128S;
    if (strcmp(s, "SPHINCS_SHA2_192F") == 0)   return SPHINCS_SHA2_192F;
    if (strcmp(s, "SPHINCS_SHA2_192S") == 0)   return SPHINCS_SHA2_192S;
    if (strcmp(s, "SPHINCS_SHA2_256F") == 0)   return SPHINCS_SHA2_256F;
    if (strcmp(s, "SPHINCS_SHA2_256S") == 0)   return SPHINCS_SHA2_256S;

    /* ========= SPHINCS+ SHAKE ========= */
    if (strcmp(s, "SPHINCS_SHAKE_128F") == 0)  return SPHINCS_SHAKE_128F;
    if (strcmp(s, "SPHINCS_SHAKE_128S") == 0)  return SPHINCS_SHAKE_128S;
    if (strcmp(s, "SPHINCS_SHAKE_192F") == 0)  return SPHINCS_SHAKE_192F;
    if (strcmp(s, "SPHINCS_SHAKE_192S") == 0)  return SPHINCS_SHAKE_192S;
    if (strcmp(s, "SPHINCS_SHAKE_256F") == 0)  return SPHINCS_SHAKE_256F;
    if (strcmp(s, "SPHINCS_SHAKE_256S") == 0)  return SPHINCS_SHAKE_256S;

    /* ========= MAYO ========= */
    if (strcmp(s, "MAYO_1") == 0)              return MAYO_SIG_1;
    // optionnel : tolérer quelques variantes
    if (strcmp(s, "MAYO1") == 0)               return MAYO_SIG_1;

    /* ========= RSA ========= */
    if (strcmp(s, "RSA_2048") == 0)            return RSA_2048;

    /* ========= Unknown ========= */
    printf("[ESP32-LOCAL] ERROR: Unknown BENCH_ALG='%s' -> default ML_DSA_44\n", s);
    return ML_DSA_44;
}

// ---------- Memory tracker (per op, local peak) ----------
typedef struct {
    int64_t heap0;
    int64_t largest0;
    int64_t heap_min;
    int64_t largest_min;
    uint32_t hw_min_words; // min highwater => max stack used
} memtrack_t;

static inline void memtrack_start(memtrack_t *m) {
    m->heap0 = bench_heap_free_bytes();
    m->largest0 = bench_heap_largest_free_block_bytes();
    m->heap_min = m->heap0;
    m->largest_min = m->largest0;
    m->hw_min_words = bench_stack_highwater_words();
}

static inline void memtrack_snap(memtrack_t *m) {
    int64_t h = bench_heap_free_bytes();
    int64_t l = bench_heap_largest_free_block_bytes();
    uint32_t hw = bench_stack_highwater_words();
    if (h < m->heap_min) m->heap_min = h;
    if (l < m->largest_min) m->largest_min = l;
    if (hw < m->hw_min_words) m->hw_min_words = hw;
}

static inline int64_t static_used_bytes_from_hwmin(uint32_t hw_min_words) {
    int64_t free_bytes = (int64_t)hw_min_words * (int64_t)sizeof(StackType_t);
    return (int64_t)BENCH_STACK_BYTES - free_bytes;
}

// ---------- Utilitaire: générer une clé fixe (pk/sk) ----------
static int make_fixed_keypair(enum DSA_ALGO algo, uint8_t **pk, uint8_t **sk,
                              size_t *pk_len, size_t *sk_len, size_t *sig_len_max)
{
    *pk = NULL; *sk = NULL;
    *pk_len = 0; *sk_len = 0; *sig_len_max = 0;

    size_t pk_l = 0, sk_l = 0, sig_m = 0;
    alloc_space_for_dsa(algo, pk, sk, &pk_l, &sk_l, &sig_m);
    if (!(*pk) || !(*sk) || pk_l == 0 || sk_l == 0 || sig_m == 0) {
        free_space_for_dsa(*pk, *sk);
        *pk = NULL; *sk = NULL;
        return -1;
    }

    diag_stack_heap("BEFORE_fixed_keygen");
    vTaskDelay(pdMS_TO_TICKS(YIELD_MS));

    int rc = dsa_keygen(algo, *pk, *sk);

    vTaskDelay(pdMS_TO_TICKS(YIELD_MS));
    diag_stack_heap("AFTER_fixed_keygen");

    if (rc != 0) {
        free_space_for_dsa(*pk, *sk);
        *pk = NULL; *sk = NULL;
        return rc;
    }

    *pk_len = pk_l;
    *sk_len = sk_l;
    *sig_len_max = sig_m;
    return 0;
}

// ---------- KEYPAIR ----------
static void measure_keypair(enum DSA_ALGO algo, const char *alg_name,
                            size_t pk_len, size_t sk_len, size_t sig_len_max)
{
#if (KEYPAIR_ITERS <= 0)
    (void)algo; (void)alg_name; (void)pk_len; (void)sk_len; (void)sig_len_max;
    printf("[ESP32-LOCAL] keypair skipped (KEYPAIR_ITERS=0)\n");
    return;
#else
    printf("###MEAS_START###\n");
    for (int it = 0; it < KEYPAIR_ITERS; it++) {

        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_l = 0, sk_l = 0, sig_m = 0;
        alloc_space_for_dsa(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);

        memtrack_t mt;
        memtrack_start(&mt);

        int64_t heap_before = mt.heap0;
        int64_t t0 = bench_now_us();

        diag_stack_heap("BEFORE_keygen");
        vTaskDelay(pdMS_TO_TICKS(YIELD_MS));

        memtrack_snap(&mt);
        int rc = -999;
        if (pk && sk) rc = dsa_keygen(algo, pk, sk);
        memtrack_snap(&mt);

        vTaskDelay(pdMS_TO_TICKS(YIELD_MS));
        diag_stack_heap("AFTER_keygen");

        int64_t t1 = bench_now_us();
        int64_t heap_after = bench_heap_free_bytes();
        int64_t heap_min_global = bench_heap_min_free_bytes();

        int ok = (rc == 0);

        int64_t useful_heap = mt.heap0 - mt.heap_min;
        int64_t extra_heap  = mt.largest0 - mt.largest_min;
        if (useful_heap < 0) useful_heap = 0;
        if (extra_heap  < 0) extra_heap  = 0;

        int64_t static_used = static_used_bytes_from_hwmin(mt.hw_min_words);
        int64_t total_mem   = useful_heap + extra_heap + static_used;

        emit_jsonl("esp32-local", "local", alg_name, "keypair",
                   it, 0, (t1 - t0),
                   heap_before, heap_after, heap_min_global,
                   mt.heap_min, mt.largest0, mt.largest_min,
                   useful_heap, extra_heap, static_used, total_mem,
                   (int)pk_len, (int)sk_len, (int)sig_len_max, ok);

        free_space_for_dsa(pk, sk);
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    printf("###MEAS_STOP###\n");
#endif
}

// ---------- SIGN ONLY ----------
static void measure_sign_only_fixed_key(enum DSA_ALGO algo, const char *alg_name,
                                        const uint8_t *msg, size_t msg_len,
                                        size_t pk_len, size_t sk_len, size_t sig_len_max)
{
#if (SV_ITERS <= 0)
    (void)algo; (void)alg_name; (void)msg; (void)msg_len; (void)pk_len; (void)sk_len; (void)sig_len_max;
    printf("[ESP32-LOCAL] sign skipped (SV_ITERS=0)\n");
    return;
#else
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_l = 0, sk_l = 0, sig_m = 0;

    printf("[ESP32-LOCAL] fixed keypair for SIGN begin\n");
    int rc_k = make_fixed_keypair(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);
    printf("[ESP32-LOCAL] fixed keypair for SIGN end rc=%d\n", rc_k);
    if (rc_k != 0) return;

    uint8_t *sig = (uint8_t*)malloc(sig_len_max);
    if (!sig) {
        printf("[ESP32-LOCAL] sign skipped (malloc sig failed)\n");
        free_space_for_dsa(pk, sk);
        return;
    }

    printf("###MEAS_START###\n");
    vTaskDelay(pdMS_TO_TICKS(50));

    for (int it = 0; it < SV_ITERS; it++) {
        size_t sig_len = 0;

        memtrack_t mt;
        memtrack_start(&mt);

        int64_t heap_before = mt.heap0;
        int64_t t0 = bench_now_us();

        diag_stack_heap("BEFORE_sign");
        vTaskDelay(pdMS_TO_TICKS(1));

        memtrack_snap(&mt);
        int ok_s = (dsa_signature(algo, sig, &sig_len, msg, msg_len, sk) == 0);
        memtrack_snap(&mt);

        vTaskDelay(pdMS_TO_TICKS(1));
        diag_stack_heap("AFTER_sign");

        int64_t t1 = bench_now_us();
        int64_t heap_after = bench_heap_free_bytes();
        int64_t heap_min_global = bench_heap_min_free_bytes();

        int64_t useful_heap = mt.heap0 - mt.heap_min;
        int64_t extra_heap  = mt.largest0 - mt.largest_min;
        if (useful_heap < 0) useful_heap = 0;
        if (extra_heap  < 0) extra_heap  = 0;

        int64_t static_used = static_used_bytes_from_hwmin(mt.hw_min_words);
        int64_t total_mem   = useful_heap + extra_heap + static_used;

        emit_jsonl("esp32-local", "local", alg_name, "sign",
                   it, (int)msg_len, (t1 - t0),
                   heap_before, heap_after, heap_min_global,
                   mt.heap_min, mt.largest0, mt.largest_min,
                   useful_heap, extra_heap, static_used, total_mem,
                   (int)pk_len, (int)sk_len, ok_s ? (int)sig_len : -1, ok_s);

        vTaskDelay(pdMS_TO_TICKS(YIELD_MS));
    }

    printf("###MEAS_STOP###\n");

    free(sig);
    free_space_for_dsa(pk, sk);
#endif
}


// ---------- VERIFY ONLY ----------
static void measure_verify_only_fixed_key(enum DSA_ALGO algo, const char *alg_name,
                                          const uint8_t *msg, size_t msg_len,
                                          size_t pk_len, size_t sk_len, size_t sig_len_max)
{
#if (SV_ITERS <= 0)
    (void)algo; (void)alg_name; (void)msg; (void)msg_len; (void)pk_len; (void)sk_len; (void)sig_len_max;
    printf("[ESP32-LOCAL] verify skipped (SV_ITERS=0)\n");
    return;
#else
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_l = 0, sk_l = 0, sig_m = 0;

    printf("[ESP32-LOCAL] fixed keypair for VERIFY begin\n");
    int rc_k = make_fixed_keypair(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);
    printf("[ESP32-LOCAL] fixed keypair for VERIFY end rc=%d\n", rc_k);
    if (rc_k != 0) return;

    uint8_t *sig = (uint8_t*)malloc(sig_len_max);
    if (!sig) {
        printf("[ESP32-LOCAL] verify skipped (malloc sig failed)\n");
        free_space_for_dsa(pk, sk);
        return;
    }

    size_t sig_len = 0;
    int ok_pre = (dsa_signature(algo, sig, &sig_len, msg, msg_len, sk) == 0);
    if (!ok_pre) {
        printf("[ESP32-LOCAL] verify skipped (pre-sign failed)\n");
        free(sig);
        free_space_for_dsa(pk, sk);
        return;
    }

    printf("###MEAS_START###\n");
    vTaskDelay(pdMS_TO_TICKS(50));

    for (int it = 0; it < SV_ITERS; it++) {
        memtrack_t mt;
        memtrack_start(&mt);

        int64_t heap_before = mt.heap0;
        int64_t t0 = bench_now_us();

        diag_stack_heap("BEFORE_verify");
        vTaskDelay(pdMS_TO_TICKS(1));

        memtrack_snap(&mt);
        int ok_v = (dsa_verify(algo, sig, sig_len, msg, msg_len, pk) == 0);
        memtrack_snap(&mt);

        vTaskDelay(pdMS_TO_TICKS(1));
        diag_stack_heap("AFTER_verify");

        int64_t t1 = bench_now_us();
        int64_t heap_after = bench_heap_free_bytes();
        int64_t heap_min_global = bench_heap_min_free_bytes();

        int64_t useful_heap = mt.heap0 - mt.heap_min;
        int64_t extra_heap  = mt.largest0 - mt.largest_min;
        if (useful_heap < 0) useful_heap = 0;
        if (extra_heap  < 0) extra_heap  = 0;

        int64_t static_used = static_used_bytes_from_hwmin(mt.hw_min_words);
        int64_t total_mem   = useful_heap + extra_heap + static_used;

        emit_jsonl("esp32-local", "local", alg_name, "verify",
                   it, (int)msg_len, (t1 - t0),
                   heap_before, heap_after, heap_min_global,
                   mt.heap_min, mt.largest0, mt.largest_min,
                   useful_heap, extra_heap, static_used, total_mem,
                   (int)pk_len, (int)sk_len, (int)sig_len, ok_v);

        vTaskDelay(pdMS_TO_TICKS(YIELD_MS));
    }

    printf("###MEAS_STOP###\n");

    free(sig);
    free_space_for_dsa(pk, sk);
#endif
}


// ---------- WHOLE (keypair+sign+verify) ----------
static void measure_whole_full(enum DSA_ALGO algo, const char *alg_name,
                               const uint8_t *msg, size_t msg_len,
                               size_t pk_len, size_t sk_len, size_t sig_len_max)
{
#if (WHOLE_ITERS <= 0)
    (void)algo; (void)alg_name; (void)msg; (void)msg_len; (void)pk_len; (void)sk_len; (void)sig_len_max;
    printf("[ESP32-LOCAL] whole skipped (WHOLE_ITERS=0)\n");
    return;
#else
    uint8_t *sig = (uint8_t*)malloc(sig_len_max);
    if (!sig) {
        printf("[ESP32-LOCAL] whole skipped (malloc sig failed)\n");
        return;
    }

    printf("###MEAS_START###\n");
    vTaskDelay(pdMS_TO_TICKS(50));

    for (int it = 0; it < WHOLE_ITERS; it++) {

        memtrack_t mt;
        memtrack_start(&mt);

        int64_t heap_before = mt.heap0;
        int64_t t0 = bench_now_us();

        diag_stack_heap("BEFORE_whole");
        vTaskDelay(pdMS_TO_TICKS(YIELD_MS));

        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_l = 0, sk_l = 0, sig_m = 0;
        alloc_space_for_dsa(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);

        memtrack_snap(&mt);

        int ok_k = (pk && sk && (dsa_keygen(algo, pk, sk) == 0));

        size_t sig_len = 0;
        int ok_s = 0;
        if (ok_k && dsa_signature(algo, sig, &sig_len, msg, msg_len, sk) == 0) {
            ok_s = 1;
        }

        int ok_v = 0;
        if (ok_s && dsa_verify(algo, sig, sig_len, msg, msg_len, pk) == 0) {
            ok_v = 1;
        }

        memtrack_snap(&mt);

        int ok_all = ok_k && ok_s && ok_v;

        vTaskDelay(pdMS_TO_TICKS(YIELD_MS));
        diag_stack_heap("AFTER_whole");

        int64_t t1 = bench_now_us();
        int64_t heap_after = bench_heap_free_bytes();
        int64_t heap_min_global = bench_heap_min_free_bytes();

        int64_t useful_heap = mt.heap0 - mt.heap_min;
        int64_t extra_heap  = mt.largest0 - mt.largest_min;
        if (useful_heap < 0) useful_heap = 0;
        if (extra_heap  < 0) extra_heap  = 0;

        int64_t static_used = static_used_bytes_from_hwmin(mt.hw_min_words);
        int64_t total_mem   = useful_heap + extra_heap + static_used;

        emit_jsonl("esp32-local", "local", alg_name, "whole",
                   it, (int)msg_len, (t1 - t0),
                   heap_before, heap_after, heap_min_global,
                   mt.heap_min, mt.largest0, mt.largest_min,
                   useful_heap, extra_heap, static_used, total_mem,
                   (int)pk_len, (int)sk_len, ok_all ? (int)sig_len : -1, ok_all);

        free_space_for_dsa(pk, sk);
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    printf("###MEAS_STOP###\n");

    free(sig);
#endif
}
// ---------- BENCH one op ----------
static void bench_one_op(enum DSA_ALGO algo)
{
    const char *alg_name = getAlgoName(algo);

    uint8_t msg[MSG_LEN];
    for (int i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;

    // tailles "théoriques"
    uint8_t *pk0 = NULL, *sk0 = NULL;
    size_t pk_len = 0, sk_len = 0, sig_len_max = 0;
    alloc_space_for_dsa(algo, &pk0, &sk0, &pk_len, &sk_len, &sig_len_max);
    free_space_for_dsa(pk0, sk0);

    printf("[ESP32-LOCAL] selected alg=%s (BENCH_ALG='%s') op=%s\n", alg_name, BENCH_ALG, BENCH_OP);

#if (WARMUP > 0)
    warmup_safe();
#endif

    if (strcmp(BENCH_OP, "keypair") == 0) {
        measure_keypair(algo, alg_name, pk_len, sk_len, sig_len_max);
        return;
    }
    if (strcmp(BENCH_OP, "sign") == 0) {
        measure_sign_only_fixed_key(algo, alg_name, msg, MSG_LEN, pk_len, sk_len, sig_len_max);
        return;
    }
    if (strcmp(BENCH_OP, "verify") == 0) {
        measure_verify_only_fixed_key(algo, alg_name, msg, MSG_LEN, pk_len, sk_len, sig_len_max);
        return;
    }
    if (strcmp(BENCH_OP, "whole") == 0) {
        measure_whole_full(algo, alg_name, msg, MSG_LEN, pk_len, sk_len, sig_len_max);
        return;
    }

    printf("[ESP32-LOCAL] ERROR: unknown BENCH_OP='%s'\n", BENCH_OP);
}

// ---------- Entry point ----------
void bench_local_run(void)
{
    printf("[ESP32-LOCAL] start op=%s alg=%s keypair_iters=%d sv_iters=%d whole_iters=%d warmup=%d msg_len=%d stack_bytes=%d\n",
           BENCH_OP, BENCH_ALG, KEYPAIR_ITERS, SV_ITERS, WHOLE_ITERS, WARMUP, MSG_LEN, (int)BENCH_STACK_BYTES);

    enum DSA_ALGO algo = bench_alg_from_str(BENCH_ALG);

    const char *resolved = getAlgoName(algo);
    if (strcmp(BENCH_ALG, "MAYO_1") == 0 && strcmp(resolved, "MAYO_1") != 0) {
        printf("[ESP32-LOCAL] ERROR: BENCH_ALG='%s' resolved to '%s' (mapping bug)\n", BENCH_ALG, resolved);
    }

    bench_one_op(algo);

    printf("[ESP32-LOCAL] done\n");
}