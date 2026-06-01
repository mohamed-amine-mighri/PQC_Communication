#include "Particle.h"
#include "dsa.h"
#include "bench_local.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KEYPAIR_ITERS
#define KEYPAIR_ITERS 0
#endif

#ifndef SV_ITERS
#define SV_ITERS 0
#endif

#ifndef WHOLE_ITERS
#define WHOLE_ITERS 5
#endif

#ifndef MSG_LEN
#define MSG_LEN 32
#endif

#ifndef YIELD_MS
#define YIELD_MS 10
#endif

#ifndef BENCH_OP
#define BENCH_OP "whole"
#endif

static void diag_mem(const char *where) {
    int free_mem = System.freeMemory();
    Serial.printf("[ARGON-RSA] diag %s free_mem=%d\n", where, free_mem);
}

static inline int sample_min_free(int current_min) {
    int now = System.freeMemory();
    return (now < current_min) ? now : current_min;
}

static void emit_jsonl_argon(
    const char *alg_name,
    const char *op,
    int iter,
    int msg_len,
    uint32_t time_us,
    int free_before,
    int free_after,
    int min_free_during,
    int pk_len,
    int sk_len,
    int sig_len,
    int ok
) {
    int mem_delta = free_before - free_after;
    if (mem_delta < 0) mem_delta = 0;

    Serial.printf(
        "{\"platform\":\"argon-local\","
        "\"scope\":\"local\","
        "\"alg\":\"%s\","
        "\"op\":\"%s\","
        "\"iter\":%d,"
        "\"msg_len\":%d,"
        "\"time_us\":%lu,"
        "\"free_mem_before\":%d,"
        "\"free_mem_after\":%d,"
        "\"mem_delta\":%d,"
        "\"min_free_mem_during\":%d,"
        "\"pk_len\":%d,"
        "\"sk_len\":%d,"
        "\"sig_len\":%d,"
        "\"ok\":%d}\n",
        alg_name,
        op,
        iter,
        msg_len,
        (unsigned long)time_us,
        free_before,
        free_after,
        mem_delta,
        min_free_during,
        pk_len,
        sk_len,
        sig_len,
        ok
    );
}

static int make_fixed_keypair(
    uint8_t **pk,
    uint8_t **sk,
    size_t *pk_len,
    size_t *sk_len,
    size_t *sig_len_max
) {
    *pk = NULL;
    *sk = NULL;
    *pk_len = 0;
    *sk_len = 0;
    *sig_len_max = 0;

    alloc_space_for_dsa(pk, sk, pk_len, sk_len, sig_len_max);

    if (!(*pk) || !(*sk) || *pk_len == 0 || *sk_len == 0 || *sig_len_max == 0) {
        free_space_for_dsa(*pk, *sk);
        *pk = NULL;
        *sk = NULL;
        return -1;
    }

    diag_mem("BEFORE_fixed_keygen");
    delay(YIELD_MS);

    int rc = dsa_keygen(*pk, *sk);
    Serial.printf("[ARGON-RSA] fixed dsa_keygen rc=%d\n", rc);

    delay(YIELD_MS);
    diag_mem("AFTER_fixed_keygen");

    if (rc != 0) {
        free_space_for_dsa(*pk, *sk);
        *pk = NULL;
        *sk = NULL;
        return rc;
    }

    return 0;
}

static void measure_keypair(void) {
#if (KEYPAIR_ITERS <= 0)
    Serial.println("[ARGON-RSA] keypair skipped");
    return;
#else
    Serial.println("###MEAS_START###");

    for (int it = 0; it < KEYPAIR_ITERS; it++) {
        uint8_t *pk = NULL;
        uint8_t *sk = NULL;
        size_t pk_len = 0, sk_len = 0, sig_len_max = 0;

        alloc_space_for_dsa(&pk, &sk, &pk_len, &sk_len, &sig_len_max);

        int free_before = System.freeMemory();
        int min_free_during = free_before;

        uint32_t t0 = micros();

        diag_mem("BEFORE_keygen");
        delay(YIELD_MS);
        min_free_during = sample_min_free(min_free_during);

        int rc = -1;
        if (pk && sk) {
            rc = dsa_keygen(pk, sk);
        }

        min_free_during = sample_min_free(min_free_during);
        delay(YIELD_MS);
        diag_mem("AFTER_keygen");

        uint32_t t1 = micros();
        int free_after = System.freeMemory();
        min_free_during = sample_min_free(min_free_during);

        emit_jsonl_argon(
            getAlgoName(),
            "keypair",
            it,
            0,
            t1 - t0,
            free_before,
            free_after,
            min_free_during,
            (int)pk_len,
            (int)sk_len,
            (int)sig_len_max,
            (rc == 0)
        );

        free_space_for_dsa(pk, sk);
        delay(50);
    }

    Serial.println("###MEAS_STOP###");
#endif
}

static void measure_sign(void) {
#if (SV_ITERS <= 0)
    Serial.println("[ARGON-RSA] sign skipped");
    return;
#else
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    size_t pk_len = 0, sk_len = 0, sig_len_max = 0;

    if (make_fixed_keypair(&pk, &sk, &pk_len, &sk_len, &sig_len_max) != 0) {
        return;
    }

    uint8_t msg[MSG_LEN];
    for (int i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;

    uint8_t *sig = (uint8_t *)malloc(sig_len_max);
    if (!sig) {
        free_space_for_dsa(pk, sk);
        return;
    }

    Serial.println("###MEAS_START###");
    delay(50);

    for (int it = 0; it < SV_ITERS; it++) {
        size_t sig_len = 0;
        int free_before = System.freeMemory();
        int min_free_during = free_before;

        uint32_t t0 = micros();

        diag_mem("BEFORE_sign");
        delay(1);
        min_free_during = sample_min_free(min_free_during);

        int ok = (dsa_signature(sig, &sig_len, msg, MSG_LEN, sk) == 0);

        min_free_during = sample_min_free(min_free_during);
        delay(1);
        diag_mem("AFTER_sign");

        uint32_t t1 = micros();
        int free_after = System.freeMemory();

        emit_jsonl_argon(
            getAlgoName(),
            "sign",
            it,
            MSG_LEN,
            t1 - t0,
            free_before,
            free_after,
            min_free_during,
            (int)pk_len,
            (int)sk_len,
            ok ? (int)sig_len : -1,
            ok
        );

        delay(YIELD_MS);
    }

    Serial.println("###MEAS_STOP###");

    free(sig);
    free_space_for_dsa(pk, sk);
#endif
}

static void measure_verify(void) {
#if (SV_ITERS <= 0)
    Serial.println("[ARGON-RSA] verify skipped");
    return;
#else
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    size_t pk_len = 0, sk_len = 0, sig_len_max = 0;

    if (make_fixed_keypair(&pk, &sk, &pk_len, &sk_len, &sig_len_max) != 0) {
        return;
    }

    uint8_t msg[MSG_LEN];
    for (int i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;

    uint8_t *sig = (uint8_t *)malloc(sig_len_max);
    if (!sig) {
        free_space_for_dsa(pk, sk);
        return;
    }

    size_t sig_len = 0;
    if (dsa_signature(sig, &sig_len, msg, MSG_LEN, sk) != 0) {
        free(sig);
        free_space_for_dsa(pk, sk);
        return;
    }

    Serial.println("###MEAS_START###");
    delay(50);

    for (int it = 0; it < SV_ITERS; it++) {
        int free_before = System.freeMemory();
        int min_free_during = free_before;

        uint32_t t0 = micros();

        diag_mem("BEFORE_verify");
        delay(1);
        min_free_during = sample_min_free(min_free_during);

        int ok = (dsa_verify(sig, sig_len, msg, MSG_LEN, pk) == 0);

        min_free_during = sample_min_free(min_free_during);
        delay(1);
        diag_mem("AFTER_verify");

        uint32_t t1 = micros();
        int free_after = System.freeMemory();

        emit_jsonl_argon(
            getAlgoName(),
            "verify",
            it,
            MSG_LEN,
            t1 - t0,
            free_before,
            free_after,
            min_free_during,
            (int)pk_len,
            (int)sk_len,
            (int)sig_len,
            ok
        );

        delay(YIELD_MS);
    }

    Serial.println("###MEAS_STOP###");

    free(sig);
    free_space_for_dsa(pk, sk);
#endif
}

static void measure_whole(void) {
#if (WHOLE_ITERS <= 0)
    Serial.println("[ARGON-RSA] whole skipped");
    return;
#else
    uint8_t msg[MSG_LEN];
    for (int i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;

    Serial.println("###MEAS_START###");
    delay(50);

    for (int it = 0; it < WHOLE_ITERS; it++) {
        uint8_t *pk = NULL;
        uint8_t *sk = NULL;
        size_t pk_len = 0, sk_len = 0, sig_len_max = 0;

        alloc_space_for_dsa(&pk, &sk, &pk_len, &sk_len, &sig_len_max);
        uint8_t *sig = (uint8_t *)malloc(sig_len_max);

        int free_before = System.freeMemory();
        int min_free_during = free_before;

        uint32_t t0 = micros();

        int ok_k = 0, ok_s = 0, ok_v = 0;
        size_t sig_len = 0;

        if (pk && sk && sig) {
            ok_k = (dsa_keygen(pk, sk) == 0);
            if (ok_k) ok_s = (dsa_signature(sig, &sig_len, msg, MSG_LEN, sk) == 0);
            if (ok_s) ok_v = (dsa_verify(sig, sig_len, msg, MSG_LEN, pk) == 0);
        }

        uint32_t t1 = micros();
        int free_after = System.freeMemory();
        min_free_during = sample_min_free(min_free_during);

        emit_jsonl_argon(
            getAlgoName(),
            "whole",
            it,
            MSG_LEN,
            t1 - t0,
            free_before,
            free_after,
            min_free_during,
            (int)pk_len,
            (int)sk_len,
            (ok_k && ok_s && ok_v) ? (int)sig_len : -1,
            (ok_k && ok_s && ok_v)
        );

        if (sig) free(sig);
        free_space_for_dsa(pk, sk);
        delay(50);
    }

    Serial.println("###MEAS_STOP###");
#endif
}

// ---------- Entry point ----------
void run_bench_local(void) {
    Serial.printf(
        "[ARGON-RSA] start op=%s keypair_iters=%d sv_iters=%d whole_iters=%d msg_len=%d alg=%s\n",
        BENCH_OP, KEYPAIR_ITERS, SV_ITERS, WHOLE_ITERS, MSG_LEN, getAlgoName()
    );

    if (strcmp(BENCH_OP, "keypair") == 0) {
        measure_keypair();
    } else if (strcmp(BENCH_OP, "sign") == 0) {
        measure_sign();
    } else if (strcmp(BENCH_OP, "verify") == 0) {
        measure_verify();
    } else if (strcmp(BENCH_OP, "whole") == 0) {
        measure_whole();
    } else {
        Serial.printf("[ARGON-RSA] ERROR: unknown BENCH_OP='%s'\n", BENCH_OP);
    }

    Serial.println("[ARGON-RSA] done");
}
