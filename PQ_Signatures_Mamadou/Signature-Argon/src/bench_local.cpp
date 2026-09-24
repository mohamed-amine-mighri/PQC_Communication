#include "Particle.h"
#include "../lib/pqc/dsa.h"
#include "bench_local.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------- Prototypes ----------
static void diag_mem(const char *where);

static DSA_ALGO bench_alg_from_str(const char *s);

static void emit_jsonl_argon(
    const char *alg_name,
    const char *op,
    int iter,
    int msg_len,
    uint32_t time_us,
    int free_before,
    int free_after,
    int pk_len,
    int sk_len,
    int sig_len,
    int ok
);

static int make_fixed_keypair(
    DSA_ALGO algo,
    uint8_t **pk,
    uint8_t **sk,
    size_t *pk_len,
    size_t *sk_len,
    size_t *sig_len_max
);

static void measure_keypair(
    DSA_ALGO algo,
    const char *alg_name,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
);

static void measure_sign_only_fixed_key(
    DSA_ALGO algo,
    const char *alg_name,
    const uint8_t *msg,
    size_t msg_len,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
);

static void measure_verify_only_fixed_key(
    DSA_ALGO algo,
    const char *alg_name,
    const uint8_t *msg,
    size_t msg_len,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
);

static void measure_whole_full(
    DSA_ALGO algo,
    const char *alg_name,
    const uint8_t *msg,
    size_t msg_len,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
);

static void run_one_bench_op(DSA_ALGO algo);

// ---------- Paramètres ----------
#ifndef KEYPAIR_ITERS
#define KEYPAIR_ITERS 0
#endif

#ifndef SV_ITERS
#define SV_ITERS 20
#endif

#ifndef WHOLE_ITERS
#define WHOLE_ITERS 0
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
#define BENCH_OP "verify"
#endif

#ifndef BENCH_ALG
#define BENCH_ALG "SPHINCS_SHAKE_128S"
#endif

// ---------- Diagnostics ----------
static void diag_mem(const char *where) {
    int free_mem = System.freeMemory();
    Serial.printf("[ARGON-LOCAL] diag %s free_mem=%d\n", where, free_mem);
}

static inline int sample_min_free(int current_min) {
    int now = System.freeMemory();
    return (now < current_min) ? now : current_min;
}

#if (WARMUP > 0)
static void warmup_safe(void) {
    for (int w = 0; w < WARMUP; w++) {
        delay(50);
    }
}
#endif

// ---------- Choix algos ----------
static DSA_ALGO bench_alg_from_str(const char *s) {
    if (!s) {
        Serial.println("[ARGON-LOCAL] WARN: NULL alg -> using ML_DSA_44");
        return ML_DSA_44;
    }

    if (strcmp(s, "ML_DSA_44") == 0) return ML_DSA_44;
    //if (strcmp(s, "ML_DSA_65") == 0) return ML_DSA_65;
    //if (strcmp(s, "ML_DSA_87") == 0) return ML_DSA_87;

    //if (strcmp(s, "FALCON_512") == 0) return FALCON_512;
    //if (strcmp(s, "FALCON_1024") == 0) return FALCON_1024;
    //if (strcmp(s, "FALCON_PADDED_512") == 0) return FALCON_PADDED_512;
    if (strcmp(s, "FALCON_PADDED_1024") == 0) return FALCON_PADDED_1024;

    //if (strcmp(s, "SPHINCS_SHAKE_128F") == 0) return SPHINCS_SHAKE_128F;
    if (strcmp(s, "SPHINCS_SHAKE_128S") == 0) return SPHINCS_SHAKE_128S;
    //if (strcmp(s, "SPHINCS_SHAKE_192F") == 0) return SPHINCS_SHAKE_192F;
    //if (strcmp(s, "SPHINCS_SHAKE_192S") == 0) return SPHINCS_SHAKE_192S;
    //if (strcmp(s, "SPHINCS_SHAKE_256F") == 0) return SPHINCS_SHAKE_256F;
    //if (strcmp(s, "SPHINCS_SHAKE_256S") == 0) return SPHINCS_SHAKE_256S;

    //if (strcmp(s, "SPHINCS_SHA2_128F") == 0) return SPHINCS_SHA2_128F;
    //if (strcmp(s, "SPHINCS_SHA2_128S") == 0) return SPHINCS_SHA2_128S;

    Serial.printf(
        "[ARGON-LOCAL] WARN: unsupported alg '%s' -> using ML_DSA_44\n",
        s
    );
    return ML_DSA_44;
}
// ---------- JSON ----------
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
    if (mem_delta < 0) {
        mem_delta = 0;
    }

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


// ---------- Utilitaire: générer une clé fixe ----------
static int make_fixed_keypair(
    DSA_ALGO algo,
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

    size_t pk_l = 0, sk_l = 0, sig_m = 0;
    alloc_space_for_dsa(algo, pk, sk, &pk_l, &sk_l, &sig_m);

    if (!(*pk) || !(*sk) || pk_l == 0 || sk_l == 0 || sig_m == 0) {
        free_space_for_dsa(*pk, *sk);
        *pk = NULL;
        *sk = NULL;
        return -1;
    }

    diag_mem("BEFORE_fixed_keygen");
    delay(YIELD_MS);

    Serial.println("[ARGON-LOCAL] calling dsa_keygen (fixed)");
    int rc = dsa_keygen(algo, *pk, *sk);
    Serial.printf("[ARGON-LOCAL] dsa_keygen (fixed) returned rc=%d\n", rc);

    delay(YIELD_MS);
    diag_mem("AFTER_fixed_keygen");

    if (rc != 0) {
        free_space_for_dsa(*pk, *sk);
        *pk = NULL;
        *sk = NULL;
        return rc;
    }

    *pk_len = pk_l;
    *sk_len = sk_l;
    *sig_len_max = sig_m;
    return 0;
}

// ---------- KEYPAIR ----------
static void measure_keypair(
    DSA_ALGO algo,
    const char *alg_name,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
) {
#if (KEYPAIR_ITERS <= 0)
    (void)algo;
    (void)alg_name;
    (void)pk_len;
    (void)sk_len;
    (void)sig_len_max;
    Serial.println("[ARGON-LOCAL] keypair skipped (KEYPAIR_ITERS=0)");
    return;
#else
    Serial.println("###MEAS_START###");
    delay(1500);

    for (int it = 0; it < KEYPAIR_ITERS; it++) {
        uint8_t *pk = NULL;
        uint8_t *sk = NULL;
        size_t pk_l = 0, sk_l = 0, sig_m = 0;

        alloc_space_for_dsa(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);

        int free_before = System.freeMemory();
        int min_free_during = free_before;
        min_free_during = sample_min_free(min_free_during);

        uint32_t t0 = micros();

        diag_mem("BEFORE_keygen");
        delay(YIELD_MS);
        min_free_during = sample_min_free(min_free_during);

        int rc = -999;
        if (pk && sk) {
            Serial.println("[ARGON-LOCAL] calling dsa_keygen");
            rc = dsa_keygen(algo, pk, sk);
            Serial.printf("[ARGON-LOCAL] dsa_keygen returned rc=%d\n", rc);
            min_free_during = sample_min_free(min_free_during);
        } else {
            Serial.println("[ARGON-LOCAL] ERROR: pk/sk allocation failed before keygen");
        }

        delay(YIELD_MS);
        diag_mem("AFTER_keygen");

        uint32_t t1 = micros();
        int free_after = System.freeMemory();
        min_free_during = sample_min_free(min_free_during);

        int ok = (rc == 0);

        emit_jsonl_argon(
            alg_name,
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
            ok
        );

        free_space_for_dsa(pk, sk);
        delay(50);
    }

    Serial.println("###MEAS_STOP###");
#endif
}
// ---------- SIGN ONLY ----------
static void measure_sign_only_fixed_key(
    DSA_ALGO algo,
    const char *alg_name,
    const uint8_t *msg,
    size_t msg_len,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
) {
#if (SV_ITERS <= 0)
    (void)algo;
    (void)alg_name;
    (void)msg;
    (void)msg_len;
    (void)pk_len;
    (void)sk_len;
    (void)sig_len_max;
    Serial.println("[ARGON-LOCAL] sign skipped (SV_ITERS=0)");
    return;
#else
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    size_t pk_l = 0, sk_l = 0, sig_m = 0;

    Serial.println("[ARGON-LOCAL] fixed keypair for SIGN begin");
    int rc_k = make_fixed_keypair(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);
    Serial.printf("[ARGON-LOCAL] fixed keypair for SIGN end rc=%d\n", rc_k);
    if (rc_k != 0) {
        return;
    }

    uint8_t *sig = (uint8_t*)malloc(sig_len_max);
    if (!sig) {
        Serial.println("[ARGON-LOCAL] sign skipped (malloc sig failed)");
        free_space_for_dsa(pk, sk);
        return;
    }

    Serial.println("###MEAS_START###");
    delay(1500);

    for (int it = 0; it < SV_ITERS; it++) {
        size_t sig_len = 0;

        int free_before = System.freeMemory();
        int min_free_during = free_before;
        min_free_during = sample_min_free(min_free_during);

        uint32_t t0 = micros();

        diag_mem("BEFORE_sign");
        delay(1);
        min_free_during = sample_min_free(min_free_during);

        int ok_s = (dsa_signature(algo, sig, &sig_len, msg, msg_len, sk) == 0);
        min_free_during = sample_min_free(min_free_during);

        delay(1);
        diag_mem("AFTER_sign");

        uint32_t t1 = micros();
        int free_after = System.freeMemory();
        min_free_during = sample_min_free(min_free_during);

        emit_jsonl_argon(
            alg_name,
            "sign",
            it,
            (int)msg_len,
            t1 - t0,
            free_before,
            free_after,
            min_free_during,
            (int)pk_len,
            (int)sk_len,
            ok_s ? (int)sig_len : -1,
            ok_s
        );

        delay(YIELD_MS);
    }

    Serial.println("###MEAS_STOP###");

    free(sig);
    free_space_for_dsa(pk, sk);
#endif
}
// ---------- VERIFY ONLY ----------
static void measure_verify_only_fixed_key(
    DSA_ALGO algo,
    const char *alg_name,
    const uint8_t *msg,
    size_t msg_len,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
) {
#if (SV_ITERS <= 0)
    (void)algo;
    (void)alg_name;
    (void)msg;
    (void)msg_len;
    (void)pk_len;
    (void)sk_len;
    (void)sig_len_max;
    Serial.println("[ARGON-LOCAL] verify skipped (SV_ITERS=0)");
    return;
#else
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    size_t pk_l = 0, sk_l = 0, sig_m = 0;

    Serial.println("[ARGON-LOCAL] fixed keypair for VERIFY begin");
    int rc_k = make_fixed_keypair(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);
    Serial.printf("[ARGON-LOCAL] fixed keypair for VERIFY end rc=%d\n", rc_k);
    if (rc_k != 0) {
        return;
    }

    uint8_t *sig = (uint8_t*)malloc(sig_len_max);
    if (!sig) {
        Serial.println("[ARGON-LOCAL] verify skipped (malloc sig failed)");
        free_space_for_dsa(pk, sk);
        return;
    }

    size_t sig_len = 0;
    int ok_pre = (dsa_signature(algo, sig, &sig_len, msg, msg_len, sk) == 0);
    if (!ok_pre) {
        Serial.println("[ARGON-LOCAL] verify skipped (pre-sign failed)");
        free(sig);
        free_space_for_dsa(pk, sk);
        return;
    }

    Serial.println("###MEAS_START###");
    delay(1500);

    for (int it = 0; it < SV_ITERS; it++) {
        int free_before = System.freeMemory();
        int min_free_during = free_before;
        min_free_during = sample_min_free(min_free_during);

        uint32_t t0 = micros();

        diag_mem("BEFORE_verify");
        delay(1);
        min_free_during = sample_min_free(min_free_during);

        int ok_v = (dsa_verify(algo, sig, sig_len, msg, msg_len, pk) == 0);
        min_free_during = sample_min_free(min_free_during);

        delay(1);
        diag_mem("AFTER_verify");

        uint32_t t1 = micros();
        int free_after = System.freeMemory();
        min_free_during = sample_min_free(min_free_during);

        emit_jsonl_argon(
            alg_name,
            "verify",
            it,
            (int)msg_len,
            t1 - t0,
            free_before,
            free_after,
            min_free_during,
            (int)pk_len,
            (int)sk_len,
            (int)sig_len,
            ok_v
        );

        delay(YIELD_MS);
    }

    Serial.println("###MEAS_STOP###");

    free(sig);
    free_space_for_dsa(pk, sk);
#endif
}

// ---------- WHOLE ----------
static void measure_whole_full(
    DSA_ALGO algo,
    const char *alg_name,
    const uint8_t *msg,
    size_t msg_len,
    size_t pk_len,
    size_t sk_len,
    size_t sig_len_max
) {
#if (WHOLE_ITERS <= 0)
    (void)algo;
    (void)alg_name;
    (void)msg;
    (void)msg_len;
    (void)pk_len;
    (void)sk_len;
    (void)sig_len_max;
    Serial.println("[ARGON-LOCAL] whole skipped (WHOLE_ITERS=0)");
    return;
#else
    uint8_t *sig = (uint8_t*)malloc(sig_len_max);
    if (!sig) {
        Serial.println("[ARGON-LOCAL] whole skipped (malloc sig failed)");
        return;
    }

    Serial.println("###MEAS_START###");
    delay(1500);

    for (int it = 0; it < WHOLE_ITERS; it++) {
        int free_before = System.freeMemory();
        int min_free_during = free_before;
        min_free_during = sample_min_free(min_free_during);

        uint32_t t0 = micros();

        diag_mem("BEFORE_whole");
        delay(YIELD_MS);
        min_free_during = sample_min_free(min_free_during);

        uint8_t *pk = NULL;
        uint8_t *sk = NULL;
        size_t pk_l = 0, sk_l = 0, sig_m = 0;
        alloc_space_for_dsa(algo, &pk, &sk, &pk_l, &sk_l, &sig_m);
        min_free_during = sample_min_free(min_free_during);

        int ok_k = (pk && sk && (dsa_keygen(algo, pk, sk) == 0));
        min_free_during = sample_min_free(min_free_during);

        size_t sig_len = 0;
        int ok_s = 0;
        if (ok_k && dsa_signature(algo, sig, &sig_len, msg, msg_len, sk) == 0) {
            ok_s = 1;
        }
        min_free_during = sample_min_free(min_free_during);

        int ok_v = 0;
        if (ok_s && dsa_verify(algo, sig, sig_len, msg, msg_len, pk) == 0) {
            ok_v = 1;
        }
        min_free_during = sample_min_free(min_free_during);

        int ok_all = ok_k && ok_s && ok_v;

        delay(YIELD_MS);
        diag_mem("AFTER_whole");

        free_space_for_dsa(pk, sk);

        uint32_t t1 = micros();
        int free_after = System.freeMemory();
        min_free_during = sample_min_free(min_free_during);

        emit_jsonl_argon(
            alg_name,
            "whole",
            it,
            (int)msg_len,
            t1 - t0,
            free_before,
            free_after,
            min_free_during,
            (int)pk_len,
            (int)sk_len,
            ok_all ? (int)sig_len : -1,
            ok_all
        );

        delay(50);
    }

    Serial.println("###MEAS_STOP###");

    free(sig);
#endif
}
// ---------- BENCH one op ----------
static void run_one_bench_op(DSA_ALGO algo) {
    const char *alg_name = getAlgoName(algo);

    uint8_t msg[MSG_LEN];
    for (int i = 0; i < MSG_LEN; i++) {
        msg[i] = (uint8_t)i;
    }

    uint8_t *pk0 = NULL;
    uint8_t *sk0 = NULL;
    size_t pk_len = 0, sk_len = 0, sig_len_max = 0;
    alloc_space_for_dsa(algo, &pk0, &sk0, &pk_len, &sk_len, &sig_len_max);
    free_space_for_dsa(pk0, sk0);

    Serial.printf(
        "[ARGON-LOCAL] selected alg=%s (BENCH_ALG='%s') op=%s\n",
        alg_name, BENCH_ALG, BENCH_OP
    );

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

    Serial.printf("[ARGON-LOCAL] ERROR: unknown BENCH_OP='%s'\n", BENCH_OP);
}

// ---------- Entry point ----------
void run_bench_local(void) {
    Serial.printf(
        "[ARGON-LOCAL] start op=%s alg=%s keypair_iters=%d sv_iters=%d whole_iters=%d warmup=%d msg_len=%d\n",
        BENCH_OP, BENCH_ALG, KEYPAIR_ITERS, SV_ITERS, WHOLE_ITERS, WARMUP, MSG_LEN
    );

    DSA_ALGO algo = bench_alg_from_str(BENCH_ALG);

    delay(3000);
    run_one_bench_op(algo);

    Serial.println("[ARGON-LOCAL] done");
}