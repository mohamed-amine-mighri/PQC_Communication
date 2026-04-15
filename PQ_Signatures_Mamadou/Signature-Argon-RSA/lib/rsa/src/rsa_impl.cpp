#include "Particle.h"
#include "dsa.h"

#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/sha256.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define RSA_MOD_BITS        2048
#define RSA_MOD_BYTES       (RSA_MOD_BITS / 8)   // 256
#define RSA_SIG_BYTES       RSA_MOD_BYTES
#define RSA_PUBLIC_EXPONENT 65537

// pk = N (256 bytes)
// sk = N || D (512 bytes)
#define RSA_PK_PACKED_BYTES RSA_MOD_BYTES
#define RSA_SK_PACKED_BYTES (2 * RSA_MOD_BYTES)

static int particle_rng(void *p_rng, unsigned char *output, size_t output_len) {
    (void)p_rng;

    if (!output) {
        return -1;
    }

    size_t off = 0;
    while (off < output_len) {
        uint32_t r = HAL_RNG_GetRandomNumber();
        size_t chunk = output_len - off;
        if (chunk > sizeof(r)) {
            chunk = sizeof(r);
        }
        memcpy(output + off, &r, chunk);
        off += chunk;
    }

    return 0;
}

static void set_lengths(size_t *pk_len, size_t *sk_len, size_t *sig_len_max) {
    if (pk_len)      *pk_len = RSA_PK_PACKED_BYTES;
    if (sk_len)      *sk_len = RSA_SK_PACKED_BYTES;
    if (sig_len_max) *sig_len_max = RSA_SIG_BYTES;
}

void alloc_space_for_dsa(uint8_t **pk, uint8_t **sk,
                         size_t *pk_len, size_t *sk_len,
                         size_t *sig_len_max) {
    if (!pk || !sk || !pk_len || !sk_len || !sig_len_max) {
        return;
    }

    set_lengths(pk_len, sk_len, sig_len_max);

    *pk = (uint8_t *)malloc(*pk_len);
    *sk = (uint8_t *)malloc(*sk_len);

    if (!*pk || !*sk) {
        if (*pk) free(*pk);
        if (*sk) free(*sk);
        *pk = NULL;
        *sk = NULL;
        *pk_len = 0;
        *sk_len = 0;
        *sig_len_max = 0;
    }
}

void free_space_for_dsa(uint8_t *pk, uint8_t *sk) {
    if (pk) free(pk);
    if (sk) free(sk);
}

static int export_public_key_N(const mbedtls_rsa_context *rsa, uint8_t *pk) {
    int rc;
    mbedtls_mpi N, P, Q, D, E;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);

    rc = mbedtls_rsa_export((mbedtls_rsa_context *)rsa, &N, &P, &Q, &D, &E);
    if (rc != 0) goto cleanup;

    rc = mbedtls_mpi_write_binary(&N, pk, RSA_MOD_BYTES);

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    return rc;
}

static int export_secret_key_ND(const mbedtls_rsa_context *rsa, uint8_t *sk) {
    int rc;
    mbedtls_mpi N, P, Q, D, E;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);

    rc = mbedtls_rsa_export((mbedtls_rsa_context *)rsa, &N, &P, &Q, &D, &E);
    if (rc != 0) goto cleanup;

    rc = mbedtls_mpi_write_binary(&N, sk, RSA_MOD_BYTES);
    if (rc != 0) goto cleanup;

    rc = mbedtls_mpi_write_binary(&D, sk + RSA_MOD_BYTES, RSA_MOD_BYTES);

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    return rc;
}

static int import_public_key(mbedtls_rsa_context *rsa, const uint8_t *pk) {
    int rc;
    mbedtls_mpi N, E;

    if (!rsa || !pk) {
        return -1;
    }

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);

    rc = mbedtls_mpi_read_binary(&N, pk, RSA_MOD_BYTES);
    if (rc != 0) goto cleanup;

    rc = mbedtls_mpi_lset(&E, RSA_PUBLIC_EXPONENT);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_complete(rsa);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_check_pubkey(rsa);

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    return rc;
}

static int import_secret_key(mbedtls_rsa_context *rsa, const uint8_t *sk) {
    int rc;
    mbedtls_mpi N, D, E;

    if (!rsa || !sk) {
        return -1;
    }

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);

    rc = mbedtls_mpi_read_binary(&N, sk, RSA_MOD_BYTES);
    if (rc != 0) goto cleanup;

    rc = mbedtls_mpi_read_binary(&D, sk + RSA_MOD_BYTES, RSA_MOD_BYTES);
    if (rc != 0) goto cleanup;

    rc = mbedtls_mpi_lset(&E, RSA_PUBLIC_EXPONENT);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_import(rsa, &N, NULL, NULL, &D, &E);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_complete(rsa);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_check_privkey(rsa);

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    return rc;
}

static int hash_message_sha256(const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    if (!out) {
        return -1;
    }

    if (!msg && msg_len != 0) {
        return -1;
    }

    return mbedtls_sha256_ret(msg, msg_len, out, 0);
}

int dsa_keygen(uint8_t *pk, uint8_t *sk) {
    int rc;
    mbedtls_rsa_context rsa;

    if (!pk || !sk) {
        return -1;
    }

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    rc = mbedtls_rsa_gen_key(&rsa, particle_rng, NULL, RSA_MOD_BITS, RSA_PUBLIC_EXPONENT);
    if (rc != 0) goto cleanup;

    rc = export_public_key_N(&rsa, pk);
    if (rc != 0) goto cleanup;

    rc = export_secret_key_ND(&rsa, sk);
    if (rc != 0) goto cleanup;

cleanup:
    mbedtls_rsa_free(&rsa);
    return rc;
}

int dsa_signature(uint8_t *sig, size_t *sig_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *sk) {
    int rc;
    uint8_t hash[32];
    mbedtls_rsa_context rsa;

    if (!sig || !sig_len || !sk) {
        return -1;
    }

    rc = hash_message_sha256(msg, msg_len, hash);
    if (rc != 0) {
        return rc;
    }

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    rc = import_secret_key(&rsa, sk);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_pkcs1_sign(&rsa,
                                particle_rng,
                                NULL,
                                MBEDTLS_RSA_PRIVATE,
                                MBEDTLS_MD_SHA256,
                                32,
                                hash,
                                sig);
    if (rc != 0) goto cleanup;

    *sig_len = RSA_SIG_BYTES;

cleanup:
    mbedtls_rsa_free(&rsa);
    return rc;
}

int dsa_verify(const uint8_t *sig, size_t sig_len,
               const uint8_t *msg, size_t msg_len,
               const uint8_t *pk) {
    int rc;
    uint8_t hash[32];
    mbedtls_rsa_context rsa;

    if (!sig || !pk) {
        return -1;
    }

    if (sig_len != RSA_SIG_BYTES) {
        return -1;
    }

    rc = hash_message_sha256(msg, msg_len, hash);
    if (rc != 0) {
        return rc;
    }

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    rc = import_public_key(&rsa, pk);
    if (rc != 0) goto cleanup;

    rc = mbedtls_rsa_pkcs1_verify(&rsa,
                                  NULL,
                                  NULL,
                                  MBEDTLS_RSA_PUBLIC,
                                  MBEDTLS_MD_SHA256,
                                  32,
                                  hash,
                                  sig);

cleanup:
    mbedtls_rsa_free(&rsa);
    return rc;
}

const char* getAlgoName(void) {
    return "RSA_2048_mbedTLS";
}