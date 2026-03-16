// main/dsa.c
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

/*
 * BUT:
 * - PQClean headers (via dsa.h) peuvent définir des macros CRYPTO_*.
 * - MAYO (api.h) définit aussi CRYPTO_*.
 *
 * On veut:
 * 1) Inclure MAYO en isolation (variant mayo_1)
 * 2) Capturer les tailles (pk/sk/sig) pour MAYO_1
 * 3) Nettoyer CRYPTO_* pour ne pas casser PQClean
 * 4) Inclure dsa.h ensuite
 */

// -------------------- MAYO include (isolé) --------------------
#ifdef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#endif
#ifdef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_SECRETKEYBYTES
#endif
#ifdef CRYPTO_BYTES
#undef CRYPTO_BYTES
#endif
#ifdef CRYPTO_ALGNAME
#undef CRYPTO_ALGNAME
#endif

// IMPORTANT:
// Avec ton CMake, "mayo/src/mayo_1" est dans INCLUDE_DIRS du composant DSA.
// Donc on inclut directement le api.h de la variante mayo_1.
#include "mayo_1/api.h"
// Vérifie que MAYO a bien posé les macros attendues
#ifndef CRYPTO_PUBLICKEYBYTES
#error "MAYO api.h did not define CRYPTO_PUBLICKEYBYTES (include path / variant issue)"
#endif
#ifndef CRYPTO_SECRETKEYBYTES
#error "MAYO api.h did not define CRYPTO_SECRETKEYBYTES (include path / variant issue)"
#endif
#ifndef CRYPTO_BYTES
#error "MAYO api.h did not define CRYPTO_BYTES (include path / variant issue)"
#endif


// ----- RSA fixed sizes (DER + 2 bytes length header) -----
#define RSA_DER_LEN_HDR_BYTES 2

// Buffers fixes: [len_le16][DER bytes][zero padding]
#define RSA2048_PK_BYTES  512   // largement suffisant pour pubkey DER (SPKI)
#define RSA2048_SK_BYTES  2048  // suffisant pour private key DER (PKCS#1 ou PKCS#8)
#define RSA2048_SIG_BYTES 256   // exact: 2048 bits / 8

static size_t read_le16_len(const uint8_t *buf, size_t buf_sz) {
    if (buf_sz < 2) return 0;
    return (size_t)buf[0] | ((size_t)buf[1] << 8);
}

static void write_le16_len(uint8_t *buf, size_t len) {
    buf[0] = (uint8_t)(len & 0xFF);
    buf[1] = (uint8_t)((len >> 8) & 0xFF);
}

// ----- RSA RNG (init once) -----
static bool g_rng_ready = false;
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr;

static int rng_ensure_ready(void) {
    if (g_rng_ready) return 0;

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr);

    const char *pers = "esp32-rsa-bench";
    int r = mbedtls_ctr_drbg_seed(&g_ctr, mbedtls_entropy_func, &g_entropy,
                                  (const unsigned char *)pers, strlen(pers));
    if (r == 0) g_rng_ready = true;
    return r;
}

// Capture des tailles MAYO (constantes locales à ce TU)
static const size_t MAYO_PK_BYTES  = (size_t)CRYPTO_PUBLICKEYBYTES;
static const size_t MAYO_SK_BYTES  = (size_t)CRYPTO_SECRETKEYBYTES;
static const size_t MAYO_SIG_BYTES = (size_t)CRYPTO_BYTES;

// Nettoyage pour éviter de polluer le reste du TU (et PQClean)
#ifdef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#endif
#ifdef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_SECRETKEYBYTES
#endif
#ifdef CRYPTO_BYTES
#undef CRYPTO_BYTES
#endif
#ifdef CRYPTO_ALGNAME
#undef CRYPTO_ALGNAME
#endif

// -------------------- PQClean (dsa.h) après MAYO --------------------
#include "dsa.h"

// ---------- Helpers ----------
const char* getAlgoName(enum DSA_ALGO algo) {
    switch (algo) {
        case FALCON_512:          return "FALCON_512";
        case FALCON_1024:         return "FALCON_1024";
        case FALCON_PADDED_512:   return "FALCON_PADDED_512";
        case FALCON_PADDED_1024:  return "FALCON_PADDED_1024";
        case ML_DSA_44:           return "ML_DSA_44";
        case ML_DSA_65:           return "ML_DSA_65";
        case ML_DSA_87:           return "ML_DSA_87";
        case SPHINCS_SHA2_128F:   return "SPHINCS_SHA2_128F";
        case SPHINCS_SHA2_128S:   return "SPHINCS_SHA2_128S";
        case SPHINCS_SHA2_192F:   return "SPHINCS_SHA2_192F";
        case SPHINCS_SHA2_192S:   return "SPHINCS_SHA2_192S";
        case SPHINCS_SHA2_256F:   return "SPHINCS_SHA2_256F";
        case SPHINCS_SHA2_256S:   return "SPHINCS_SHA2_256S";
        case SPHINCS_SHAKE_128F:  return "SPHINCS_SHAKE_128F";
        case SPHINCS_SHAKE_128S:  return "SPHINCS_SHAKE_128S";
        case SPHINCS_SHAKE_192F:  return "SPHINCS_SHAKE_192F";
        case SPHINCS_SHAKE_192S:  return "SPHINCS_SHAKE_192S";
        case SPHINCS_SHAKE_256F:  return "SPHINCS_SHAKE_256F";
        case SPHINCS_SHAKE_256S:  return "SPHINCS_SHAKE_256S";
        case MAYO_SIG_1:              return "MAYO_1";
        case RSA_2048: return "RSA_2048";
        default:                  return "UNKNOWN";
    }
}

// ---------- Keypair ----------
int dsa_keygen(enum DSA_ALGO algo, uint8_t *pk, uint8_t *sk) {
    switch (algo) {
        case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
        case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
        case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
        case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);

        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
        case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
        case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);

        case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_192F:  return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_192S:  return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_256F:  return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_256S:  return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

        case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

        case MAYO_SIG_1:{
            printf("[MAYO] calling crypto_sign_keypair...\n");
            int r = crypto_sign_keypair(pk, sk);
            printf("[MAYO] crypto_sign_keypair returned %d\n", r);
            return r;
        }

        case RSA_2048: {
            int r = rng_ensure_ready();
            if (r != 0) return r;

            mbedtls_pk_context pkctx;
            mbedtls_pk_init(&pkctx);

            r = mbedtls_pk_setup(&pkctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
            if (r != 0) { mbedtls_pk_free(&pkctx); return r; }

            mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pkctx);
            mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

            r = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &g_ctr, 2048, 65537);
            if (r != 0) { mbedtls_pk_free(&pkctx); return r; }

            // Nettoyer les buffers cibles AVANT de copier
            memset(pk, 0, RSA2048_PK_BYTES);
            memset(sk, 0, RSA2048_SK_BYTES);

            // ---------- PUBKEY DER ----------
            {
                uint8_t work[RSA2048_PK_BYTES - RSA_DER_LEN_HDR_BYTES];
                memset(work, 0, sizeof(work));

                int pub_len = mbedtls_pk_write_pubkey_der(&pkctx, work, (int)sizeof(work));
                if (pub_len < 0) { mbedtls_pk_free(&pkctx); return pub_len; }

                size_t start = sizeof(work) - (size_t)pub_len;
                write_le16_len(pk, (size_t)pub_len);
                memcpy(pk + RSA_DER_LEN_HDR_BYTES, work + start, (size_t)pub_len);
            }

            // ---------- PRIVKEY DER ----------
            {
                uint8_t work[RSA2048_SK_BYTES - RSA_DER_LEN_HDR_BYTES];
                memset(work, 0, sizeof(work));

                int sk_len = mbedtls_pk_write_key_der(&pkctx, work, (int)sizeof(work));
                if (sk_len < 0) { mbedtls_pk_free(&pkctx); return sk_len; }

                size_t start = sizeof(work) - (size_t)sk_len;
                write_le16_len(sk, (size_t)sk_len);
                memcpy(sk + RSA_DER_LEN_HDR_BYTES, work + start, (size_t)sk_len);
            }

            mbedtls_pk_free(&pkctx);
            return 0;
        }

        default: return -1;
    }
}

// ---------- Signature-only API ----------
int dsa_signature(enum DSA_ALGO algo,
                  uint8_t *sig, size_t *siglen,
                  const uint8_t *m, size_t mlen,
                  const uint8_t *sk)
{
    switch (algo) {
        case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_192F:  return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_192S:  return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_256F:  return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_256S:  return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        case MAYO_SIG_1:             return crypto_sign_signature(sig, siglen, m, mlen, sk);

        case RSA_2048: {
            int r = rng_ensure_ready();
            if (r != 0) return r;

            size_t der_len = read_le16_len(sk, RSA2048_SK_BYTES);
            if (der_len == 0 || der_len > (RSA2048_SK_BYTES - RSA_DER_LEN_HDR_BYTES)) return -1;

            const uint8_t *der = sk + RSA_DER_LEN_HDR_BYTES;

            mbedtls_pk_context skctx;
            mbedtls_pk_init(&skctx);

            r = mbedtls_pk_parse_key(&skctx, der, der_len,
                                    NULL, 0,
                                    mbedtls_ctr_drbg_random, &g_ctr);
            if (r != 0) {
                char errbuf[128];
                mbedtls_strerror(r, errbuf, sizeof(errbuf));
                printf("[RSA] parse_key error: %d (%s)\n", r, errbuf);
                mbedtls_pk_free(&skctx);
                return r;
            }

            if (!mbedtls_pk_can_do(&skctx, MBEDTLS_PK_RSA)) {
                mbedtls_pk_free(&skctx);
                return -1;
            }

            // Padding signature: PKCS#1 v1.5 + SHA256
            mbedtls_rsa_set_padding(mbedtls_pk_rsa(skctx), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

            unsigned char hash[32];
            r = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), m, mlen, hash);
            if (r != 0) {
                char errbuf[128];
                mbedtls_strerror(r, errbuf, sizeof(errbuf));
                printf("[RSA] sha256 error: %d (%s)\n", r, errbuf);
                mbedtls_pk_free(&skctx);
                return r;
            }

            size_t out_len = 0;
            r = mbedtls_pk_sign(&skctx,
                                MBEDTLS_MD_SHA256,
                                hash, 0,                 // ✅ IMPORTANT: hash_len = 0
                                sig, RSA2048_SIG_BYTES,
                                &out_len,
                                mbedtls_ctr_drbg_random, &g_ctr);

            if (r != 0) {
                char errbuf[128];
                mbedtls_strerror(r, errbuf, sizeof(errbuf));
                printf("[RSA] sign error: %d (%s)\n", r, errbuf);
                mbedtls_pk_free(&skctx);
                return r;
            }

            mbedtls_pk_free(&skctx);
            *siglen = out_len;  // devrait être 256
            return 0;
        }

        default: return -1;
    }
}

int dsa_verify(enum DSA_ALGO algo,
               const uint8_t *sig, size_t siglen,
               const uint8_t *m, size_t mlen,
               const uint8_t *pk)
{
    switch (algo) {
        case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_192F:  return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_192S:  return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_256F:  return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_256S:  return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        // case MAYO_SIG_1:             return crypto_sign_verify(sig, siglen, m, mlen, pk);

        case RSA_2048: {
            size_t der_len = read_le16_len(pk, RSA2048_PK_BYTES);
            if (der_len == 0 || der_len > (RSA2048_PK_BYTES - RSA_DER_LEN_HDR_BYTES)) return -1;

            const uint8_t *der = pk + RSA_DER_LEN_HDR_BYTES;

            mbedtls_pk_context pkctx;
            mbedtls_pk_init(&pkctx);

            int r = mbedtls_pk_parse_public_key(&pkctx, der, der_len);
            if (r != 0) {
                char errbuf[128];
                mbedtls_strerror(r, errbuf, sizeof(errbuf));
                printf("[RSA] parse_pubkey error: %d (%s)\n", r, errbuf);
                mbedtls_pk_free(&pkctx);
                return r;
            }

            if (!mbedtls_pk_can_do(&pkctx, MBEDTLS_PK_RSA)) {
                mbedtls_pk_free(&pkctx);
                return -1;
            }

            mbedtls_rsa_set_padding(mbedtls_pk_rsa(pkctx), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

            unsigned char hash[32];
            r = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), m, mlen, hash);
            if (r != 0) {
                char errbuf[128];
                mbedtls_strerror(r, errbuf, sizeof(errbuf));
                printf("[RSA] sha256 error: %d (%s)\n", r, errbuf);
                mbedtls_pk_free(&pkctx);
                return r;
            }

            r = mbedtls_pk_verify(&pkctx,
                                MBEDTLS_MD_SHA256,
                                hash, 0,               // ✅ IMPORTANT: hash_len = 0
                                sig, siglen);

            if (r != 0) {
                char errbuf[128];
                mbedtls_strerror(r, errbuf, sizeof(errbuf));
                printf("[RSA] verify error: %d (%s)\n", r, errbuf);
            }

            mbedtls_pk_free(&pkctx);
            return r;  // 0 = OK
        }
        default: return -1;
    }
}

// ---------- Sizes ----------
size_t get_public_key_length(enum DSA_ALGO algo) {
    switch (algo) {
        case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;

        case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_192F:  return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_192S:  return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_256F:  return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_256S:  return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;

        // FIX: BYBYTES -> BYTES
        case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;

        case MAYO_SIG_1:             return MAYO_PK_BYTES;
        case RSA_2048: return RSA2048_PK_BYTES;
        default: return 0;
    }
}

size_t get_secret_key_length(enum DSA_ALGO algo) {
    switch (algo) {
        case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;
        case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;
        case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES;
        case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES;

        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
        case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
        case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;

        case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_192F:  return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_192S:  return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_256F:  return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_256S:  return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;

        case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;

        case MAYO_SIG_1:             return MAYO_SK_BYTES;
        case RSA_2048: return RSA2048_SK_BYTES;
        default: return 0;
    }
}

size_t get_signature_length(enum DSA_ALGO algo) {
    switch (algo) {
        case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;
        case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES;
        case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES;
        case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES;

        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;
        case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
        case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;

        case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_192F:  return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_192S:  return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_256F:  return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_256S:  return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES;

        case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES;

        case MAYO_SIG_1:             return MAYO_SIG_BYTES;
        case RSA_2048: return RSA2048_SIG_BYTES;
        default: return 0;
    }
}

// ---------- Allocation ----------
void alloc_space_for_dsa(enum DSA_ALGO algo,
                         uint8_t **pk, uint8_t **sk,
                         size_t *pk_len, size_t *sk_len, size_t *sig_len)
{
    *pk_len  = get_public_key_length(algo);
    *sk_len  = get_secret_key_length(algo);
    *sig_len = get_signature_length(algo);

    if (*pk_len == 0 || *sk_len == 0 || *sig_len == 0) {
        *pk = NULL; *sk = NULL;
        return;
    }

    *pk = (uint8_t*)malloc(*pk_len);
    *sk = (uint8_t*)malloc(*sk_len);

    if (!*pk || !*sk) {
        free(*pk); free(*sk);
        *pk = NULL; *sk = NULL;
    }
}

void free_space_for_dsa(uint8_t *pk, uint8_t *sk) {
    if (pk) free(pk);
    if (sk) free(sk);
}