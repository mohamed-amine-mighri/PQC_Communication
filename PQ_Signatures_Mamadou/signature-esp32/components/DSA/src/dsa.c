#include "dsa.h"
#include "string.h"
#include "freertos/FreeRTOS.h"

const char* getAlgoName(enum DSA_ALGO algo){
    switch (algo)
    {
        case FALCON_512: return "FALCON_512";
        case FALCON_1024: return "FALCON_1024";
        case FALCON_PADDED_512: return "FALCON_PADDED_512";
        case FALCON_PADDED_1024: return "FALCON_PADDED_1024";
        case ML_DSA_44: return "ML_DSA_44";
        case ML_DSA_65: return "ML_DSA_65";
        case ML_DSA_87: return "ML_DSA_87";
        case SPHINCS_SHA2_128F: return "SPHINCS_SHA2_128F";
        case SPHINCS_SHA2_128S: return "SPHINCS_SHA2_128S";
        case SPHINCS_SHA2_192F: return "SPHINCS_SHA2_192F";
        case SPHINCS_SHA2_192S: return "SPHINCS_SHA2_192S";
        case SPHINCS_SHA2_256F: return "SPHINCS_SHA2_256F";
        case SPHINCS_SHA2_256S: return "SPHINCS_SHA2_256S";
        case SPHINCS_SHAKE_128F: return "SPHINCS_SHAKE_128F";
        case SPHINCS_SHAKE_128S: return "SPHINCS_SHAKE_128S";
        case SPHINCS_SHAKE_192F: return "SPHINCS_SHAKE_192F";
        case SPHINCS_SHAKE_192S: return "SPHINCS_SHAKE_192S";
        case SPHINCS_SHAKE_256F: return "SPHINCS_SHAKE_256F";
        case SPHINCS_SHAKE_256S: return "SPHINCS_SHAKE_256S";
        default: return "Unknown Algorithm";
    }
}

int dsa_keygen(enum DSA_ALGO algo, uint8_t *pk, uint8_t *sk) {
    switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
        default:
            return -1; // Unsupported algorithm
    }
}

int dsa_sign(enum DSA_ALGO algo, uint8_t *sig, size_t *siglen,
            const uint8_t *m, size_t mlen, const uint8_t *sk) {
    switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign(sig, siglen, m, mlen, sk);
        default:
            return -1; // Unsupported algorithm
    }
}

int dsa_signature(enum DSA_ALGO algo, uint8_t *sig, size_t *siglen,
            const uint8_t *m, size_t mlen, const uint8_t *sk) {
                switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
        default:
            return -1; // Unsupported algorithm
    }
}

int dsa_verify(enum DSA_ALGO algo, const uint8_t *sig, size_t siglen,
            const uint8_t *m, size_t mlen, const uint8_t *pk) {
    switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
        default:
            return -1; // Unsupported algorithm
    }
}

int dsa_open(enum DSA_ALGO algo, uint8_t *m, size_t *mlen,
            const uint8_t *sm, size_t smlen, const uint8_t *pk) {
    switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
        default:
            return -1; // Unsupported algorithm
    }
}

void alloc_space_for_dsa(enum DSA_ALGO algo,
            uint8_t **pk, uint8_t **sk,
            size_t *pk_len, size_t *sk_len, size_t *sig_len) {
    switch (algo) {
        case FALCON_512:
            *pk_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;
            break;
        case FALCON_1024:
            *pk_len = PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES;
            break;
        case FALCON_PADDED_512:
            *pk_len = PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES;
            break;
        case FALCON_PADDED_1024:
            *pk_len = PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES;
            break;
        case ML_DSA_44:
            *pk_len = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;
            break;
        case ML_DSA_65:
            *pk_len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
            break;
        case ML_DSA_87:
            *pk_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHA2_128F:
            *pk_len = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHA2_128S:
            *pk_len = PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHA2_192F:
            *pk_len = PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHA2_192S:
            *pk_len = PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHA2_256F:
            *pk_len = PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHA2_256S:
            *pk_len = PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHAKE_128F:
            *pk_len = PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHAKE_128S:
            *pk_len = PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHAKE_192F:
            *pk_len = PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHAKE_192S:
            *pk_len = PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHAKE_256F:
            *pk_len = PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        case SPHINCS_SHAKE_256S:
            *pk_len = PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
            *sk_len = PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
            *sig_len = PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES;
            break;
        default:
            *pk_len = 0;
            *sk_len = 0;
            *sig_len = 0;
            return; // Unsupported algorithm
    }
    *pk = (uint8_t *)malloc(*pk_len);
    *sk = (uint8_t *)malloc(*sk_len);
}

void free_space_for_dsa(uint8_t *pk, uint8_t *sk) {
    if (pk) free(pk);
    if (sk) free(sk);
}

size_t get_public_key_length(enum DSA_ALGO algo) {
    switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        default:
            return 0; // Unsupported algorithm
    }
}

size_t get_secret_key_length(enum DSA_ALGO algo) {
    switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES;
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES;
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        default:
            return 0; // Unsupported algorithm
    }
}

size_t get_signature_length(enum DSA_ALGO algo) {
    switch (algo) {
        case FALCON_512:
            return PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;
        case FALCON_1024:
            return PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES;
        case FALCON_PADDED_512:
            return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES;
        case FALCON_PADDED_1024:
            return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES;
        case ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;
        case ML_DSA_65:
            return PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
        case ML_DSA_87:
            return PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_128F:
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_128S:
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_192F:
            return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_192S:
            return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_256F:
            return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHA2_256S:
            return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_128F:
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_128S:
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_192F:
            return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_192S:
            return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_256F:
            return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_256S:
            return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES;
        default:
            return 0; // Unsupported algorithm
    }
}

bool test_dsa(enum DSA_ALGO algo) {
    uint8_t *pk = NULL, *sk = NULL;
    size_t pk_len = 0, sk_len = 0, sig_len = 0;

    alloc_space_for_dsa(algo, &pk, &sk, &pk_len, &sk_len, &sig_len);
    if (!pk || !sk || pk_len == 0 || sk_len == 0 || sig_len == 0) {
        printf("Failed to allocate memory for key.\n");
        free_space_for_dsa(pk, sk);
        return false;
    }

    if (dsa_keygen(algo, pk, sk) != 0) {
        printf("Failed to generate keys\n");
        free_space_for_dsa(pk, sk);
        return false;
    }


    const char *message = "Test message for DSA";
    size_t message_len = strlen(message);
    uint8_t* signed_message = malloc(message_len+sig_len);

    size_t actual_sm_len = message_len+sig_len;
    if (dsa_sign(algo, signed_message, &actual_sm_len, (const uint8_t *)message, message_len, sk) != 0) {
        printf("Failed to sign message\n");
        free_space_for_dsa(pk, sk);
        free(signed_message);
        return false;
    }

    uint8_t* message_decoded = malloc(actual_sm_len);
    size_t actual_message_size = actual_sm_len;
    if(!message_decoded) {
        printf("Failed to allocate memory for message_decoded");
        free_space_for_dsa(pk, sk);
        free(signed_message);
        free(message_decoded);
        return false;
    }
    
    if(dsa_open(algo, message_decoded, &actual_message_size, signed_message, actual_sm_len, pk) != 0) {
        printf("Failed to open message\n");
        free_space_for_dsa(pk, sk);
        free(signed_message);
        free(message_decoded);
        return false;
    }

    if(actual_message_size == message_len) {
        if(memcmp(message_decoded, message, actual_message_size)) {
            printf("Message is not the same.\n");
            free_space_for_dsa(pk, sk);
            free(signed_message);
            free(message_decoded);
            return false;
        }
    } else {
        printf("Message is not the same size.\n");
        free_space_for_dsa(pk, sk);
        free(signed_message);
        free(message_decoded);
        return false;
    }

    free_space_for_dsa(pk, sk);
    free(message_decoded);
    return true;
}

void test_all_dsa() {
    enum DSA_ALGO algorithms[] = {
        FALCON_512,
        FALCON_1024,
        FALCON_PADDED_512,
        FALCON_PADDED_1024,
        ML_DSA_44,
        ML_DSA_65,
        ML_DSA_87,
        SPHINCS_SHA2_128F,
        SPHINCS_SHA2_128S,
        SPHINCS_SHA2_192F,
        SPHINCS_SHA2_192S,
        SPHINCS_SHA2_256F,
        SPHINCS_SHA2_256S,
        SPHINCS_SHAKE_128F,
        SPHINCS_SHAKE_128S,
        SPHINCS_SHAKE_192F,
        SPHINCS_SHAKE_192S,
        SPHINCS_SHAKE_256F,
        SPHINCS_SHAKE_256S
    };
    size_t num_algorithms = sizeof(algorithms) / sizeof(algorithms[0]);

    for (size_t i = 0; i < num_algorithms; i++) {
        if (test_dsa(algorithms[i])) {
            printf("DSA algorithm %s passed the test.\n", getAlgoName(algorithms[i]));
        } else {
            printf("DSA algorithm %s failed the test.\n", getAlgoName(algorithms[i]));
        }
    }
    printf("All Algo done\n");
}