#include "dsa.h"
#include "Particle.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const char* getAlgoName(enum DSA_ALGO algo) {
    switch (algo) {
        //case FALCON_512:         return "FALCON_512";
        //case FALCON_1024:        return "FALCON_1024";
        //case FALCON_PADDED_512:  return "FALCON_PADDED_512";
        case FALCON_PADDED_1024: return "FALCON_PADDED_1024";
        case ML_DSA_44:          return "ML_DSA_44";
        //case SPHINCS_SHA2_128F: return "SPHINCS_SHA2_128F";
        //case SPHINCS_SHA2_128S: return "SPHINCS_SHA2_128S";
        //case ML_DSA_65:          return "ML_DSA_65";
        //case ML_DSA_87:          return "ML_DSA_87";
        //case SPHINCS_SHAKE_128F: return "SPHINCS_SHAKE_128F";
        case SPHINCS_SHAKE_128S: return "SPHINCS_SHAKE_128S";
        //case SPHINCS_SHAKE_192F: return "SPHINCS_SHAKE_192F";
        //case SPHINCS_SHAKE_192S: return "SPHINCS_SHAKE_192S";
        //case SPHINCS_SHAKE_256F: return "SPHINCS_SHAKE_256F";
        //case SPHINCS_SHAKE_256S: return "SPHINCS_SHAKE_256S";
        default: return "UNKNOWN";
    }
}

int dsa_keygen(DSA_ALGO algo, uint8_t *pk, uint8_t *sk) {
    Serial.println("[DSA] entering dsa_keygen");

    if (!pk || !sk) {
        Serial.println("[DSA] ERROR: NULL pk/sk in dsa_keygen");
        return -1;
    }

    switch (algo) {
        /*case FALCON_512:
            Serial.println("[DSA] before PQCLEAN_FALCON512 keypair");
            return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);*/

        /*case FALCON_1024:
            Serial.println("[DSA] before PQCLEAN_FALCON1024 keypair");
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);*/

        //case FALCON_PADDED_512:
            //Serial.println("[DSA] before PQCLEAN_FALCONPADDED512 keypair");
            //return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);

        case FALCON_PADDED_1024:
            Serial.println("[DSA] before PQCLEAN_FALCONPADDED1024 keypair");
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);

        case ML_DSA_44:
            Serial.println("[DSA] before PQCLEAN_MLDSA44 keypair");
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);

        /*case SPHINCS_SHA2_128F:
            Serial.println("[DSA] before PQCLEAN_SPHINCSSHA2128FSIMPLE keypair");
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);*/

        /*case SPHINCS_SHA2_128S:
            Serial.println("[DSA] before PQCLEAN_SPHINCSSHA2128SSIMPLE keypair");
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);*/

        //case ML_DSA_65:
            //Serial.println("[DSA] before PQCLEAN_MLDSA65 keypair");
            //return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);

        //case ML_DSA_87:
            //Serial.println("[DSA] before PQCLEAN_MLDSA87 keypair");
            //return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);

        /*case SPHINCS_SHAKE_128F:
            Serial.println("[DSA] before PQCLEAN_SPHINCSSHAKE128FSIMPLE keypair");
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);*/

        case SPHINCS_SHAKE_128S:
            Serial.println("[DSA] before PQCLEAN_SPHINCSSHAKE128SSIMPLE keypair");
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

        //case SPHINCS_SHAKE_192F:
            //Serial.println("[DSA] before PQCLEAN_SPHINCSSHAKE192FSIMPLE keypair");
            //return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

        //case SPHINCS_SHAKE_192S:
            //Serial.println("[DSA] before PQCLEAN_SPHINCSSHAKE192SSIMPLE keypair");
            //return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

        //case SPHINCS_SHAKE_256F:
            //Serial.println("[DSA] before PQCLEAN_SPHINCSSHAKE256FSIMPLE keypair");
            //return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

        //case SPHINCS_SHAKE_256S:
            //Serial.println("[DSA] before PQCLEAN_SPHINCSSHAKE256SSIMPLE keypair");
            //return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

        default:
            Serial.println("[DSA] ERROR: unsupported algorithm in dsa_keygen");
            return -1;
    }
}

int dsa_signature(enum DSA_ALGO algo,
                  uint8_t *sig, size_t *siglen,
                  const uint8_t *m, size_t mlen,
                  const uint8_t *sk) {

    if (!sig || !siglen || !m || !sk) {
        Serial.println("[DSA] ERROR: NULL pointer in dsa_signature");
        return -1;
    }

    switch (algo) {

        /*case FALCON_512:
            Serial.println("[DSA] signing with FALCON_512");
            return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);*/

        /*case FALCON_1024:
            Serial.println("[DSA] signing with FALCON_1024");
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);*/

        //case FALCON_PADDED_512:
            //Serial.println("[DSA] signing with FALCON_PADDED_512");
            //return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        case FALCON_PADDED_1024:
            Serial.println("[DSA] signing with FALCON_PADDED_1024");
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);


        case ML_DSA_44:
            Serial.println("[DSA] signing with ML_DSA_44");
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        /*case SPHINCS_SHA2_128F:
            Serial.println("[DSA] signing with SPHINCS_SHA2_128F");
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);*/

        /*case SPHINCS_SHA2_128S:
            Serial.println("[DSA] signing with SPHINCS_SHA2_128S");
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);*/

        //case ML_DSA_65:
            //Serial.println("[DSA] signing with ML_DSA_65");
            //return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        //case ML_DSA_87:
            //Serial.println("[DSA] signing with ML_DSA_87");
            //return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);


        /*case SPHINCS_SHAKE_128F:
            Serial.println("[DSA] signing with SPHINCS_SHAKE_128F");
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);*/

        case SPHINCS_SHAKE_128S:
            Serial.println("[DSA] signing with SPHINCS_SHAKE_128S");
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        //case SPHINCS_SHAKE_192F:
            //Serial.println("[DSA] signing with SPHINCS_SHAKE_192F");
            //return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        //case SPHINCS_SHAKE_192S:
            //Serial.println("[DSA] signing with SPHINCS_SHAKE_192S");
            //return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        //case SPHINCS_SHAKE_256F:
            //Serial.println("[DSA] signing with SPHINCS_SHAKE_256F");
            //return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        //case SPHINCS_SHAKE_256S:
            //Serial.println("[DSA] signing with SPHINCS_SHAKE_256S");
            //return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

        default:
            Serial.println("[DSA] ERROR: unsupported algorithm in dsa_signature");
            return -1;
    }
}

int dsa_verify(enum DSA_ALGO algo,
               const uint8_t *sig, size_t siglen,
               const uint8_t *m, size_t mlen,
               const uint8_t *pk) {

    if (!sig || !m || !pk) {
        Serial.println("[DSA] ERROR: NULL pointer in dsa_verify");
        return -1;
    }

    switch (algo) {

        /*case FALCON_512:
            Serial.println("[DSA] verifying with FALCON_512");
            return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        case FALCON_1024:
            Serial.println("[DSA] verifying with FALCON_1024");
            return PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);*/

        //case FALCON_PADDED_512:
            //Serial.println("[DSA] verifying with FALCON_PADDED_512");
            //return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        case FALCON_PADDED_1024:
            Serial.println("[DSA] verifying with FALCON_PADDED_1024");
            return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);


        case ML_DSA_44:
            Serial.println("[DSA] verifying with ML_DSA_44");
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        /*case SPHINCS_SHA2_128F:
            Serial.println("[DSA] verifying with SPHINCS_SHA2_128F");
            return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);*/

        /*case SPHINCS_SHA2_128S:
            Serial.println("[DSA] verifying with SPHINCS_SHA2_128S");
            return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);*/

                //case ML_DSA_65:
            //Serial.println("[DSA] verifying with ML_DSA_65");
            //return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        //case ML_DSA_87:
            //Serial.println("[DSA] verifying with ML_DSA_87");
            //return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);


        /*case SPHINCS_SHAKE_128F:
            Serial.println("[DSA] verifying with SPHINCS_SHAKE_128F");
            return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);*/

        case SPHINCS_SHAKE_128S:
            Serial.println("[DSA] verifying with SPHINCS_SHAKE_128S");
            return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        //case SPHINCS_SHAKE_192F:
            //Serial.println("[DSA] verifying with SPHINCS_SHAKE_192F");
            //return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        //case SPHINCS_SHAKE_192S:
            //Serial.println("[DSA] verifying with SPHINCS_SHAKE_192S");
            //return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        //case SPHINCS_SHAKE_256F:
            //Serial.println("[DSA] verifying with SPHINCS_SHAKE_256F");
            //return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        //case SPHINCS_SHAKE_256S:
            //Serial.println("[DSA] verifying with SPHINCS_SHAKE_256S");
            //return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);

        default:
            Serial.println("[DSA] ERROR: unsupported algorithm in dsa_verify");
            return -1;
    }
}

size_t get_public_key_length(enum DSA_ALGO algo) {
    switch (algo) {
        //case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        //case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;
        default: return 0;
    }
}

size_t get_secret_key_length(enum DSA_ALGO algo) {
    switch (algo) {
        //case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES;
        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        //case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;
        default: return 0;
    }
}

size_t get_signature_length(enum DSA_ALGO algo) {
    switch (algo) {
        //case FALCON_512:         return PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;
        //case FALCON_1024:        return PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES;
        //case FALCON_PADDED_512:  return PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES;
        //case FALCON_PADDED_1024: return PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES;
        case ML_DSA_44:          return PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;
        //case SPHINCS_SHA2_128F:  return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES;
        //case SPHINCS_SHA2_128S:  return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES;
        //case ML_DSA_65:          return PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
        //case ML_DSA_87:          return PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        //case SPHINCS_SHAKE_128F: return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES;
        case SPHINCS_SHAKE_128S: return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES;
        //case SPHINCS_SHAKE_192F: return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES;
        //case SPHINCS_SHAKE_192S: return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES;
        //case SPHINCS_SHAKE_256F: return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES;
        //case SPHINCS_SHAKE_256S: return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES;
        default: return 0;
    }
}

void alloc_space_for_dsa(enum DSA_ALGO algo,
                         uint8_t **pk, uint8_t **sk,
                         size_t *pk_len, size_t *sk_len, size_t *sig_len) {
    *pk_len  = get_public_key_length(algo);
    *sk_len  = get_secret_key_length(algo);
    *sig_len = get_signature_length(algo);

    if (*pk_len == 0 || *sk_len == 0 || *sig_len == 0) {
        *pk = NULL;
        *sk = NULL;
        return;
    }

    *pk = (uint8_t*)malloc(*pk_len);
    *sk = (uint8_t*)malloc(*sk_len);

    if (!*pk || !*sk) {
        free(*pk);
        free(*sk);
        *pk = NULL;
        *sk = NULL;
    }
}

void free_space_for_dsa(uint8_t *pk, uint8_t *sk) {
    if (pk) free(pk);
    if (sk) free(sk);
}