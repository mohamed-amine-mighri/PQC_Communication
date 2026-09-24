#include "mlkem.h"
#include "api.h"

#if defined(PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME)
    #define MLKEM_PUBLICKEYBYTES (PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES)
    #define MLKEM_SECRETKEYBYTES (PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES)
    #define MLKEM_CIPHERTEXTBYTES (PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES)
    #define MLKEM_SHAREDSECRETBYTES (PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES)


    int mlkem_keypair(uint8_t *pk, uint8_t *sk) {
        return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    }

    int mlkem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
        return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
    }

    int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
        return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
    }
#elif defined(PQCLEAN_MLKEM768_CLEAN_CRYPTO_ALGNAME)
    #define MLKEM_PUBLICKEYBYTES (PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES)
    #define MLKEM_SECRETKEYBYTES (PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES)
    #define MLKEM_CIPHERTEXTBYTES (PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES)
    #define MLKEM_SHAREDSECRETBYTES (PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES)

    int mlkem_keypair(uint8_t *pk, uint8_t *sk) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    }

    int mlkem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
    }

    int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
    }
#elif defined(PQCLEAN_MLKEM1024_CLEAN_CRYPTO_ALGNAME)
    #define MLKEM_PUBLICKEYBYTES (PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES)
    #define MLKEM_SECRETKEYBYTES (PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES)
    #define MLKEM_CIPHERTEXTBYTES (PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES)
    #define MLKEM_SHAREDSECRETBYTES (PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES)

    int mlkem_keypair(uint8_t *pk, uint8_t *sk) {
        return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
    }

    int mlkem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
        return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
    }

    int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
        return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk);
    }

#else
    #error "No ML-KEM variant defined"
#endif
