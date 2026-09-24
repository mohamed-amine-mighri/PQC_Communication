#ifndef MLKEM_INTERNAL_H
#define MLKEM_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// PQCLEAN ML-KEM512 functions
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Random bytes (provided by platform/mlkem_impl.cpp)
int PQCLEAN_randombytes(uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // MLKEM_INTERNAL_H
