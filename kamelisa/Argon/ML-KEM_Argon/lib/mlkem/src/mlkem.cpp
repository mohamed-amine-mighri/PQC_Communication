// ML-KEM wrapper for Particle Argon
// Provides platform-specific implementations and public wrapper functions

#include <stdint.h>
#include <stddef.h>

// Include Particle header to access random number generator
#include "Particle.h"

extern "C" {
    // Provide randombytes implementation using Particle's random()
    int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
        for (size_t i = 0; i < outlen; i++) {
            // Use Particle's random() function
            // Need 8 bits, so we take random() & 0xFF
            out[i] = (uint8_t)(random() & 0xFF);
        }
        return 0;  // Success
    }

    // Forward declare the PQCLEAN functions from mlkem_impl.c
    int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
    int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

    // Public wrapper functions
    int mlkem_keypair(uint8_t *pk, uint8_t *sk) {
        return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    }

    int mlkem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
        return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
    }

    int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
        return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
    }
}
