// ML-KEM implementation compilation unit for Particle
// This file compiles the ML-KEM library from components/mlkem/clean512

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Include Particle header to access random32()
#include "Particle.h"

// Provide randombytes implementation using Particle's hardware RNG
// Note: randombytes is macro'd to PQCLEAN_randombytes in the headers
// and should return int (0 for success)
extern "C" {
    int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
        for (size_t i = 0; i < outlen; i++) {
            out[i] = random32() & 0xFF;
        }
        return 0;  // Success
    }

    // Now include all the ML-KEM implementation files in C linkage context
    #include "../../../components/mlkem/clean512/params.h"
    #include "../../../components/mlkem/clean512/api.h"
    #include "../../../components/mlkem/clean512/compat.h"
    #include "../../../components/mlkem/clean512/cbd.h"
    #include "../../../components/mlkem/clean512/fips202.h"
    #include "../../../components/mlkem/clean512/indcpa.h"
    #include "../../../components/mlkem/clean512/kem.h"
    #include "../../../components/mlkem/clean512/ntt.h"
    #include "../../../components/mlkem/clean512/poly.h"
    #include "../../../components/mlkem/clean512/polyvec.h"
    #include "../../../components/mlkem/clean512/reduce.h"
    #include "../../../components/mlkem/clean512/symmetric.h"
    #include "../../../components/mlkem/clean512/verify.h"

    // Include the implementation files as C code (not C++)
    #include "../../../components/mlkem/clean512/cbd.c"
    #include "../../../components/mlkem/clean512/fips202.c"
    #include "../../../components/mlkem/clean512/indcpa.c"
    #include "../../../components/mlkem/clean512/kem.c"
    #include "../../../components/mlkem/clean512/ntt.c"
    #include "../../../components/mlkem/clean512/poly.c"
    #include "../../../components/mlkem/clean512/polyvec.c"
    #include "../../../components/mlkem/clean512/reduce.c"
    #include "../../../components/mlkem/clean512/symmetric-shake.c"
    #include "../../../components/mlkem/clean512/verify.c"
}
