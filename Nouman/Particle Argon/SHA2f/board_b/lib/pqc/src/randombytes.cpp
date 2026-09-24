// randombytes.cpp
// Hardware RNG-backed randombytes() for Particle Argon (nRF52840)

#include "Particle.h"
#include "randombytes.h"

int PQCLEAN_randombytes(uint8_t *buf, size_t n) {
    size_t i = 0;

    while (i < n) {
        uint32_t r = HAL_RNG_GetRandomNumber();
        size_t chunk = (n - i) < 4 ? (n - i) : 4;

        for (size_t j = 0; j < chunk; j++) {
            buf[i + j] = (uint8_t)(r >> (8 * j));
        }

        i += chunk;
    }

    return 0;
}