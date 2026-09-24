#include "Particle.h"

extern "C" {
#include <stdint.h>
#include <stddef.h>
}

extern "C" int PQCLEAN_randombytes(uint8_t *output, size_t n)
{
    static bool first = true;

    if (first) {
        Serial.printf("[RNG] PQCLEAN_randombytes first call, n=%u\n", (unsigned)n);
        first = false;
    }

    if (!output) {
        return -1;
    }

    for (size_t i = 0; i < n; i++) {
        output[i] = (uint8_t) random(0, 256);
    }

    return 0;
}