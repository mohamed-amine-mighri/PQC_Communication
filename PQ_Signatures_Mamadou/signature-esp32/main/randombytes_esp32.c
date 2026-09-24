#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "esp_random.h"

void randombytes(uint8_t *out, size_t outlen)
{
    static int first = 1;
    if (first) {
        first = 0;
        printf("[RNG] randombytes() is used (outlen=%u)\n", (unsigned)outlen);
        fflush(stdout);
    }

    if (!out || outlen == 0) return;
    esp_fill_random(out, outlen);
}