// main/randombytes_esp32.c  (PQCLEAN RNG uniquement)
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "esp_random.h"

// PQClean expects this exact symbol:
void PQCLEAN_randombytes(uint8_t *out, size_t outlen)
{
    size_t i = 0;
    while (i < outlen) {
        uint32_t r = esp_random();
        size_t n = (outlen - i < 4) ? (outlen - i) : 4;
        memcpy(out + i, &r, n);
        i += n;
    }
}