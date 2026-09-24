#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "esp_random.h"

/* PQClean expects EXACTLY this symbol name */
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