// components/DSA/common/randombytes_mayo_esp32.c
#include <stddef.h>
#include <stdint.h>

#include "esp_random.h"      // esp_fill_random
#include "randombytes.h"     // prototypes attendus par MAYO

int randombytes(unsigned char *x, size_t xlen)
{
    if (!x || xlen == 0) return 0;
    esp_fill_random(x, xlen);
    return 0; // 0 = OK (comme l'impl linux)
}

void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength)
{
    (void)entropy_input;
    (void)personalization_string;
    (void)security_strength;
    // no-op
}