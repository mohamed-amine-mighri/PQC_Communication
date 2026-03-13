#include "randombytes.h"
#include "esp_random.h"  // for esp_random()

int randombytes(uint8_t *output, size_t n) {
    esp_fill_random(output, n);
    return 0;
}