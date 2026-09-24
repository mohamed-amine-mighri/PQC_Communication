#include "randombytes.h"
#include "stm32wbxx_hal.h"

extern RNG_HandleTypeDef hrng; // Declared by STM32CubeMX in main.c

int randombytes(uint8_t *out, size_t n) {
    while (n > 0) {
        uint32_t random32;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &random32) != HAL_OK) {
            return -1; // RNG error
        }
        
        size_t to_copy = (n < 4) ? n : 4;
        for (size_t i = 0; i < to_copy; i++) {
            out[i] = (uint8_t)(random32 >> (i * 8));
        }
        
        out += to_copy;
        n -= to_copy;
    }
    return 0;
}