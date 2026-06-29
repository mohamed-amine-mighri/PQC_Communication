#ifndef MLKEM_CLEAN_RANDOMBYTES_H
#define MLKEM_CLEAN_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#define randombytes     PQCLEAN_randombytes
int randombytes(uint8_t *output, size_t n);

#endif