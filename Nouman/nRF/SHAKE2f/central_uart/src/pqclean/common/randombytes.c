/*
 * randombytes.c — Zephyr CSPRNG backend for PQClean
 *
 * Implements the randombytes() function PQClean's ML-DSA-44 code calls
 * for key generation and signing, backed by Zephyr's entropy-seeded CSPRNG.
 */

#include "randombytes.h"
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

int randombytes(uint8_t *output, size_t n)
{
    int ret = sys_csrand_get(output, n);

    if (ret != 0) {
        /* CSPRNG not seeded/available — CONFIG_ENTROPY_GENERATOR must be
         * set in prj.conf. Don't let PQClean silently get weak or
         * uninitialized randomness. */
        return ret;
    }

    return 0;
}