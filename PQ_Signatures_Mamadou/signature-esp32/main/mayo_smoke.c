// main/mayo_smoke.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "mayo_1/api.h"   // NIST API wrappers for MAYO_1

void mayo_smoke_run(void)
{
    printf("[MAYO_SMOKE] start\n");

    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];

    printf("[MAYO_SMOKE] calling crypto_sign_keypair...\n");
    int rc = crypto_sign_keypair(pk, sk);
    printf("[MAYO_SMOKE] keypair rc=%d\n", rc);

    // simple sanity
    int sum = 0;
    for (size_t i = 0; i < sizeof(pk); i++) sum ^= pk[i];
    printf("[MAYO_SMOKE] pk_xor=%d\n", sum);

    printf("[MAYO_SMOKE] done\n");
}