// demo_main.c — Démo locale SIKE + SHAKE-256 masking (sans MQTT)
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sidh_bridge.h"

int main(void) {
    printf("== Démo SIKE p434 + SHAKE-256 masking ==\n");

    uint8_t pk[SIKE_P434_PK_LEN];
    memset(pk, 0, sizeof(pk));

    if (demo_mask_unmask_sike_p434(pk, sizeof(pk))) {
        printf("[OK] demo_mask_unmask_sike_p434: round-trip réussi.\n");
    } else {
        printf("[FAIL] demo_mask_unmask_sike_p434: échec.\n");
    }

    return 0;
}
