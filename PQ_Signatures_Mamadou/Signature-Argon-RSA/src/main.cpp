#include "Particle.h"
#include "dsa.h"

SYSTEM_MODE(MANUAL);
SYSTEM_THREAD(ENABLED);

Thread *benchThread = nullptr;

void run_rsa_test() {
    Serial.println("==================================");
    Serial.println(" Particle Argon RSA Local Test");
    Serial.println("==================================");

    uint8_t *pk = nullptr;
    uint8_t *sk = nullptr;
    size_t pk_len = 0, sk_len = 0, sig_len_max = 0;

    alloc_space_for_dsa(&pk, &sk, &pk_len, &sk_len, &sig_len_max);

    Serial.printf("alg=%s\r\n", getAlgoName());
    Serial.printf("pk_len=%u sk_len=%u sig_len_max=%u\r\n",
                  (unsigned)pk_len,
                  (unsigned)sk_len,
                  (unsigned)sig_len_max);

    if (!pk || !sk) {
        Serial.println("ERROR: alloc_space_for_dsa failed");
        return;
    }

    Serial.println("[STEP] keygen...");
    int rc = dsa_keygen(pk, sk);
    Serial.printf("dsa_keygen rc=%d\r\n", rc);
    if (rc != 0) {
        free_space_for_dsa(pk, sk);
        return;
    }

    const uint8_t msg[] = "Hello RSA on Argon";
    uint8_t *sig = (uint8_t *)malloc(sig_len_max);
    size_t sig_len = 0;

    if (!sig) {
        Serial.println("ERROR: malloc(sig) failed");
        free_space_for_dsa(pk, sk);
        return;
    }

    Serial.println("[STEP] sign...");
    rc = dsa_signature(sig, &sig_len, msg, sizeof(msg) - 1, sk);
    Serial.printf("dsa_signature rc=%d sig_len=%u\r\n", rc, (unsigned)sig_len);
    if (rc != 0) {
        free(sig);
        free_space_for_dsa(pk, sk);
        return;
    }

    Serial.println("[STEP] verify...");
    rc = dsa_verify(sig, sig_len, msg, sizeof(msg) - 1, pk);
    Serial.printf("dsa_verify rc=%d\r\n", rc);

    if (rc == 0) {
        Serial.println("RSA TEST PASSED");
    } else {
        Serial.println("RSA TEST FAILED");
    }

    Serial.print("pk[0..7]=");
    for (size_t i = 0; i < 8 && i < pk_len; i++) {
        Serial.printf("%02X", pk[i]);
    }
    Serial.println();

    Serial.print("sig[0..7]=");
    for (size_t i = 0; i < 8 && i < sig_len; i++) {
        Serial.printf("%02X", sig[i]);
    }
    Serial.println();

    free(sig);
    free_space_for_dsa(pk, sk);

    Serial.println("[ARGON] RSA test finished");
}

void bench_task(void *) {
    Serial.println("[ARGON] RSA thread started");
    run_rsa_test();
    Serial.println("[ARGON] RSA thread finished");
}

void setup() {
    Serial.begin(115200);
    waitUntil(Serial.isConnected);
    delay(1000);

    Serial.printf("[ARGON] reset reason = %d\n", (int)System.resetReason());

    benchThread = new Thread(
        "rsa-test",
        bench_task,
        NULL,
        OS_THREAD_PRIORITY_DEFAULT,
        65536
    );
}

void loop() {
}