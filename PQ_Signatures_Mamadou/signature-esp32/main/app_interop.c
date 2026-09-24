// app_local.c (CORRIGÉ - prêt à copier)
// Corrections principales :
// - Ajout des includes manquants (stdlib.h, stdint.h)
// - crypto_sign_message: allocation correcte (2 + msg + sig), HDR en uint8_t, check retours
// - crypto_open_message: validations smlen/2 + mlen, pas d'allocation inutile de signature (verify directement)
// - Gestion mémoire: ne pas free(NULL) inutile, ne pas free(pk) reçu sans savoir si malloc() -> on garde free(messageReceived.content) uniquement
// - test_dsa_all_alice_bob: suppression de "switch role" impossible via macro compile-time; on exécute UNE fois selon ROLE_*
// - Meilleurs timeouts + flush queue réception
// - Stack task: 130000 mots est énorme; laisser si tu sais, sinon réduire. (ESP-IDF = mots, pas bytes)

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "dsa.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "transport.h"

// ---------------- Role compile-time ----------------
#define ROLE_ALICE_1_BOB_0 0
#if (ROLE_ALICE_1_BOB_0)
  #define ROLE_ALICE
#else
  #define ROLE_BOB
#endif

static const char* message        = "Test message for DSA";
static const char* ready_message  = "ready";
static const char* ack_message    = "ack";
static const char* failed_message = "failed";

enum ROLE { ALICE, BOB };

// ---------------- Algorithms list ----------------
static enum DSA_ALGO algorithms[] = {
    FALCON_512,
    FALCON_1024,
    FALCON_PADDED_512,
    FALCON_PADDED_1024,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    SPHINCS_SHA2_128F,
    SPHINCS_SHA2_128S,
    SPHINCS_SHA2_192F,
    SPHINCS_SHA2_192S,
    SPHINCS_SHA2_256F,
    SPHINCS_SHA2_256S,
    SPHINCS_SHAKE_128F,
    SPHINCS_SHAKE_128S,
    SPHINCS_SHAKE_192F,
    SPHINCS_SHAKE_192S,
    SPHINCS_SHAKE_256F,
    SPHINCS_SHAKE_256S
};
static const size_t num_algorithms = sizeof(algorithms) / sizeof(algorithms[0]);

// ---------------- Signed message format ----------------
// [2 bytes mlen big-endian][m bytes msg][sig bytes]
static int crypto_sign_message(
    uint8_t* sm, size_t* smlen,
    const uint8_t* m, size_t mlen,
    const uint8_t* sk,
    enum DSA_ALGO algo
){
    if (!sm || !smlen || !m || !sk) return -1;

    const size_t sig_max = get_signature_length(algo);
    uint8_t *signature = (uint8_t*)malloc(sig_max);
    if (!signature) return -1;

    size_t signature_len = 0;

    // IMPORTANT: check return code
    if (dsa_signature(algo, signature, &signature_len, m, mlen, sk) != 0) {
        free(signature);
        return -1;
    }

    if (signature_len > sig_max) { // safety
        free(signature);
        return -1;
    }

    // Need 2 bytes header + msg + signature
    // Caller must have allocated enough.
    sm[0] = (uint8_t)((mlen >> 8) & 0xFF);
    sm[1] = (uint8_t)(mlen & 0xFF);

    memcpy(sm + 2, m, mlen);
    memcpy(sm + 2 + mlen, signature, signature_len);

    free(signature);

    *smlen = 2 + mlen + signature_len;
    return 0;
}

static int crypto_open_message(
    uint8_t* m, size_t* mlen,
    const uint8_t* sm, size_t smlen,
    const uint8_t* pk,
    enum DSA_ALGO algo
){
    if (!m || !mlen || !sm || !pk) return -1;
    if (smlen < 2) return -1;

    size_t msg_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
    if (2 + msg_len > smlen) return -1;

    size_t sig_len = smlen - 2 - msg_len;
    if (sig_len == 0) return -1;

    // Verify directly from buffer (no need malloc signature)
    if (dsa_verify(algo, sm + 2 + msg_len, sig_len, sm + 2, msg_len, pk) != 0) {
        return -1;
    }

    memcpy(m, sm + 2, msg_len);
    *mlen = msg_len;
    return 0;
}

// ---------------- Synchronization ----------------
static void synchronize(enum ROLE role) {
    bool got = false;
    message_struct_t rx;

    switch (role) {
    case ALICE:
        printf("Starting as Alice\n");
        while(!got){
            if (xQueueReceive(receive_queue, &rx, portMAX_DELAY) == pdTRUE) {
                if (rx.size == strlen(ready_message) &&
                    memcmp(ready_message, rx.content, rx.size) == 0) {
                    printf("READY received\n");
                    int s = send_message((const uint8_t*)ack_message, strlen(ack_message));
                    printf("Ack sent: %d\n", s);
                    got = true;
                }
                free(rx.content);
            }
        }
        break;

    case BOB:
        printf("Starting as Bob\n");
        while(!got){
            // Check if ack arrived
            if (xQueueReceive(receive_queue, &rx, pdMS_TO_TICKS(1500)) == pdTRUE) {
                if (rx.size == strlen(ack_message) &&
                    memcmp(ack_message, rx.content, rx.size) == 0) {
                    printf("Ack received\n");
                    got = true;
                } else {
                    // Might be noise; print safe as hex
                    printf("Got %u bytes (not ack)\n", (unsigned)rx.size);
                }
                free(rx.content);
            }

            if (!got) {
                (void)send_message((const uint8_t*)ready_message, strlen(ready_message));
                vTaskDelay(pdMS_TO_TICKS(500));
            }
        }
        break;

    default:
        printf("Wrong role\n");
        break;
    }
}

static void flush_receive_queue(void){
    message_struct_t rx;
    while (xQueueReceive(receive_queue, &rx, 0) == pdTRUE) {
        free(rx.content);
    }
}

// ---------------- ALICE test ----------------
static bool test_dsa_Alice(enum DSA_ALGO algo){
    uint8_t *pk=NULL, *sk=NULL;
    size_t pk_len=0, sk_len=0, sig_len=0;

    alloc_space_for_dsa(algo, &pk, &sk, &pk_len, &sk_len, &sig_len);
    if(!pk || !sk || pk_len==0 || sk_len==0 || sig_len==0){
        printf("Failed to allocate keys\n");
        free_space_for_dsa(pk, sk);
        return false;
    }

    if(dsa_keygen(algo, pk, sk) != 0){
        printf("Failed to generate keypair\n");
        free_space_for_dsa(pk, sk);
        return false;
    }

    // Send pk
    if (send_message(pk, pk_len) <= 0) {
        printf("Failed to send pk\n");
        free_space_for_dsa(pk, sk);
        return false;
    }

    const size_t mlen = strlen(message);
    // Need 2 header + msg + max signature
    uint8_t *sm = (uint8_t*)malloc(2 + mlen + sig_len);
    if(!sm){
        printf("Failed to allocate signed_message\n");
        free_space_for_dsa(pk, sk);
        return false;
    }

    size_t smlen = 0;
    if (crypto_sign_message(sm, &smlen, (const uint8_t*)message, mlen, sk, algo) != 0) {
        printf("Failed to sign message\n");
        free(sm);
        free_space_for_dsa(pk, sk);
        return false;
    }

    if (send_message(sm, smlen) <= 0) {
        printf("Failed to send signed_message\n");
        free(sm);
        free_space_for_dsa(pk, sk);
        return false;
    }

    // Wait for echo/plain message back
    message_struct_t rx;
    bool got = false;
    int tries = 0;
    while(!got && tries < 20){
        if(xQueueReceive(receive_queue, &rx, pdMS_TO_TICKS(500)) == pdTRUE){
            got = true;
        } else {
            tries++;
        }
    }

    if(!got){
        printf("Timeout waiting response\n");
        free(sm);
        free_space_for_dsa(pk, sk);
        return false;
    }

    bool ok = (rx.size == mlen && memcmp(message, rx.content, mlen) == 0);
    if(!ok){
        printf("Response mismatch (got %u bytes)\n", (unsigned)rx.size);
    }

    free(rx.content);
    free(sm);
    free_space_for_dsa(pk, sk);
    return ok;
}

// ---------------- BOB test ----------------
static void test_dsa_Bob(enum DSA_ALGO algo){
    const size_t pk_len = get_public_key_length(algo);

    printf("Waiting for public key (len=%u)\n", (unsigned)pk_len);

    uint8_t *pk = NULL;
    message_struct_t rx;

    // Wait pk
    while(1){
        if (xQueueReceive(receive_queue, &rx, portMAX_DELAY) == pdTRUE) {
            if (rx.size == pk_len) {
                pk = (uint8_t*)rx.content; // keep it
                printf("Received pk\n");
                break;
            } else {
                printf("Wrong pk size: %u (expected %u)\n", (unsigned)rx.size, (unsigned)pk_len);
                free(rx.content);
            }
        }
    }

    // Wait signed message
    printf("Waiting for signed message\n");
    uint8_t *sm = NULL;
    size_t smlen = 0;

    while(1){
        if (xQueueReceive(receive_queue, &rx, portMAX_DELAY) == pdTRUE) {
            sm = (uint8_t*)rx.content;
            smlen = rx.size;
            printf("Received sm of size %u\n", (unsigned)smlen);
            break;
        }
    }

    // Open/verify
    const size_t out_cap = strlen(message) + 8; // enough
    uint8_t *out = (uint8_t*)malloc(out_cap);
    if(!out){
        (void)send_message((const uint8_t*)failed_message, strlen(failed_message));
        printf("No memory for out\n");
        free(pk);
        free(sm);
        return;
    }

    size_t outlen = 0;
    if (crypto_open_message(out, &outlen, sm, smlen, pk, algo) != 0) {
        (void)send_message((const uint8_t*)failed_message, strlen(failed_message));
        printf("Verify/open failed\n");
        free(pk);
        free(sm);
        free(out);
        return;
    }

    // Send plain message back
    printf("Sending message back (%u bytes)\n", (unsigned)outlen);
    (void)send_message(out, outlen);

    free(pk);
    free(sm);
    free(out);
}

// ---------------- Run all algorithms ----------------
static void test_dsa_alice_bob(enum ROLE role){
    flush_receive_queue();
    synchronize(role);
    flush_receive_queue();

    if (role == ALICE) {
        for(size_t i=0; i<num_algorithms; i++){
            printf("Beginning algorithm %s\n", getAlgoName(algorithms[i]));
            bool ok = test_dsa_Alice(algorithms[i]);
            printf("DSA algorithm %s %s\n", getAlgoName(algorithms[i]), ok ? "PASSED" : "FAILED");
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    } else {
        for(size_t i=0; i<num_algorithms; i++){
            printf("Beginning algorithm %s\n", getAlgoName(algorithms[i]));
            test_dsa_Bob(algorithms[i]);
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }

    printf("All algorithms done\n");
}

// IMPORTANT: on ne peut pas “changer de rôle” à runtime si c’est un macro compile-time.
// Donc on exécute une seule fois selon ROLE_ALICE/ROLE_BOB.
static void test_dsa_all_alice_bob(void){
#if defined(ROLE_ALICE)
    test_dsa_alice_bob(ALICE);
#elif defined(ROLE_BOB)
    test_dsa_alice_bob(BOB);
#else
    printf("No role defined\n");
#endif
}

static void task_test_all_dsa(void *pvParameter){
    (void)pvParameter;
    vTaskDelay(pdMS_TO_TICKS(1000));
    test_dsa_all_alice_bob();
    vTaskDelete(NULL);
}

void app_main(void){
    setup_transport();
    while(!initialized){
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (xTaskCreatePinnedToCore(&receive_task, "receive_task", 4096, NULL, 5, NULL, 1) != pdPASS) {
        printf("Couldn't create receive task\n");
    }

    // NOTE: stack size is in WORDS in ESP-IDF.
    // 130000 words is huge. Keep if you know you need it, otherwise reduce (e.g., 8192/16384).
    if (xTaskCreatePinnedToCore(&task_test_all_dsa, "task_test_all_dsa", 16384, NULL, 3, NULL, 0) != pdPASS) {
        printf("Couldn't create task\n");
    }
}
