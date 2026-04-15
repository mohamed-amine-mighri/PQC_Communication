#include <oqs/oqs.h>
#include "transport.h"
#include "queue.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define Alice_1_Bob_0 1
#if Alice_1_Bob_0
    #define ROLE_ALICE
#else
    #define ROLE_BOB
#endif

// -----------------------------------------------------------------------------
// Fallback-free helper: prefer secure free if available, else free().
// If OQS_MEM_secure_free exists in your liboqs headers, use it. Otherwise, free.
// -----------------------------------------------------------------------------
#if defined(OQS_MEM_secure_free)
  #define OQS_FREE(ptr, len) do { if ((ptr) != NULL) OQS_MEM_secure_free((ptr), (len)); } while(0)
#else
  #define OQS_FREE(ptr, len) do { (void)(len); if ((ptr) != NULL) free((ptr)); } while(0)
#endif

static const char* message = "Test message for DSA";
static const char* ready_message = "ready";
static const char* ack_message = "ack";
static const char* failed_message = "failed";

enum ROLE { ALICE, BOB };

char* algorithms[] = {
    OQS_SIG_alg_falcon_512,
    OQS_SIG_alg_falcon_1024,
    OQS_SIG_alg_falcon_padded_512,
    OQS_SIG_alg_falcon_padded_1024,
    OQS_SIG_alg_ml_dsa_44,
    OQS_SIG_alg_ml_dsa_65,
    OQS_SIG_alg_ml_dsa_87,
    OQS_SIG_alg_sphincs_sha2_128f_simple,
    OQS_SIG_alg_sphincs_sha2_128s_simple,
    OQS_SIG_alg_sphincs_sha2_192f_simple,
    OQS_SIG_alg_sphincs_sha2_192s_simple,
    OQS_SIG_alg_sphincs_sha2_256f_simple,
    OQS_SIG_alg_sphincs_sha2_256s_simple,
    OQS_SIG_alg_sphincs_shake_128f_simple,
    OQS_SIG_alg_sphincs_shake_128s_simple,
    OQS_SIG_alg_sphincs_shake_192f_simple,
    OQS_SIG_alg_sphincs_shake_192s_simple,
    OQS_SIG_alg_sphincs_shake_256f_simple,
    OQS_SIG_alg_sphincs_shake_256s_simple
};
size_t num_algorithms = sizeof(algorithms) / sizeof(algorithms[0]);

extern Queue receiving_queue;
extern pthread_mutex_t queue_lock;

// -----------------------------------------------------------------------------
// Signed message format: [2 bytes mlen big-endian] [m bytes message] [sig bytes]
// -----------------------------------------------------------------------------
int crypto_sign_message(
    uint8_t* sm, size_t* smlen,
    const uint8_t* m, size_t mlen,
    const uint8_t* sk, OQS_SIG* algo
) {
    if (!sm || !smlen || !m || !sk || !algo) return -1;

    uint8_t* signature = OQS_MEM_malloc(algo->length_signature);
    size_t signature_len = 0;
    if (!signature) return -1;

    uint8_t hdr[2] = { (uint8_t)((mlen >> 8) & 0xFF), (uint8_t)(mlen & 0xFF) };

    if (OQS_SIG_sign(algo, signature, &signature_len, m, mlen, sk) != OQS_SUCCESS) {
        OQS_FREE(signature, algo->length_signature);
        return -1;
    }

    memcpy(sm, hdr, 2);
    memcpy(sm + 2, m, mlen);
    memcpy(sm + 2 + mlen, signature, signature_len);

    OQS_FREE(signature, algo->length_signature);

    *smlen = 2 + mlen + signature_len;
    return 0;
}

int crypto_open_message(
    uint8_t* m, size_t* mlen,
    const uint8_t* sm, size_t smlen,
    const uint8_t* pk, OQS_SIG* algo
) {
    if (!m || !mlen || !sm || !pk || !algo) return -1;
    if (smlen < 2) return -1;

    *mlen = ((size_t)sm[0] << 8) | sm[1];

    if (2 + *mlen > smlen) return -1;

    size_t signature_len = smlen - 2 - *mlen;
    if (signature_len > algo->length_signature) return -1;

    uint8_t* signature = OQS_MEM_malloc(algo->length_signature);
    if (!signature) return -1;

    memcpy(signature, sm + 2 + *mlen, signature_len);

    if (OQS_SIG_verify(algo, sm + 2, *mlen, signature, signature_len, pk) != OQS_SUCCESS) {
        OQS_FREE(signature, algo->length_signature);
        return -1;
    }

    memcpy(m, sm + 2, *mlen);
    OQS_FREE(signature, algo->length_signature);
    return 0;
}

// -----------------------------------------------------------------------------
// Queue drain to avoid stale messages when restarting
// -----------------------------------------------------------------------------
static void drain_receiving_queue(void) {
    Message_struct *mm = NULL;

    pthread_mutex_lock(&queue_lock);
    while (!isEmpty(&receiving_queue)) {
        mm = dequeue(&receiving_queue);
        if (mm) {
            free(mm->content);
            free(mm);
        }
    }
    pthread_mutex_unlock(&queue_lock);
}

void synchronize(enum ROLE role) {
    bool isMessageReceived = false;
    Message_struct* msg = NULL;

    drain_receiving_queue();

    switch (role) {
    case ALICE:
        printf("Starting as Alice\n");
        while (!isMessageReceived) {
            pthread_mutex_lock(&queue_lock);
            msg = (!isEmpty(&receiving_queue)) ? dequeue(&receiving_queue) : NULL;
            pthread_mutex_unlock(&queue_lock);

            if (msg) {
                if (msg->size == strlen(ready_message) &&
                    memcmp(ready_message, msg->content, msg->size) == 0) {

                    printf("READY received\n");
                    int sent = send_message((const uint8_t*)ack_message, strlen(ack_message));
                    printf("Ack sent: %d\n", sent);
                    isMessageReceived = true;

                } else {
                    printf("Alice got unexpected msg: %.*s\n",
                           (int)msg->size, (char*)msg->content);
                }
                free(msg->content);
                free(msg);
            }

            if (!isMessageReceived) sleep(1);
        }
        return;

    case BOB:
        printf("Starting as Bob\n");

        send_message((const uint8_t*)ready_message, strlen(ready_message));

        while (!isMessageReceived) {
            pthread_mutex_lock(&queue_lock);
            msg = (!isEmpty(&receiving_queue)) ? dequeue(&receiving_queue) : NULL;
            pthread_mutex_unlock(&queue_lock);

            if (msg) {
                if (msg->size == strlen(ack_message) &&
                    memcmp(ack_message, msg->content, msg->size) == 0) {

                    printf("Ack received\n");
                    isMessageReceived = true;

                } else {
                    printf("Bob got unexpected msg: %.*s\n",
                           (int)msg->size, (char*)msg->content);
                }
                free(msg->content);
                free(msg);
            }

            if (!isMessageReceived) {
                sleep(2);
                send_message((const uint8_t*)ready_message, strlen(ready_message));
            }
        }
        return;

    default:
        printf("Wrong role\n");
        return;
    }
}

// -----------------------------------------------------------------------------
// Alice side
// -----------------------------------------------------------------------------
bool test_dsa_Alice(char* algo) {
    OQS_SIG *algorithm = OQS_SIG_new(algo);
    if (!algorithm) {
        printf("OQS_SIG_new failed for %s\n", algo);
        return false;
    }

    uint8_t *pk = OQS_MEM_malloc(algorithm->length_public_key);
    uint8_t *sk = OQS_MEM_malloc(algorithm->length_secret_key);
    if (!pk || !sk) {
        printf("Failed to allocate space for keys\n");
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        return false;
    }

    if (OQS_SIG_keypair(algorithm, pk, sk) != OQS_SUCCESS) {
        printf("Failed to generate keypair\n");
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        return false;
    }

    send_message(pk, algorithm->length_public_key);

    uint8_t* signed_message = malloc(2 + strlen(message) + algorithm->length_signature);
    if (!signed_message) {
        printf("Failed to allocate memory for signed_message\n");
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        return false;
    }

    size_t actual_sm_size = 0;
    if (crypto_sign_message(
            signed_message, &actual_sm_size,
            (const uint8_t*)message, strlen(message),
            sk, algorithm
        ) != 0) {
        printf("Failed to sign message\n");
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        free(signed_message);
        return false;
    }

    send_message(signed_message, actual_sm_size);

    bool got = false;
    Message_struct* msg = NULL;

    while (!got) {
        pthread_mutex_lock(&queue_lock);
        if (!isEmpty(&receiving_queue)) {
            msg = dequeue(&receiving_queue);
            got = true;
        }
        pthread_mutex_unlock(&queue_lock);

        if (!got) sleep(1);
    }

    if (strlen(message) != msg->size || memcmp(message, msg->content, msg->size) != 0) {
        printf("Unexpected response\n");
        free(msg->content);
        free(msg);
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        free(signed_message);
        return false;
    }

    free(msg->content);
    free(msg);
    OQS_FREE(pk, algorithm->length_public_key);
    OQS_FREE(sk, algorithm->length_secret_key);
    free(signed_message);

    OQS_destroy();
    return true;
}

// -----------------------------------------------------------------------------
// Bob side
// -----------------------------------------------------------------------------
void test_dsa_Bob(char* algo) {
    OQS_SIG *algorithm = OQS_SIG_new(algo);
    if (!algorithm) {
        printf("OQS_SIG_new failed for %s\n", algo);
        return;
    }

    uint8_t *pk = OQS_MEM_malloc(algorithm->length_public_key);
    uint8_t *sk = OQS_MEM_malloc(algorithm->length_secret_key);
    if (!pk || !sk) {
        printf("Failed to allocate keys\n");
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        return;
    }

    printf("Waiting for public key\n");
    bool got_pk = false;
    Message_struct* msg = NULL;

    while (!got_pk) {
        pthread_mutex_lock(&queue_lock);
        msg = (!isEmpty(&receiving_queue)) ? dequeue(&receiving_queue) : NULL;
        pthread_mutex_unlock(&queue_lock);

        if (msg) {
            if (msg->size == algorithm->length_public_key) {
                printf("Received pk\n");
                memcpy(pk, msg->content, msg->size);
                got_pk = true;
            } else {
                printf("Received wrong size : %zu, expecting : %zu\n",
                       msg->size, algorithm->length_public_key);
            }
            free(msg->content);
            free(msg);
        } else {
            sleep(1);
        }
    }

    printf("Waiting for signed message\n");
    bool got_sm = false;
    uint8_t* signed_message = NULL;
    size_t sm_actual_len = 0;

    while (!got_sm) {
        pthread_mutex_lock(&queue_lock);
        msg = (!isEmpty(&receiving_queue)) ? dequeue(&receiving_queue) : NULL;
        pthread_mutex_unlock(&queue_lock);

        if (msg) {
            signed_message = msg->content;
            sm_actual_len = msg->size;
            printf("Received sm of size %zu\n", sm_actual_len);
            printf("sig len %zu\n", algorithm->length_signature);
            free(msg); // keep content in signed_message
            got_sm = true;
        } else {
            sleep(1);
        }
    }

    printf("Decrypting message\n");
    uint8_t* message_to_send = malloc(strlen(message) + 20);
    if (!message_to_send) {
        send_message((const uint8_t*)failed_message, strlen(failed_message));
        printf("Unable to allocate space\n");
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        free(signed_message);
        return;
    }

    size_t message_len = 0;
    if (crypto_open_message(message_to_send, &message_len, signed_message, sm_actual_len, pk, algorithm) != 0) {
        send_message((const uint8_t*)failed_message, strlen(failed_message));
        printf("failed to verify/decrypt message\n");
        OQS_FREE(pk, algorithm->length_public_key);
        OQS_FREE(sk, algorithm->length_secret_key);
        free(signed_message);
        free(message_to_send);
        return;
    }

    printf("Sending message\n");
    send_message(message_to_send, message_len);

    OQS_FREE(pk, algorithm->length_public_key);
    OQS_FREE(sk, algorithm->length_secret_key);
    free(signed_message);
    free(message_to_send);

    OQS_destroy();
}

// -----------------------------------------------------------------------------
// Test harness
// -----------------------------------------------------------------------------
void test_dsa_alice_bob(enum ROLE role) {
    synchronize(role);

    switch (role) {
    case ALICE:
        for (size_t i = 0; i < num_algorithms; i++) {
            printf("Beginning algorithm %s.\n", algorithms[i]);
            if (test_dsa_Alice(algorithms[i])) {
                printf("DSA algorithm %s passed the test.\n", algorithms[i]);
            } else {
                printf("DSA algorithm %s failed the test.\n", algorithms[i]);
            }
        }
        break;

    case BOB:
        for (size_t i = 0; i < num_algorithms; i++) {
            printf("Beginning algorithm %s.\n", algorithms[i]);
            test_dsa_Bob(algorithms[i]);
        }
        break;

    default:
        printf("Wrong role\n");
        break;
    }

    printf("All algorithms done\n");
}

void test_dsa_all_alice_bob(void) {
    enum ROLE role;

    #if defined(ROLE_ALICE)
        role = ALICE;
    #elif defined(ROLE_BOB)
        role = BOB;
    #else
        role = ALICE;
    #endif

    test_dsa_alice_bob(role);

    #if defined(ROLE_ALICE)
        role = BOB;
    #elif defined(ROLE_BOB)
        role = ALICE;
    #endif

    test_dsa_alice_bob(role);
}

int main(void) {
    if (setup() < 0) return -1;

    test_dsa_all_alice_bob();

    destroy();
    return 0;
}
