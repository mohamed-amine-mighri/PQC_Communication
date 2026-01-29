#include <oqs/oqs.h>
#include "transport.h"
#include "queue.h"
#include <stdio.h>

#define Alice_1_Bob_0 1
#if Alice_1_Bob_0
    #define ROLE_ALICE
#else
    #define ROLE_BOB
#endif

#define NONCELEN 40 

static const char* message = "Test message for DSA";
static const char* ready_message = "ready";
static const char* ack_message = "ack";
static const char* failed_message = "failed";

enum ROLE {
    ALICE,
    BOB
};

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

int crypto_sign_message(
    uint8_t* sm, size_t* smlen,
    const uint8_t* m, size_t mlen, const uint8_t* sk, 
    OQS_SIG* algo) {
        uint8_t* signature = OQS_MEM_malloc(algo->length_signature);
        size_t signature_len = 0;
        if (!signature) return -1;

        uint8_t hdr[2] = {(uint16_t)mlen >> 8, (uint16_t)mlen & 0xFF };
        OQS_SIG_sign(algo, signature, &signature_len, m, mlen, sk);

        memcpy(sm, hdr, 2);
        memcpy(sm + 2, m, mlen);
        memcpy(sm + 2 + mlen, signature, signature_len);
        free(signature);
        *smlen = 2 + mlen + signature_len;
        return 0;
    }

int crypto_open_message(
    uint8_t* m, size_t* mlen,
    const uint8_t* sm, size_t smlen, const uint8_t* pk,
    OQS_SIG* algo) {
        *mlen = ((size_t)sm[0] << 8) | sm[1];

        uint8_t* signature = OQS_MEM_malloc(algo->length_signature);
        size_t signature_len = smlen - *mlen - 2;
        if (!signature) return -1;

        memcpy(signature, sm + 2 + *mlen, signature_len);

        if (OQS_SIG_verify(algo, sm + 2, mlen, signature, signature_len, pk) != OQS_SUCCESS) {
            free(signature);
            return -1;
        }

        memcpy(m, sm + 2, mlen);
        free(signature);
        return 0;
    }

void synchronize(enum ROLE role) {
    bool isMessageReceived = false;
    Message_struct* msg = NULL;
    switch(role){
        case ALICE:
                // IF ALICE wait for ready then send ack
                printf("Starting as Alice\n");
                while(!isMessageReceived){
                    pthread_mutex_lock(&queue_lock);
                    if(!isEmpty(&receiving_queue)){
                        msg = dequeue(&receiving_queue);
                        if(msg->size == strlen(ready_message) && memcmp(ready_message, msg->content, msg->size) == 0) {
                            printf("READY received\n");
                            int send = send_message((const uint8_t*)ack_message, strlen(ack_message));
                            printf("Ack send : %d\n", send);
                            isMessageReceived = true;
                        }
                        free(msg->content);
                    }
                    pthread_mutex_unlock(&queue_lock);
                    sleep(1);
                }
                return;
            break;

        case BOB:
                // IF BOB send ready until got ack
                printf("Starting as Bob\n");
                while(!isMessageReceived){
                    pthread_mutex_lock(&queue_lock);
                    if(!isEmpty(&receiving_queue)) {
                        if(msg->size == strlen(ack_message) && memcmp(ack_message, msg->content, msg->size) == 0) {
                            printf("Ack received\n");
                            isMessageReceived = true;
                        } else {
                            printf("Got %s\n", msg->content);
                        }
                        free(msg->content);
                    }
                    pthread_mutex_unlock(&queue_lock);
                    
                    if(!isMessageReceived) {
                        send_message((uint8_t*)ready_message, strlen(ready_message));
                        sleep(2);
                    }
                }
                return;
            break;
        default:
            printf("Wrong role\n");
            return;
            break;
    }
}

bool test_dsa_Alice(char* algo){
    OQS_SIG *algorithm = NULL;
    uint8_t *pk = NULL, *sk = NULL;

    algorithm = OQS_SIG_new(algo);
    pk = OQS_MEM_malloc(algorithm->length_public_key);
    sk = OQS_MEM_malloc(algorithm->length_secret_key);
    if(!pk || !sk){
        printf("Failed to allocate space for keys\n");
        free(pk);
        free(sk);
        return false;
    }

    // Generate key
    if(OQS_SIG_keypair(algorithm, pk, sk) != OQS_SUCCESS) {
        printf("Failed to generate keypair\n");
        free(pk);
        free(sk);
        return false;
    }

    // Send pk
    send_message(pk, algorithm->length_public_key);

    // Sign message
    uint8_t* signed_message = malloc(strlen(message) + algorithm->length_signature + 20);
    if(!signed_message) {
        printf("Failed to allocate memory for signed_message\n");
        free(pk);
        free(sk);
        free(signed_message);
        return false;
    }

    size_t actual_sm_size = strlen(message) + algorithm->length_signature;
    if(crypto_sign_message(algo, signed_message, &actual_sm_size, (const uint8_t*)message, strlen(message), sk) != 0) {
        printf("Failed to sign message\n");
        free(pk);
        free(sk);
        free(signed_message);
        return false;
    }

    // Send signed message
    int send_size = send_message(signed_message, actual_sm_size);

    // Wait for message
    bool isMessageReceived = false;
    Message_struct* msg;
    while(!isMessageReceived){
        pthread_mutex_lock(&queue_lock);
        if(!isEmpty(&receiving_queue)){
            isMessageReceived = true;
            msg = dequeue(&receiving_queue);
        }
        pthread_mutex_unlock(&queue_lock);

        if(!isMessageReceived) {
            sleep(1);
        }

    }

    // Verify message
    if(strlen(message) != msg->size || memcmp(message, msg->content, msg->size) != 0) {
        printf("sm :");
        for(int i = 0; i < actual_sm_size; i++) {
            printf("%02x", signed_message[i]);
        }
        printf("\n");

        free(pk);
        free(sk);
        free(signed_message);
        free(msg->content);
        return false;
    }

    free(pk);
    free(sk);
    free(signed_message);
    free(msg->content);
    OQS_destroy();
    return true;
}

void test_dsa_Bob(char* algo){
    OQS_SIG* algorithm = NULL;
    uint8_t *pk = NULL, *sk = NULL;

    algorithm = OQS_SIG_new(algo);
    pk = OQS_MEM_malloc(algorithm->length_public_key);
    sk = OQS_MEM_malloc(algorithm->length_secret_key);
    if(!pk || !sk){
        printf("Failed to get keys len\n");
        return;
    }
    
    // Wait for pk
    printf("Waiting for public key\n");
    bool isMessageReceived = false;
    Message_struct* msg;
    while(!isMessageReceived){
        pthread_mutex_lock(&queue_lock);
        if(!isEmpty(&receiving_queue)) {
            msg = dequeue(&receiving_queue);
            if(msg->size == algorithm->length_public_key) {
                printf("Received pk\n");
                pk = msg->content;
                isMessageReceived = true;
            } else {
                printf("Received wrong size : %zu, expecting : %zu\n", msg->size, algorithm->length_public_key);
                free(msg->content);
            }
        }
        pthread_mutex_unlock(&queue_lock);

        if(!isMessageReceived) {
            sleep(1);
        }
    }

    uint8_t* signed_message;
    size_t sm_actual_len = 0;

    // Wait for signed message
    printf("Waiting for signed message\n");
    isMessageReceived = false;
    while(!isMessageReceived){
        pthread_mutex_lock(&queue_lock);
        if(!isEmpty(&receiving_queue)){
            msg = dequeue(&receiving_queue);
            signed_message = msg->content;
            sm_actual_len = msg->size;
            isMessageReceived = true;
            printf("Received sm of size %zu\n", sm_actual_len);
            printf("sig len %zu\n", algorithm->length_signature);
        }
        pthread_mutex_unlock(&queue_lock);

        if(!isMessageReceived) {
            sleep(1);
        }
    }

    // Decrypt message
    printf("Decrypting message\n");
    uint8_t* message_to_send = malloc(strlen(message) + 20);
    if(!message_to_send) {
        send_message((uint8_t*)failed_message, strlen(failed_message));
        printf("Unable to allocate space\n");
        free(pk);
        free(signed_message);
        free(message_to_send);
        return;
    }
    size_t message_len = 0;
    if(crypto_open_message(algo, message_to_send, &message_len, signed_message, sm_actual_len, pk) != 0) {
        send_message((uint8_t*)failed_message, strlen(failed_message));
        printf("Sm :");
        for(int i = 0; i < sm_actual_len; i++) {
            printf("%02x", signed_message[i]);
        }
        printf("\n");
        free(pk);
        free(signed_message);
        free(message_to_send);
        printf("failed to decrypt message\n");
        return;
    }

    // Send message
    printf("Sending message\n");
    send_message(message_to_send, message_len);

    free(pk);
    free(signed_message);
    free(message_to_send);
    OQS_destroy();
    return;
}

void test_dsa_alice_bob(enum ROLE role) {
    synchronize(role);

    switch (role) {
    case ALICE:
        for(int i = 0; i < num_algorithms; i++) {
            printf("Beginning algorithm %s.\n", algorithms[i]);
            if(test_dsa_Alice(algorithms[i])) {
                printf("DSA algorithm %s passed the test.\n", algorithms[i]);
            } else {
                printf("DSA algorithm %s failed the test.\n", algorithms[i]);
            }
        }
        break;
    
    case BOB:
        for(int i = 0; i < num_algorithms; i++) {
            printf("Beginning algorithm %s.\n", algorithms[i]);
            test_dsa_Bob(algorithms[i]);
        }
        break;
    
    default:
        printf("Wrong algorithm \n");
        break;
    }
    printf("All algorithms done \n");
}

void test_dsa_all_alice_bob() {


    enum ROLE role;
    #if defined(ROLE_ALICE)
        role = ALICE;
    #elif defined(ROLE_BOB)
        role = BOB;
    #endif
    
    test_dsa_alice_bob(role);

    // change les roles
    #if defined(ROLE_ALICE)
        role = BOB;
    #elif defined(ROLE_BOB)
        role = ALICE;
    #endif

    test_dsa_alice_bob(role);
}



int main() {
    if(setup() < 0) return -1;

    test_dsa_all_alice_bob();

    destroy();
}
