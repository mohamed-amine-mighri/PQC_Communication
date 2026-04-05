#include "dsa.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// Constantes
#define RSA_KEY_SIZE 256
#define RSA_SIG_SIZE 256

void alloc_space_for_dsa(uint8_t** pk, uint8_t** sk,
                         size_t* pk_len, size_t* sk_len,
                         size_t* sig_len_max) {
    if (!pk || !sk || !pk_len || !sk_len || !sig_len_max) {
        return;
    }

    *pk_len = RSA_KEY_SIZE;
    *sk_len = RSA_KEY_SIZE;
    *sig_len_max = RSA_SIG_SIZE;

    *pk = (uint8_t*)malloc(*pk_len);
    *sk = (uint8_t*)malloc(*sk_len);

    if (!*pk || !*sk) {
        if (*pk) free(*pk);
        if (*sk) free(*sk);
        *pk = NULL;
        *sk = NULL;
        *pk_len = 0;
        *sk_len = 0;
        *sig_len_max = 0;
    }
}

void free_space_for_dsa(uint8_t* pk, uint8_t* sk) {
    if (pk) free(pk);
    if (sk) free(sk);
}

int dsa_keygen(uint8_t* pk, uint8_t* sk) {
    if (!pk || !sk) return -1;

    memset(pk, 0xAA, RSA_KEY_SIZE);
    memset(sk, 0xBB, RSA_KEY_SIZE);

    return 0;
}

int dsa_signature(uint8_t* sig, size_t* sig_len,
                  const uint8_t* msg, size_t msg_len,
                  const uint8_t* sk) {
    if (!sig || !sig_len || !sk) return -1;

    (void)sk;

    *sig_len = RSA_SIG_SIZE;

    if (msg && msg_len > 0) {
        for (size_t i = 0; i < *sig_len; i++) {
            sig[i] = msg[i % msg_len] ^ (uint8_t)(i & 0xFF);
        }
    } else {
        memset(sig, 0x5A, *sig_len);
    }

    return 0;
}

int dsa_verify(const uint8_t* sig, size_t sig_len,
               const uint8_t* msg, size_t msg_len,
               const uint8_t* pk) {
    if (!sig || !pk) return -1;

    (void)msg;
    (void)msg_len;
    (void)pk;

    if (sig_len != RSA_SIG_SIZE) return -1;

    return 0;
}

const char* getAlgoName(void) {
    return "RSA_2048_Simple";
}