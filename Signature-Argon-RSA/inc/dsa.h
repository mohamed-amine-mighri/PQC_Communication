#ifndef DSA_H
#define DSA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Fonctions principales
void alloc_space_for_dsa(uint8_t** pk, uint8_t** sk, 
                         size_t* pk_len, size_t* sk_len, 
                         size_t* sig_len_max);

void free_space_for_dsa(uint8_t* pk, uint8_t* sk);

int dsa_keygen(uint8_t* pk, uint8_t* sk);

int dsa_signature(uint8_t* sig, size_t* sig_len,
                  const uint8_t* msg, size_t msg_len, 
                  const uint8_t* sk);

int dsa_verify(const uint8_t* sig, size_t sig_len,
               const uint8_t* msg, size_t msg_len, 
               const uint8_t* pk);

// Utilitaires
const char* getAlgoName(void);

#ifdef __cplusplus
}
#endif

#endif
