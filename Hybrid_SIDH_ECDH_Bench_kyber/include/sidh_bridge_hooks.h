// sidh_bridge_hooks.h
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Génération clés SIKE p434 (adapte à tes signatures réelles)
int sike_p434_keypair(uint8_t* pk, size_t* pk_len,
                      uint8_t* sk, size_t* sk_len);

// Masquage/Démasquage hybride (ECC DER + SHAKE-256 keystream + XOR)
int hyb_mask_pubkey(const uint8_t* pk_in, size_t pk_in_len,
                    uint8_t* pk_out, size_t* pk_out_len);

int hyb_unmask_pubkey(const uint8_t* pk_in, size_t pk_in_len,
                      uint8_t* pk_out, size_t* pk_out_len);

#ifdef __cplusplus
}
#endif
