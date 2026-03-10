#ifndef MASKING_H
#define MASKING_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Masque/démasque in-place `inout` avec un flot dérivé de :
 *   - ECDH(secp256k1) entre ma clé privée et la pub DER du pair,
 *   - un label de séparation (interne),
 *   - un contexte directionnel (ex: "sike-mask|A2B|v1"),
 *   - un nonce (recommandé: 16 octets),
 *   - les deux clés publiques DER triées lexicographiquement,
 *   - le secret partagé ECDH Z.
 *
 * Appeler la même fonction avec EXACTEMENT les mêmes paramètres re-XOR le
 * buffer → démasquage.
 *
 * @return 1 si succès, 0 sinon.
 */
int mask_bytes_with_ecdh_shake256_ex(const uint8_t *peer_pub_der, size_t peer_pub_len,
                                     EVP_PKEY *my_ec_priv,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const char *context_info,
                                     uint8_t *inout, size_t len);

/* Alias pratique (même signature) */
#define mask_bytes_with_ecdh_shake256  mask_bytes_with_ecdh_shake256_ex

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MASKING_H */
