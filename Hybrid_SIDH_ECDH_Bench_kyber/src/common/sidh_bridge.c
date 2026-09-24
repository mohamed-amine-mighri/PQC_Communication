// sidh_bridge.c (FINAL)
#include "sidh_bridge.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "masking.h"  // mask_bytes_with_ecdh_shake256_ex(...)

/* ===================== Sélection API KEM PQCrypto-SIDH =================== */
#if defined(SIDH_BRIDGE_USE_COMPRESSED)
  #include "P434_compressed_api.h"
  #define SIKE_KEYPAIR   crypto_kem_keypair_SIKEp434_compressed
  #define SIKE_ENCAPS    crypto_kem_enc_SIKEp434_compressed
  #define SIKE_DECAPS    crypto_kem_dec_SIKEp434_compressed
  #ifndef SIKE_P434_PK_LEN
  #define SIKE_P434_PK_LEN   CRYPTO_PUBLICKEYBYTES
  #endif
  #ifndef SIKE_P434_SK_LEN
  #define SIKE_P434_SK_LEN   CRYPTO_SECRETKEYBYTES
  #endif
  #ifndef SIKE_P434_CT_LEN
  #define SIKE_P434_CT_LEN   CRYPTO_CIPHERTEXTBYTES
  #endif
  #ifndef SIKE_P434_SS_LEN
  #define SIKE_P434_SS_LEN   CRYPTO_BYTES
  #endif
#else
  #include "P434_api.h"
  #define SIKE_KEYPAIR   crypto_kem_keypair_SIKEp434
  #define SIKE_ENCAPS    crypto_kem_enc_SIKEp434
  #define SIKE_DECAPS    crypto_kem_dec_SIKEp434
  // Tailles par défaut si non déjà définies ailleurs
  #ifndef SIKE_P434_PK_LEN
  #define SIKE_P434_PK_LEN   CRYPTO_PUBLICKEYBYTES  /* 330 */
  #endif
  #ifndef SIKE_P434_SK_LEN
  #define SIKE_P434_SK_LEN   CRYPTO_SECRETKEYBYTES  /* 374 */
  #endif
  #ifndef SIKE_P434_CT_LEN
  #define SIKE_P434_CT_LEN   CRYPTO_CIPHERTEXTBYTES /* 346 */
  #endif
  #ifndef SIKE_P434_SS_LEN
  #define SIKE_P434_SS_LEN   CRYPTO_BYTES           /* 16  */
  #endif
#endif

#ifndef NONCE_LEN
#define NONCE_LEN 16u
#endif

/* ===================== Helpers OpenSSL (ECDH secp256k1) ================== */

static EVP_PKEY* gen_secp256k1_keypair(void) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0) {
        EVP_PKEY_CTX_free(pctx); return NULL;
    }
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static int export_pubkey_der(EVP_PKEY* pkey, unsigned char** out, size_t* outlen) {
    if (!pkey || !out || !outlen) return 0;
    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) return 0;
    *out = (unsigned char*)OPENSSL_malloc((size_t)len);
    if (!*out) return 0;
    unsigned char* p = *out;
    if (i2d_PUBKEY(pkey, &p) != len) { OPENSSL_free(*out); *out = NULL; return 0; }
    *outlen = (size_t)len;
    return 1;
}

/* ===================== Implémentations Bridge ============================ */

int sikep434_generate_keypair(uint8_t *pk, size_t pk_len,
                              uint8_t *sk, size_t sk_len)
{
    if (!pk || !sk) return 0;
    if (pk_len < SIKE_P434_PK_LEN || sk_len < SIKE_P434_SK_LEN) return 0;

    // API KEM : retourne 0 si succès
    int rc = SIKE_KEYPAIR(pk, sk);
    return (rc == 0) ? 1 : 0;
}

/* Démonstration locale de round-trip mask/unmask sur une clé publique SIKE. */
int demo_mask_unmask_sike_p434(uint8_t *pk, size_t pk_len) {
    if (!pk || pk_len < SIKE_P434_PK_LEN) {
        fprintf(stderr, "[bridge] pk buffer too small (need >= %zu)\n",
                (size_t)SIKE_P434_PK_LEN);
        return 0;
    }

    /* 1) Générer une vraie paire SIKE p434 via KEM */
    uint8_t sk[SIKE_P434_SK_LEN];
    if (!sikep434_generate_keypair(pk, pk_len, sk, sizeof(sk))) {
        fprintf(stderr, "[bridge] KEM keypair failed\n");
        return 0;
    }

    uint8_t pk_ref[SIKE_P434_PK_LEN];
    memcpy(pk_ref, pk, SIKE_P434_PK_LEN);

    /* 2) Générer deux paires ECDH secp256k1 (Alice/Bob) */
    EVP_PKEY *alice_priv = gen_secp256k1_keypair();
    EVP_PKEY *bob_priv   = gen_secp256k1_keypair();
    if (!alice_priv || !bob_priv) {
        fprintf(stderr, "[bridge] secp256k1 keygen failed\n");
        if (alice_priv) EVP_PKEY_free(alice_priv);
        if (bob_priv)   EVP_PKEY_free(bob_priv);
        OPENSSL_cleanse(sk, sizeof(sk));
        return 0;
    }

    unsigned char *alice_pub_der = NULL, *bob_pub_der = NULL;
    size_t alice_pub_len = 0, bob_pub_len = 0;
    if (!export_pubkey_der(alice_priv, &alice_pub_der, &alice_pub_len) ||
        !export_pubkey_der(bob_priv,   &bob_pub_der,   &bob_pub_len)) {
        fprintf(stderr, "[bridge] export DER failed\n");
        if (alice_pub_der) OPENSSL_free(alice_pub_der);
        if (bob_pub_der)   OPENSSL_free(bob_pub_der);
        EVP_PKEY_free(alice_priv); EVP_PKEY_free(bob_priv);
        OPENSSL_cleanse(sk, sizeof(sk));
        return 0;
    }

    /* 3) Nonce + contexte (direction Alice→Bob) */
    uint8_t nonce[NONCE_LEN];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "[bridge] RAND_bytes failed\n");
        OPENSSL_free(alice_pub_der); OPENSSL_free(bob_pub_der);
        EVP_PKEY_free(alice_priv); EVP_PKEY_free(bob_priv);
        OPENSSL_cleanse(sk, sizeof(sk));
        return 0;
    }
    const char *CTX_A2B = "sike-mask|A2B|v1";

    /* 4) MASQUAGE (Alice masque avec la pub de Bob) */
    if (!mask_bytes_with_ecdh_shake256_ex(bob_pub_der, bob_pub_len, alice_priv,
                                          nonce, sizeof(nonce), CTX_A2B,
                                          pk, SIKE_P434_PK_LEN)) {
        fprintf(stderr, "[bridge] mask (SHAKE256) failed\n");
        OPENSSL_free(alice_pub_der); OPENSSL_free(bob_pub_der);
        EVP_PKEY_free(alice_priv); EVP_PKEY_free(bob_priv);
        OPENSSL_cleanse(sk, sizeof(sk));
        return 0;
    }

    /* 5) DÉMASQUAGE (Bob avec la pub d’Alice, même nonce/contexte) */
    if (!mask_bytes_with_ecdh_shake256_ex(alice_pub_der, alice_pub_len, bob_priv,
                                          nonce, sizeof(nonce), CTX_A2B,
                                          pk, SIKE_P434_PK_LEN)) {
        fprintf(stderr, "[bridge] unmask (SHAKE256) failed\n");
        OPENSSL_free(alice_pub_der); OPENSSL_free(bob_pub_der);
        EVP_PKEY_free(alice_priv); EVP_PKEY_free(bob_priv);
        OPENSSL_cleanse(sk, sizeof(sk));
        return 0;
    }

    /* 6) Vérification round-trip */
    int ok = (memcmp(pk, pk_ref, SIKE_P434_PK_LEN) == 0);
    if (!ok) {
        fprintf(stderr, "[bridge] round-trip mismatch (unmask != original)\n");
    } else {
        fprintf(stdout, "[bridge][OK] SIKE p434 mask/unmask round-trip valid.\n");
    }

    /* 7) Nettoyage */
    OPENSSL_free(alice_pub_der); OPENSSL_free(bob_pub_der);
    EVP_PKEY_free(alice_priv); EVP_PKEY_free(bob_priv);
    OPENSSL_cleanse(sk, sizeof(sk));
    return ok ? 1 : 0;
}
