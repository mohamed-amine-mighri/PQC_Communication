// src/sidh_bridge_hooks.c
#include "sidh_bridge_hooks.h"
#include "masking.h"  // mask_bytes_with_ecdh_shake256_ex(...)

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* ===================== Sélection API KEM PQCrypto-SIDH =================== */
#ifdef SIDH_BRIDGE_USE_COMPRESSED
  #include <P434_compressed_api.h>
  #define KEM_KEYPAIR(pk,sk)  crypto_kem_keypair_SIKEp434_compressed((pk),(sk))
#else
  #include <P434/P434_api.h>
  #define KEM_KEYPAIR(pk,sk)  crypto_kem_keypair_SIKEp434((pk),(sk))
#endif

/* ===================== Tailles par défaut (fallback) ===================== */
#if defined(CRYPTO_PUBLICKEYBYTES)
  #define SIKE_P434_PK_LEN   ((size_t)CRYPTO_PUBLICKEYBYTES)
#else
  #define SIKE_P434_PK_LEN   ((size_t)330)   /* p434 non compressé usuel */
#endif

#if defined(CRYPTO_SECRETKEYBYTES)
  #define SIKE_P434_SK_LEN   ((size_t)CRYPTO_SECRETKEYBYTES)
#else
  #define SIKE_P434_SK_LEN   ((size_t)374)   /* peut varier selon build */
#endif

#ifndef NONCE_LEN
#define NONCE_LEN 16
#endif

/* ===================== Contexte par défaut =============================== */
#ifndef HYB_CONTEXT_A2B
#define HYB_CONTEXT_A2B "sike-mask|A2B|v1"
#endif

/* ===================== Helpers endian ==================================== */
static void be16enc(uint8_t out[2], uint16_t v){
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)(v);
}
static uint16_t be16dec(const uint8_t in[2]){
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

/* ===================== Helpers OpenSSL (EC secp256k1) ==================== */

static EVP_PKEY* gen_secp256k1_keypair(void){
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!pctx) return NULL;
    if(EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0){
        EVP_PKEY_CTX_free(pctx); return NULL;
    }
    if(EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return NULL; }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static EVP_PKEY* load_or_generate_local_priv(const char* path_pem){
    EVP_PKEY* p = NULL;
    FILE* f = fopen(path_pem, "rb");
    if(f){
        p = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        if(p) return p;
        fprintf(stderr, "[hooks] Warning: failed to read PEM '%s', regenerating\n", path_pem);
    }
    // generate
    p = gen_secp256k1_keypair();
    if(!p){ fprintf(stderr, "[hooks] EC keygen failed\n"); return NULL; }
    f = fopen(path_pem, "wb");
    if(f){
        PEM_write_PrivateKey(f, p, NULL, NULL, 0, NULL, NULL);
        fclose(f);
    } else {
        fprintf(stderr, "[hooks] Warning: cannot write PEM '%s'\n", path_pem);
    }
    return p;
}

static int load_peer_pub_der(const char* path_der, unsigned char** out, size_t* outlen){
    *out = NULL; *outlen = 0;
    FILE* f = fopen(path_der, "rb");
    if(!f){ fprintf(stderr, "[hooks] peer DER not found: %s\n", path_der); return 0; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if(sz <= 0){ fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = OPENSSL_malloc((size_t)sz);
    if(!buf){ fclose(f); return 0; }
    if(fread(buf, 1, (size_t)sz, f) != (size_t)sz){
        fclose(f); OPENSSL_free(buf); return 0;
    }
    fclose(f);
    *out = buf; *outlen = (size_t)sz;
    return 1;
}

/* ===================== Hook: SIKE keypair ================================ */

int sike_p434_keypair(uint8_t *pk, size_t *pk_len,
                      uint8_t *sk, size_t *sk_len)
{
    if(!pk || !pk_len || !sk || !sk_len){
        fprintf(stderr, "[hooks] sike_p434_keypair: bad args\n");
        return -1;
    }
    if(*pk_len < SIKE_P434_PK_LEN || *sk_len < SIKE_P434_SK_LEN){
        fprintf(stderr, "[hooks] sike_p434_keypair: buffers too small (pk>=%zu, sk>=%zu)\n",
                SIKE_P434_PK_LEN, SIKE_P434_SK_LEN);
        return -2;
    }
    int rc = KEM_KEYPAIR(pk, sk);   // 0 = success
    if(rc != 0){
        fprintf(stderr, "[hooks] KEM_KEYPAIR failed rc=%d\n", rc);
        return rc ? rc : -3;
    }
    *pk_len = SIKE_P434_PK_LEN;
    *sk_len = SIKE_P434_SK_LEN;
    return 0;
}

/* ===================== Hook: HYBRID mask (Alice) =========================
   Construit un paquet:
     [u16 der_len][u8 nonce_len][u8 ctx_len]
     [DER_Alice][NONCE][CTX][PK_XOR]
   - DER_Alice = i2d_PUBKEY(priv_local)
   - NONCE = NONCE_LEN octets
   - CTX = HYB_CONTEXT_A2B (ou env HYB_CONTEXT_A2B_STR)
   - PK_XOR = pk_in XOR keystream(ECDH(Z: Alice_priv x Bob_pub), DS, ctx, nonce, pubs triées)
   Nécessite de connaître la pub DER de Bob (peer) via fichier: HYB_PEER_PUB_DER (ou "peer_pub.der")
*/

int hyb_mask_pubkey(const uint8_t *pk_in, size_t pk_in_len,
                    uint8_t *packet_out, size_t *packet_out_len)
{
    if(!pk_in || pk_in_len == 0 || !packet_out || !packet_out_len){
        fprintf(stderr, "[hooks] hyb_mask_pubkey: bad args\n");
        return -1;
    }

    /* 1) Charger ou générer la clé privée locale (Alice) */
    const char* priv_path = getenv("HYB_EC_PRIV");
    if(!priv_path) priv_path = "ec_local_priv.pem";
    EVP_PKEY* my_priv = load_or_generate_local_priv(priv_path);
    if(!my_priv) return -2;

    /* 2) Charger le DER de la pub du pair (Bob) */
    const char* peer_der_path = getenv("HYB_PEER_PUB_DER");
    if(!peer_der_path) peer_der_path = "peer_pub.der";
    unsigned char* peer_der = NULL; size_t peer_der_len = 0;
    if(!load_peer_pub_der(peer_der_path, &peer_der, &peer_der_len)){
        EVP_PKEY_free(my_priv);
        return -3;
    }

    /* 3) Exporter ma pub DER */
    unsigned char* my_pub_der = NULL; int my_pub_der_len = i2d_PUBKEY(my_priv, &my_pub_der);
    if(my_pub_der_len <= 0){
        OPENSSL_free(peer_der); EVP_PKEY_free(my_priv);
        return -4;
    }

    /* 4) Nonce + contexte */
    uint8_t nonce[NONCE_LEN];
    if(RAND_bytes(nonce, sizeof(nonce)) != 1){
        OPENSSL_free(my_pub_der); OPENSSL_free(peer_der); EVP_PKEY_free(my_priv);
        return -5;
    }
    const char* ctx_env = getenv("HYB_CONTEXT_A2B_STR");
    const char* ctx = ctx_env && *ctx_env ? ctx_env : HYB_CONTEXT_A2B;
    size_t ctx_len = strlen(ctx);

    /* 5) Construire le paquet et appliquer le masque in-place */
    const size_t header_len = 2 /*der_len*/ + 1 /*nonce_len*/ + 1 /*ctx_len*/;
    const size_t out_needed = header_len + (size_t)my_pub_der_len + sizeof(nonce) + ctx_len + pk_in_len;

    // On écrit directement dans packet_out (le bench fournit un buffer > 1KB)
    uint8_t* p = packet_out;
    be16enc(p, (uint16_t)my_pub_der_len); p += 2;
    *p++ = (uint8_t)sizeof(nonce);
    *p++ = (uint8_t)ctx_len;

    memcpy(p, my_pub_der, (size_t)my_pub_der_len); p += my_pub_der_len;
    memcpy(p, nonce, sizeof(nonce));               p += sizeof(nonce);
    memcpy(p, ctx, ctx_len);                       p += ctx_len;

    // Copie de la pk à masquer
    memcpy(p, pk_in, pk_in_len);

    // Appliquer XOR avec keystream (Alice_priv, Bob_pub)
    int ok = mask_bytes_with_ecdh_shake256_ex(
        /*peer_pub_der=*/peer_der, /*peer_pub_len=*/peer_der_len,
        /*my_ec_priv=*/my_priv,
        /*nonce=*/nonce, /*nonce_len=*/sizeof(nonce),
        /*context_info=*/ctx,
        /*inout=*/p, /*len=*/pk_in_len
    );

    if(!ok){
        fprintf(stderr, "[hooks] mask_bytes_with_ecdh_shake256_ex failed\n");
        OPENSSL_free(my_pub_der); OPENSSL_free(peer_der); EVP_PKEY_free(my_priv);
        return -6;
    }

    *packet_out_len = out_needed;

    /* 6) Nettoyage */
    OPENSSL_free(my_pub_der);
    OPENSSL_free(peer_der);
    EVP_PKEY_free(my_priv);
    return 0;
}

/* ===================== Hook: HYBRID unmask (Bob) =========================
   Parse le paquet, récupère DER_Alice, NONCE, CTX et MASKED_PK, puis charge
   la clé privée locale (Bob) et appelle mask_bytes_with_ecdh_shake256_ex avec
   (peer_pub = DER_Alice, my_priv = Bob_priv) pour restaurer la pk.
*/

int hyb_unmask_pubkey(const uint8_t *packet_in, size_t packet_in_len,
                      uint8_t *pk_out, size_t *pk_out_len)
{
    if(!packet_in || packet_in_len < 4 || !pk_out || !pk_out_len){
        fprintf(stderr, "[hooks] hyb_unmask_pubkey: bad args\n");
        return -1;
    }

    const uint8_t* p = packet_in;
    const uint8_t* end = packet_in + packet_in_len;

    if(p + 2 > end) return -2;
    uint16_t der_len = be16dec(p); p += 2;
    if(p + 1 > end) return -2;
    uint8_t nonce_len = *p++;
    if(p + 1 > end) return -2;
    uint8_t ctx_len = *p++;

    if(p + der_len + nonce_len + ctx_len > end) return -3;

    const uint8_t* der_alice = p; p += der_len;
    const uint8_t* nonce     = p; p += nonce_len;
    const char*    ctx       = (const char*)p; p += ctx_len;

    size_t masked_len = (size_t)(end - p);
    if(masked_len != SIKE_P434_PK_LEN){
        // on peut autoriser masked_len == *pk_out_len si on bench autre chose
        if(*pk_out_len < masked_len){
            fprintf(stderr, "[hooks] hyb_unmask_pubkey: pk_out too small (need >= %zu)\n", masked_len);
            return -4;
        }
    } else {
        if(*pk_out_len < SIKE_P434_PK_LEN){
            fprintf(stderr, "[hooks] hyb_unmask_pubkey: pk_out too small (need >= %zu)\n", (size_t)SIKE_P434_PK_LEN);
            return -4;
        }
    }

    memcpy(pk_out, p, masked_len); // copie masked -> out (sera XOR in-place)

    /* Charger/générer la clé privée locale (Bob) */
    const char* priv_path = getenv("HYB_EC_PRIV");
    if(!priv_path) priv_path = "ec_local_priv.pem";
    EVP_PKEY* my_priv = load_or_generate_local_priv(priv_path);
    if(!my_priv) return -5;

    int ok = mask_bytes_with_ecdh_shake256_ex(
        /*peer_pub_der=*/der_alice, /*peer_pub_len=*/der_len,
        /*my_ec_priv=*/my_priv,
        /*nonce=*/nonce, /*nonce_len=*/nonce_len,
        /*context_info=*/ctx,
        /*inout=*/pk_out, /*len=*/masked_len
    );

    EVP_PKEY_free(my_priv);

    if(!ok){
        fprintf(stderr, "[hooks] unmask: shake256_ex failed\n");
        return -6;
    }

    *pk_out_len = masked_len;
    return 0;
}
