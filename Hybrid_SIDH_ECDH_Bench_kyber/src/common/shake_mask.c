// shake_mask.c — ECDH(secp256k1) + SHAKE-256 keystream (nonce + contexte)
#include "masking.h"

#include <string.h>
#include <openssl/ec.h>
#include <openssl/x509.h>   // d2i_PUBKEY(), i2d_PUBKEY()
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define DS_LABEL "sike-mask|shake256|v1"   /* domain-separation label */

/* --- Exporter ma clé publique DER depuis une EVP_PKEY privée --- */
static int export_pubkey_der(EVP_PKEY* pkey, unsigned char** out, size_t* outlen){
    if (!pkey || !out || !outlen) return 0;
    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) return 0;
    *out = OPENSSL_malloc((size_t)len);
    if (!*out) return 0;
    unsigned char* p = *out;
    if (i2d_PUBKEY(pkey, &p) != len) { OPENSSL_free(*out); *out = NULL; return 0; }
    *outlen = (size_t)len;
    return 1;
}

/* --- Import DER -> EVP_PKEY pour la clé publique du pair --- */
static EVP_PKEY* import_peer_pubkey(const uint8_t *der, size_t der_len){
    const unsigned char *p = (const unsigned char*)der;
    return d2i_PUBKEY(NULL, &p, (long)der_len); /* NULL si échec */
}

/* --- Comparaison lexicographique (DER) pour ordre stable des pubkeys --- */
static int der_less(const unsigned char* a, size_t alen,
                    const unsigned char* b, size_t blen)
{
    size_t m = (alen < blen ? alen : blen);
    int c = memcmp(a, b, m);
    if (c != 0) return (c < 0);
    return (alen < blen);
}

/* --- Helpers SHAKE256 keystream --- */
static int shake256_keystream_xor_begin(EVP_MD_CTX **pctx){
    *pctx = EVP_MD_CTX_new();
    if (!*pctx) return 0;
    if (EVP_DigestInit_ex(*pctx, EVP_shake256(), NULL) <= 0) {
        EVP_MD_CTX_free(*pctx); *pctx = NULL; return 0;
    }
    return 1;
}
static int shake256_absorb(EVP_MD_CTX *ctx, const void* data, size_t len){
    if (len == 0) return 1;
    return EVP_DigestUpdate(ctx, data, len) > 0;
}
static int shake256_squeeze_xor(EVP_MD_CTX *ctx, uint8_t *inout, size_t len){
    unsigned char ks[1024];
    size_t off = 0;
    while (off < len){
        size_t chunk = (len - off > sizeof(ks)) ? sizeof(ks) : (len - off);
        if (EVP_DigestFinalXOF(ctx, ks, chunk) <= 0) return 0;
        for (size_t i = 0; i < chunk; i++) inout[off + i] ^= ks[i];
        off += chunk;
        /* SHAKE: on peut rappeler DigestFinalXOF successivement pour continuer le flux */
    }
    return 1;
}

/* --- ECDH + SHAKE256 nonce+contexte --- */
int mask_bytes_with_ecdh_shake256_ex(const uint8_t *peer_pub_der, size_t peer_pub_len,
                                     EVP_PKEY *my_ec_priv,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const char *context_info,
                                     uint8_t *inout, size_t len)
{
    if (!peer_pub_der || peer_pub_len == 0 || !my_ec_priv || !inout) return 0;

    /* 1) Import pub du pair & export de ma pub (pour lier les deux côtés) */
    EVP_PKEY *peer = import_peer_pubkey(peer_pub_der, peer_pub_len);
    if (!peer) return 0;

    unsigned char *my_pub_der = NULL;
    size_t my_pub_len = 0;
    if (!export_pubkey_der(my_ec_priv, &my_pub_der, &my_pub_len)){
        EVP_PKEY_free(peer);
        return 0;
    }

    /* 2) ECDH -> secret partagé Z */
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(my_ec_priv, NULL);
    if (!dctx) { OPENSSL_free(my_pub_der); EVP_PKEY_free(peer); return 0; }
    if (EVP_PKEY_derive_init(dctx) <= 0) { EVP_PKEY_CTX_free(dctx); OPENSSL_free(my_pub_der); EVP_PKEY_free(peer); return 0; }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) { EVP_PKEY_CTX_free(dctx); OPENSSL_free(my_pub_der); EVP_PKEY_free(peer); return 0; }

    unsigned char Z[64]; size_t Zlen = sizeof(Z);
    if (EVP_PKEY_derive(dctx, NULL, &Zlen) <= 0 ||
        Zlen == 0 || Zlen > sizeof(Z) ||
        EVP_PKEY_derive(dctx, Z, &Zlen) <= 0)
    {
        EVP_PKEY_CTX_free(dctx); OPENSSL_free(my_pub_der); EVP_PKEY_free(peer); return 0;
    }
    EVP_PKEY_CTX_free(dctx);

    /* 3) SHAKE-256 absorb: DS label, contexte, nonce, pubs triées, secret Z */
    EVP_MD_CTX *mdctx = NULL;
    if (!shake256_keystream_xor_begin(&mdctx)) {
        OPENSSL_cleanse(Z, sizeof(Z)); OPENSSL_free(my_pub_der); EVP_PKEY_free(peer);
        return 0;
    }

    const char *ctx = (context_info && *context_info) ? context_info : "";
    if (!shake256_absorb(mdctx, DS_LABEL, strlen(DS_LABEL)) ||
        !shake256_absorb(mdctx, ctx, strlen(ctx)) ||
        !shake256_absorb(mdctx, nonce, nonce_len))
    {
        EVP_MD_CTX_free(mdctx); OPENSSL_cleanse(Z, sizeof(Z)); OPENSSL_free(my_pub_der); EVP_PKEY_free(peer);
        return 0;
    }

    /* Ordonner (min, max) des deux DER pour une vue commune */
    const unsigned char *A = my_pub_der;       size_t Alen = my_pub_len;
    const unsigned char *B = peer_pub_der;     size_t Blen = peer_pub_len;
    int a_lt_b = der_less(A,Alen,B,Blen);
    const unsigned char *MIN = a_lt_b ? A : B; size_t MINlen = a_lt_b ? Alen : Blen;
    const unsigned char *MAX = a_lt_b ? B : A; size_t MAXlen = a_lt_b ? Blen : Alen;

    if (!shake256_absorb(mdctx, MIN, MINlen) ||
        !shake256_absorb(mdctx, MAX, MAXlen) ||
        !shake256_absorb(mdctx, Z, Zlen))
    {
        EVP_MD_CTX_free(mdctx); OPENSSL_cleanse(Z, sizeof(Z)); OPENSSL_free(my_pub_der); EVP_PKEY_free(peer);
        return 0;
    }

    /* 4) Squeeze & XOR in-place */
    int ok = shake256_squeeze_xor(mdctx, inout, len);
    EVP_MD_CTX_free(mdctx);

    /* 5) Nettoyage */
    OPENSSL_cleanse(Z, sizeof(Z));
    OPENSSL_free(my_pub_der);
    EVP_PKEY_free(peer);
    return ok;
}
