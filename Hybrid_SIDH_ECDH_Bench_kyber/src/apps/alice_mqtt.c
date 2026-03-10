// alice_mqtt.c (FINAL: SIKE p434 + SHAKE256 nonce+context, single RX/TX topics + framing)
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "transport_mqtt.h"
#include "masking.h"      // int mask_bytes_with_ecdh_shake256_ex(...);
#include "sidh_bridge.h"  // sikep434_generate_keypair(...)

static const char* BROKER_HOST = "192.168.137.8";
static const int   BROKER_PORT = 1883;

// Un seul couple de topics (RX = B2A, TX = A2B) — miroir de Bob
static const char* TOPIC_A2B = "sike/demo/alice2bob";   // TX (Alice -> Bob)
static const char* TOPIC_B2A = "sike/demo/bob2alice";   // RX (Bob -> Alice)

#define SIKE_LEN   SIKE_P434_PK_LEN   // 330 pour p434 non compressé
#define NONCE_LEN  16
#define PACKET_LEN (NONCE_LEN + SIKE_LEN)

// --- Framing ---
// type (1 byte) | len (2 bytes big-endian) | payload[len]
enum { FT_EC_PUB_DER = 0x01, FT_SIKE_MASKED = 0x02 };

static void die(const char* where){
    fprintf(stderr, "[ERR] %s\n", where);
    exit(EXIT_FAILURE);
}
static void die_openssl(const char* where){
    fprintf(stderr, "[ERR] %s failed\n", where);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}
static void* xmalloc(size_t n){
    void* p = malloc(n);
    if(!p){ perror("malloc"); exit(EXIT_FAILURE); }
    return p;
}

// ---- ECC utils ----
static EVP_PKEY* gen_secp256k1_keypair(void){
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) die_openssl("EVP_PKEY_CTX_new_id");
    if (EVP_PKEY_keygen_init(pctx) <= 0) die_openssl("EVP_PKEY_keygen_init");
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0)
        die_openssl("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) die_openssl("EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
static int export_pubkey_der(EVP_PKEY* pkey, unsigned char** out, size_t* outlen){
    if (!pkey || !out || !outlen) return 0;
    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) return 0;
    *out = (unsigned char*)xmalloc((size_t)len);
    unsigned char* p = *out;
    if (i2d_PUBKEY(pkey, &p) != len) return 0;
    *outlen = (size_t)len;
    return 1;
}

// ---- Frame I/O using transport_mqtt raw APIs ----
static int send_frame(struct mqtt_client* mq, uint8_t type,
                      const uint8_t* payload, uint16_t len)
{
    uint8_t hdr[3] = { type, (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
    if (mqtt_pub_raw(mq, hdr, sizeof(hdr)) != 0) return -1;
    if (len > 0 && mqtt_pub_raw(mq, payload, len) != 0) return -1;
    return 0;
}

static int recv_frame(struct mqtt_client* mq, uint8_t* type,
                      uint8_t** out, uint16_t* outlen, int timeout_ms)
{
    uint8_t hdr[3];
    int r = mqtt_read_raw(mq, hdr, sizeof(hdr), timeout_ms);
    if (r < 0) return -1;
    *type = hdr[0];
    uint16_t len = (uint16_t)((hdr[1] << 8) | hdr[2]);
    *outlen = len;
    if (len == 0) { *out = NULL; return 0; }
    *out = (uint8_t*)xmalloc(len);
    r = mqtt_read_raw(mq, *out, len, timeout_ms);
    if (r < 0) { free(*out); *out = NULL; return -2; }
    return 0;
}

int main(void){
    ERR_load_ERR_strings();

    // 1) ECC d'Alice
    EVP_PKEY* alice_priv = gen_secp256k1_keypair();
    unsigned char* alice_pub_der = NULL; size_t alice_pub_len = 0;
    if(!export_pubkey_der(alice_priv, &alice_pub_der, &alice_pub_len))
        die_openssl("export_pubkey_der(alice)");

    // 2) MQTT (nouvelle API): souscrit TOPIC_B2A, publie TOPIC_A2B
    struct mqtt_client* mq = mqtt_connect_simple("alice",
                                BROKER_HOST, BROKER_PORT,
                                TOPIC_B2A,   // topic_sub (RX)
                                TOPIC_A2B);  // topic_pub (TX)
    if(!mq) die("MQTT connect failed");

    // 3) Envoyer la clé EC DER d'Alice à Bob
    if (send_frame(mq, FT_EC_PUB_DER, alice_pub_der, (uint16_t)alice_pub_len) != 0)
        die("send_frame(EC_PUB_DER alice)");
    printf("[Alice] Envoyé Alice EC DER (%zu bytes)\n", alice_pub_len);

    // 4) Recevoir la clé EC DER de Bob
    uint8_t ftype = 0; uint8_t* fbuf = NULL; uint16_t flen = 0;
    if (recv_frame(mq, &ftype, &fbuf, &flen, /*timeout_ms*/15000) != 0)
        die("recv_frame(EC_PUB_DER bob)");
    if (ftype != FT_EC_PUB_DER) die("unexpected frame type (expected EC_PUB_DER)");
    unsigned char* bob_pub_der = (unsigned char*)fbuf;
    size_t bob_pub_len = flen;
    printf("[Alice] Reçu Bob EC DER (%zu bytes)\n", bob_pub_len);

    // 5) Générer la VRAIE clé publique SIKE p434 d'Alice
    uint8_t alice_sike_pub[SIKE_LEN];
    uint8_t alice_sike_sk[SIKE_P434_SK_LEN];
    if (!sikep434_generate_keypair(alice_sike_pub, sizeof(alice_sike_pub),
                                   alice_sike_sk, sizeof(alice_sike_sk))) {
        die_openssl("sikep434_generate_keypair(alice)");
    }
    // Copie pour vérification remask
    uint8_t alice_sike_copy[SIKE_LEN];
    memcpy(alice_sike_copy, alice_sike_pub, SIKE_LEN);

    // 6) Masquer avec SHAKE-256 (nonce unique + contexte A2B, direction Alice->Bob)
    uint8_t nonce[NONCE_LEN];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) die_openssl("RAND_bytes");

    if(!mask_bytes_with_ecdh_shake256_ex(bob_pub_der, bob_pub_len, alice_priv,
                                         nonce, sizeof(nonce),
                                         "sike-mask|A2B|v1",
                                         alice_sike_pub, SIKE_LEN)){
        die_openssl("mask_bytes_with_ecdh_shake256_ex(Alice mask)");
    }

    // 7) Envoyer frame SIKE_MASKED: payload = nonce||masked_sike
    uint8_t pkt[PACKET_LEN];
    memcpy(pkt, nonce, NONCE_LEN);
    memcpy(pkt+NONCE_LEN, alice_sike_pub, SIKE_LEN);
    if (send_frame(mq, FT_SIKE_MASKED, pkt, (uint16_t)sizeof(pkt)) != 0)
        die("send_frame(SIKE_MASKED alice)");
    printf("[Alice] Envoyé nonce+masked (%zu bytes)\n", sizeof(pkt));

    // 8) Recevoir la frame SIKE_MASKED de Bob
    uint8_t* b_payload = NULL; uint16_t b_len = 0;
    if (recv_frame(mq, &ftype, &b_payload, &b_len, 15000) != 0)
        die("recv_frame(SIKE_MASKED bob)");
    if (ftype != FT_SIKE_MASKED || b_len != PACKET_LEN)
        die("unexpected frame for SIKE_MASKED (bob)");
    const uint8_t* bob_nonce  = b_payload;
    const uint8_t* bob_masked = b_payload + NONCE_LEN;

    // 9) Démasquer la SIKE de Bob (contexte B2A)
    uint8_t bob_sike_unmasked[SIKE_LEN];
    memcpy(bob_sike_unmasked, bob_masked, SIKE_LEN);
    if(!mask_bytes_with_ecdh_shake256_ex(bob_pub_der, bob_pub_len, alice_priv,
                                         bob_nonce, NONCE_LEN,
                                         "sike-mask|B2A|v1",
                                         bob_sike_unmasked, SIKE_LEN)){
        die_openssl("mask_bytes_with_ecdh_shake256_ex(Alice unmask)");
    }

    // 10) Vérif remask facultative côté Alice (cohérence)
    uint8_t tmp[SIKE_LEN];
    memcpy(tmp, bob_sike_unmasked, SIKE_LEN);
    if(!mask_bytes_with_ecdh_shake256_ex(bob_pub_der, bob_pub_len, alice_priv,
                                         bob_nonce, NONCE_LEN,
                                         "sike-mask|B2A|v1",
                                         tmp, SIKE_LEN)){
        die_openssl("mask_bytes_with_ecdh_shake256_ex(Alice remask)");
    }
    if (memcmp(tmp, bob_masked, SIKE_LEN) == 0)
        printf("[Alice][OK] Démasquage/remasquage Bob cohérent.\n");
    else
        printf("[Alice][WARN] Remask!=payload reçu (OK si Bob a changé le buffer).\n");

    // 11) Nettoyage
    mqtt_disconnect_simple(mq);
    if(alice_priv) EVP_PKEY_free(alice_priv);
    free(alice_pub_der);
    free(bob_pub_der);
    if (b_payload) free(b_payload);
    OPENSSL_cleanse(alice_sike_sk, sizeof(alice_sike_sk));
    return 0;
}
