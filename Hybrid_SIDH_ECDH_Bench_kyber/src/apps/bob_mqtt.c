// bob_mqtt.c (FINAL: SIKE p434 + SHAKE256 nonce+context, single RX/TX topics + framing)
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

// Un seul couple de topics (RX = A2B, TX = B2A)
static const char* TOPIC_A2B   = "sike/demo/alice2bob";   // RX
static const char* TOPIC_B2A   = "sike/demo/bob2alice";   // TX

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
    // publish header then payload
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

    // 1) ECC de Bob
    EVP_PKEY* bob_priv = gen_secp256k1_keypair();
    unsigned char* bob_pub_der = NULL; size_t bob_pub_len = 0;
    if(!export_pubkey_der(bob_priv, &bob_pub_der, &bob_pub_len))
        die_openssl("export_pubkey_der(bob)");

    // 2) MQTT (nouvelle API): souscrit TOPIC_A2B, publie TOPIC_B2A
    struct mqtt_client* mq = mqtt_connect_simple("bob",
                                BROKER_HOST, BROKER_PORT,
                                TOPIC_A2B,   // topic_sub (RX)
                                TOPIC_B2A);  // topic_pub (TX)
    if(!mq) die("MQTT connect failed");

    // 3) Attendre la clé EC DER d'Alice (frame type=FT_EC_PUB_DER)
    uint8_t ftype = 0; uint8_t* fbuf = NULL; uint16_t flen = 0;
    if (recv_frame(mq, &ftype, &fbuf, &flen, /*timeout_ms*/15000) != 0)
        die("recv_frame(EC_PUB_DER)");
    if (ftype != FT_EC_PUB_DER) die("unexpected frame type (expected EC_PUB_DER)");
    unsigned char* alice_pub_der = (unsigned char*)fbuf;
    size_t alice_pub_len = flen;
    printf("[Bob] Reçu Alice EC DER (%zu bytes)\n", alice_pub_len);

    // 4) Publier la clé EC DER de Bob
    if (send_frame(mq, FT_EC_PUB_DER, bob_pub_der, (uint16_t)bob_pub_len) != 0)
        die("send_frame(EC_PUB_DER bob)");
    printf("[Bob] Envoyé Bob EC DER (%zu bytes)\n", bob_pub_len);

    // 5) Générer la VRAIE clé publique SIKE p434 de Bob
    uint8_t bob_sike_pub[SIKE_LEN];
    uint8_t bob_sike_sk[SIKE_P434_SK_LEN];
    if (!sikep434_generate_keypair(bob_sike_pub, sizeof(bob_sike_pub),
                                   bob_sike_sk, sizeof(bob_sike_sk))) {
        die_openssl("sikep434_generate_keypair(bob)");
    }
    uint8_t bob_sike_copy[SIKE_LEN];
    memcpy(bob_sike_copy, bob_sike_pub, SIKE_LEN);

    // 6) Masquer (nonce unique + contexte B2A)
    uint8_t nonce[NONCE_LEN];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) die_openssl("RAND_bytes");

    if(!mask_bytes_with_ecdh_shake256_ex(alice_pub_der, alice_pub_len, bob_priv,
                                         nonce, sizeof(nonce),
                                         "sike-mask|B2A|v1",
                                         bob_sike_pub, SIKE_LEN)){
        die_openssl("mask_bytes_with_ecdh_shake256_ex(Bob mask)");
    }

    // 7) Envoyer frame SIKE_MASKED: payload = nonce||masked_sike
    uint8_t pkt[PACKET_LEN];
    memcpy(pkt, nonce, NONCE_LEN);
    memcpy(pkt+NONCE_LEN, bob_sike_pub, SIKE_LEN);
    if (send_frame(mq, FT_SIKE_MASKED, pkt, (uint16_t)sizeof(pkt)) != 0)
        die("send_frame(SIKE_MASKED bob)");
    printf("[Bob] Envoyé nonce+masked (%zu bytes)\n", sizeof(pkt));

    // 8) Recevoir frame SIKE_MASKED d'Alice (nonce||masked)
    uint8_t* a_payload = NULL; uint16_t a_len = 0;
    if (recv_frame(mq, &ftype, &a_payload, &a_len, 15000) != 0)
        die("recv_frame(SIKE_MASKED alice)");
    if (ftype != FT_SIKE_MASKED || a_len != PACKET_LEN)
        die("unexpected frame for SIKE_MASKED");
    const uint8_t* alice_nonce = a_payload;
    const uint8_t* alice_masked = a_payload + NONCE_LEN;

    // 9) Démasquer la SIKE d'Alice (contexte A2B)
    uint8_t alice_sike_unmasked[SIKE_LEN];
    memcpy(alice_sike_unmasked, alice_masked, SIKE_LEN);
    if(!mask_bytes_with_ecdh_shake256_ex(alice_pub_der, alice_pub_len, bob_priv,
                                         alice_nonce, NONCE_LEN,
                                         "sike-mask|A2B|v1",
                                         alice_sike_unmasked, SIKE_LEN)){
        die_openssl("mask_bytes_with_ecdh_shake256_ex(Bob unmask)");
    }

    // 10) Vérif remask côté Bob (cohérence)
    uint8_t check_bob[SIKE_LEN];
    memcpy(check_bob, bob_sike_copy, SIKE_LEN);
    if(!mask_bytes_with_ecdh_shake256_ex(alice_pub_der, alice_pub_len, bob_priv,
                                         nonce, NONCE_LEN,
                                         "sike-mask|B2A|v1",
                                         check_bob, SIKE_LEN)){
        die_openssl("mask_bytes_with_ecdh_shake256_ex(Bob remask)");
    }
    if (memcmp(check_bob, pkt+NONCE_LEN, SIKE_LEN) == 0)
        printf("[Bob][OK] Masquage cohérent (remask==payload envoyé).\n");
    else
        printf("[Bob][FAIL] Remask!=payload envoyé.\n");

    // 11) Nettoyage
    mqtt_disconnect_simple(mq);
    if(bob_priv) EVP_PKEY_free(bob_priv);
    free(bob_pub_der);
    free(alice_pub_der);
    if (a_payload) free(a_payload);
    OPENSSL_cleanse(bob_sike_sk, sizeof(bob_sike_sk));
    return 0;
}
