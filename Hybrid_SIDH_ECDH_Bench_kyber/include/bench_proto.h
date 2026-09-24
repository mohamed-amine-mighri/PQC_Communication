#pragma once
#include <stdint.h>
#include <stddef.h>
#include "transport_mqtt.h"   // apporte ack_t

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================
 *  MQTT defaults (overridable)
 * =========================== */
#ifndef BROKER_HOST
#  define BROKER_HOST   "192.168.137.8"
#endif

#ifndef BROKER_PORT
#  define BROKER_PORT   1883
#endif

/* Topics par défaut :
 *  - TOPIC_A2B : Alice -> Bob
 *  - TOPIC_B2A : Bob   -> Alice
 */
#ifndef TOPIC_A2B
#  define TOPIC_A2B     "sike/demo/alice2bob"
#endif
#ifndef TOPIC_B2A
#  define TOPIC_B2A     "sike/demo/bob2alice"
#endif

/* ===========================
 *  Contextes & tailles par défaut
 * =========================== */

/* Contexte directionnel injecté dans le KDF/masquage (SHAKE-256)
 * pour séparer les flux A->B et B->A. */
#ifndef CTX_A2B_STR
#  define CTX_A2B_STR   "A2B"
#endif
#ifndef CTX_B2A_STR
#  define CTX_B2A_STR   "B2A"
#endif

/* Longueurs typiques */
#ifndef NONCE_LEN
#  define NONCE_LEN             16      /* recommandé >= 16 */
#endif

/* Longueurs SIKE p434 (non compressé, PQCrypto-SIDH) */
#ifndef SIKE_P434_PK_LEN
#  define SIKE_P434_PK_LEN      330     /* public key length */
#endif
#ifndef SIKE_P434_SK_LEN
#  define SIKE_P434_SK_LEN      374     /* secret key length */
#endif
#ifndef SIKE_P434_CT_LEN
#  define SIKE_P434_CT_LEN      346     /* ciphertext length (KEM) */
#endif
#ifndef SIKE_P434_SS_LEN
#  define SIKE_P434_SS_LEN      16      /* shared secret length (KEM) */
#endif

/* Pour les bancs de test masquage (clé publique SIKE masquée) */
#ifndef BENCH_PKT_MAX
#  define BENCH_PKT_MAX         2048    /* marge pour buffers RX/TX */
#endif

/* ===========================
 *  Codes d’ACK (convention)
 * =========================== */
enum {
    ACK_OK                = 0,   /* succès */
    ACK_ERR_GENERIC       = 1,   /* erreur générique */
    ACK_ERR_TIMEOUT       = 2,   /* timeout côté pair */
    ACK_ERR_DEMASK        = 3,   /* échec unmask/décryptage */
    ACK_ERR_FORMAT        = 4,   /* paquet invalide */
    ACK_ERR_LEN           = 5,   /* longueur inattendue */
    ACK_ERR_INTERNAL      = 6,   /* autre erreur interne */
};

/* ===========================
 *  Helpers utilitaires
 * =========================== */

/* Encodage/decodage big-endian 32-bit (utile pour seq, tailles, etc.) */
static inline void be_store_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}
static inline uint32_t be_load_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* Convertit une durée ns -> ms (double) */
static inline double ns_to_ms(uint64_t ns) {
    return (double)ns / 1e6;
}

/* Convertit µs -> ms (double) */
static inline double us_to_ms(uint32_t us) {
    return (double)us / 1000.0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
