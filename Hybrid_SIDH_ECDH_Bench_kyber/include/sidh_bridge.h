#ifndef SIDH_BRIDGE_H
#define SIDH_BRIDGE_H
/*
 * sidh_bridge.h — Pont minimal entre PQCrypto-SIDH (p434) et ton code.
 *
 * Par défaut : p434 NON compressé (clé publique 330 octets).
 * Pour la version compressée, définis SIDH_BRIDGE_USE_COMPRESSED=1 dans la
 * ligne de compilation (ou via CMake target_compile_definitions) AVANT
 * d'inclure ce header.
 *
 *   add_definitions(-DSIDH_BRIDGE_USE_COMPRESSED=1)
 *   // et lie la lib correspondante (lib434_compressed/libsidh.a)
 */

#include <stddef.h>
#include <stdint.h>

/* ===================== Sélection API PQCrypto-SIDH ====================== */
#pragma once

#if defined(SIDH_BRIDGE_USE_COMPRESSED)
  #include "P434_compressed_api.h"
#else
  #include "P434_api.h"
#endif

/* ===================== Tailles dérivées des headers officiels =========== */
/* Les headers PQCrypto-SIDH exposent CRYPTO_PUBLICKEYBYTES / SECRETKEYBYTES */
#ifndef SIKE_P434_PK_LEN
  #ifdef CRYPTO_PUBLICKEYBYTES
    #define SIKE_P434_PK_LEN ((size_t)CRYPTO_PUBLICKEYBYTES)
  #else
    /* Valeur de secours : 330 pour p434 non compressé. */
    #define SIKE_P434_PK_LEN ((size_t)330)
  #endif
#endif

#ifndef SIKE_P434_SK_LEN
  #ifdef CRYPTO_SECRETKEYBYTES
    #define SIKE_P434_SK_LEN ((size_t)CRYPTO_SECRETKEYBYTES)
  #else
    /* Valeur indicative ; préférer CRYPTO_SECRETKEYBYTES du header officiel. */
    #define SIKE_P434_SK_LEN ((size_t)44)
  #endif
#endif

/* Garde une cohérence compile-time si les macros existent */
#if defined(CRYPTO_PUBLICKEYBYTES)
  _Static_assert(SIKE_P434_PK_LEN == CRYPTO_PUBLICKEYBYTES,
                 "SIKE_P434_PK_LEN mismatch vs CRYPTO_PUBLICKEYBYTES");
#endif
#if defined(CRYPTO_SECRETKEYBYTES)
  _Static_assert(SIKE_P434_SK_LEN == CRYPTO_SECRETKEYBYTES,
                 "SIKE_P434_SK_LEN mismatch vs CRYPTO_SECRETKEYBYTES");
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ===================== API du bridge ==================================== */
/**
 * Génère une vraie paire SIKE p434 via l’API KEM de PQCrypto-SIDH.
 * pk : out[SIKE_P434_PK_LEN]
 * sk : out[SIKE_P434_SK_LEN]
 * Retourne 1 si succès, 0 sinon.
 */
int sikep434_generate_keypair(uint8_t *pk, size_t pk_len,
                              uint8_t *sk, size_t sk_len);

/**
 * Démo locale :
 *  - génère pk (SIKE p434),
 *  - applique un masquage ECDH(secp256k1)+SHAKE-256 puis démasque (round-trip),
 *  - vérifie que pk est restaurée à l’identique.
 *
 * NOTE : cette démo n’envoie rien sur MQTT — c’est un test “offline”.
 *
 * @param pk     buffer (≥ SIKE_P434_PK_LEN) passé par l’appelant
 * @param pk_len taille du buffer pk
 * @return 1 si le round-trip est valide, 0 sinon.
 */
int demo_mask_unmask_sike_p434(uint8_t *pk, size_t pk_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIDH_BRIDGE_H */
