// src/apps/bob_kyber_mqtt.c
// Bob (KEM responder): generate Kyber-512 keypair, publish pk to Alice,
// receive ciphertext over MQTT, decapsulate, print timings & an 8-byte SHA256 tag.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <openssl/sha.h>

#include "bench_proto.h"       // BROKER_HOST/BROKER_PORT/TOPIC_A2B/TOPIC_B2A + transport_mqtt.h
#include "transport_mqtt.h"    // mqtt_client API, now_ns(), msleep

static void die(const char* msg){
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void usage(const char* prog){
    fprintf(stderr, "Usage: %s [host] [port] [iterations] [sleep_ms]\n", prog);
    fprintf(stderr, "Defaults: host=%s port=%d iterations=100 sleep_ms=0\n",
            BROKER_HOST, BROKER_PORT);
}

int main(int argc, char** argv){
    const char* host = BROKER_HOST;
    int         port = BROKER_PORT;
    int         iterations = 100;
    int         sleep_ms = 0;

    if (argc >= 2) host       = argv[1];
    if (argc >= 3) port       = atoi(argv[2]);
    if (argc >= 4) iterations = atoi(argv[3]);
    if (argc >= 5) sleep_ms   = atoi(argv[4]);
    if (argc == 2 && (strcmp(host, "-h")==0 || strcmp(host, "--help")==0)) {
        usage(argv[0]);
        return 0;
    }

    setlinebuf(stdout);

    // Init Kyber-512
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if(!kem) die("[ERR] OQS_KEM_new(kyber_512)");

    uint8_t* pk   = (uint8_t*)malloc(kem->length_public_key);
    uint8_t* sk   = (uint8_t*)malloc(kem->length_secret_key);
    uint8_t* ct   = (uint8_t*)malloc(kem->length_ciphertext);
    uint8_t* ssB  = (uint8_t*)malloc(kem->length_shared_secret);
    if(!pk || !sk || !ct || !ssB) die("[ERR] malloc");

    // MQTT connect: subscribe A->B, publish B->A
    struct mqtt_client* cli = mqtt_connect_simple("bob_kyber", host, port,
                                                  /*sub*/ TOPIC_A2B,
                                                  /*pub*/ TOPIC_B2A);
    if(!cli) die("[ERR] mqtt_connect_simple");

    // CSV header
    printf("# scheme,platform,transport,iterations,inter_delay_ms,pk_bytes,sk_bytes,ct_bytes,"
           "T_keygen_ms,T_tx_ms,T_decaps_ms,T_total_ms,ok,ssB_sha256_8\n");

    for(int it = 1; it <= iterations; ++it){
        // KeyGen
        uint64_t t0 = now_ns();
        if(OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) die("[ERR] OQS_KEM_keypair");
        uint64_t t1 = now_ns();

        // Publish Bob's pk to Alice
        if(mqtt_pub_raw(cli, pk, kem->length_public_key) != 0){
            fprintf(stderr, "[ERR] publish pk (iter=%d)\n", it);
            break;
        }

        // Wait for ciphertext from Alice
        int r = mqtt_read_raw(cli, ct, kem->length_ciphertext, /*timeout_ms*/10000);
        if (r != (int)kem->length_ciphertext){
            fprintf(stderr, "[ERR] read ct timeout/short (%d/%zu) (iter=%d)\n",
                    r, kem->length_ciphertext, it);
            break;
        }
        uint64_t t2 = now_ns();

        // Decapsulate
        if(OQS_KEM_decaps(kem, ssB, ct, sk) != OQS_SUCCESS) die("[ERR] OQS_KEM_decaps");
        uint64_t t3 = now_ns();

        // Timings
        const double T_keygen_ms = (double)(t1 - t0) / 1e6;
        const double T_tx_ms     = (double)(t2 - t1) / 1e6;
        const double T_dec_ms    = (double)(t3 - t2) / 1e6;
        const double T_total_ms  = (double)(t3 - t0) / 1e6;

        // Short tag of shared secret
        unsigned char h[SHA256_DIGEST_LENGTH];
        SHA256(ssB, kem->length_shared_secret, h);

        // Print CSV line (one operation per line; keep "iterations" as 1 for a per-iter record)
        printf("Kyber-512,RPi,MQTT,1,%d,%zu,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%d,%02x%02x%02x%02x%02x%02x%02x%02x\n",
               sleep_ms,
               kem->length_public_key, kem->length_secret_key, kem->length_ciphertext,
               T_keygen_ms, T_tx_ms, T_dec_ms, T_total_ms,
               1,
               h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);

        if (sleep_ms > 0) msleep((unsigned)sleep_ms);
    }

    mqtt_disconnect_simple(cli);
    free(pk); free(sk); free(ct); free(ssB);
    OQS_KEM_free(kem);
    return 0;
}
