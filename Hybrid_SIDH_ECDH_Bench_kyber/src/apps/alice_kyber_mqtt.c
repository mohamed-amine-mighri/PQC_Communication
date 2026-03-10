// src/apps/alice_kyber_mqtt.c
// Alice (KEM initiator): receive Bob's Kyber-512 public key over MQTT,
// encapsulate, publish ciphertext to Bob, print timings & an 8-byte SHA256 tag.

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
    uint8_t* ct   = (uint8_t*)malloc(kem->length_ciphertext);
    uint8_t* ssA  = (uint8_t*)malloc(kem->length_shared_secret);
    if(!pk || !ct || !ssA) die("[ERR] malloc");

    // MQTT connect: subscribe B->A (Bob publishes pk), publish A->B (Alice sends ct)
    struct mqtt_client* cli = mqtt_connect_simple("alice_kyber", host, port,
                                                  /*sub*/ TOPIC_B2A,
                                                  /*pub*/ TOPIC_A2B);
    if(!cli) die("[ERR] mqtt_connect_simple");

    // CSV header
    printf("# scheme,platform,transport,iterations,inter_delay_ms,pk_bytes,ct_bytes,"
           "T_wait_pk_ms,T_encap_ms,T_tx_ms,T_total_ms,ok,ssA_sha256_8\n");

    for(int it = 1; it <= iterations; ++it){
        // Wait for Bob's public key
        uint64_t t0 = now_ns();
        int r = mqtt_read_raw(cli, pk, kem->length_public_key, /*timeout_ms*/10000);
        if (r != (int)kem->length_public_key){
            fprintf(stderr, "[ERR] read pk timeout/short (%d/%zu) (iter=%d)\n",
                    r, kem->length_public_key, it);
            break;
        }
        uint64_t t1 = now_ns();

        // Encapsulate (produces ct and ssA)
        if(OQS_KEM_encaps(kem, ct, ssA, pk) != OQS_SUCCESS) die("[ERR] OQS_KEM_encaps");
        uint64_t t2 = now_ns();

        // Send ciphertext to Bob
        if(mqtt_pub_raw(cli, ct, kem->length_ciphertext) != 0){
            fprintf(stderr, "[ERR] publish ct (iter=%d)\n", it);
            break;
        }
        uint64_t t3 = now_ns();

        // Timings
        const double T_wait_pk_ms = (double)(t1 - t0) / 1e6;
        const double T_encap_ms   = (double)(t2 - t1) / 1e6;
        const double T_tx_ms      = (double)(t3 - t2) / 1e6;
        const double T_total_ms   = (double)(t3 - t0) / 1e6;

        // Short tag of shared secret
        unsigned char h[SHA256_DIGEST_LENGTH];
        SHA256(ssA, kem->length_shared_secret, h);

        // One CSV line per operation (keep "iterations" as 1 for per-iter record)
        printf("Kyber-512,RPi,MQTT,1,%d,%zu,%zu,%.3f,%.3f,%.3f,%.3f,%d,%02x%02x%02x%02x%02x%02x%02x%02x\n",
               sleep_ms,
               kem->length_public_key, kem->length_ciphertext,
               T_wait_pk_ms, T_encap_ms, T_tx_ms, T_total_ms,
               1,
               h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);

        if (sleep_ms > 0) msleep((unsigned)sleep_ms);
    }

    mqtt_disconnect_simple(cli);
    free(pk); free(ct); free(ssA);
    OQS_KEM_free(kem);
    return 0;
}
