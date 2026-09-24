// bench_tx_alice.c
// Sends masked SIKE public keys Alice->Bob over MQTT and waits for an ACK struct.
// Measures per-iteration timings and prints a short summary.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <openssl/rand.h>

#include "bench_proto.h"       // BROKER_HOST/BROKER_PORT/TOPIC_A2B/TOPIC_B2A + transport_mqtt.h
#include "transport_mqtt.h"    // mqtt_client, mqtt_* API, now_ns()
#include "sidh_bridge.h"       // sikep434_generate_keypair(), hyb_mask_pubkey()

#ifndef NONCE_LEN
#define NONCE_LEN 16
#endif
#ifndef SIKE_LEN
#define SIKE_LEN 330
#endif
#define PACKET_LEN (NONCE_LEN + SIKE_LEN)

static void usage(const char* prog){
    fprintf(stderr, "Usage: %s <host> <port> <iterations> <sleep_ms>\n", prog);
    fprintf(stderr, "Example: %s %s %d 100 1000\n", prog, BROKER_HOST, BROKER_PORT);
}

int main(int argc, char** argv)
{
    const char* host = BROKER_HOST;
    int         port = BROKER_PORT;
    int         iters = 100;
    int         sleep_ms = 1000;

    if (argc >= 3) {
        host = argv[1];
        port = atoi(argv[2]);
    }
    if (argc >= 4) iters = atoi(argv[3]);
    if (argc >= 5) sleep_ms = atoi(argv[4]);
    if (argc == 2) { usage(argv[0]); return 1; }

    printf("[Alice] MQTT %s:%d | iterations=%d | pause=%dms\n",
           host, port, iters, sleep_ms);

    struct mqtt_client* c = mqtt_connect_simple(
        "bench_alice", host, port,
        TOPIC_B2A,   // subscribe: Bob -> Alice
        TOPIC_A2B    // publish  : Alice -> Bob
    );
    if(!c){ fprintf(stderr, "[Alice] mqtt_connect_simple failed\n"); return 1; }

    // Accumulate stats (ns)
    long double sum_keygen_ns = 0.0L, sum_mask_ns = 0.0L, sum_tx_ns = 0.0L, sum_total_ns = 0.0L;
    long double sum_unmask_us = 0.0L;

    for(int i=0;i<iters;i++){
        // --- 1) Generate SIKE keypair
        uint8_t pk_sike[SIKE_LEN];
        uint8_t sk_sike[512]; // not used further; size large enough for SIDH secret
        uint64_t t0 = now_ns();
        if (sikep434_generate_keypair(pk_sike, sk_sike) != 0){
            fprintf(stderr, "[Alice] sikep434_generate_keypair failed at iter %d\n", i);
            break;
        }
        uint64_t t1 = now_ns();

        // --- 2) Mask with ECDH+SHAKE-256 and NONCE
        uint8_t nonce[NONCE_LEN];
        RAND_bytes(nonce, NONCE_LEN);

        uint8_t pk_masked[SIKE_LEN];
        if (hyb_mask_pubkey(pk_sike, nonce, pk_masked) != 0){
            fprintf(stderr, "[Alice] hyb_mask_pubkey failed at iter %d\n", i);
            break;
        }
        uint64_t t2 = now_ns();

        // --- 3) Build packet: NONCE || PK_MASKED and publish
        uint8_t packet[PACKET_LEN];
        memcpy(packet, nonce, NONCE_LEN);
        memcpy(packet+NONCE_LEN, pk_masked, SIKE_LEN);

        uint64_t t_pub_start = now_ns();
        if (mqtt_pub_raw(c, packet, sizeof(packet)) != 0){
            fprintf(stderr, "[Alice] mqtt_pub_raw failed at iter %d\n", i);
            break;
        }

        // --- 4) Wait for ACK (raw read of ack_t)
        ack_t ack;
        int rc = mqtt_read_raw(c, &ack, sizeof(ack), /*timeout_ms*/5000);
        uint64_t t_pub_end = now_ns();

        if (rc < 0){
            fprintf(stderr, "[Alice] timeout waiting for ACK at iter %d\n", i);
            break;
        }

        double T_keygen_ms = (double)(t1 - t0) / 1e6;
        double T_mask_ms   = (double)(t2 - t1) / 1e6;
        double T_tx_ms     = (double)(t_pub_end - t_pub_start) / 1e6;
        double T_total_ms  = (double)(t_pub_end - t0) / 1e6;
        double T_unmask_ms = (double)ack.t_unmask_us / 1000.0;

        sum_keygen_ns += (long double)(t1 - t0);
        sum_mask_ns   += (long double)(t2 - t1);
        sum_tx_ns     += (long double)(t_pub_end - t_pub_start);
        sum_total_ns  += (long double)(t_pub_end - t0);
        sum_unmask_us += (long double)ack.t_unmask_us;

        printf("[Alice][%d/%d] seq=%u code=%u T_keygen=%.3f ms  T_mask=%.3f ms  T_tx=%.3f ms  Bob.T_unmask=%.3f ms  T_total=%.3f ms\n",
               i+1, iters, ack.seq, ack.code, T_keygen_ms, T_mask_ms, T_tx_ms, T_unmask_ms, T_total_ms);

        if (sleep_ms > 0) msleep((unsigned)sleep_ms);
    }

    // --- Summary
    if (iters > 0){
        double avg_keygen_ms = (double)(sum_keygen_ns / iters) / 1e6;
        double avg_mask_ms   = (double)(sum_mask_ns   / iters) / 1e6;
        double avg_tx_ms     = (double)(sum_tx_ns     / iters) / 1e6;
        double avg_total_ms  = (double)(sum_total_ns  / iters) / 1e6;
        double avg_unmask_ms = (double)(sum_unmask_us / iters) / 1000.0;

        printf("\n[Alice] Averages over %d ops:\n", iters);
        printf("  Avg T_keygen = %.3f ms\n", avg_keygen_ms);
        printf("  Avg T_mask   = %.3f ms\n", avg_mask_ms);
        printf("  Avg T_tx     = %.3f ms\n", avg_tx_ms);
        printf("  Avg Bob T_unmask = %.3f ms\n", avg_unmask_ms);
        printf("  Avg T_total  = %.3f ms\n", avg_total_ms);
    }

    mqtt_disconnect_simple(c);
    return 0;
}
