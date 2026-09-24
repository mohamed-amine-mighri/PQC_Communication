// bench_tx_bob.c
// Receives NONCE||PK_MASKED from Alice, performs unmasking, and returns an ACK with t_unmask_us.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "bench_proto.h"       // BROKER_HOST/BROKER_PORT/TOPIC_A2B/TOPIC_B2A + transport_mqtt.h
#include "transport_mqtt.h"    // mqtt_client, mqtt_* API, now_ns()
#include "sidh_bridge.h"       // hyb_unmask_pubkey()

#ifndef NONCE_LEN
#define NONCE_LEN 16
#endif
#ifndef SIKE_LEN
#define SIKE_LEN 330
#endif
#define PACKET_LEN (NONCE_LEN + SIKE_LEN)

static void usage(const char* prog){
    fprintf(stderr, "Usage: %s <host> <port> <iterations>\n", prog);
    fprintf(stderr, "Example: %s %s %d 100\n", prog, BROKER_HOST, BROKER_PORT);
}

int main(int argc, char** argv)
{
    const char* host = BROKER_HOST;
    int         port = BROKER_PORT;
    int         iters = 100;

    if (argc >= 3) {
        host = argv[1];
        port = atoi(argv[2]);
    }
    if (argc >= 4) iters = atoi(argv[3]);
    if (argc == 2) { usage(argv[0]); return 1; }

    printf("[Bob] MQTT %s:%d | iterations=%d\n", host, port, iters);

    struct mqtt_client* c = mqtt_connect_simple(
        "bench_bob", host, port,
        TOPIC_A2B,   // subscribe: Alice -> Bob
        TOPIC_B2A    // publish  : Bob   -> Alice
    );
    if(!c){ fprintf(stderr, "[Bob] mqtt_connect_simple failed\n"); return 1; }

    for(int i=0;i<iters;i++){
        uint8_t packet[PACKET_LEN];

        // --- 1) Read exactly NONCE||PK_MASKED
        int rc = mqtt_read_raw(c, packet, sizeof(packet), /*timeout_ms*/10000);
        if (rc < 0){
            fprintf(stderr, "[Bob] timeout or short read at iter %d\n", i);
            break;
        }

        // --- 2) Split NONCE and MASKED PK
        const uint8_t* nonce     = packet;
        const uint8_t* pk_masked = packet + NONCE_LEN;

        // --- 3) Unmask and time it
        uint8_t pk_unmasked[SIKE_LEN];
        uint64_t t0 = now_ns();
        int urc = hyb_unmask_pubkey(pk_masked, nonce, pk_unmasked);
        uint64_t t1 = now_ns();

        uint32_t t_unmask_us = (uint32_t)((t1 - t0) / 1000ull);

        // --- 4) Send ACK back (even on error; set code accordingly)
        ack_t ack = {0};
        ack.seq          = (uint32_t)i;          // simple echo of loop index
        ack.code         = (urc == 0) ? 0u : 1u; // 0=OK, 1=ERR
        ack.t_ns         = now_ns();
        ack.t_unmask_us  = t_unmask_us;
        ack.reserved     = 0;

        if (mqtt_pub_raw(c, &ack, sizeof(ack)) != 0){
            fprintf(stderr, "[Bob] mqtt_pub_raw(ACK) failed at iter %d\n", i);
            break;
        }

        printf("[Bob][%d/%d] code=%u  T_unmask=%.3f ms\n",
               i+1, iters, ack.code, (double)t_unmask_us/1000.0);
    }

    mqtt_disconnect_simple(c);
    return 0;
}
