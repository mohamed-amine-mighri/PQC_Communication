// bench_tx_bob_normal.c
#include "transport_mqtt.h"
#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bench_proto.h"


static struct mosquitto* M = NULL;

static void on_message_bob(struct mosquitto* m, void* userdata,
                           const struct mosquitto_message* msg)
{
    (void)userdata;
    if(!msg || !msg->payload || msg->payloadlen < (int)sizeof(uint32_t)) return;

    // Payload normal: [seq||pk_plain]
    uint32_t seq = 0;
    memcpy(&seq, msg->payload, sizeof(uint32_t));

    // Ici pas d’unmask: on ignore le reste et on renvoie un ACK avec t_unmask_us=0
    ack_t a = {.seq = seq, .t_unmask_us = 0};
    int rc = mosquitto_publish(m, NULL, TOPIC_B2A, (int)sizeof(a), &a, 1, false);
    if(rc != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[Bob-N] ACK publish failed rc=%d\n", rc);
    } else {
        printf("[Bob-N] ACK seq=%u (T_unmask=0.000 ms)\n", seq);
        fflush(stdout);
    }
}

int main(int argc, char** argv){
    const char* host = (argc>1)? argv[1] : "127.0.0.1";
    int   port = (argc>2)? atoi(argv[2]) : 1883;

    mosquitto_lib_init();
    M = mosquitto_new("bob_bench_normal", true, NULL);
    if(!M){ fprintf(stderr,"[Bob-N] mosquitto_new failed\n"); return 1; }

    mosquitto_message_callback_set(M, on_message_bob);

    if(mosquitto_connect(M, host, port, 30) != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[Bob-N] connect %s:%d failed\n", host, port);
        return 2;
    }
    if(mosquitto_subscribe(M, NULL, TOPIC_A2B, 1) != MOSQ_ERR_SUCCESS){
        fprintf(stderr, "[Bob-N] subscribe %s failed\n", TOPIC_A2B);
        return 3;
    }
    printf("[Bob-N] Prêt (mode NORMAL). J’attends A2B et je réponds en B2A.\n");
    mosquitto_loop_forever(M, -1, 1);
    mosquitto_destroy(M);
    mosquitto_lib_cleanup();
    return 0;
}
