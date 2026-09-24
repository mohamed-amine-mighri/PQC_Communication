// bench_tx_alice_normal.c
#define _GNU_SOURCE
#include "transport_mqtt.h"
#include "sidh_bridge_hooks.h"   // pour sike_p434_keypair()
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "bench_proto.h"

static inline uint64_t ns_now(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;
}

#define PK_MAX 1024
#define SK_MAX 1024
#define BUF_MAX 2048

int main(int argc, char** argv){
    const char* host = (argc>1)? argv[1] : "127.0.0.1";
    int   port = (argc>2)? atoi(argv[2]) : 1883;
    int   iterations = (argc>3)? atoi(argv[3]) : 100;
    int   sleep_ms = (argc>4)? atoi(argv[4]) : 1000;

    const char* topic_sub = "sike/demo/bob2alice";
    const char* topic_pub = "sike/demo/alice2bob";

    struct mqtt_client* c = mqtt_connect_simple("alice_bench_normal", host, port, topic_sub, topic_pub);
    if(!c){ fprintf(stderr,"[Alice-N] MQTT connect failed\n"); return 1; }

    uint8_t pk[PK_MAX], sk[SK_MAX], pkt[BUF_MAX];
    size_t pk_len = sizeof(pk), sk_len = sizeof(sk), pkt_len = sizeof(pkt);

    printf("[Alice-N] MQTT %s:%d | itérations=%d | pause=%dms (mode NORMAL)\n", host, port, iterations, sleep_ms);

    FILE* f = fopen("results_normal.csv", "w");
    if(f){ fprintf(f,"iter,T_keygen_ms,T_mask_ms,T_tx_ms,T_unmask_ms,T_total_ms\n"); }

    double sum_key=0, sum_mask=0, sum_tx=0, sum_unmask=0, sum_total=0;

    uint64_t bench_start = ns_now();
    for(int i=1;i<=iterations;i++){
        // keygen (SIKE p434)
        uint64_t t0 = ns_now();
        pk_len = sizeof(pk); sk_len = sizeof(sk);
        if(sike_p434_keypair(pk,&pk_len, sk,&sk_len)!=0){
            fprintf(stderr,"[Alice-N] keypair error\n"); break;
        }
        uint64_t t1 = ns_now();
        double T_key = (t1 - t0)/1e6;

        // PAS de mask: on copie juste la pk brute dans le paquet
        t0 = ns_now();
        memcpy(pkt, pk, pk_len);
        pkt_len = pk_len;
        t1 = ns_now();
        double T_mask = (t1 - t0)/1e6; // ~0 (copie mémoire) — on la loggue quand même

        // Tx roundtrip + réception ACK (t_unmask_us=0 côté Bob)
        ack_t ack = {0};
        t0 = ns_now();
        int rc = mqtt_tx_roundtrip(c, pkt, pkt_len, (uint32_t)i, 3000, &ack);
        t1 = ns_now();
        double T_tx = (t1 - t0)/1e6;
        double T_unmask = ack.t_unmask_us / 1000.0; // sera ~0

        if(rc!=0){
            fprintf(stderr,"[Alice-N] tx timeout/err (seq=%d)\n", i);
        }

        double T_total = T_key + T_mask + T_tx;

        sum_key += T_key; sum_mask += T_mask; sum_tx += T_tx; sum_unmask += T_unmask; sum_total += T_total;

        printf("[Alice-N] op %d.. T_keygen=%.3f ms, T_mask=%.3f ms, T_tx=%.3f ms, (Bob T_unmask=%.3f ms), T_total=%.3f ms\n",
               i, T_key, T_mask, T_tx, T_unmask, T_total);
        fflush(stdout);

        if(f){
            fprintf(f,"%d,%.3f,%.3f,%.3f,%.3f,%.3f\n", i, T_key, T_mask, T_tx, T_unmask, T_total);
            fflush(f);
        }

        usleep(sleep_ms * 1000);
    }
    uint64_t bench_end = ns_now();
    if(f) fclose(f);

    printf("\nstart time (ns): %llu\nend   time (ns): %llu\n",
           (unsigned long long)bench_start, (unsigned long long)bench_end);
    if(iterations>0){
        printf("[Alice-N] Averages over %d ops:\n", iterations);
        printf("  Avg T_keygen = %.3f ms\n", sum_key/iterations);
        printf("  Avg T_mask   = %.3f ms\n", sum_mask/iterations);
        printf("  Avg T_tx     = %.3f ms\n", sum_tx/iterations);
        printf("  Avg Bob T_unmask = %.3f ms\n", sum_unmask/iterations);
        printf("  Avg T_total  = %.3f ms\n", sum_total/iterations);
        printf("[Alice-N] Résultats dans results_normal.csv\n");
    }

    mqtt_disconnect_simple(c);
    return 0;
}
