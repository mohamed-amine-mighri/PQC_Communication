// src/bench_hybrid.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// ===== HOOKS à fournir par ton projet =====
// Clés SIDH
extern int sike_p434_keypair(uint8_t *pk, size_t *pk_len, uint8_t *sk, size_t *sk_len);
// Masquage hybride (ECC keystream DER + XOR)
extern int hyb_mask_pubkey(const uint8_t *pk_in, size_t pk_in_len,
                           uint8_t *pk_out, size_t *pk_out_len);
// Démasquage hybride
extern int hyb_unmask_pubkey(const uint8_t *pk_in, size_t pk_in_len,
                             uint8_t *pk_out, size_t *pk_out_len);

// ===== Utilitaires temps =====
static inline uint64_t ns_now(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;
}

// stats simples
typedef struct {
    double sum, sum2;
    double min, max;
    int n;
} stats_t;

static void stats_init(stats_t *s){ s->sum=s->sum2=0.0; s->min=1e300; s->max=-1e300; s->n=0; }
static void stats_add(stats_t *s, double v){
    s->sum += v; s->sum2 += v*v; if(v<s->min) s->min=v; if(v>s->max) s->max=v; s->n++;
}
static double stats_avg(const stats_t *s){ return s->n? s->sum/s->n : 0.0; }
static double stats_std(const stats_t *s){
    if(!s->n) return 0.0;
    double m = s->sum/s->n;
    double var = (s->sum2/s->n) - m*m;
    return var>0? sqrt(var) : 0.0;
}

// ===== Paramètres =====
#define ITER_DEFAULT 100
#define SLEEP_BETWEEN_MS 1000
#define PK_MAX 1024
#define SK_MAX 1024

int main(int argc, char** argv){
    int iterations = ITER_DEFAULT;
    int mode_hybrid = 1; // 1 = hybride, 0 = normal

    // usage: ./bench_hybrid --normal|--hybrid --n 100
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--normal")) mode_hybrid = 0;
        else if(!strcmp(argv[i],"--hybrid")) mode_hybrid = 1;
        else if(!strcmp(argv[i],"--n") && i+1<argc) iterations = atoi(argv[++i]);
    }

    printf("[Mode] %s | itérations=%d\n", mode_hybrid? "HYBRID":"SIDH-NORMAL", iterations);

    uint8_t pk[PK_MAX], sk[SK_MAX];
    size_t pk_len=0, sk_len=0;

    // buffers mask/unmask
    uint8_t pk_masked[PK_MAX*2];
    size_t pk_masked_len=0;
    uint8_t pk_unmasked[PK_MAX*2];
    size_t pk_unmasked_len=0;

    stats_t st_keygen, st_mask, st_tx, st_unmask, st_total;
    stats_init(&st_keygen); stats_init(&st_mask);
    stats_init(&st_tx);     stats_init(&st_unmask); stats_init(&st_total);

    uint64_t bench_start = ns_now();

    for(int i=1;i<=iterations;i++){
        pk_len = sk_len = 0;
        pk_masked_len = pk_unmasked_len = 0;

        uint64_t t0_total = ns_now();

        // --- Keygen SIDH ---
        uint64_t t0 = ns_now();
        int rc = sike_p434_keypair(pk, &pk_len, sk, &sk_len);
        uint64_t t1 = ns_now();
        if(rc!=0){ fprintf(stderr,"[ERR] sike_p434_keypair rc=%d\n", rc); return 1; }
        double T_keygen_ms = (t1 - t0)/1e6;
        stats_add(&st_keygen, T_keygen_ms);

        double T_mask_ms=0.0, T_tx_ms=0.0, T_unmask_ms=0.0;

        if(mode_hybrid){
            // --- Mask ---
            t0 = ns_now();
            rc = hyb_mask_pubkey(pk, pk_len, pk_masked, &pk_masked_len);
            t1 = ns_now();
            if(rc!=0){ fprintf(stderr,"[ERR] hyb_mask_pubkey rc=%d\n", rc); return 1; }
            T_mask_ms = (t1 - t0)/1e6;
            stats_add(&st_mask, T_mask_ms);

            // --- Tx (option) : ici, on mesure un coût “local” d’encodage/copie.
            t0 = ns_now();
            // Simuler un envoi/copie mémoire ; si tu veux MQTT réel, remplace par publish/flush.
            volatile uint8_t sink = pk_masked[0];
            (void)sink;
            t1 = ns_now();
            T_tx_ms = (t1 - t0)/1e6;
            stats_add(&st_tx, T_tx_ms);

            // --- Unmask (côté Bob, simulé local) ---
            t0 = ns_now();
            rc = hyb_unmask_pubkey(pk_masked, pk_masked_len, pk_unmasked, &pk_unmasked_len);
            t1 = ns_now();
            if(rc!=0){ fprintf(stderr,"[ERR] hyb_unmask_pubkey rc=%d\n", rc); return 1; }
            T_unmask_ms = (t1 - t0)/1e6;
            stats_add(&st_unmask, T_unmask_ms);

            // (sanity) vérifier égalité
            if(pk_unmasked_len!=pk_len || memcmp(pk_unmasked, pk, pk_len)!=0){
                fprintf(stderr,"[ERR] pk_unmasked != pk (iter %d)\n", i);
                return 2;
            }
        }

        uint64_t t1_total = ns_now();
        double T_total_ms = (t1_total - t0_total)/1e6;
        stats_add(&st_total, T_total_ms);

        // Affichage itératif
        printf("operation %d..  T_keygen=%.3f ms", i, T_keygen_ms);
        if(mode_hybrid){
            printf(", T_mask=%.3f, T_tx=%.3f, T_unmask=%.3f", T_mask_ms, T_tx_ms, T_unmask_ms);
        }
        printf(", T_total=%.3f\n", T_total_ms);

        // pause 1s entre opérations (pour reproduire ton scénario)
        usleep(SLEEP_BETWEEN_MS * 1000);
    }

    uint64_t bench_end = ns_now();

    // Résumé
    printf("\nstart time (ns): %llu\n", (unsigned long long)bench_start);
    printf("end   time (ns): %llu\n", (unsigned long long)bench_end);
    printf("Averages over %d ops:\n", iterations);
    printf("  Avg T_keygen = %.3f ms (±%.3f) [min=%.3f max=%.3f]\n",
           stats_avg(&st_keygen), stats_std(&st_keygen), st_keygen.min, st_keygen.max);
    if(mode_hybrid){
        printf("  Avg T_mask   = %.3f ms (±%.3f) [min=%.3f max=%.3f]\n",
               stats_avg(&st_mask), stats_std(&st_mask), st_mask.min, st_mask.max);
        printf("  Avg T_tx     = %.3f ms (±%.3f) [min=%.3f max=%.3f]\n",
               stats_avg(&st_tx), stats_std(&st_tx), st_tx.min, st_tx.max);
        printf("  Avg T_unmask = %.3f ms (±%.3f) [min=%.3f max=%.3f]\n",
               stats_avg(&st_unmask), stats_std(&st_unmask), st_unmask.min, st_unmask.max);
    }
    printf("  Avg T_total  = %.3f ms (±%.3f) [min=%.3f max=%.3f]\n",
           stats_avg(&st_total), stats_std(&st_total), st_total.min, st_total.max);

    return 0;
}
