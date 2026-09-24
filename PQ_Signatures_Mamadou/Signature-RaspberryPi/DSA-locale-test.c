// DSA-Test-local.c (FINAL - FIXED)
// - --mode run|idle (idle-match)
// - 1 PPK2 window per batch
// - JSONL buffered (no per-iter fflush, optional --flush-each)
// - sign/verify benches: keypair prepared once OUTSIDE energy window
// - --list-algs: lists liboqs enabled/disabled signature algs
//
// Build: cmake -DUSE_OPENSSL=ON .. (optional)

#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#if defined(__GLIBC__)
  #include <malloc.h>
#endif



#ifdef USE_OPENSSL
  #include <openssl/evp.h>
  #include <openssl/crypto.h>
  #include <openssl/rsa.h>
  #include <openssl/pem.h>
#endif


#ifdef USE_OPENSSL
#define RSA_BITS 2048
#define RSA_ALG_NAME "RSA-2048"

/* Encodage PEM en mémoire :
   - pk_pem : clé publique PEM
   - sk_pem : clé privée PEM
*/
static int rsa_generate_keypair(uint8_t **pk_pem, size_t *pk_len,
                                uint8_t **sk_pem, size_t *sk_len)
{
    int ret = -1;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio_pub = NULL;
    BIO *bio_priv = NULL;

    if (!pk_pem || !pk_len || !sk_pem || !sk_len) return -1;

    *pk_pem = NULL; *pk_len = 0;
    *sk_pem = NULL; *sk_len = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;

    bio_pub = BIO_new(BIO_s_mem());
    bio_priv = BIO_new(BIO_s_mem());
    if (!bio_pub || !bio_priv) goto cleanup;

    if (PEM_write_bio_PUBKEY(bio_pub, pkey) <= 0) goto cleanup;
    if (PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL) <= 0) goto cleanup;

    {
        char *pub_data = NULL, *priv_data = NULL;
        long pub_sz = BIO_get_mem_data(bio_pub, &pub_data);
        long priv_sz = BIO_get_mem_data(bio_priv, &priv_data);

        if (pub_sz <= 0 || priv_sz <= 0) goto cleanup;

        *pk_pem = (uint8_t*)malloc((size_t)pub_sz);
        *sk_pem = (uint8_t*)malloc((size_t)priv_sz);
        if (!*pk_pem || !*sk_pem) goto cleanup;

        memcpy(*pk_pem, pub_data, (size_t)pub_sz);
        memcpy(*sk_pem, priv_data, (size_t)priv_sz);
        *pk_len = (size_t)pub_sz;
        *sk_len = (size_t)priv_sz;
    }

    ret = 0;

cleanup:
    if (ret != 0) {
        free(*pk_pem); *pk_pem = NULL; *pk_len = 0;
        free(*sk_pem); *sk_pem = NULL; *sk_len = 0;
    }
    if (bio_pub) BIO_free(bio_pub);
    if (bio_priv) BIO_free(bio_priv);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}
#endif



// ---------------- Algorithms list (compiled list you want to benchmark) ----------------
static const char* algorithms[] = {
    "Falcon-512",
    "Falcon-padded-512",
    "ML-DSA-44",
    "MAYO-1",
    "SPHINCS+-SHA2-128f-simple",
    "SPHINCS+-SHA2-128s-simple",
    "SPHINCS+-SHAKE-128f-simple",
    "SPHINCS+-SHAKE-128s-simple"
};
static const size_t num_algorithms = sizeof(algorithms)/sizeof(algorithms[0]);

// ---------------- Bench helpers ----------------
static uint64_t now_us(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec*1000000ull + (uint64_t)ts.tv_nsec/1000ull;
}

static long read_peak_rss_kb(void){
    FILE *f = fopen("/proc/self/status","r");
    if(!f) return -1;

    char line[256];
    long peak = -1;

    while(fgets(line, sizeof(line), f)){
        if(sscanf(line, "VmHWM: %ld kB", &peak) == 1) break;
    }

    fclose(f);
    return peak;
}




static long read_rss_kb(void){
    FILE *f = fopen("/proc/self/status","r");
    if(!f) return -1;
    char line[256];
    long rss = -1;
    while(fgets(line,sizeof(line),f)){
        if(sscanf(line,"VmRSS: %ld kB",&rss)==1) break;
    }
    fclose(f);
    return rss;
}

static long heap_used_bytes(void){
#if defined(__GLIBC__)
    struct mallinfo2 mi = mallinfo2();
    return (long)mi.uordblks;
#else
    return -1;
#endif
}

// mkdir -p
static int mkdir_p(const char *path){
    char tmp[1024];
    size_t len;

    if (!path) return -1;
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0) return -1;

    if (tmp[len-1] == '/') tmp[len-1] = '\0';

    for(char *p = tmp + 1; *p; p++){
        if(*p == '/'){
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "mkdir_p failed at '%s': %s\n", tmp, strerror(errno));
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir_p failed at '%s': %s\n", tmp, strerror(errno));
        return -1;
    }
    return 0;
}

static void sanitize_alg(const char *alg, char *out, size_t out_sz){
    size_t j=0;
    for(size_t i=0; alg[i] && j+1<out_sz; i++){
        char c = alg[i];
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-'){
            out[j++] = c;
        } else {
            out[j++] = '_';
        }
    }
    out[j]=0;
}

static FILE* open_result_file(const char *base_dir, const char *op, const char *alg){
    char safe[256];
    sanitize_alg(alg, safe, sizeof(safe));

    char dir[512];
    snprintf(dir, sizeof(dir), "%s/%s", base_dir, op);

    // FIX: create base_dir (not hard-coded "results/local")
    if (mkdir_p(base_dir) < 0) return NULL;
    if (mkdir_p(dir) < 0) return NULL;

    char path[768];
    snprintf(path, sizeof(path), "%s/%s/%s.jsonl", base_dir, op, safe);

    FILE *f = fopen(path, "a");
    if(!f) {
        fprintf(stderr, "ERROR: cannot open %s (%s)\n", path, strerror(errno));
        return NULL;
    }

    // Big buffer to avoid disk I/O noise during benches
    setvbuf(f, NULL, _IOFBF, 1<<20); // 1MB buffer
    return f;
}

static int g_flush_each = 0;

static void emit_jsonl(FILE *f,
    const char *platform, const char *alg, const char *op, int iter, int msg_len,
    uint64_t time_us,
    long heap_before, long heap_after,
    long rss_before, long rss_after,
    long peak_rss_before, long peak_rss_after,
    long useful_heap_bytes, long extra_heap_bytes,
    long static_mem_bytes, long total_mem_bytes,
    int pk_len, int sk_len, int sig_len,
    int ok
){
    if(!f) return;

    long peak_rss_delta_kb = -1;
    if (peak_rss_before >= 0 && peak_rss_after >= 0) {
        peak_rss_delta_kb = peak_rss_after - peak_rss_before;
    }

    fprintf(f,
      "{\"platform\":\"%s\",\"alg\":\"%s\",\"op\":\"%s\","
      "\"iter\":%d,\"msg_len\":%d,\"time_us\":%llu,"
      "\"heap_used_before\":%ld,\"heap_used_after\":%ld,"
      "\"rss_kb_before\":%ld,\"rss_kb_after\":%ld,"
      "\"peak_rss_kb_before\":%ld,\"peak_rss_kb_after\":%ld,\"peak_rss_delta_kb\":%ld,"
      "\"useful_heap_bytes\":%ld,\"extra_heap_bytes\":%ld,"
      "\"static_mem_bytes\":%ld,\"total_mem_bytes\":%ld,"
      "\"pk_len\":%d,\"sk_len\":%d,\"sig_len\":%d,\"ok\":%d}\n",
      platform, alg, op, iter, msg_len, (unsigned long long)time_us,
      heap_before, heap_after,
      rss_before, rss_after,
      peak_rss_before, peak_rss_after, peak_rss_delta_kb,
      useful_heap_bytes, extra_heap_bytes, static_mem_bytes, total_mem_bytes,
      pk_len, sk_len, sig_len, ok
    );

    if(g_flush_each) fflush(f);
}


static void emit_jsonl_whole(FILE *f,
    const char *platform, const char *alg, int iter, int msg_len,
    uint64_t t_keypair_us, uint64_t t_sign_us, uint64_t t_verify_us, uint64_t t_total_us,
    long heap_before, long heap_after,
    long rss_before, long rss_after,
    long peak_rss_before, long peak_rss_after,
    long useful_heap_bytes, long extra_heap_bytes,
    long static_mem_bytes, long total_mem_bytes,
    int pk_len, int sk_len, int sig_len,
    int ok_k, int ok_s, int ok_v, int ok_all
){
    if(!f) return;

    long peak_rss_delta_kb = -1;
    if (peak_rss_before >= 0 && peak_rss_after >= 0) {
        peak_rss_delta_kb = peak_rss_after - peak_rss_before;
    }

    fprintf(f,
      "{"
      "\"platform\":\"%s\",\"alg\":\"%s\",\"op\":\"whole\","
      "\"iter\":%d,\"msg_len\":%d,"
      "\"t_keypair_us\":%llu,\"t_sign_us\":%llu,\"t_verify_us\":%llu,"
      "\"time_us\":%llu,"
      "\"heap_used_before\":%ld,\"heap_used_after\":%ld,"
      "\"rss_kb_before\":%ld,\"rss_kb_after\":%ld,"
      "\"peak_rss_kb_before\":%ld,\"peak_rss_kb_after\":%ld,\"peak_rss_delta_kb\":%ld,"
      "\"useful_heap_bytes\":%ld,\"extra_heap_bytes\":%ld,"
      "\"static_mem_bytes\":%ld,\"total_mem_bytes\":%ld,"
      "\"pk_len\":%d,\"sk_len\":%d,\"sig_len\":%d,"
      "\"ok_keypair\":%d,\"ok_sign\":%d,\"ok_verify\":%d,\"ok\":%d"
      "}\n",
      platform, alg, iter, msg_len,
      (unsigned long long)t_keypair_us,
      (unsigned long long)t_sign_us,
      (unsigned long long)t_verify_us,
      (unsigned long long)t_total_us,
      heap_before, heap_after,
      rss_before, rss_after,
      peak_rss_before, peak_rss_after, peak_rss_delta_kb,
      useful_heap_bytes, extra_heap_bytes,
      static_mem_bytes, total_mem_bytes,
      pk_len, sk_len, sig_len,
      ok_k, ok_s, ok_v, ok_all
    );

    if(g_flush_each) fflush(f);
}


// -------- PPK2 markers (ONE window per batch) --------
static void ppk2_begin_batch(const char *op, const char *alg, const char *mode, int iters, int msg_len){
    printf("@@PPK2_BEGIN op=%s alg=%s mode=%s iters=%d msg_len=%d\n", op, alg, mode, iters, msg_len);
    fflush(stdout);
}
static void ppk2_end_batch(const char *op, const char *alg, const char *mode){
    printf("@@PPK2_END op=%s alg=%s mode=%s\n", op, alg, mode);
    fflush(stdout);
}

// ---------------- Signed message format ----------------
// [2 bytes mlen big-endian][m bytes msg][sig bytes]
static int crypto_sign_message(
    uint8_t* sm, size_t* smlen,
    const uint8_t* m, size_t mlen,
    const uint8_t* sk, OQS_SIG* algo
){
    if (!sm || !smlen || !m || !sk || !algo) return -1;

    uint8_t* signature = OQS_MEM_malloc(algo->length_signature);
    size_t signature_len = 0;
    if (!signature) return -1;

    uint8_t hdr[2] = { (uint8_t)((mlen >> 8) & 0xFF), (uint8_t)(mlen & 0xFF) };

    if (OQS_SIG_sign(algo, signature, &signature_len, m, mlen, sk) != OQS_SUCCESS) {
        OQS_MEM_secure_free(signature, algo->length_signature);
        return -1;
    }

    memcpy(sm, hdr, 2);
    memcpy(sm + 2, m, mlen);
    memcpy(sm + 2 + mlen, signature, signature_len);

    OQS_MEM_secure_free(signature, algo->length_signature);

    *smlen = 2 + mlen + signature_len;
    return 0;
}

static int crypto_open_message(
    uint8_t* m, size_t* mlen,
    const uint8_t* sm, size_t smlen,
    const uint8_t* pk, OQS_SIG* algo
){
    if (!m || !mlen || !sm || !pk || !algo) return -1;
    if (smlen < 2) return -1;

    *mlen = ((size_t)sm[0] << 8) | sm[1];
    if (2 + *mlen > smlen) return -1;

    size_t signature_len = smlen - 2 - *mlen;
    if (signature_len > algo->length_signature) return -1;

    if (OQS_SIG_verify(algo, sm + 2, *mlen, sm + 2 + *mlen, signature_len, pk) != OQS_SUCCESS) {
        return -1;
    }

    memcpy(m, sm + 2, *mlen);
    return 0;
}

// ---------------- CLI ----------------
typedef enum { OP_KEYPAIR, OP_SIGN, OP_VERIFY, OP_ALL } op_t;
typedef enum { BENCH_MODE_RUN, BENCH_MODE_IDLE } bench_mode_t;

typedef struct {
    int iters;
    int warmup;
    int msg_len;
    const char *alg;
    op_t op;
    int include_rsa;
    bench_mode_t mode;
    int flush_each;
} options_t;

static void opts_default(options_t *o){
    o->iters = 50;
    o->warmup = 5;
    o->msg_len = 32;
    o->alg = "all";
    o->op = OP_ALL;
    o->include_rsa = 0;
    o->mode = BENCH_MODE_RUN;
    o->flush_each = 0;
}

static const char* op_name(op_t op){
    switch(op){
        case OP_KEYPAIR: return "keypair";
        case OP_SIGN:    return "sign";
        case OP_VERIFY:  return "verify";
        case OP_ALL:     return "all";
        default:         return "all";
    }
}

static const char* mode_name(bench_mode_t m){
    return (m == BENCH_MODE_IDLE) ? "idle" : "run";
}

static op_t parse_op(const char *s){
    if(!s) return OP_ALL;
    if(strcmp(s,"keypair")==0) return OP_KEYPAIR;
    if(strcmp(s,"sign")==0)    return OP_SIGN;
    if(strcmp(s,"verify")==0)  return OP_VERIFY;
    if(strcmp(s,"all")==0)     return OP_ALL;
    return OP_ALL;
}

// ---- list-algs ----
static void list_algs(void){
    printf("=== liboqs signature algorithms available ===\n");
    printf("OQS_SIG_algs_length = %zu\n", (size_t)OQS_SIG_algs_length);

    for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
        const char *id = OQS_SIG_alg_identifier(i);
        if (!id) continue;
        int enabled = OQS_SIG_alg_is_enabled(id);
        printf("%s%s\n", id, enabled ? "" : " (disabled)");
    }
    fflush(stdout);
}

static void usage(const char *p){
    fprintf(stderr,
      "Usage: %s --op keypair|sign|verify|all --alg <ALG|all> [--iters N] [--warmup N] [--msg-len N]\n"
      "          [--mode run|idle] [--flush-each] [--rsa] [--list-algs]\n"
      "Output: results/local/{keypair,sign,verify,whole}/ALG.jsonl\n"
      "PPK2 markers: @@PPK2_BEGIN/END (one per batch)\n",
      p);
}

static int parse_args(int argc, char **argv, options_t *o){
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--iters")==0 && i+1<argc) o->iters = atoi(argv[++i]);
        else if(strcmp(argv[i],"--warmup")==0 && i+1<argc) o->warmup = atoi(argv[++i]);
        else if(strcmp(argv[i],"--msg-len")==0 && i+1<argc) o->msg_len = atoi(argv[++i]);
        else if(strcmp(argv[i],"--alg")==0 && i+1<argc) o->alg = argv[++i];
        else if(strcmp(argv[i],"--op")==0 && i+1<argc) o->op = parse_op(argv[++i]);
        else if(strcmp(argv[i],"--mode")==0 && i+1<argc){
            const char *m = argv[++i];
            if(strcmp(m,"run")==0) o->mode = BENCH_MODE_RUN;
            else if(strcmp(m,"idle")==0) o->mode = BENCH_MODE_IDLE;
            else { fprintf(stderr,"--mode must be run|idle\n"); return -1; }
        }
        else if(strcmp(argv[i],"--flush-each")==0) o->flush_each = 1;
        else if(strcmp(argv[i],"--rsa")==0) o->include_rsa = 1;

        else if(strcmp(argv[i],"--list-algs")==0){
            OQS_init();
            list_algs();
            OQS_destroy();
            exit(0);
        }

        else if(strcmp(argv[i],"--help")==0 || strcmp(argv[i],"-h")==0){
            usage(argv[0]);
            exit(0);
        }
        else {
            fprintf(stderr,"Unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }
    if(o->iters<1) o->iters=1;
    if(o->warmup<0) o->warmup=0;
    if(o->msg_len<1) o->msg_len=1;
    return 0;
}

// ---------------- Message generator ----------------
static uint8_t* make_msg(size_t n){
    uint8_t *m = malloc(n);
    if(!m) return NULL;
    for(size_t i=0;i<n;i++) m[i] = (uint8_t)(i & 0xFF);
    return m;
}

static int alg_selected(const options_t *o, const char *alg){
    if(strcmp(o->alg, "rsa") == 0) return 0;   // on exclut les PQC si rsa demandé
    if(strcmp(o->alg, "pqc") == 0) return 1;
    return (strcmp(o->alg, "all") == 0) || (strcmp(o->alg, alg) == 0);
}
// ---------------- IDLE helpers (match allocations + memory work) ----------------
static void idle_fill_keypair(uint8_t *pk, size_t pklen, uint8_t *sk, size_t sklen){
    for(size_t i=0;i<pklen;i++) pk[i] = (uint8_t)(0x11 ^ (i & 0xFF));
    for(size_t i=0;i<sklen;i++) sk[i] = (uint8_t)(0x22 ^ (i & 0xFF));
}

static void idle_make_signed_message(uint8_t *sm, size_t *smlen,
                                     const uint8_t *msg, size_t msg_len,
                                     size_t sig_len){
    uint8_t hdr[2] = { (uint8_t)((msg_len >> 8) & 0xFF), (uint8_t)(msg_len & 0xFF) };
    memcpy(sm, hdr, 2);
    memcpy(sm + 2, msg, msg_len);
    memset(sm + 2 + msg_len, 0xA5, sig_len);
    *smlen = 2 + msg_len + sig_len;
}

static int idle_open_message(uint8_t *out, size_t *outlen, const uint8_t *sm, size_t smlen){
    if(smlen < 2) return 0;
    size_t mlen = ((size_t)sm[0] << 8) | sm[1];
    if(2 + mlen > smlen) return 0;
    memcpy(out, sm + 2, mlen);
    *outlen = mlen;
    return 1;
}

// ---------------- Bench prototypes ----------------
static void bench_keypair_local(const char *alg, const options_t *opt);
static void bench_sign_local(const char *alg, const options_t *opt, const uint8_t *msg, size_t msg_len);
static void bench_verify_local(const char *alg, const options_t *opt, const uint8_t *msg, size_t msg_len);
static void bench_all_local(const char *alg, const options_t *opt, const uint8_t *msg, size_t msg_len);

// ---------------- LOCAL BENCH OPS ----------------

static void bench_keypair_local(const char *alg, const options_t *opt){
    OQS_SIG *A = OQS_SIG_new(alg);
    if(!A){
        fprintf(stderr, "OQS_SIG_new failed: %s\n", alg);
        return;
    }

    FILE *f_key = open_result_file("results/local", "keypair", alg);
    if(!f_key){
        OQS_SIG_free(A);
        return;
    }

    // Warmup
    for(int w = 0; w < opt->warmup; w++){
        uint8_t *pk = OQS_MEM_malloc(A->length_public_key);
        uint8_t *sk = OQS_MEM_malloc(A->length_secret_key);

        if(pk && sk){
            if(opt->mode == BENCH_MODE_RUN){
                (void)OQS_SIG_keypair(A, pk, sk);
            } else {
                idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
            }
        }

        if(pk) OQS_MEM_secure_free(pk, A->length_public_key);
        if(sk) OQS_MEM_secure_free(sk, A->length_secret_key);
    }

    ppk2_begin_batch("keypair", alg, mode_name(opt->mode), opt->iters, 0);

    for(int it = 0; it < opt->iters; it++){
        uint8_t *pk = OQS_MEM_malloc(A->length_public_key);
        uint8_t *sk = OQS_MEM_malloc(A->length_secret_key);

        if(!pk || !sk){
            if(pk) OQS_MEM_secure_free(pk, A->length_public_key);
            if(sk) OQS_MEM_secure_free(sk, A->length_secret_key);

            emit_jsonl(
                f_key,
                "rpi-local", alg, "keypair", it, 0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0, 0, 0,
                (int)A->length_public_key, (int)A->length_secret_key, -1,
                0
            );
            continue;
        }

        long h0  = heap_used_bytes();
        long r0  = read_rss_kb();
        long pr0 = read_peak_rss_kb();
        uint64_t t0 = now_us();

        int ok_k = 0;
        if(opt->mode == BENCH_MODE_RUN){
            ok_k = (OQS_SIG_keypair(A, pk, sk) == OQS_SUCCESS);
        } else {
            idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
            ok_k = 1;
        }

        uint64_t t1 = now_us();
        long h1  = heap_used_bytes();
        long r1  = read_rss_kb();
        long pr1 = read_peak_rss_kb();

        // Décomposition mémoire
        long useful_heap_bytes = (long)A->length_public_key + (long)A->length_secret_key;

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(h0 >= 0 && h1 >= 0){
            heap_delta = h1 - h0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0){
            extra_heap_bytes = 0;
        }

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl(
            f_key,
            "rpi-local", alg, "keypair", it, 0, (t1 - t0),
            h0, h1,
            r0, r1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)A->length_public_key, (int)A->length_secret_key, -1,
            ok_k
        );

        OQS_MEM_secure_free(pk, A->length_public_key);
        OQS_MEM_secure_free(sk, A->length_secret_key);
    }

    ppk2_end_batch("keypair", alg, mode_name(opt->mode));

    fflush(f_key);
    fclose(f_key);
    OQS_SIG_free(A);
}

static void bench_sign_local(const char *alg, const options_t *opt, const uint8_t *msg, size_t msg_len){
    OQS_SIG *A = OQS_SIG_new(alg);
    if(!A){
        fprintf(stderr, "OQS_SIG_new failed: %s\n", alg);
        return;
    }

    FILE *f_sign = open_result_file("results/local", "sign", alg);
    if(!f_sign){
        OQS_SIG_free(A);
        return;
    }

    uint8_t *pk = OQS_MEM_malloc(A->length_public_key);
    uint8_t *sk = OQS_MEM_malloc(A->length_secret_key);
    if(!pk || !sk){
        if(pk) OQS_MEM_secure_free(pk, A->length_public_key);
        if(sk) OQS_MEM_secure_free(sk, A->length_secret_key);
        fclose(f_sign);
        OQS_SIG_free(A);
        return;
    }

    for(int w = 0; w < opt->warmup; w++){
        uint8_t *sm = malloc(2 + msg_len + A->length_signature);
        size_t smlen = 0;

        if(sm){
            if(opt->mode == BENCH_MODE_RUN){
                (void)OQS_SIG_keypair(A, pk, sk);
                (void)crypto_sign_message(sm, &smlen, msg, msg_len, sk, A);
            } else {
                idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
                idle_make_signed_message(sm, &smlen, msg, msg_len, A->length_signature);
            }
        }

        free(sm);
    }

    int ok_k = 0;
    if(opt->mode == BENCH_MODE_RUN){
        ok_k = (OQS_SIG_keypair(A, pk, sk) == OQS_SUCCESS);
    } else {
        idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
        ok_k = 1;
    }

    ppk2_begin_batch("sign", alg, mode_name(opt->mode), opt->iters, (int)msg_len);

    for(int it = 0; it < opt->iters; it++){
        uint8_t *sm = malloc(2 + msg_len + A->length_signature);
        size_t smlen = 0;

        if(!sm){
            emit_jsonl(
                f_sign,
                "rpi-local", alg, "sign", it, (int)msg_len, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0, 0, 0,
                (int)A->length_public_key, (int)A->length_secret_key, -1,
                0
            );
            continue;
        }

        long h0  = heap_used_bytes();
        long r0  = read_rss_kb();
        long pr0 = read_peak_rss_kb();
        uint64_t t0 = now_us();

        int ok_s = 0;
        if(opt->mode == BENCH_MODE_RUN){
            ok_s = ok_k && (crypto_sign_message(sm, &smlen, msg, msg_len, sk, A) == 0);
        } else {
            if(ok_k){
                idle_make_signed_message(sm, &smlen, msg, msg_len, A->length_signature);
                ok_s = 1;
            }
        }

        uint64_t t1 = now_us();
        long h1  = heap_used_bytes();
        long r1  = read_rss_kb();
        long pr1 = read_peak_rss_kb();

        int sig_len_real = ok_s ? (int)(smlen - 2 - (int)msg_len) : -1;

        long useful_heap_bytes =
            (long)A->length_secret_key +
            (long)(2 + msg_len + A->length_signature);

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(h0 >= 0 && h1 >= 0){
            heap_delta = h1 - h0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0){
            extra_heap_bytes = 0;
        }

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl(
            f_sign,
            "rpi-local", alg, "sign", it, (int)msg_len, (t1 - t0),
            h0, h1,
            r0, r1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)A->length_public_key, (int)A->length_secret_key, sig_len_real,
            ok_s
        );

        free(sm);
    }

    ppk2_end_batch("sign", alg, mode_name(opt->mode));

    fflush(f_sign);
    fclose(f_sign);

    OQS_MEM_secure_free(pk, A->length_public_key);
    OQS_MEM_secure_free(sk, A->length_secret_key);
    OQS_SIG_free(A);
}

static void bench_verify_local(const char *alg, const options_t *opt, const uint8_t *msg, size_t msg_len){
    OQS_SIG *A = OQS_SIG_new(alg);
    if(!A){
        fprintf(stderr, "OQS_SIG_new failed: %s\n", alg);
        return;
    }

    FILE *f_ver = open_result_file("results/local", "verify", alg);
    if(!f_ver){
        OQS_SIG_free(A);
        return;
    }

    uint8_t *pk = OQS_MEM_malloc(A->length_public_key);
    uint8_t *sk = OQS_MEM_malloc(A->length_secret_key);
    if(!pk || !sk){
        if(pk) OQS_MEM_secure_free(pk, A->length_public_key);
        if(sk) OQS_MEM_secure_free(sk, A->length_secret_key);
        fclose(f_ver);
        OQS_SIG_free(A);
        return;
    }

    // ---------------- Warmup (full sequence) ----------------
    for(int w = 0; w < opt->warmup; w++){
        uint8_t *smw  = malloc(2 + msg_len + A->length_signature);
        uint8_t *outw = malloc(msg_len);
        size_t smlenw = 0, outlenw = 0;

        if(smw && outw){
            if(opt->mode == BENCH_MODE_RUN){
                (void)OQS_SIG_keypair(A, pk, sk);
                (void)crypto_sign_message(smw, &smlenw, msg, msg_len, sk, A);
                (void)crypto_open_message(outw, &outlenw, smw, smlenw, pk, A);
            } else {
                idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
                idle_make_signed_message(smw, &smlenw, msg, msg_len, A->length_signature);
                (void)idle_open_message(outw, &outlenw, smw, smlenw);
            }
        }

        free(smw);
        free(outw);
    }

    // ---------------- Prepare ONE valid signed message for verify loop ----------------
    uint8_t *sm = malloc(2 + msg_len + A->length_signature);
    size_t smlen = 0;
    int ok_prep = 0;

    if(sm){
        if(opt->mode == BENCH_MODE_RUN){
            ok_prep =
                (OQS_SIG_keypair(A, pk, sk) == OQS_SUCCESS) &&
                (crypto_sign_message(sm, &smlen, msg, msg_len, sk, A) == 0);
        } else {
            idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
            idle_make_signed_message(sm, &smlen, msg, msg_len, A->length_signature);
            ok_prep = 1;
        }
    }

    const int sig_len_real = ok_prep ? (int)(smlen - 2 - (int)msg_len) : -1;

    ppk2_begin_batch("verify", alg, mode_name(opt->mode), opt->iters, (int)msg_len);

    // ---------------- Verify bench loop ----------------
    for(int it = 0; it < opt->iters; it++){
        uint8_t *out = malloc(msg_len);
        size_t outlen = 0;

        if(!out || !sm || !ok_prep){
            free(out);

            emit_jsonl(
                f_ver,
                "rpi-local", alg, "verify", it, (int)msg_len, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0, 0, 0,
                (int)A->length_public_key, (int)A->length_secret_key, sig_len_real,
                0
            );
            continue;
        }

        long h0  = heap_used_bytes();
        long r0  = read_rss_kb();
        long pr0 = read_peak_rss_kb();
        uint64_t t0 = now_us();

        int ok_v = 0;
        if(opt->mode == BENCH_MODE_RUN){
            ok_v = (crypto_open_message(out, &outlen, sm, smlen, pk, A) == 0);
        } else {
            ok_v = idle_open_message(out, &outlen, sm, smlen);
        }

        uint64_t t1 = now_us();
        long h1  = heap_used_bytes();
        long r1  = read_rss_kb();
        long pr1 = read_peak_rss_kb();

        long useful_heap_bytes =
            (long)A->length_public_key +
            (long)(2 + msg_len + A->length_signature) +
            (long)msg_len;

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(h0 >= 0 && h1 >= 0){
            heap_delta = h1 - h0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0){
            extra_heap_bytes = 0;
        }

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl(
            f_ver,
            "rpi-local", alg, "verify", it, (int)msg_len, (t1 - t0),
            h0, h1,
            r0, r1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)A->length_public_key, (int)A->length_secret_key, sig_len_real,
            ok_v
        );

        free(out);
    }

    ppk2_end_batch("verify", alg, mode_name(opt->mode));

    fflush(f_ver);
    fclose(f_ver);

    free(sm);
    OQS_MEM_secure_free(pk, A->length_public_key);
    OQS_MEM_secure_free(sk, A->length_secret_key);
    OQS_SIG_free(A);
}

static void bench_all_local(const char *alg, const options_t *opt, const uint8_t *msg, size_t msg_len){
    OQS_SIG *A = OQS_SIG_new(alg);
    if(!A){
        fprintf(stderr, "OQS_SIG_new failed: %s\n", alg);
        return;
    }

    FILE *f_whole = open_result_file("results/local", "whole", alg);
    if(!f_whole){
        OQS_SIG_free(A);
        return;
    }

    // Warmup: séquence complète (hors mesures)
    for(int w = 0; w < opt->warmup; w++){
        uint8_t *pk  = OQS_MEM_malloc(A->length_public_key);
        uint8_t *sk  = OQS_MEM_malloc(A->length_secret_key);
        uint8_t *sm  = malloc(2 + msg_len + A->length_signature);
        uint8_t *out = malloc(msg_len);
        size_t smlen = 0, outlen = 0;

        if(pk && sk && sm && out){
            if(opt->mode == BENCH_MODE_RUN){
                (void)OQS_SIG_keypair(A, pk, sk);
                (void)crypto_sign_message(sm, &smlen, msg, msg_len, sk, A);
                (void)crypto_open_message(out, &outlen, sm, smlen, pk, A);
            } else {
                idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
                idle_make_signed_message(sm, &smlen, msg, msg_len, A->length_signature);
                (void)idle_open_message(out, &outlen, sm, smlen);
            }
        }

        if(pk) OQS_MEM_secure_free(pk, A->length_public_key);
        if(sk) OQS_MEM_secure_free(sk, A->length_secret_key);
        free(sm);
        free(out);
    }

    ppk2_begin_batch("whole", alg, mode_name(opt->mode), opt->iters, (int)msg_len);

    for(int it = 0; it < opt->iters; it++){
        long heap0 = heap_used_bytes();
        long rss0  = read_rss_kb();
        long pr0   = read_peak_rss_kb();
        uint64_t t_total0 = now_us();

        uint8_t *pk  = OQS_MEM_malloc(A->length_public_key);
        uint8_t *sk  = OQS_MEM_malloc(A->length_secret_key);
        uint8_t *sm  = malloc(2 + msg_len + A->length_signature);
        uint8_t *out = malloc(msg_len);

        int ok_k = 0, ok_s = 0, ok_v = 0, ok_all = 0;
        uint64_t t_k = 0, t_s = 0, t_v = 0;
        size_t smlen = 0, outlen = 0;

        if(!pk || !sk || !sm || !out){
            if(pk) OQS_MEM_secure_free(pk, A->length_public_key);
            if(sk) OQS_MEM_secure_free(sk, A->length_secret_key);
            free(sm);
            free(out);

            uint64_t t_total1 = now_us();
            long heap1 = heap_used_bytes();
            long rss1  = read_rss_kb();
            long pr1   = read_peak_rss_kb();

            emit_jsonl_whole(
                f_whole,
                "rpi-local", alg, it, (int)msg_len,
                0, 0, 0, (t_total1 - t_total0),
                heap0, heap1,
                rss0, rss1,
                pr0, pr1,
                0, 0, 0, 0,
                (int)A->length_public_key, (int)A->length_secret_key, -1,
                0, 0, 0, 0
            );
            continue;
        }

        // --- keypair ---
        uint64_t t0 = now_us();
        if(opt->mode == BENCH_MODE_RUN){
            ok_k = (OQS_SIG_keypair(A, pk, sk) == OQS_SUCCESS);
        } else {
            idle_fill_keypair(pk, A->length_public_key, sk, A->length_secret_key);
            ok_k = 1;
        }
        uint64_t t1 = now_us();
        t_k = (t1 - t0);

        // --- sign ---
        t0 = now_us();
        if(opt->mode == BENCH_MODE_RUN){
            ok_s = ok_k && (crypto_sign_message(sm, &smlen, msg, msg_len, sk, A) == 0);
        } else {
            if(ok_k){
                idle_make_signed_message(sm, &smlen, msg, msg_len, A->length_signature);
                ok_s = 1;
            }
        }
        t1 = now_us();
        t_s = (t1 - t0);

        int sig_len_real = ok_s ? (int)(smlen - 2 - (int)msg_len) : -1;

        // --- verify ---
        t0 = now_us();
        if(opt->mode == BENCH_MODE_RUN){
            ok_v = ok_s && (crypto_open_message(out, &outlen, sm, smlen, pk, A) == 0);
        } else {
            ok_v = ok_s && idle_open_message(out, &outlen, sm, smlen);
        }
        t1 = now_us();
        t_v = (t1 - t0);

        uint64_t t_total1 = now_us();
        long heap1 = heap_used_bytes();
        long rss1  = read_rss_kb();
        long pr1   = read_peak_rss_kb();

        ok_all = ok_k && ok_s && ok_v &&
                 (outlen == msg_len) &&
                 (memcmp(out, msg, msg_len) == 0);

        long useful_heap_bytes =
            (long)A->length_public_key +
            (long)A->length_secret_key +
            (long)(2 + msg_len + A->length_signature) +
            (long)msg_len;

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(heap0 >= 0 && heap1 >= 0){
            heap_delta = heap1 - heap0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0){
            extra_heap_bytes = 0;
        }

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl_whole(
            f_whole,
            "rpi-local", alg, it, (int)msg_len,
            t_k, t_s, t_v, (t_total1 - t_total0),
            heap0, heap1,
            rss0, rss1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)A->length_public_key, (int)A->length_secret_key, sig_len_real,
            ok_k, ok_s, ok_v, ok_all
        );

        OQS_MEM_secure_free(pk, A->length_public_key);
        OQS_MEM_secure_free(sk, A->length_secret_key);
        free(sm);
        free(out);
    }

    ppk2_end_batch("whole", alg, mode_name(opt->mode));

    fflush(f_whole);
    fclose(f_whole);
    OQS_SIG_free(A);
}


#ifdef USE_OPENSSL
static void bench_rsa_keypair_local(const options_t *opt){
    FILE *f_key = open_result_file("results/local", "keypair", RSA_ALG_NAME);
    if(!f_key) return;

    /* Warmup */
    for(int w = 0; w < opt->warmup; w++){
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;

        if(opt->mode == BENCH_MODE_RUN){
            (void)rsa_generate_keypair(&pk, &pk_len, &sk, &sk_len);
        } else {
            pk_len = 451;   /* approx PEM public RSA-2048 */
            sk_len = 1700;  /* approx PEM private RSA-2048 */
            pk = (uint8_t*)malloc(pk_len);
            sk = (uint8_t*)malloc(sk_len);
            if(pk && sk){
                memset(pk, 0x11, pk_len);
                memset(sk, 0x22, sk_len);
            }
        }

        free(pk);
        free(sk);
    }

    ppk2_begin_batch("keypair", RSA_ALG_NAME, mode_name(opt->mode), opt->iters, 0);

    for(int it = 0; it < opt->iters; it++){
        uint8_t *pk = NULL, *sk = NULL;
        size_t pk_len = 0, sk_len = 0;

        long h0  = heap_used_bytes();
        long r0  = read_rss_kb();
        long pr0 = read_peak_rss_kb();
        uint64_t t0 = now_us();

        int ok_k = 0;

        if(opt->mode == BENCH_MODE_RUN){
            ok_k = (rsa_generate_keypair(&pk, &pk_len, &sk, &sk_len) == 0);
        } else {
            pk_len = 451;
            sk_len = 1700;
            pk = (uint8_t*)malloc(pk_len);
            sk = (uint8_t*)malloc(sk_len);
            if(pk && sk){
                memset(pk, 0x11, pk_len);
                memset(sk, 0x22, sk_len);
                ok_k = 1;
            }
        }

        uint64_t t1 = now_us();
        long h1  = heap_used_bytes();
        long r1  = read_rss_kb();
        long pr1 = read_peak_rss_kb();

        long useful_heap_bytes = (long)pk_len + (long)sk_len;

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(h0 >= 0 && h1 >= 0){
            heap_delta = h1 - h0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0) extra_heap_bytes = 0;

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl(
            f_key,
            "rpi-local", RSA_ALG_NAME, "keypair", it, 0, (t1 - t0),
            h0, h1,
            r0, r1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)pk_len, (int)sk_len, -1,
            ok_k
        );

        free(pk);
        free(sk);
    }

    ppk2_end_batch("keypair", RSA_ALG_NAME, mode_name(opt->mode));

    fflush(f_key);
    fclose(f_key);
}
#endif


#ifdef USE_OPENSSL
static int rsa_sign_message(const uint8_t *sk_pem, size_t sk_len,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t **sig, size_t *sig_len)
{
    int ret = -1;
    BIO *bio_priv = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    size_t req = 0;

    if(!sk_pem || !msg || !sig || !sig_len) return -1;

    *sig = NULL;
    *sig_len = 0;

    bio_priv = BIO_new_mem_buf((const void*)sk_pem, (int)sk_len);
    if(!bio_priv) goto cleanup;

    pkey = PEM_read_bio_PrivateKey(bio_priv, NULL, NULL, NULL);
    if(!pkey) goto cleanup;

    mdctx = EVP_MD_CTX_new();
    if(!mdctx) goto cleanup;

    if(EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) goto cleanup;
    if(EVP_DigestSignUpdate(mdctx, msg, msg_len) <= 0) goto cleanup;

    if(EVP_DigestSignFinal(mdctx, NULL, &req) <= 0) goto cleanup;

    *sig = (uint8_t*)malloc(req);
    if(!*sig) goto cleanup;

    if(EVP_DigestSignFinal(mdctx, *sig, &req) <= 0) goto cleanup;

    *sig_len = req;
    ret = 0;

cleanup:
    if(ret != 0){
        free(*sig);
        *sig = NULL;
        *sig_len = 0;
    }
    if(mdctx) EVP_MD_CTX_free(mdctx);
    if(pkey) EVP_PKEY_free(pkey);
    if(bio_priv) BIO_free(bio_priv);
    return ret;
}
#endif


#ifdef USE_OPENSSL
static void bench_rsa_sign_local(const options_t *opt, const uint8_t *msg, size_t msg_len){
    FILE *f_sign = open_result_file("results/local", "sign", RSA_ALG_NAME);
    if(!f_sign) return;

    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    size_t pk_len = 0, sk_len = 0;

    /* Warmup */
    for(int w = 0; w < opt->warmup; w++){
        uint8_t *wpk = NULL, *wsk = NULL, *wsig = NULL;
        size_t wpk_len = 0, wsk_len = 0, wsig_len = 0;

        if(opt->mode == BENCH_MODE_RUN){
            if(rsa_generate_keypair(&wpk, &wpk_len, &wsk, &wsk_len) == 0){
                (void)rsa_sign_message(wsk, wsk_len, msg, msg_len, &wsig, &wsig_len);
            }
        } else {
            wsk_len = 1700;
            wsig_len = 256;
            wsk = (uint8_t*)malloc(wsk_len);
            wsig = (uint8_t*)malloc(wsig_len);
            if(wsk && wsig){
                memset(wsk, 0x22, wsk_len);
                memset(wsig, 0x5A, wsig_len);
            }
        }

        free(wpk);
        free(wsk);
        free(wsig);
    }

    /* Keypair fixe hors fenêtre */
    int ok_k = 0;
    if(opt->mode == BENCH_MODE_RUN){
        ok_k = (rsa_generate_keypair(&pk, &pk_len, &sk, &sk_len) == 0);
    } else {
        pk_len = 451;
        sk_len = 1700;
        pk = (uint8_t*)malloc(pk_len);
        sk = (uint8_t*)malloc(sk_len);
        if(pk && sk){
            memset(pk, 0x11, pk_len);
            memset(sk, 0x22, sk_len);
            ok_k = 1;
        }
    }

    ppk2_begin_batch("sign", RSA_ALG_NAME, mode_name(opt->mode), opt->iters, (int)msg_len);

    for(int it = 0; it < opt->iters; it++){
        uint8_t *sig = NULL;
        size_t sig_len = 0;

        long h0  = heap_used_bytes();
        long r0  = read_rss_kb();
        long pr0 = read_peak_rss_kb();
        uint64_t t0 = now_us();

        int ok_s = 0;
        if(opt->mode == BENCH_MODE_RUN){
            if(ok_k){
                ok_s = (rsa_sign_message(sk, sk_len, msg, msg_len, &sig, &sig_len) == 0);
            }
        } else {
            sig_len = 256;
            sig = (uint8_t*)malloc(sig_len);
            if(sig){
                memset(sig, 0x5A, sig_len);
                ok_s = ok_k;
            }
        }

        uint64_t t1 = now_us();
        long h1  = heap_used_bytes();
        long r1  = read_rss_kb();
        long pr1 = read_peak_rss_kb();

        long useful_heap_bytes =
            (long)sk_len +
            (long)sig_len;

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(h0 >= 0 && h1 >= 0){
            heap_delta = h1 - h0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0) extra_heap_bytes = 0;

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl(
            f_sign,
            "rpi-local", RSA_ALG_NAME, "sign", it, (int)msg_len, (t1 - t0),
            h0, h1,
            r0, r1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)pk_len, (int)sk_len, (int)sig_len,
            ok_s
        );

        free(sig);
    }

    ppk2_end_batch("sign", RSA_ALG_NAME, mode_name(opt->mode));

    fflush(f_sign);
    fclose(f_sign);

    free(pk);
    free(sk);
}
#endif


#ifdef USE_OPENSSL
static int rsa_verify_message(const uint8_t *pk_pem, size_t pk_len,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len)
{
    int ret = -1;
    BIO *bio_pub = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if(!pk_pem || !msg || !sig) return -1;

    bio_pub = BIO_new_mem_buf((const void*)pk_pem, (int)pk_len);
    if(!bio_pub) goto cleanup;

    pkey = PEM_read_bio_PUBKEY(bio_pub, NULL, NULL, NULL);
    if(!pkey) goto cleanup;

    mdctx = EVP_MD_CTX_new();
    if(!mdctx) goto cleanup;

    if(EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) goto cleanup;
    if(EVP_DigestVerifyUpdate(mdctx, msg, msg_len) <= 0) goto cleanup;

    ret = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    ret = (ret == 1) ? 0 : -1;

cleanup:
    if(mdctx) EVP_MD_CTX_free(mdctx);
    if(pkey) EVP_PKEY_free(pkey);
    if(bio_pub) BIO_free(bio_pub);
    return ret;
}
#endif


#ifdef USE_OPENSSL
static void bench_rsa_verify_local(const options_t *opt, const uint8_t *msg, size_t msg_len){
    FILE *f_ver = open_result_file("results/local", "verify", RSA_ALG_NAME);
    if(!f_ver) return;

    uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
    size_t pk_len = 0, sk_len = 0, sig_len = 0;

    /* Warmup */
    for(int w = 0; w < opt->warmup; w++){
        uint8_t *wpk = NULL, *wsk = NULL, *wsig = NULL;
        size_t wpk_len = 0, wsk_len = 0, wsig_len = 0;

        if(opt->mode == BENCH_MODE_RUN){
            if(rsa_generate_keypair(&wpk, &wpk_len, &wsk, &wsk_len) == 0){
                if(rsa_sign_message(wsk, wsk_len, msg, msg_len, &wsig, &wsig_len) == 0){
                    (void)rsa_verify_message(wpk, wpk_len, msg, msg_len, wsig, wsig_len);
                }
            }
        } else {
            wpk_len = 451;
            wsig_len = 256;
            wpk = (uint8_t*)malloc(wpk_len);
            wsig = (uint8_t*)malloc(wsig_len);
            if(wpk && wsig){
                memset(wpk, 0x11, wpk_len);
                memset(wsig, 0x5A, wsig_len);
            }
        }

        free(wpk);
        free(wsk);
        free(wsig);
    }

    /* Préparation hors fenêtre */
    int ok_prep = 0;
    if(opt->mode == BENCH_MODE_RUN){
        ok_prep =
            (rsa_generate_keypair(&pk, &pk_len, &sk, &sk_len) == 0) &&
            (rsa_sign_message(sk, sk_len, msg, msg_len, &sig, &sig_len) == 0);
    } else {
        pk_len = 451;
        sk_len = 1700;
        sig_len = 256;
        pk = (uint8_t*)malloc(pk_len);
        sk = (uint8_t*)malloc(sk_len);
        sig = (uint8_t*)malloc(sig_len);
        if(pk && sk && sig){
            memset(pk, 0x11, pk_len);
            memset(sk, 0x22, sk_len);
            memset(sig, 0x5A, sig_len);
            ok_prep = 1;
        }
    }

    ppk2_begin_batch("verify", RSA_ALG_NAME, mode_name(opt->mode), opt->iters, (int)msg_len);

    for(int it = 0; it < opt->iters; it++){
        long h0  = heap_used_bytes();
        long r0  = read_rss_kb();
        long pr0 = read_peak_rss_kb();
        uint64_t t0 = now_us();

        int ok_v = 0;
        if(opt->mode == BENCH_MODE_RUN){
            if(ok_prep){
                ok_v = (rsa_verify_message(pk, pk_len, msg, msg_len, sig, sig_len) == 0);
            }
        } else {
            ok_v = ok_prep;
        }

        uint64_t t1 = now_us();
        long h1  = heap_used_bytes();
        long r1  = read_rss_kb();
        long pr1 = read_peak_rss_kb();

        long useful_heap_bytes =
            (long)pk_len +
            (long)sig_len;

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(h0 >= 0 && h1 >= 0){
            heap_delta = h1 - h0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0) extra_heap_bytes = 0;

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl(
            f_ver,
            "rpi-local", RSA_ALG_NAME, "verify", it, (int)msg_len, (t1 - t0),
            h0, h1,
            r0, r1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)pk_len, (int)sk_len, (int)sig_len,
            ok_v
        );
    }

    ppk2_end_batch("verify", RSA_ALG_NAME, mode_name(opt->mode));

    fflush(f_ver);
    fclose(f_ver);

    free(pk);
    free(sk);
    free(sig);
}
#endif


#ifdef USE_OPENSSL
static void bench_rsa_all_local(const options_t *opt, const uint8_t *msg, size_t msg_len){
    FILE *f_whole = open_result_file("results/local", "whole", RSA_ALG_NAME);
    if(!f_whole) return;

    /* Warmup */
    for(int w = 0; w < opt->warmup; w++){
        uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
        size_t pk_len = 0, sk_len = 0, sig_len = 0;

        if(opt->mode == BENCH_MODE_RUN){
            if(rsa_generate_keypair(&pk, &pk_len, &sk, &sk_len) == 0){
                if(rsa_sign_message(sk, sk_len, msg, msg_len, &sig, &sig_len) == 0){
                    (void)rsa_verify_message(pk, pk_len, msg, msg_len, sig, sig_len);
                }
            }
        } else {
            pk_len = 451;
            sk_len = 1700;
            sig_len = 256;
            pk = (uint8_t*)malloc(pk_len);
            sk = (uint8_t*)malloc(sk_len);
            sig = (uint8_t*)malloc(sig_len);
            if(pk && sk && sig){
                memset(pk, 0x11, pk_len);
                memset(sk, 0x22, sk_len);
                memset(sig, 0x5A, sig_len);
            }
        }

        free(pk);
        free(sk);
        free(sig);
    }

    ppk2_begin_batch("whole", RSA_ALG_NAME, mode_name(opt->mode), opt->iters, (int)msg_len);

    for(int it = 0; it < opt->iters; it++){
        long h0  = heap_used_bytes();
        long r0  = read_rss_kb();
        long pr0 = read_peak_rss_kb();
        uint64_t t_total0 = now_us();

        uint8_t *pk = NULL, *sk = NULL, *sig = NULL;
        size_t pk_len = 0, sk_len = 0, sig_len = 0;

        int ok_k = 0, ok_s = 0, ok_v = 0, ok_all = 0;
        uint64_t t_k = 0, t_s = 0, t_v = 0;

        uint64_t t0 = now_us();
        if(opt->mode == BENCH_MODE_RUN){
            ok_k = (rsa_generate_keypair(&pk, &pk_len, &sk, &sk_len) == 0);
        } else {
            pk_len = 451;
            sk_len = 1700;
            pk = (uint8_t*)malloc(pk_len);
            sk = (uint8_t*)malloc(sk_len);
            if(pk && sk){
                memset(pk, 0x11, pk_len);
                memset(sk, 0x22, sk_len);
                ok_k = 1;
            }
        }
        uint64_t t1 = now_us();
        t_k = t1 - t0;

        t0 = now_us();
        if(opt->mode == BENCH_MODE_RUN){
            if(ok_k){
                ok_s = (rsa_sign_message(sk, sk_len, msg, msg_len, &sig, &sig_len) == 0);
            }
        } else {
            sig_len = 256;
            sig = (uint8_t*)malloc(sig_len);
            if(sig){
                memset(sig, 0x5A, sig_len);
                ok_s = ok_k;
            }
        }
        t1 = now_us();
        t_s = t1 - t0;

        t0 = now_us();
        if(opt->mode == BENCH_MODE_RUN){
            if(ok_s){
                ok_v = (rsa_verify_message(pk, pk_len, msg, msg_len, sig, sig_len) == 0);
            }
        } else {
            ok_v = ok_s;
        }
        t1 = now_us();
        t_v = t1 - t0;

        uint64_t t_total1 = now_us();
        long h1  = heap_used_bytes();
        long r1  = read_rss_kb();
        long pr1 = read_peak_rss_kb();

        ok_all = ok_k && ok_s && ok_v;

        long useful_heap_bytes =
            (long)pk_len +
            (long)sk_len +
            (long)sig_len;

        long static_mem_bytes = 0;
        if(pr0 >= 0 && pr1 >= 0 && pr1 >= pr0){
            static_mem_bytes = (pr1 - pr0) * 1024L;
        }

        long heap_delta = 0;
        if(h0 >= 0 && h1 >= 0){
            heap_delta = h1 - h0;
        }

        long extra_heap_bytes = heap_delta - useful_heap_bytes;
        if(extra_heap_bytes < 0) extra_heap_bytes = 0;

        long total_mem_bytes = useful_heap_bytes + extra_heap_bytes + static_mem_bytes;

        emit_jsonl_whole(
            f_whole,
            "rpi-local", RSA_ALG_NAME, it, (int)msg_len,
            t_k, t_s, t_v, (t_total1 - t_total0),
            h0, h1,
            r0, r1,
            pr0, pr1,
            useful_heap_bytes, extra_heap_bytes,
            static_mem_bytes, total_mem_bytes,
            (int)pk_len, (int)sk_len, (int)sig_len,
            ok_k, ok_s, ok_v, ok_all
        );

        free(pk);
        free(sk);
        free(sig);
    }

    ppk2_end_batch("whole", RSA_ALG_NAME, mode_name(opt->mode));

    fflush(f_whole);
    fclose(f_whole);
}
#endif


// ---------------- main ----------------


int main(int argc, char **argv){
    options_t opt;
    opts_default(&opt);

    if(parse_args(argc, argv, &opt) < 0) return 1;

    OQS_init();

    g_flush_each = opt.flush_each;

    // single-op outputs
    if(mkdir_p("results/local/keypair") < 0) { OQS_destroy(); return 2; }
    if(mkdir_p("results/local/sign") < 0)    { OQS_destroy(); return 2; }
    if(mkdir_p("results/local/verify") < 0)  { OQS_destroy(); return 2; }
    if(mkdir_p("results/local/whole") < 0)   { OQS_destroy(); return 2; }

    uint8_t *msg = make_msg((size_t)opt.msg_len);
    if(!msg){
        fprintf(stderr, "Cannot alloc msg\n");
        OQS_destroy();
        return 1;
    }

#ifdef USE_OPENSSL
    if (opt.include_rsa || strcmp(opt.alg, "rsa") == 0) {
        fprintf(stderr, "[LOCAL] alg=%s op=%s mode=%s iters=%d warmup=%d msg_len=%d\n",
                RSA_ALG_NAME,
                op_name(opt.op),
                mode_name(opt.mode),
                opt.iters,
                opt.warmup,
                opt.msg_len);

        if (opt.op == OP_KEYPAIR) {
            bench_rsa_keypair_local(&opt);
        } else if (opt.op == OP_SIGN) {
            bench_rsa_sign_local(&opt, msg, (size_t)opt.msg_len);
        } else if (opt.op == OP_VERIFY) {
            bench_rsa_verify_local(&opt, msg, (size_t)opt.msg_len);
        } else {
            bench_rsa_all_local(&opt, msg, (size_t)opt.msg_len);
        }

        free(msg);
        OQS_destroy();
        return 0;
    }
#endif

    for(size_t i = 0; i < num_algorithms; i++){
        const char *alg = algorithms[i];
        if(!alg_selected(&opt, alg)) continue;

        fprintf(stderr, "[LOCAL] alg=%s op=%s mode=%s iters=%d warmup=%d msg_len=%d\n",
                alg,
                op_name(opt.op),
                mode_name(opt.mode),
                opt.iters,
                opt.warmup,
                opt.msg_len);

        if(opt.op == OP_KEYPAIR) {
            bench_keypair_local(alg, &opt);
        } else if(opt.op == OP_SIGN) {
            bench_sign_local(alg, &opt, msg, (size_t)opt.msg_len);
        } else if(opt.op == OP_VERIFY) {
            bench_verify_local(alg, &opt, msg, (size_t)opt.msg_len);
        } else {
            bench_all_local(alg, &opt, msg, (size_t)opt.msg_len);
        }
    }

    free(msg);
    OQS_destroy();
    return 0;
}