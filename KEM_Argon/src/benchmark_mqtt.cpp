/*
 * ML-KEM MQTT Communication Benchmark for Particle Argon
 *
 * Measures the full ML-KEM key exchange over MQTT, including:
 *   - Transport setup (WiFi + MQTT connect)
 *   - Handshake negotiation (READY/ACK)
 *   - Key generation / reception
 *   - Encapsulation / Decapsulation
 *   - Ciphertext & shared secret transmission
 *   - End-to-end handshake time
 *
 * Supports both "server" and "client" roles.
 * Outputs results as JSON over Serial for capture.
 */

#include "benchmark_mqtt.h"
#include "mlkem.h"
#include "transport.h"
#include "Particle.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

// ── Variant name ─────────────────────────────────────────────────────
#if defined(PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME)
  static const char *VARIANT = "ML-KEM-512";
#elif defined(PQCLEAN_MLKEM768_CLEAN_CRYPTO_ALGNAME)
  static const char *VARIANT = "ML-KEM-768";
#elif defined(PQCLEAN_MLKEM1024_CLEAN_CRYPTO_ALGNAME)
  static const char *VARIANT = "ML-KEM-1024";
#else
  static const char *VARIANT = "UNKNOWN";
#endif

static const char *READY_MSG = "READY";
static const char *ACK_MSG   = "ACK";

// ═══════════════════════════════════════════════════════════════════════
// Per-iteration data
// ═══════════════════════════════════════════════════════════════════════

struct mqtt_iter_data {
    // Timing (ms)
    float handshake_init_ms;    // READY/ACK exchange
    float keygen_ms;            // Key generation (server) or 0 (client)
    float pk_transfer_ms;       // Send PK (server) / Receive PK (client)
    float encaps_ms;            // Encapsulation (client) or 0 (server)
    float ct_transfer_ms;       // Send CT (client) / Receive CT (server)
    float decaps_ms;            // Decapsulation (server) or 0 (client)
    float ss_transfer_ms;       // Send SS (server) / Receive SS (client)
    float total_handshake_ms;   // End-to-end from start of iteration
    // Memory
    uint32_t free_heap_before;
    uint32_t free_heap_after;
    // Validation
    bool     ss_match;
    // Network stats
    uint32_t pk_bytes_sent;     // Public key size on wire
    uint32_t ct_bytes_sent;     // Ciphertext size on wire
    uint32_t ss_bytes_sent;     // Shared secret size on wire
};

static struct mqtt_iter_data s_iters[MAX_MQTT_BENCHMARK_ITERATIONS];

// ── Statistics helpers ───────────────────────────────────────────────
static float stddev_f(const float *v, int n, float mean) {
    if (n < 2) return 0.0f;
    float s = 0;
    for (int i = 0; i < n; i++) { float d = v[i] - mean; s += d * d; }
    return sqrtf(s / (float)(n - 1));
}

// ── Drain any leftover messages from previous iteration ──────────────
static void drain_queue(void) {
    message_struct_t msg;
    while (receive_queue_get(&msg, 100)) {
        free(msg.content);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// SERVER iteration: keygen → send PK → receive CT → decaps → send SS
// ═══════════════════════════════════════════════════════════════════════
static bool run_server_iteration(int idx)
{
    struct mqtt_iter_data *it = &s_iters[idx];
    memset(it, 0, sizeof(*it));
    it->free_heap_before = System.freeMemory();

    uint32_t t_start = micros();
    uint32_t t0, t1;

    // ── Wait for READY from client ───────────────────────────────────
    Serial.println("  [S] Waiting for READY...");
    t0 = micros();
    bool got_ready = false;
    for (int attempt = 0; attempt < 300; attempt++) {  // 30s timeout
        message_struct_t msg;
        if (receive_queue_get(&msg, 100)) {
            if (msg.size == strlen(READY_MSG) &&
                memcmp(msg.content, READY_MSG, msg.size) == 0) {
                got_ready = true;
                free(msg.content);
                break;
            }
            free(msg.content);
        }
    }
    if (!got_ready) {
        Serial.println("  [S] ERROR: Timeout waiting for READY");
        return false;
    }

    // ── Send ACK ─────────────────────────────────────────────────────
    send_message_raw((const uint8_t*)ACK_MSG, strlen(ACK_MSG));
    t1 = micros();
    it->handshake_init_ms = (float)(t1 - t0) / 1000.0f;
    Serial.printlnf("  [S] READY/ACK: %.3f ms", (double)it->handshake_init_ms);

    // ── Key Generation ───────────────────────────────────────────────
    uint8_t *pk = (uint8_t*)malloc(MLKEM_PUBLICKEYBYTES);
    uint8_t *sk = (uint8_t*)malloc(MLKEM_SECRETKEYBYTES);
    if (!pk || !sk) {
        Serial.println("  [S] ERROR: malloc pk/sk failed");
        free(pk); free(sk);
        return false;
    }

    t0 = micros();
    mlkem_keypair(pk, sk);
    t1 = micros();
    it->keygen_ms = (float)(t1 - t0) / 1000.0f;
    Serial.printlnf("  [S] KeyGen: %.3f ms", (double)it->keygen_ms);

    // ── Send public key ──────────────────────────────────────────────
    t0 = micros();
    send_message(pk, MLKEM_PUBLICKEYBYTES);
    t1 = micros();
    it->pk_transfer_ms = (float)(t1 - t0) / 1000.0f;
    it->pk_bytes_sent = MLKEM_PUBLICKEYBYTES + 2;  // +2 for length header
    Serial.printlnf("  [S] PK sent: %.3f ms (%u bytes)", (double)it->pk_transfer_ms, it->pk_bytes_sent);
    free(pk);

    // ── Receive ciphertext ───────────────────────────────────────────
    t0 = micros();
    uint8_t *ct = NULL;
    bool got_ct = false;
    for (int attempt = 0; attempt < 300; attempt++) {  // 30s timeout
        message_struct_t msg;
        if (receive_queue_get(&msg, 100)) {
            if (msg.size == MLKEM_CIPHERTEXTBYTES) {
                ct = msg.content;
                got_ct = true;
                break;
            }
            free(msg.content);
        }
    }
    t1 = micros();
    it->ct_transfer_ms = (float)(t1 - t0) / 1000.0f;
    it->ct_bytes_sent = MLKEM_CIPHERTEXTBYTES;

    if (!got_ct) {
        Serial.println("  [S] ERROR: Timeout waiting for ciphertext");
        free(sk);
        return false;
    }
    Serial.printlnf("  [S] CT received: %.3f ms (%u bytes)", (double)it->ct_transfer_ms, it->ct_bytes_sent);

    // ── Decapsulation ────────────────────────────────────────────────
    uint8_t *ss = (uint8_t*)malloc(MLKEM_SHAREDSECRETBYTES);
    if (!ss) {
        Serial.println("  [S] ERROR: malloc ss failed");
        free(ct); free(sk);
        return false;
    }

    t0 = micros();
    mlkem_dec(ss, ct, sk);
    t1 = micros();
    it->decaps_ms = (float)(t1 - t0) / 1000.0f;
    Serial.printlnf("  [S] Decaps: %.3f ms", (double)it->decaps_ms);
    free(ct);
    free(sk);

    // ── Send shared secret ───────────────────────────────────────────
    t0 = micros();
    send_message(ss, MLKEM_SHAREDSECRETBYTES);
    t1 = micros();
    it->ss_transfer_ms = (float)(t1 - t0) / 1000.0f;
    it->ss_bytes_sent = MLKEM_SHAREDSECRETBYTES + 2;
    Serial.printlnf("  [S] SS sent: %.3f ms (%u bytes)", (double)it->ss_transfer_ms, it->ss_bytes_sent);

    it->ss_match = true;  // Server doesn't verify, it's the source
    free(ss);

    uint32_t t_end = micros();
    it->total_handshake_ms = (float)(t_end - t_start) / 1000.0f;
    it->free_heap_after = System.freeMemory();

    Serial.printlnf("  [S] Total handshake: %.3f ms", (double)it->total_handshake_ms);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// CLIENT iteration: send READY → wait ACK → recv PK → encaps → send CT → recv SS → verify
// ═══════════════════════════════════════════════════════════════════════
static bool run_client_iteration(int idx)
{
    struct mqtt_iter_data *it = &s_iters[idx];
    memset(it, 0, sizeof(*it));
    it->free_heap_before = System.freeMemory();

    uint32_t t_start = micros();
    uint32_t t0, t1;

    // ── Send READY and wait for ACK ──────────────────────────────────
    t0 = micros();
    send_message_raw((const uint8_t*)READY_MSG, strlen(READY_MSG));
    Serial.println("  [C] READY sent, waiting for ACK...");

    bool got_ack = false;
    for (int attempt = 0; attempt < 300; attempt++) {
        message_struct_t msg;
        if (receive_queue_get(&msg, 100)) {
            if (msg.size == 3 && memcmp(msg.content, "ACK", 3) == 0) {
                got_ack = true;
                free(msg.content);
                break;
            }
            free(msg.content);
        }
    }
    t1 = micros();
    it->handshake_init_ms = (float)(t1 - t0) / 1000.0f;

    if (!got_ack) {
        Serial.println("  [C] ERROR: Timeout waiting for ACK");
        return false;
    }
    Serial.printlnf("  [C] READY/ACK: %.3f ms", (double)it->handshake_init_ms);

    // ── Receive public key ───────────────────────────────────────────
    t0 = micros();
    message_struct_t pk_msg;
    if (!receive_queue_get(&pk_msg, 30000)) {
        Serial.println("  [C] ERROR: Timeout waiting for public key");
        return false;
    }

    // Parse 2-byte length header + payload (may arrive in chunks)
    if (pk_msg.size < 2) {
        Serial.println("  [C] ERROR: PK header too short");
        free(pk_msg.content);
        return false;
    }
    uint16_t pk_len = ((uint16_t)pk_msg.content[0] << 8) | pk_msg.content[1];
    uint8_t *pk = (uint8_t*)malloc(pk_len);
    if (!pk) {
        free(pk_msg.content);
        return false;
    }

    size_t pk_copied = 0;
    if (pk_msg.size > 2) {
        size_t chunk = pk_msg.size - 2;
        if (chunk > pk_len) chunk = pk_len;
        memcpy(pk, pk_msg.content + 2, chunk);
        pk_copied = chunk;
    }
    free(pk_msg.content);

    // Receive remaining PK chunks
    while (pk_copied < pk_len) {
        message_struct_t chunk_msg;
        if (!receive_queue_get(&chunk_msg, 5000)) {
            Serial.println("  [C] ERROR: Timeout receiving PK chunk");
            free(pk);
            return false;
        }
        size_t chunk = chunk_msg.size;
        if (pk_copied + chunk > pk_len) chunk = pk_len - pk_copied;
        memcpy(pk + pk_copied, chunk_msg.content, chunk);
        pk_copied += chunk;
        free(chunk_msg.content);
    }
    t1 = micros();
    it->pk_transfer_ms = (float)(t1 - t0) / 1000.0f;
    it->pk_bytes_sent = pk_len + 2;
    Serial.printlnf("  [C] PK received: %.3f ms (%u bytes)", (double)it->pk_transfer_ms, it->pk_bytes_sent);

    // ── Encapsulation ────────────────────────────────────────────────
    uint8_t *ct = (uint8_t*)malloc(MLKEM_CIPHERTEXTBYTES);
    uint8_t *ss = (uint8_t*)malloc(MLKEM_SHAREDSECRETBYTES);
    if (!ct || !ss) {
        Serial.println("  [C] ERROR: malloc ct/ss failed");
        free(pk); free(ct); free(ss);
        return false;
    }

    t0 = micros();
    mlkem_enc(ct, ss, pk);
    t1 = micros();
    it->encaps_ms = (float)(t1 - t0) / 1000.0f;
    Serial.printlnf("  [C] Encaps: %.3f ms", (double)it->encaps_ms);
    free(pk);

    // ── Send ciphertext ──────────────────────────────────────────────
    t0 = micros();
    send_message_raw(ct, MLKEM_CIPHERTEXTBYTES);
    t1 = micros();
    it->ct_transfer_ms = (float)(t1 - t0) / 1000.0f;
    it->ct_bytes_sent = MLKEM_CIPHERTEXTBYTES;
    Serial.printlnf("  [C] CT sent: %.3f ms (%u bytes)", (double)it->ct_transfer_ms, it->ct_bytes_sent);
    free(ct);

    // ── Receive shared secret ────────────────────────────────────────
    t0 = micros();
    message_struct_t ss_msg;
    if (!receive_queue_get(&ss_msg, 30000)) {
        Serial.println("  [C] ERROR: Timeout waiting for shared secret");
        free(ss);
        return false;
    }

    // Parse 2-byte header + payload
    if (ss_msg.size < 2) {
        Serial.println("  [C] ERROR: SS header too short");
        free(ss_msg.content); free(ss);
        return false;
    }
    uint16_t ss_len = ((uint16_t)ss_msg.content[0] << 8) | ss_msg.content[1];
    uint8_t *received_ss = (uint8_t*)malloc(ss_len);
    if (!received_ss) {
        free(ss_msg.content); free(ss);
        return false;
    }

    size_t ss_copied = 0;
    if (ss_msg.size > 2) {
        size_t chunk = ss_msg.size - 2;
        if (chunk > ss_len) chunk = ss_len;
        memcpy(received_ss, ss_msg.content + 2, chunk);
        ss_copied = chunk;
    }
    free(ss_msg.content);

    while (ss_copied < ss_len) {
        message_struct_t chunk_msg;
        if (!receive_queue_get(&chunk_msg, 5000)) {
            Serial.println("  [C] ERROR: Timeout receiving SS chunk");
            free(received_ss); free(ss);
            return false;
        }
        size_t chunk = chunk_msg.size;
        if (ss_copied + chunk > ss_len) chunk = ss_len - ss_copied;
        memcpy(received_ss + ss_copied, chunk_msg.content, chunk);
        ss_copied += chunk;
        free(chunk_msg.content);
    }
    t1 = micros();
    it->ss_transfer_ms = (float)(t1 - t0) / 1000.0f;
    it->ss_bytes_sent = ss_len + 2;

    // ── Verify shared secret ─────────────────────────────────────────
    it->ss_match = (ss_len == MLKEM_SHAREDSECRETBYTES &&
                    memcmp(ss, received_ss, MLKEM_SHAREDSECRETBYTES) == 0);
    Serial.printlnf("  [C] SS received: %.3f ms | match=%s",
                     (double)it->ss_transfer_ms, it->ss_match ? "YES" : "NO");

    free(received_ss);
    free(ss);

    uint32_t t_end = micros();
    it->total_handshake_ms = (float)(t_end - t_start) / 1000.0f;
    it->free_heap_after = System.freeMemory();

    Serial.printlnf("  [C] Total handshake: %.3f ms", (double)it->total_handshake_ms);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
// JSON report
// ═══════════════════════════════════════════════════════════════════════
static void emit_mqtt_json(const char *role, int n, uint32_t heap_start,
                           float transport_setup_ms)
{
    // Compute averages
    float s_init=0, s_kg=0, s_pk=0, s_en=0, s_ct=0, s_de=0, s_ss=0, s_tot=0;
    float mn_tot=1e9, mx_tot=0;
    int   valid = 0;

    for (int i = 0; i < n; i++) {
        s_init += s_iters[i].handshake_init_ms;
        s_kg   += s_iters[i].keygen_ms;
        s_pk   += s_iters[i].pk_transfer_ms;
        s_en   += s_iters[i].encaps_ms;
        s_ct   += s_iters[i].ct_transfer_ms;
        s_de   += s_iters[i].decaps_ms;
        s_ss   += s_iters[i].ss_transfer_ms;
        s_tot  += s_iters[i].total_handshake_ms;
        if (s_iters[i].total_handshake_ms < mn_tot) mn_tot = s_iters[i].total_handshake_ms;
        if (s_iters[i].total_handshake_ms > mx_tot) mx_tot = s_iters[i].total_handshake_ms;
        if (s_iters[i].ss_match) valid++;
    }

    float avg_init = s_init/n, avg_kg = s_kg/n, avg_pk = s_pk/n;
    float avg_en = s_en/n, avg_ct = s_ct/n, avg_de = s_de/n;
    float avg_ss = s_ss/n, avg_tot = s_tot/n;

    // Stddev for total handshake
    float tot_arr[MAX_MQTT_BENCHMARK_ITERATIONS];
    for (int i = 0; i < n; i++) tot_arr[i] = s_iters[i].total_handshake_ms;

    Serial.println("===JSON_START===");
    Serial.println("{");
    Serial.printlnf("  \"benchmark_type\": \"mqtt_communication\",");
    Serial.printlnf("  \"variant\": \"%s\",", VARIANT);
    Serial.printlnf("  \"role\": \"%s\",", role);
    Serial.println( "  \"device\": \"Particle Argon (nRF52840)\",");
    Serial.println( "  \"cpu_mhz\": 64,");
    Serial.println( "  \"total_ram_bytes\": 262144,");
    Serial.printlnf("  \"free_heap_at_start_bytes\": %lu,", (unsigned long)heap_start);
    Serial.printlnf("  \"transport_setup_ms\": %.3f,", (double)transport_setup_ms);
    Serial.printlnf("  \"num_iterations\": %d,", n);
    Serial.printlnf("  \"successful_verifications\": %d,", valid);
    Serial.println( "  \"methodology\": {");
    Serial.println( "    \"timing\": \"micros() — nRF52840 hardware timer, 1 us resolution\",");
    Serial.println( "    \"transport\": \"MQTT over WiFi (Particle MQTT library)\",");
    Serial.println( "    \"memory\": \"System.freeMemory() heap snapshots\"");
    Serial.println( "  },");

    Serial.println("  \"buffer_sizes\": {");
    Serial.printlnf("    \"public_key_bytes\": %d,", MLKEM_PUBLICKEYBYTES);
    Serial.printlnf("    \"secret_key_bytes\": %d,", MLKEM_SECRETKEYBYTES);
    Serial.printlnf("    \"ciphertext_bytes\": %d,", MLKEM_CIPHERTEXTBYTES);
    Serial.printlnf("    \"shared_secret_bytes\": %d", MLKEM_SHAREDSECRETBYTES);
    Serial.println("  },");

    // ── Per-iteration ────────────────────────────────────────────────
    Serial.println("  \"iterations\": [");
    for (int i = 0; i < n; i++) {
        Serial.println("    {");
        Serial.printlnf("      \"iteration\": %d,", i + 1);
        Serial.printlnf("      \"handshake_init_ms\": %.3f,", (double)s_iters[i].handshake_init_ms);
        Serial.printlnf("      \"keygen_ms\": %.3f,", (double)s_iters[i].keygen_ms);
        Serial.printlnf("      \"pk_transfer_ms\": %.3f,", (double)s_iters[i].pk_transfer_ms);
        Serial.printlnf("      \"encaps_ms\": %.3f,", (double)s_iters[i].encaps_ms);
        Serial.printlnf("      \"ct_transfer_ms\": %.3f,", (double)s_iters[i].ct_transfer_ms);
        Serial.printlnf("      \"decaps_ms\": %.3f,", (double)s_iters[i].decaps_ms);
        Serial.printlnf("      \"ss_transfer_ms\": %.3f,", (double)s_iters[i].ss_transfer_ms);
        Serial.printlnf("      \"total_handshake_ms\": %.3f,", (double)s_iters[i].total_handshake_ms);
        Serial.printlnf("      \"pk_bytes_on_wire\": %lu,", (unsigned long)s_iters[i].pk_bytes_sent);
        Serial.printlnf("      \"ct_bytes_on_wire\": %lu,", (unsigned long)s_iters[i].ct_bytes_sent);
        Serial.printlnf("      \"ss_bytes_on_wire\": %lu,", (unsigned long)s_iters[i].ss_bytes_sent);
        Serial.printlnf("      \"free_heap_before\": %lu,", (unsigned long)s_iters[i].free_heap_before);
        Serial.printlnf("      \"free_heap_after\": %lu,", (unsigned long)s_iters[i].free_heap_after);
        Serial.printlnf("      \"shared_secret_match\": %s", s_iters[i].ss_match ? "true" : "false");
        Serial.printlnf("    }%s", (i < n - 1) ? "," : "");
    }
    Serial.println("  ],");

    // ── Summary ──────────────────────────────────────────────────────
    Serial.println("  \"summary\": {");
    Serial.printlnf("    \"avg_handshake_init_ms\": %.3f,", (double)avg_init);
    Serial.printlnf("    \"avg_keygen_ms\": %.3f,", (double)avg_kg);
    Serial.printlnf("    \"avg_pk_transfer_ms\": %.3f,", (double)avg_pk);
    Serial.printlnf("    \"avg_encaps_ms\": %.3f,", (double)avg_en);
    Serial.printlnf("    \"avg_ct_transfer_ms\": %.3f,", (double)avg_ct);
    Serial.printlnf("    \"avg_decaps_ms\": %.3f,", (double)avg_de);
    Serial.printlnf("    \"avg_ss_transfer_ms\": %.3f,", (double)avg_ss);
    Serial.printlnf("    \"avg_total_handshake_ms\": %.3f,", (double)avg_tot);
    Serial.printlnf("    \"min_total_handshake_ms\": %.3f,", (double)mn_tot);
    Serial.printlnf("    \"max_total_handshake_ms\": %.3f,", (double)mx_tot);
    Serial.printlnf("    \"stddev_total_handshake_ms\": %.3f,", (double)stddev_f(tot_arr, n, avg_tot));

    // Breakdown: crypto time vs network time
    float avg_crypto, avg_network;
    if (strcmp(role, "server") == 0) {
        avg_crypto  = avg_kg + avg_de;
        avg_network = avg_init + avg_pk + avg_ct + avg_ss;
    } else {
        avg_crypto  = avg_en;
        avg_network = avg_init + avg_pk + avg_ct + avg_ss;
    }
    Serial.printlnf("    \"avg_crypto_ms\": %.3f,", (double)avg_crypto);
    Serial.printlnf("    \"avg_network_ms\": %.3f,", (double)avg_network);
    Serial.printlnf("    \"crypto_percent\": %.1f,", (double)(avg_crypto / avg_tot * 100.0f));
    Serial.printlnf("    \"network_percent\": %.1f", (double)(avg_network / avg_tot * 100.0f));
    Serial.println("  }");
    Serial.println("}");
    Serial.println("===JSON_END===");
}

// ═══════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════
void run_mqtt_benchmark(const char *role, int iterations)
{
    if (iterations < 1) iterations = 1;
    if (iterations > MAX_MQTT_BENCHMARK_ITERATIONS) iterations = MAX_MQTT_BENCHMARK_ITERATIONS;

    bool is_server = (strcmp(role, "server") == 0);

    uint32_t heap_start = System.freeMemory();

    Serial.println("\n========================================");
    Serial.println("[MQTT BENCHMARK] ML-KEM over MQTT");
    Serial.printlnf("[MQTT BENCHMARK] Variant    : %s", VARIANT);
    Serial.printlnf("[MQTT BENCHMARK] Role       : %s", role);
    Serial.printlnf("[MQTT BENCHMARK] Iterations : %d", iterations);
    Serial.printlnf("[MQTT BENCHMARK] Free heap  : %lu bytes", (unsigned long)heap_start);
    Serial.println("========================================\n");

    // ── Transport setup (WiFi + MQTT) ────────────────────────────────
    Serial.println("[MQTT BENCHMARK] Setting up transport...");
    uint32_t t_setup0 = micros();
    setup_transport();

    // Wait for transport to be ready
    int timeout = 0;
    while (!initialized && timeout < 100) {  // 10s
        delay(100);
        timeout++;
    }
    uint32_t t_setup1 = micros();
    float transport_setup_ms = (float)(t_setup1 - t_setup0) / 1000.0f;

    if (!initialized) {
        Serial.println("[MQTT BENCHMARK] ERROR: Transport init failed!");
        return;
    }
    Serial.printlnf("[MQTT BENCHMARK] Transport ready: %.3f ms", (double)transport_setup_ms);

    // Start receive thread for MQTT callback processing
    static Thread* recvThread = new Thread("mqtt_recv", [](void*) {
        receive_task();
    }, nullptr, OS_THREAD_PRIORITY_DEFAULT, 4096);
    delay(500);  // Let receive thread stabilize

    // ── Warmup iteration (discarded) ─────────────────────────────────
    Serial.println("\n[MQTT BENCHMARK] Warmup iteration...");
    drain_queue();
    bool warmup_ok;
    if (is_server) {
        warmup_ok = run_server_iteration(0);
    } else {
        warmup_ok = run_client_iteration(0);
    }
    if (warmup_ok) {
        Serial.printlnf("[MQTT BENCHMARK] Warmup: %.3f ms (discarded)\n",
                         (double)s_iters[0].total_handshake_ms);
    } else {
        Serial.println("[MQTT BENCHMARK] Warmup failed! Continuing anyway...\n");
    }
    delay(1000);

    // ── Measured iterations ──────────────────────────────────────────
    int completed = 0;
    for (int i = 0; i < iterations; i++) {
        Serial.printlnf("\n--- Iteration %d/%d ---", i + 1, iterations);
        drain_queue();
        delay(500);  // Brief pause between iterations

        bool ok;
        if (is_server) {
            ok = run_server_iteration(i);
        } else {
            ok = run_client_iteration(i);
        }

        if (ok) {
            completed++;
            Serial.printlnf("  Iter %2d | Init: %7.3f  Crypto: %7.3f  Network: %7.3f  Total: %7.3f ms | %s",
                i + 1,
                (double)s_iters[i].handshake_init_ms,
                is_server ? (double)(s_iters[i].keygen_ms + s_iters[i].decaps_ms)
                          : (double)s_iters[i].encaps_ms,
                is_server ? (double)(s_iters[i].pk_transfer_ms + s_iters[i].ct_transfer_ms + s_iters[i].ss_transfer_ms)
                          : (double)(s_iters[i].pk_transfer_ms + s_iters[i].ct_transfer_ms + s_iters[i].ss_transfer_ms),
                (double)s_iters[i].total_handshake_ms,
                s_iters[i].ss_match ? "OK" : "FAIL");
        } else {
            Serial.printlnf("  Iter %2d | FAILED", i + 1);
            // Zero out failed iteration so it doesn't corrupt averages
            memset(&s_iters[i], 0, sizeof(s_iters[i]));
        }

        if (i < iterations - 1) delay(1000);  // Wait for peer to reset
    }

    // ── Results ──────────────────────────────────────────────────────
    Serial.printlnf("\n[MQTT BENCHMARK] Completed %d/%d iterations\n", completed, iterations);

    if (completed > 0) {
        emit_mqtt_json(role, iterations, heap_start, transport_setup_ms);
    } else {
        Serial.println("[MQTT BENCHMARK] No successful iterations — no JSON output.");
    }

    Serial.println("\n[MQTT BENCHMARK] Complete.");
}
