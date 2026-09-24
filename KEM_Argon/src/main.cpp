// Main entry for Particle Argon ML-KEM project
#include "mlkem.h"
#include "transport.h"
#include "benchmark.h"
#include "benchmark_mqtt.h"
#include "Particle.h"
#include <stdio.h>
#include <string.h>

// Uncomment ONE of these to select mode:
//#define BENCHMARK_MODE          // Standalone crypto benchmarks (no network)
//#define BENCHMARK_ITERATIONS 10 // Number of measured iterations (+ 1 warmup)

#define BENCHMARK_MQTT_MODE           // ML-KEM benchmark over MQTT communication
#define BENCHMARK_MQTT_ITERATIONS 10  // Number of measured iterations (+ 1 warmup)
#define BENCHMARK_MQTT_ROLE "client"  // "client" or "server"

//#define client                   // Regular client mode
//#define server                  // Regular server mode

static const char *READY_MSG = "READY";
static const char *ACK_MSG   = "ACK";
extern volatile bool initialized;
void main_task();

// ML-KEM operations are stack-heavy. Use explicit thread stacks to avoid hard-fault resets.
static Thread* receiveThread = nullptr;
static Thread* mainThread = nullptr;

static void receive_task_entry(void*) {
    receive_task();
}

static void main_task_entry(void*) {
    main_task();
}

#if defined(server)
void main_task() {
    Serial.println("Running as server");
    Serial.println("Waiting for READY...");
    for (;;) {
        message_struct_t msg;
        if (receive_queue_get(&msg, 0)) {
            if (msg.size == strlen(READY_MSG) && memcmp(msg.content, READY_MSG, msg.size) == 0) {
                Serial.println("Got READY, sending ACK");
                send_message_raw((const uint8_t*)ACK_MSG, strlen(ACK_MSG));
                free(msg.content);
                break;
            } else {
                Serial.print("Unexpected message of size ");
                Serial.println((unsigned)msg.size);
            }
            free(msg.content);
        }
    }
    uint8_t *pk = (uint8_t*)malloc(MLKEM_PUBLICKEYBYTES);
    uint8_t *sk = (uint8_t*)malloc(MLKEM_SECRETKEYBYTES);
    uint8_t *ss = (uint8_t*)malloc(MLKEM_SHAREDSECRETBYTES);
    assert(pk && sk && ss);
    mlkem_keypair(pk, sk);
    send_message(pk, MLKEM_PUBLICKEYBYTES);
    Serial.println("Sent public key.");
    for(;;){
        message_struct_t message;
        if(receive_queue_get(&message, 100)){
            if (message.size != MLKEM_CIPHERTEXTBYTES) {
                Serial.print("Unexpected size ");
                Serial.println((unsigned)message.size);
                free(message.content);
                continue;
            }
            uint8_t *ct = (uint8_t*)message.content;
            mlkem_dec(ss, ct, sk);
            free(ct);
            send_message(ss, MLKEM_SHAREDSECRETBYTES);
            Serial.println("Sent shared secret.");
            free(pk);
            free(sk);
            free(ss);
            return;
        }
    }
}
#elif defined(client)
void main_task() {
    Serial.println("Running as client. ML-KEM-768");
    // wait_for_ack scans the incoming byte stream until the ASCII string "ACK" is found
    auto wait_for_ack = [&](uint32_t timeout_ms) {
        unsigned long start = millis();
        message_struct_t msg;
        while (millis() - start < timeout_ms) {
            if (receive_queue_get(&msg, 100)) {
                if (msg.size == 3 && memcmp(msg.content, "ACK", 3) == 0) {
                    free(msg.content);
                    return true;
                }
                free(msg.content);
            }
        }
        return false;
    };

    Serial.println("Sending READY...");
    send_message_raw((const uint8_t*)READY_MSG, strlen(READY_MSG));
    Serial.println("Waiting for ACK...");
    while (true) {
        if (wait_for_ack(5000)) {
            Serial.println("Got ACK from server! ✓");
            break;
        } else {
            Serial.println("No ACK, still waiting...");
            delay(5000);
        }
    }

    // After ACK we perform a synchronous, header-based exchange exactly like the server
    uint8_t *ss = (uint8_t*)malloc(MLKEM_SHAREDSECRETBYTES);
    assert(ss);

    // receive and parse public key with chunked receive for robustness
    Serial.println("[HANDSHAKE] Waiting for public key message");
    message_struct_t pk_msg;
    if (!receive_queue_get(&pk_msg, 10000)) {
        Serial.println("[ERROR] Timeout waiting for public key message");
        return;
    }
    uint16_t pk_len = 0;
    uint8_t *pk = NULL;
    
    // Read 2-byte length header
    if (pk_msg.size < 2) {
        Serial.println("[ERROR] Public key header too short");
        free(pk_msg.content);
        free(ss);
        return;
    }
    pk_len = ((uint16_t)pk_msg.content[0] << 8) | pk_msg.content[1];
    Serial.print("[HANDSHAKE] pk_len="); Serial.println(pk_len);
    
    // Allocate buffer for public key
    pk = (uint8_t*)malloc(pk_len);
    if (!pk) {
        Serial.println("[ERROR] malloc(pk) failed");
        free(pk_msg.content);
        free(ss);
        return;
    }
    
    // Copy any payload bytes already in the first message
    size_t pk_copied = 0;
    if (pk_msg.size > 2) {
        size_t chunk_size = pk_msg.size - 2;
        if (chunk_size > pk_len) chunk_size = pk_len;
        memcpy(pk, pk_msg.content + 2, chunk_size);
        pk_copied = chunk_size;
    }
    free(pk_msg.content);
    
    // Receive remaining public key chunks until complete
    Serial.print("[HANDSHAKE] Received "); Serial.print((unsigned)pk_copied); Serial.print(" of "); Serial.print((unsigned)pk_len); Serial.println(" bytes");
    while (pk_copied < pk_len) {
        message_struct_t pk_chunk;
        if (!receive_queue_get(&pk_chunk, 5000)) {
            Serial.println("[ERROR] Timeout receiving public key chunk");
            free(pk);
            free(ss);
            return;
        }
        size_t chunk_size = pk_chunk.size;
        if (pk_copied + chunk_size > pk_len) {
            chunk_size = pk_len - pk_copied;
        }
        memcpy(pk + pk_copied, pk_chunk.content, chunk_size);
        pk_copied += chunk_size;
        Serial.print("[HANDSHAKE] Received "); Serial.print((unsigned)pk_copied); Serial.print(" of "); Serial.print((unsigned)pk_len); Serial.println(" bytes");
        free(pk_chunk.content);
    }
    Serial.println("[HANDSHAKE] Public key received");

    // encapsulate and send ciphertext (size depends on variant)
    // Use MLKEM_CIPHERTEXTBYTES as the max, but allocate dynamically if needed
    size_t ct_len = 0;
    if (pk_len == 800) ct_len = 768; // Kyber512
    else if (pk_len == 1184) ct_len = 1088; // Kyber768
    else if (pk_len == 1568) ct_len = 1568; // Kyber1024 (ct_len == pk_len)
    else {
        // Fallback: try to use the largest possible
        ct_len = MLKEM_CIPHERTEXTBYTES;
    }
    uint8_t *ct = (uint8_t*)malloc(ct_len);
    if (!ct) {
        Serial.println("[ERROR] malloc(ct) failed");
        free(pk);
        free(ss);
        return;
    }
    Serial.println("[HANDSHAKE] Starting encapsulation");
    mlkem_enc(ct, ss, pk);
    Serial.println("[HANDSHAKE] Encapsulation done");
    free(pk);
    // First try raw ciphertext. If no response arrives, retry once with framed payload.
    send_message_raw(ct, ct_len);
    Serial.println("[HANDSHAKE] Ciphertext sent (raw)");
    Serial.println("Sent ciphertext. Waiting for shared secret...");

    // read shared secret message from queue with chunked receive
    Serial.println("[HANDSHAKE] Waiting for shared secret message");
    message_struct_t ss_msg;
    if (!receive_queue_get(&ss_msg, 5000)) {
        Serial.println("[HANDSHAKE] No response for raw ciphertext, retrying with framed ciphertext");
        send_message(ct, MLKEM_CIPHERTEXTBYTES);
        Serial.println("[HANDSHAKE] Ciphertext sent (framed)");

        if (!receive_queue_get(&ss_msg, 10000)) {
            Serial.println("[ERROR] Timeout waiting for shared secret message");
            free(ct);
            free(ss);
            return;
        }
    }
    free(ct);
    uint8_t *received_ss = NULL;
    uint16_t ss_len = 0;

    // Read 2-byte length header
    if (ss_msg.size < 2) {
        Serial.println("[ERROR] Shared secret header too short");
        free(ss_msg.content);
        free(ss);
        return;
    }
    ss_len = ((uint16_t)ss_msg.content[0] << 8) | ss_msg.content[1];
    Serial.print("[HANDSHAKE] ss_len="); Serial.println(ss_len);
    
    // Allocate buffer for shared secret
    received_ss = (uint8_t*)malloc(ss_len);
    if (!received_ss) {
        Serial.println("[ERROR] malloc(received_ss) failed");
        free(ss_msg.content);
        free(ss);
        return;
    }
    
    // Copy any payload bytes already in the first message
    size_t ss_copied = 0;
    if (ss_msg.size > 2) {
        size_t chunk_size = ss_msg.size - 2;
        if (chunk_size > ss_len) chunk_size = ss_len;
        memcpy(received_ss, ss_msg.content + 2, chunk_size);
        ss_copied = chunk_size;
    }
    free(ss_msg.content);
    
    // Receive remaining shared secret chunks until complete
    Serial.print("[HANDSHAKE] Received "); Serial.print((unsigned)ss_copied); Serial.print(" of "); Serial.print((unsigned)ss_len); Serial.println(" bytes");
    while (ss_copied < ss_len) {
        message_struct_t ss_chunk;
        if (!receive_queue_get(&ss_chunk, 5000)) {
            Serial.println("[ERROR] Timeout receiving shared secret chunk");
            free(received_ss);
            free(ss);
            return;
        }
        size_t chunk_size = ss_chunk.size;
        if (ss_copied + chunk_size > ss_len) {
            chunk_size = ss_len - ss_copied;
        }
        memcpy(received_ss + ss_copied, ss_chunk.content, chunk_size);
        ss_copied += chunk_size;
        Serial.print("[HANDSHAKE] Received "); Serial.print((unsigned)ss_copied); Serial.print(" of "); Serial.print((unsigned)ss_len); Serial.println(" bytes");
        free(ss_chunk.content);
    }

    if (memcmp(ss, received_ss, ss_len) == 0) {
        Serial.println("Shared secrets match!");
    } else {
        Serial.println("Shared secrets do NOT match!");
    }
    free(received_ss);
    free(ss);
    return;
}
#endif

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("====================");
    Serial.println("Starting ML-KEM Argon");
    Serial.println("====================");
    Serial.print("Reset reason: ");
    Serial.println((int)System.resetReason());
    
    RGB.control(true);
    RGB.color(0, 255, 0);  // Green for startup
    
    #ifdef BENCHMARK_MODE
    // Run in benchmark mode - no need for transport
    Serial.println("\nRunning in BENCHMARK MODE");
    RGB.color(255, 255, 0);  // Yellow for benchmark
    delay(1000);
    
    // ML-KEM internally uses large stack buffers (polyvec arrays ~5-6KB).
    // The default setup() thread stack is too small and causes a hard fault.
    // Spawn a dedicated thread with a 32KB stack for the benchmark.
    static Thread* benchThread = new Thread("benchmark", [](void*) {
        delay(500);

        #ifdef BENCHMARK_ITERATIONS
        run_multiple_benchmarks(BENCHMARK_ITERATIONS);
        #else
        run_ml_kem_benchmark();
        #endif
        
        RGB.color(0, 255, 0);  // Green when complete
        Serial.println("\nBenchmark mode complete. Device idle.");
    }, nullptr, OS_THREAD_PRIORITY_DEFAULT, 32768);
    
    Serial.println("Benchmark thread started (32KB stack).");

    #elif defined(BENCHMARK_MQTT_MODE)
    // Run ML-KEM benchmark over MQTT communication
    Serial.println("\nRunning in BENCHMARK MQTT MODE");
    Serial.printlnf("Role: %s  |  Iterations: %d", BENCHMARK_MQTT_ROLE, BENCHMARK_MQTT_ITERATIONS);
    RGB.color(255, 128, 0);  // Orange for MQTT benchmark
    delay(1000);

    // WiFi must be connected before MQTT transport
    WiFi.connect();
    Serial.println("Waiting for WiFi...");
    waitUntil(WiFi.ready);
    Serial.println("WiFi connected!");

    // Spawn dedicated thread with 32KB stack for ML-KEM operations
    static Thread* mqttBenchThread = new Thread("mqtt_bench", [](void*) {
        delay(1000);  // Let WiFi stabilize
        run_mqtt_benchmark(BENCHMARK_MQTT_ROLE, BENCHMARK_MQTT_ITERATIONS);
        RGB.color(0, 255, 0);  // Green when complete
        Serial.println("\nMQTT Benchmark mode complete. Device idle.");
    }, nullptr, OS_THREAD_PRIORITY_DEFAULT, 32768);

    Serial.println("MQTT Benchmark thread started (32KB stack).");
    
    #else
    // Regular client/server mode
    WiFi.connect();
    Serial.println("Waiting for WiFi...");
    if (waitUntil(WiFi.ready)) {
        Serial.println("WiFi connected!");
    } else {
        Serial.println("WiFi connection failed");
    }
    
    setup_transport();
    int timeout = 0;
    while (!initialized && timeout < 50) {
        delay(100);
        timeout++;
    }
    
    if (initialized) {
        Serial.println("Transport initialized!");
    } else {
        Serial.println("Transport init timeout!");
    }
    
    Serial.println("Starting threads...");
    if (!receiveThread) {
        receiveThread = new Thread("receive_task", receive_task_entry, nullptr, OS_THREAD_PRIORITY_DEFAULT, 4096);
    }
    if (!mainThread) {
        mainThread = new Thread("main_task", main_task_entry, nullptr, OS_THREAD_PRIORITY_DEFAULT, 24576);
    }
    
    RGB.color(0, 0, 255);  // Blue for running
    Serial.println("Setup complete!");
    #endif
}

void loop() {
    delay(1000);
}
