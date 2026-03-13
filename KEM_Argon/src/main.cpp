// Main entry for Particle Argon ML-KEM project
#include "mlkem.h"
#include "transport.h"
#include "Particle.h"
#include <stdio.h>
#include <string.h>

#define client
//#define server

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
    Serial.println("Running as client. ML-KEM-512");
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

    // receive and parse public key
    Serial.println("[HANDSHAKE] Waiting for public key message");
    message_struct_t pk_msg;
    if (!receive_queue_get(&pk_msg, 10000)) {
        Serial.println("[ERROR] Timeout waiting for public key message");
        return;
    }
    if (pk_msg.size < 2) {
        Serial.println("[ERROR] Public key message too short");
        free(pk_msg.content);
        return;
    }
    uint16_t pk_len = ((uint16_t)pk_msg.content[0] << 8) | pk_msg.content[1];
    Serial.print("[HANDSHAKE] pk_len="); Serial.println(pk_len);
    if (pk_msg.size != pk_len + 2) {
        Serial.println("[ERROR] Public key message size mismatch");
        free(pk_msg.content);
        free(ss);
        return;
    }
    if (pk_len != MLKEM_PUBLICKEYBYTES) {
        Serial.println("[ERROR] Public key length != MLKEM_PUBLICKEYBYTES");
        free(pk_msg.content);
        free(ss);
        return;
    }
    uint8_t *pk = (uint8_t*)malloc(pk_len);
    if (!pk) {
        Serial.println("[ERROR] malloc(pk) failed");
        free(pk_msg.content);
        free(ss);
        return;
    }
    memcpy(pk, pk_msg.content + 2, pk_len);
    free(pk_msg.content);
    Serial.println("[HANDSHAKE] Public key received");

    // encapsulate and send ciphertext
    uint8_t *ct = (uint8_t*)malloc(MLKEM_CIPHERTEXTBYTES);
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
    send_message_raw(ct, MLKEM_CIPHERTEXTBYTES);
    Serial.println("[HANDSHAKE] Ciphertext sent (raw)");
    Serial.println("Sent ciphertext. Waiting for shared secret...");

    // read shared secret message from queue
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

    // Accept both framed ([len_hi len_lo][payload]) and raw payload formats.
    if (ss_msg.size == MLKEM_SHAREDSECRETBYTES) {
        ss_len = MLKEM_SHAREDSECRETBYTES;
        received_ss = (uint8_t*)malloc(ss_len);
        if (!received_ss) {
            Serial.println("[ERROR] malloc(received_ss) failed");
            free(ss_msg.content);
            free(ss);
            return;
        }
        memcpy(received_ss, ss_msg.content, ss_len);
        Serial.print("[HANDSHAKE] ss_len(raw)="); Serial.println(ss_len);
    } else if (ss_msg.size >= 2) {
        ss_len = ((uint16_t)ss_msg.content[0] << 8) | ss_msg.content[1];
        Serial.print("[HANDSHAKE] ss_len(framed)="); Serial.println(ss_len);
        if (ss_msg.size != ss_len + 2) {
            Serial.println("[ERROR] Shared secret message size mismatch");
            free(ss_msg.content);
            free(ss);
            return;
        }
        received_ss = (uint8_t*)malloc(ss_len);
        if (!received_ss) {
            Serial.println("[ERROR] malloc(received_ss) failed");
            free(ss_msg.content);
            free(ss);
            return;
        }
        memcpy(received_ss, ss_msg.content + 2, ss_len);
    } else {
        Serial.println("[ERROR] Shared secret message too short");
        free(ss_msg.content);
        free(ss);
        return;
    }

    free(ss_msg.content);
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
        mainThread = new Thread("main_task", main_task_entry, nullptr, OS_THREAD_PRIORITY_DEFAULT, 12288);
    }
    
    RGB.color(0, 0, 255);  // Blue for running
    Serial.println("Setup complete!");
}

void loop() {
    delay(1000);
}
