#include "mlkem.h"
#include "transport.h"
#include "Particle.h"
#include <stdio.h>
#include <string.h>

// ==== RUNTIME VALUE ASSIGNMENT ====
int current_device_role = 1; // 1 = Alice
// ==================================

static const char *READY_MSG = "READY";
static const char *ACK_MSG   = "ACK";

extern volatile bool initialized;
static Thread* receiveThread = nullptr;
static Thread* mainThread    = nullptr;

void main_task();
static void receive_task_entry(void*) { receive_task(); }
static void main_task_entry(void*)    { main_task(); }

static void get_time_str(char *buf, size_t len) {
    if (Time.isValid()) {
        int h  = Time.hour();
        int m  = Time.minute();
        int s  = Time.second();
        unsigned long ms = millis() % 1000;
        snprintf(buf, len, "%02d:%02d:%02d:%03lu", h, m, s, ms);
    } else {
        unsigned long ms = millis();
        unsigned long s  = ms / 1000;
        unsigned long m  = s / 60;
        unsigned long h  = m / 60;
        snprintf(buf, len, "%02lu:%02lu:%02lu:%03lu (Boot)", h % 24, m % 60, s % 60, ms % 1000);
    }
}

static bool is_ready(const message_struct_t &msg) {
    return msg.size == strlen(READY_MSG) && memcmp(msg.content, READY_MSG, msg.size) == 0;
}

void main_task() {
    int round_num = 0;
    uint8_t *pk = nullptr;
    uint8_t *sk = nullptr;
    uint8_t *ss = nullptr;

    for (;;) {
        round_num++;
        char ts[16];
        get_time_str(ts, sizeof(ts));
        Serial.printlnf("\n========================================");
        Serial.printlnf("[%s] ROUND %d START (Alice)", ts, round_num);
        Serial.printlnf("========================================");

        // PHASE 1: wait for READY from Bob
wait_for_ready:
        Serial.println("[ALICE] Waiting for READY token from Bob...");
        {
            unsigned long wait_start = millis();
            bool rdy_found = false;
            while (!rdy_found) {
                message_struct_t msg;
                if (receive_queue_get(&msg, 0)) {
                    bool rdy = is_ready(msg);
                    free(msg.content);
                    if (rdy) {
                        Serial.println("[ALICE] Valid READY signature matched. Dispatching ACK.");
                        send_message((const uint8_t*)ACK_MSG, strlen(ACK_MSG));
                        rdy_found = true;
                        break;
                    }
                }
                if (millis() - wait_start > 30000) {
                    Serial.println("[ALICE] No READY from Bob for 30s — Bob may be off. Still waiting...");
                    wait_start = millis();
                }
                delay(10);
            }
        }

        // PHASE 2: keygen + send public key
        free(pk); free(sk); free(ss);
        pk = (uint8_t*)malloc(MLKEM_PUBLICKEYBYTES);
        sk = (uint8_t*)malloc(MLKEM_SECRETKEYBYTES);
        ss = (uint8_t*)malloc(MLKEM_SHAREDSECRETBYTES);
        if (!pk || !sk || !ss) {
            Serial.println("[ALICE] ERROR: Memory heap exhaustion.");
            free(pk); free(sk); free(ss);
            pk = sk = ss = nullptr;
            continue;
        }

        Serial.printlnf("[ALICE] Processing Keygen (PK:%d bytes, SK:%d bytes)", MLKEM_PUBLICKEYBYTES, MLKEM_SECRETKEYBYTES);
        uint32_t t0 = millis();
        mlkem_keypair(pk, sk);
        Serial.printlnf("[ALICE] Keypair derivation finalized in %lu ms", millis() - t0);

        Serial.printlnf("[ALICE] Publishing Public Key (%d bytes)...", MLKEM_PUBLICKEYBYTES);
        send_message(pk, MLKEM_PUBLICKEYBYTES);

        // PHASE 3: wait for ciphertext — jump back to handshake if Bob resets
        Serial.println("[ALICE] Awaiting complementary Ciphertext frame...");
        while (true) {
            message_struct_t msg;
            if (receive_queue_get(&msg, 100)) {
                if (msg.size == MLKEM_CIPHERTEXTBYTES) {
                    t0 = millis();
                    mlkem_dec(ss, msg.content, sk);
                    Serial.printlnf("[ALICE] Decapsulation completed in %lu ms", millis() - t0);
                    free(msg.content);
                    send_message(ss, MLKEM_SHAREDSECRETBYTES);
                    Serial.printlnf("[ALICE] Dispatched validated Shared Secret (%d bytes)", MLKEM_SHAREDSECRETBYTES);
                    break;
                } else if (is_ready(msg)) {
                    Serial.println("[ALICE] Bob reset mid-round — resyncing.");
                    send_message((const uint8_t*)ACK_MSG, strlen(ACK_MSG));
                    free(msg.content);
                    goto wait_for_ready;
                } else {
                    Serial.printlnf("[ALICE] Dropping unexpected frame size=%u", (unsigned)msg.size);
                    free(msg.content);
                }
            }
        }

        free(pk); free(sk); free(ss);
        pk = sk = ss = nullptr;

        get_time_str(ts, sizeof(ts));
        Serial.printlnf("[%s] ROUND %d COMPLETED (Alice)", ts, round_num);
        delay(2000);
    }
}

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n========================================");
    Serial.println("ML-KEM Argon Engine Initialization");
    Serial.println("========================================");

    setup_transport();

    int timeout = 0;
    while (!initialized && timeout < 100) { delay(100); timeout++; }

    Time.zone(-4);

    if (!receiveThread) {
        receiveThread = new Thread("receive_task", receive_task_entry, nullptr, OS_THREAD_PRIORITY_DEFAULT, 4096);
    }
    if (!mainThread) {
        mainThread = new Thread("main_task", main_task_entry, nullptr, OS_THREAD_PRIORITY_DEFAULT, 24576);
    }
}

void loop() { delay(1000); }
