#include "mlkem.h"
#include "transport.h"
#include "Particle.h"
#include <stdio.h>
#include <string.h>

SYSTEM_MODE(AUTOMATIC);

// ==== RUNTIME VALUE ASSIGNMENT ====
int current_device_role = 0; // 0 = Bob
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
    // Sync with Particle Cloud time if available, otherwise fallback to system relative time
    if (Time.isValid()) {
        int h  = Time.hour();
        int m  = Time.minute();
        int s  = Time.second();
        unsigned long ms = millis() % 1000;
        
        snprintf(buf, len, "%02d:%02d:%02d:%03lu", h, m, s, ms);
    } else {
        // Fallback layout if NTP sync hasn't completed yet
        unsigned long ms = millis();
        unsigned long s  = ms / 1000;
        unsigned long m  = s / 60;
        unsigned long h  = m / 60;
        snprintf(buf, len, "%02lu:%02lu:%02lu:%03lu (Boot)", h % 24, m % 60, s % 60, ms % 1000);
    }
}

void main_task() {
    int round_num = 0;
    for (;;) {
        round_num++;
        char ts[16];
        get_time_str(ts, sizeof(ts));
        Serial.printlnf("\n========================================");
        Serial.printlnf("[%s] ROUND %d START (Bob)", ts, round_num);
        Serial.printlnf("========================================");

        bool acked = false;
        int retries = 0;
        while (!acked && retries < 30) {
            Serial.println("[BOB] Blasting READY handshake token...");
            send_message((const uint8_t*)READY_MSG, strlen(READY_MSG));
            message_struct_t msg;
            if (receive_queue_get(&msg, 3000)) {
                if (msg.size == strlen(ACK_MSG) && memcmp(msg.content, ACK_MSG, msg.size) == 0) {
                    Serial.println("[BOB] Handshake success! ACK verified.");
                    acked = true;
                } else {
                    Serial.printlnf("[BOB] Frame mismatch while awaiting ACK: received size=%u", (unsigned)msg.size);
                }
                free(msg.content);
            } else {
                Serial.println("[BOB] Handshake timeout, retrying loop execution...");
                retries++;
            }
        }
        if (!acked) {
            Serial.println("[BOB] Pipeline failure to sync, restarting thread state...");
            delay(2000);
            continue;
        }

        Serial.println("[BOB] Listening for incoming Public Key...");
        uint8_t *pk = NULL;
        bool got_pk = false;
        while (!got_pk) {
            message_struct_t msg;
            if (receive_queue_get(&msg, 10000)) {
                if (msg.size == MLKEM_PUBLICKEYBYTES) {
                    pk = msg.content;
                    got_pk = true;
                    Serial.printlnf("[BOB] Public Key extracted successfully (%u bytes)", (unsigned)msg.size);
                } else {
                    Serial.printlnf("[BOB] Invalid PK packet footprint %u (Expected %d)", (unsigned)msg.size, MLKEM_PUBLICKEYBYTES);
                    free(msg.content);
                }
            }
        }

        uint8_t *ct = (uint8_t*)malloc(MLKEM_CIPHERTEXTBYTES);
        uint8_t *ss = (uint8_t*)malloc(MLKEM_SHAREDSECRETBYTES);
        if (!ct || !ss) {
            Serial.println("[BOB] ERROR: Allocation fault during core execution.");
            free(pk); free(ct); free(ss);
            delay(2000);
            continue;
        }

        uint32_t t0 = millis();
        mlkem_enc(ct, ss, pk);
        uint32_t enc_ms = millis() - t0;
        Serial.printlnf("[BOB] Encapsulation logic executed in %lu ms", enc_ms);
        free(pk);

        Serial.printlnf("[BOB] Packaging and sending Ciphertext payload (%d bytes)...", MLKEM_CIPHERTEXTBYTES);
        send_message(ct, MLKEM_CIPHERTEXTBYTES);
        free(ct);

        Serial.println("[BOB] Waiting for verification Shared Secret response...");
        bool got_ss = false;
        while (!got_ss) {
            message_struct_t msg;
            if (receive_queue_get(&msg, 10000)) {
                if (msg.size == MLKEM_SHAREDSECRETBYTES) {
                    if (memcmp(ss, msg.content, MLKEM_SHAREDSECRETBYTES) == 0) {
                        Serial.println("[BOB] STATUS MATCH SUCCESS: Derived secret keys align securely!");
                    } else {
                        Serial.println("[BOB] STATUS ALARM CRITICAL: Shared secret keys do NOT match!");
                    }
                    free(msg.content);
                    got_ss = true;
                } else {
                    Serial.printlnf("[BOB] Wrong validation packet footprint size: %u", (unsigned)msg.size);
                    free(msg.content);
                }
            }
        }
        free(ss);

        get_time_str(ts, sizeof(ts));
        Serial.printlnf("[%s] ROUND %d COMPLETED (Bob)", ts, round_num);
        delay(2000);
    }
}

void setup() {
    pinMode(D7, OUTPUT);
    Serial.begin(115200);
    delay(2000);
    // ...prints...

    Particle.disconnect();   // <-- added here, one line

 
    setup_transport();

    int timeout = 0;
    while (!initialized && timeout < 100) { delay(100); timeout++; }

    // ---- ADD THIS LINE HERE TO SHIFT TO YOUR TIMEZONE ----
    Time.zone(-4); // Use -4 for Eastern Daylight Time (EDT) / local 12:00 PM afternoon sync
    // ------------------------------------------------------

    if (!receiveThread) {
        receiveThread = new Thread("receive_task", receive_task_entry, nullptr, OS_THREAD_PRIORITY_DEFAULT, 4096);
    }
    if (!mainThread) {
        mainThread = new Thread("main_task", main_task_entry, nullptr, OS_THREAD_PRIORITY_DEFAULT, 24576);
    }
}

void loop() {
    digitalWrite(D7, HIGH);
    delay(500);
    digitalWrite(D7, LOW);
    delay(500);
}