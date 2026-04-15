// Particle MQTT transport implementation
#include "transport.h"

#ifdef USE_MQTT_TRANSPORT

#include "Particle.h"
#include "MQTT.h"
// legacy header parser state (no longer used)
static uint8_t hdr[2];
static int hdr_bytes = 0;
static uint8_t *msg_buf = NULL;
static int msg_len = 0;
static int msg_copied = 0;

// synchronous byte queue used by client main_task to mirror server process
#include <deque>
static std::deque<uint8_t> data_buffer;
static std::mutex data_mutex;

// read exactly len bytes from data_buffer into buf within timeout_ms
// returns true on success, false on timeout
extern "C" bool read_bytes(uint8_t *buf, size_t len, uint32_t timeout_ms) {
    unsigned long start = millis();
    size_t copied = 0;
    while (copied < len) {
        {
            std::lock_guard<std::mutex> lock(data_mutex);
            while (!data_buffer.empty() && copied < len) {
                buf[copied++] = data_buffer.front();
                data_buffer.pop_front();
            }
        }
        if (copied == len) {
            return true;
        }
        if (timeout_ms != 0 && (millis() - start) >= timeout_ms) {
            break;
        }
        delay(1);
    }
    return false;
}
void mqtt_callback(char* topic, byte* payload, unsigned int length);
// ML-KEM payloads (pk/ct + 2-byte length header) exceed the default 255-byte MQTT buffer.
// Kyber1024 public key = 1568 + 2 header + ~30 MQTT overhead => need at least 1700.
static const int MQTT_PACKET_SIZE = 2048;
MQTT client("192.168.0.11", 1883, MQTT_PACKET_SIZE, mqtt_callback);

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    Serial.print("[MQTT] Received on topic ");
    Serial.print(topic);
    Serial.print(" length=");
    Serial.print((unsigned)length);
    Serial.print(" bytes: ");
    for (unsigned int i = 0; i < length && i < 8; ++i) {
        char buf[4];
        sprintf(buf, "%02X", payload[i]);
        Serial.print(buf);
        if (i < length-1 && i < 7) Serial.print(" ");
    }
    if (length > 8) Serial.print(" ...");
    Serial.println();

    // control messages handled separately
    if (length >= 3 && memcmp(payload, "ACK", 3) == 0) {
        Serial.println("[MQTT] Detected raw ACK prefix");
        message_struct_t msg = { 
            .content = (uint8_t*)malloc(3), 
            .size = 3 
        };
        if (msg.content) {
            memcpy(msg.content, payload, 3);
            receive_queue_push(&msg);
            Serial.println("[MQTT] ACK pushed to queue");
        }
        if (length == 3) {
            return;
        }
        payload += 3;
        length -= 3;
        Serial.print("[MQTT] Leaving ");
        Serial.print((unsigned)length);
        Serial.println(" bytes for data buffer");
    }
    if (length >= 5 && memcmp(payload, "READY", 5) == 0) {
        Serial.println("[MQTT] Detected raw READY prefix");
        message_struct_t msg = { 
            .content = (uint8_t*)malloc(5), 
            .size = 5 
        };
        if (msg.content) {
            memcpy(msg.content, payload, 5);
            receive_queue_push(&msg);
            Serial.println("[MQTT] READY pushed to queue");
        }
        if (length == 5) {
            return;
        }
        payload += 5;
        length -= 5;
        Serial.print("[MQTT] Leaving ");
        Serial.print((unsigned)length);
        Serial.println(" bytes for data buffer");
    }

    // For non-control messages, always push the entire payload to queue
    if (length > 0) {
        Serial.print("[MQTT] Pushing ");
        Serial.print((unsigned)length);
        Serial.println(" bytes to queue");
        message_struct_t msg = {
            .content = (uint8_t*)malloc(length),
            .size = length
        };
        if (msg.content) {
            memcpy(msg.content, payload, length);
            receive_queue_push(&msg);
            Serial.println("[MQTT] Message pushed successfully");
        } else {
            Serial.println("[MQTT] ERROR: malloc failed");
        }
        // Keep legacy byte-stream mirror for compatibility with read_bytes().
        std::lock_guard<std::mutex> lock(data_mutex);
        for (unsigned int i = 0; i < length; ++i) {
            data_buffer.push_back(payload[i]);
        }
    }
}

extern "C" {
    void setup_transport() {
        WiFi.connect();
        waitUntil(WiFi.ready);
        client.connect("argonClient");
        client.subscribe("mlkem/esp32/server_send"); // legacy (public key, shared secret)
        client.subscribe("mlkem/esp32/public_key");  // new (public key)
        client.subscribe("mlkem/esp32/shared_secret"); // new (shared secret)
        initialized = true;
    }

    void send_message(const uint8_t *data, uint16_t length) {
        uint8_t *msg = (uint8_t*)malloc(length + 2);
        if (!msg) return;
        msg[0] = (uint8_t)(length >> 8);
        msg[1] = (uint8_t)(length & 0xFF);
        memcpy(msg + 2, data, length);
        client.publish("mlkem/esp32/client_send", msg, length + 2);
        free(msg);
    }

    void send_message_raw(const uint8_t *data, uint16_t length) {
        client.publish("mlkem/esp32/client_send", data, length);
    }

    void receive_task() {
        while (true) {
            client.loop();  // Process MQTT messages and invoke callbacks
            delay(10);
        }    }
}

#endif // USE_MQTT_TRANSPORT