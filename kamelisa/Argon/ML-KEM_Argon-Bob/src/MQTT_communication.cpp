#include "transport.h"

#ifdef USE_MQTT_TRANSPORT

#include "Particle.h"
#include "MQTT.h"

// Define runtime placeholders
static const char* sending_topic;
static const char* receive_topic;
static const char* client_id;

void mqtt_callback(char* topic, byte* payload, unsigned int length);

static const int MQTT_PACKET_SIZE = 2048;
MQTT client("192.168.137.1", 1883, MQTT_PACKET_SIZE, mqtt_callback);

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    if (length < 2) {
        Serial.println("[MQTT] ERROR: Packet dropped. Too short.");
        return;
    }

    uint16_t rx_len = ((uint16_t)payload[0] << 8) | payload[1];
    if (rx_len != (length - 2)) {
        Serial.printlnf("[MQTT] ERROR: Size mismatch! Expected %d, got %d", rx_len, (length - 2));
        return;
    }

    uint8_t *rx_buf = (uint8_t*)malloc(rx_len);
    if (!rx_buf) {
        Serial.println("[MQTT] ERROR: Callback allocation failed.");
        return;
    }

    memcpy(rx_buf, payload + 2, rx_len);

    message_struct_t msg = { .content = rx_buf, .size = (size_t)rx_len };
    receive_queue_push(&msg); 
}

extern "C" {
    void setup_transport() {
        // Resolve target topics dynamically based on the role variable from main.cpp
        if (current_device_role == 1) {
            sending_topic = "mlkem/alice/send";
            receive_topic = "mlkem/bob/send";      // Alice listens to Bob
            client_id     = "argon-alice-mlkem";
            Serial.println("[TRANSPORT] Role Confirmed: Alice Mode");
        } else {
            sending_topic = "mlkem/bob/send";
            receive_topic = "mlkem/alice/send";    // Bob listens to Alice
            client_id     = "argon-bob-mlkem";
            Serial.println("[TRANSPORT] Role Confirmed: Bob Mode");
        }

        WiFi.on();
        WiFi.clearCredentials();                            // wipe stale networks so it can't join the wrong one
        WiFi.setCredentials("pqctest", "123456789", WPA2);
        WiFi.connect();
        
        Serial.println("[TRANSPORT] Aligning Wi-Fi interface links...");
        unsigned long startAttempt = millis();
        while(!WiFi.ready() && (millis() - startAttempt < 15000)) {
            delay(500);
            Serial.print(".");
        }
        Serial.println("");

        if (WiFi.ready()) {
            Serial.printlnf("[TRANSPORT] Wi-Fi connected, IP: %s", WiFi.localIP().toString().c_str());
            Serial.printlnf("[TRANSPORT] Connecting to broker with ClientID: %s", client_id);
            
            if (client.connect(client_id)) {
                client.subscribe(receive_topic);
                Serial.printlnf("[TRANSPORT] SUCCESS! Subscribed to topic: %s", receive_topic);
                initialized = true;
            } else {
                Serial.println("[TRANSPORT] ERROR: MQTT connection rejected by host.");
            }
        } else {
            Serial.println("[TRANSPORT] ERROR: Wi-Fi connection timed out.");
        }
    }

    void send_message(const uint8_t *data, uint16_t length) {
        uint8_t *msg = (uint8_t*)malloc(length + 2);
        if (!msg) return;
        
        msg[0] = (uint8_t)(length >> 8);
        msg[1] = (uint8_t)(length & 0xFF);
        memcpy(msg + 2, data, length);
        
        client.publish(sending_topic, msg, length + 2);
        Serial.printlnf("[MQTT_SEND] Sent %u bytes data payload to %s", length, sending_topic);
        free(msg);
    }

    void send_message_raw(const uint8_t *data, uint16_t length) {
        client.publish(sending_topic, data, length);
    }

    void receive_task() {
        unsigned long last_blink = 0;
        bool led_state = false;
        while (true) {
            if (client.isConnected()) {
                client.loop();
            }
            // Blink D7 every 500ms to keep power bank alive
            if (millis() - last_blink >= 500) {
                led_state = !led_state;
                digitalWrite(D7, led_state ? HIGH : LOW);
                last_blink = millis();
            }
            delay(10);
        }
    }
}

#endif // USE_MQTT_TRANSPORT