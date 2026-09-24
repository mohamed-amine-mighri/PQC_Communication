#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

// Default to MQTT transport if nothing else is specified
#ifndef USE_MQTT_TRANSPORT
#ifndef USE_UART_TRANSPORT
#define USE_MQTT_TRANSPORT 1
#endif
#endif

typedef struct {
    uint8_t *content;
    size_t size;
} message_struct_t;

extern volatile bool initialized;

extern "C" {
    // Queue functions
    void receive_queue_push(message_struct_t *msg);
    bool receive_queue_get(message_struct_t *msg, uint32_t timeout_ms);

    // helper to synchronously read raw bytes from MQTT data buffer
    bool read_bytes(uint8_t *buf, size_t len, uint32_t timeout_ms);

    // Transport functions
    void setup_transport();
    void send_message(const uint8_t *data, uint16_t length);
    void send_message_raw(const uint8_t *data, uint16_t length);
    void receive_task();
}
