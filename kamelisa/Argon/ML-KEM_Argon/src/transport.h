#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

// FORCE MQTT MODE ACTIVATION FOR THE COMPILER
#define USE_MQTT_TRANSPORT 1

// Expose the global role indicator across files
extern int current_device_role; 

typedef struct {
    uint8_t *content;
    size_t size;
} message_struct_t;

extern volatile bool initialized;

#ifdef __cplusplus
extern "C" {
#endif

void setup_transport();
void send_message(const uint8_t *data, uint16_t length);
void send_message_raw(const uint8_t *data, uint16_t length);
void receive_task();

void receive_queue_push(message_struct_t *msg);
bool receive_queue_get(message_struct_t *msg, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif // TRANSPORT_H