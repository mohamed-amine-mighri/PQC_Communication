#ifndef MAIN_TRANSPORT_H
#define MAIN_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

typedef struct {
    uint8_t* content; //frame data
    size_t size; //total size of frame content
} message_struct_t;

extern QueueHandle_t receive_queue;
extern bool initialized;

void setup_transport();
int send_message(const uint8_t *data, uint16_t length);
void receive_task(void *arg);

#endif // MAIN_TRANSPORT_H