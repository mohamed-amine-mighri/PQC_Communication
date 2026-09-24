// Particle UART transport implementation
#include "transport.h"

#ifdef USE_UART_TRANSPORT

#include "Particle.h"
#include <stdio.h>
#define PIN_RX D1
#define PIN_TX D2
const int uart_buffer_size = 1024 * 2;

void setup_transport() {
    Serial1.begin(115200);
    initialized = true;
}
void send_message(const uint8_t *data, uint16_t length) {
    uint8_t hdr[2] = { (uint8_t)(length >> 8), (uint8_t)(length & 0xFF) };
    Serial1.write(hdr, 2);
    Serial1.write(data, length);
}
void receive_task() {
    while (true) {
        uint8_t hdr[2];
        int got = Serial1.readBytes((char*)hdr, 2);
        if (got < 2) {
            delay(20);
            continue;
        }
        uint16_t len = ((uint16_t)hdr[0] << 8) | hdr[1];
        if (len == 0 || len > 4096) continue;
        uint8_t *data = (uint8_t*)malloc(len);
        if (!data) continue;
        int got_data = Serial1.readBytes((char*)data, len);
        if (got_data < len) {
            free(data);
            continue;
        }
        message_struct_t msg = { .content = data, .size = (size_t)len };
        receive_queue_push(&msg);
    }
}

#endif // USE_UART_TRANSPORT
