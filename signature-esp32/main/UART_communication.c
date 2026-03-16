#include "transport.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_err.h"
#include "driver/gpio.h"

#define PIN_RX 18
#define PIN_TX 19

const int uart_buffer_size = 1024 * 4;
const uart_port_t uart_num = UART_NUM_2;

QueueHandle_t receive_queue;
QueueHandle_t uart_queue;

bool initialized = false;

void setup_transport(){
    receive_queue = xQueueCreate(5, sizeof(message_struct_t));

    ESP_ERROR_CHECK(uart_driver_install(uart_num, uart_buffer_size, 0, 10, &uart_queue, 0));
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };
    ESP_ERROR_CHECK(uart_param_config(uart_num, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(uart_num, PIN_TX, PIN_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    initialized = true;
}

// send

static int uart_write_all(uart_port_t port, const uint8_t *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        int n = uart_write_bytes(port, (const char *)(buf + written), len - written);
        if (n < 0) return -1;
        written += n;
    }
    return written;
}

int send_message(const uint8_t *data, uint16_t length) {
    uint8_t hdr[2] = { length >> 8, length & 0xFF };  // big-endian 2-byte length
    if(uart_write_all(uart_num, hdr, 2) < 0) {
        printf("Error sending hdr\n");
    };
    int send = uart_write_all(uart_num, data, length);
    uart_wait_tx_done(uart_num, portMAX_DELAY);
    vTaskDelay(100);
    return send;
}

// receive


static int uart_read_exact(uart_port_t port, uint8_t *buf, size_t len, TickType_t to_ticks) {
    size_t got = 0;
    uint32_t start = xTaskGetTickCount();
    while (got < len) {
        TickType_t now = xTaskGetTickCount();
        if (now - start > to_ticks) break;
        int n = uart_read_bytes(port, buf + got, len - got, pdMS_TO_TICKS(20));
        if (n > 0) got += n;
    }
    return (got == len) ? got : -1;
}

void receive_task(void *arg){
    for(;;){
        // Read 2-byte length
        uint8_t hdr[2];
        if (uart_read_exact(uart_num, hdr, 2, pdMS_TO_TICKS(5000)) < 0) {
            continue; // timeout; try again
        }
        
        uint16_t len = ((uint16_t)hdr[0] << 8) | hdr[1];
        if (len == 0) continue; // sanity check

        uint8_t *data = malloc(len);
        if (!data) {
            printf("Unable to allocate space for data\n");
            continue;
        }

        int data_read = uart_read_exact(uart_num, data, len, pdMS_TO_TICKS(5000));
        if (data_read < 0) {
            free(data);
            continue;
        }
        if((uint16_t)data_read != len) printf("Wrong read. Read %d, Expected %d", (uint16_t)data_read, len);

        message_struct_t msg = { .content = data, .size = len };
        if (xQueueSend(receive_queue, &msg, pdMS_TO_TICKS(50)) != pdTRUE) {
            free(data);
        }
    }
}
