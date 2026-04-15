#include "transport.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "mqtt_client.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#define SSID "**"
#define PASSWORD "**"

#define BROKER_URI "mqtt://192.168.137.1:1883"
#if (1)
    #define SENDING_TOPIC "send"
    #define RECEIVE_TOPIC "response"
#else
    #define RECEIVE_TOPIC "send"
    #define SENDING_TOPIC "response"
#endif

esp_mqtt_client_handle_t client;

QueueHandle_t receive_queue;

int retry_num = 0;
bool initialized = false;

static uint8_t hdr[2];
static int hdr_bytes = 0;
static uint8_t *msg_buf = NULL;
static int msg_len = 0;
static int msg_copied = 0;


// Handler 

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{

    esp_mqtt_event_handle_t event = event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        printf("MQTT_EVENT_CONNECTED\n");
        esp_mqtt_client_subscribe(client, RECEIVE_TOPIC, 0);
        initialized = true;
        break;

    case MQTT_EVENT_DISCONNECTED:
        printf("MQTT_EVENT_DISCONNECTED\n");
        if (msg_buf) {
            free(msg_buf);
            msg_buf = NULL;
        }
        break;

    case MQTT_EVENT_SUBSCRIBED:
        break;

    case MQTT_EVENT_UNSUBSCRIBED:
        break;

    case MQTT_EVENT_PUBLISHED:
        break;

    case MQTT_EVENT_DATA:

        const uint8_t *p = (const uint8_t *)event->data;
        int remaining = event->data_len;

        while (remaining > 0) {
            if (hdr_bytes < 2) {
                hdr[hdr_bytes++] = *p++;
                remaining--;

                if (hdr_bytes == 2) {
                    msg_len = ((uint16_t)hdr[0] << 8) | hdr[1];
                    msg_buf = malloc(msg_len);
                    if (!msg_buf) {
                        hdr_bytes = 0;
                        msg_len = 0;
                        break;
                    }
                    msg_copied = 0;
                }
                continue;
            }

            // Copy into message buffer
            int to_copy = (msg_len - msg_copied);
            if (to_copy > remaining) to_copy = remaining;

            memcpy(msg_buf + msg_copied, p, to_copy);
            msg_copied += to_copy;
            p += to_copy;
            remaining -= to_copy;

            // If full message received
            if (msg_copied == msg_len) {
                message_struct_t msg = {
                    .content = msg_buf,
                    .size = msg_len
                };
                if (xQueueSend(receive_queue, &msg, pdMS_TO_TICKS(50)) != pdTRUE) {
                    free(msg_buf);
                }
                hdr_bytes = 0;
                msg_len = 0;
                msg_buf = NULL;
                msg_copied = 0;
            }
        }
        break;

    case MQTT_EVENT_ERROR:
        printf("MQTT_EVENT_ERROR\n");
        if (msg_buf) {  
            free(msg_buf);
            msg_buf = NULL;
        }
        break;
    default:
        break;
    }
}

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id,void *event_data){
    if(event_id == WIFI_EVENT_STA_START) {
        printf("WIFI CONNECTING....\n");
    }
    else if (event_id == WIFI_EVENT_STA_CONNECTED) {
        printf("WiFi CONNECTED\n");
    }
    else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        printf("WiFi lost connection\n");
        if(retry_num<5) {
            esp_wifi_connect();
            printf("Retrying to Connect...\n");
        }
    }
    else if (event_id == IP_EVENT_STA_GOT_IP) {
        printf("Wifi got IP...\n\n");
        // Start MQTT client
        receive_queue = xQueueCreate(2, sizeof(message_struct_t));

        esp_mqtt_client_config_t mqtt_cfg = {
            .broker.address.uri = BROKER_URI,
        };

        client = esp_mqtt_client_init(&mqtt_cfg);
        esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
        esp_mqtt_client_start(client);
    }
}

// Setup

void setup_transport(){
    // Start Wifi
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = SSID,
            .password = PASSWORD
        },
    };
    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    esp_wifi_set_mode(WIFI_MODE_STA);
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());
}

// send

int send_message(const uint8_t *data, uint16_t length) {
    
    uint8_t hdr[2] = { length >> 8, length & 0xFF }; 

    esp_mqtt_client_publish(client, SENDING_TOPIC, (const char*)hdr, 2, 0, 0);
    return esp_mqtt_client_publish(client, SENDING_TOPIC, (const char*)data, length, 0, 0);
}

// receive

void receive_task(void *arg) {
    // MQTT Doens't need a separate receive task
    for(;;) {
        vTaskDelete(NULL);
    }
}