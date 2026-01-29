#include "transport.h"
#include <string.h>
#include <stdlib.h>
#include <wiringPi.h>
#include <wiringSerial.h>
#include <errno.h>
#include "MQTTClient.h"

#define Serial_1_MQTT_0 1

#if Serial_1_MQTT_0
    #define Serial
#else
    #define MQTT
#endif

bool end = false;
Queue receiving_queue;
pthread_mutex_t queue_lock;

// ------ Serial -----

#define SERIAL_DEV "/dev/serial0"
#define BAUD_RATE 115200

int fd;

// Setup

int serial_setup() {
    int serial_port;
    if((serial_port = serialOpen(SERIAL_DEV, BAUD_RATE)) < 0) {
        perror("SerialOpen failed");
        return -1;
    }

    if (wiringPiSetup() == -1) {
        perror("wiringPi Setup failed");
        return -1;
    }
    return serial_port;
}

// Send

void serial_send(int fd, const uint8_t *data, size_t len) {
    uint8_t hdr[2] = { (len >> 8) & 0xFF, len & 0xFF};
    serialPutchar(fd, hdr[0]);
    serialPutchar(fd, hdr[1]);
    for(size_t i = 0; i < len; i++) {
        serialPutchar(fd, data[i]);
    }
}

// Read

int serial_read_exact(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len && !end) {
        if(serialDataAvail(fd)) {
            int character = serialGetchar(fd);
            if(character < 0 ) break;
            buf[got++] = (uint8_t) character;
        }
    }
    return (got == len) ? got : -1;
}

// ------ MQTT ------

// Setup
#define CLIENTID "RaspberryPiClient"

#define ADDRESS_MQTT "mqtt://192.168.137.1:1883"
#define RECEIVING_TOPIC "mlkem/esp32/send"
#define SENDING_TOPIC "mlkem/esp32/response"

#define MAX_BUFFER 8192
#define TIMEOUT 100L

unsigned char readBuffer[MAX_BUFFER];
size_t bufferLen = 0;
MQTTClient client;


void mqtt_setup() {
    MQTTClient_connectOptions conn_options = MQTTClient_connectOptions_initializer;
    int rc;

    MQTTClient_create(&client, ADDRESS_MQTT, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);

    conn_options.keepAliveInterval = 20;
    conn_options.cleansession = 1;

    if((rc = MQTTClient_connect(client, &conn_options)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect, retur code %d\n", rc);
        return;
    }

    MQTTClient_subscribe(client, RECEIVING_TOPIC, 0);

    printf("connected to broker\n");
}

// Send

void mqtt_send(const uint8_t *data, size_t len){
    uint8_t hdr[2] = { (len >> 8) & 0xFF, len & 0xFF};
    MQTTClient_publish(client, SENDING_TOPIC, 2, hdr, 0 , 0, NULL);
    MQTTClient_publish(client, SENDING_TOPIC, len, data, 0, 0, NULL);
}

// Read

int mqtt_read(uint8_t *data, size_t len){
    int got = 0;
    char *topicName = NULL;
    int topicLen;
    MQTTClient_message *message = NULL;

    while(got < len && !end){
        if(bufferLen > 0){
            int to_copy = (len - got < bufferLen) ? (len - got) : bufferLen;
            bufferLen = bufferLen - to_copy;
            memcpy(data + got, readBuffer, to_copy);

            got += to_copy;

            if(bufferLen > 0){
                memcpy(readBuffer, readBuffer + to_copy, bufferLen);
            }
        } else if (MQTTClient_receive(client, &topicName, &topicLen, &message, TIMEOUT) == MQTTCLIENT_SUCCESS){
            if(message){
                memcpy(readBuffer + bufferLen, message->payload, message->payloadlen);
                bufferLen += message->payloadlen;
                MQTTClient_freeMessage(&message);
                MQTTClient_free(&topicName);
            }
        }
    }
    return (got == len) ? got : -1;
}

// destroy

void mqtt_destroy() {
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return;
}

//  ------ Wrapper ------

int setup() {
    initializeQueue(&receiving_queue);
    #if defined(Serial)
        if(serial_setup() < 0) {
            printf("Unable to setup\n");
            return -1;
        }
        return 0;
    #else
        mqtt_setup();
        return 0;
    #endif
}

int send_message(const uint8_t* data, size_t len) {
    #if defined(Serial)
        serial_send(fd, data, len);
    #else 
        mqtt_send(data, len);
    #endif

}

int receive_message(uint8_t* data, size_t len) {
    #if defined(Serial)
        return serial_read_exact(fd, data, len);
    #else
        return mqtt_read_exact(data, len);
    #endif
}

void* receive_task(void* arg) {
    while(!end) {

        uint8_t hdr[2];
        if(receive_message(hdr, 2) < 0) {
            printf("Unable to get hdr\n");
            continue;
        }

        uint16_t len = (hdr[0] << 8) | hdr[1];

        uint8_t* data = malloc(len);
        if (!data) {
            printf("Unable to allocate space for data\n");
            continue;
        }

        if(receive_message(data, len) < 0) {
            printf("Unable to read data\n");
            free(data);
            continue;
        }

        Message_struct msg = {.content = data, .size = len};

        pthread_mutex_lock(&queue_lock);
        if(enqueue(&receiving_queue, &msg) < 0) {
            pthread_mutex_unlock(&queue_lock);
            printf("Unable to enqueue\n");
            free(msg.content);
            continue;
        }
        pthread_mutex_unlock(&queue_lock);
    }
    return NULL;
}

void destroy() {
    end = true;
    #if defined(Serial)
        return; // Do nothing
    #else 
        mqtt_destroy();
    #endif
}
