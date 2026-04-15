#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_SIZE 10

typedef struct {
    uint8_t* content;
    uint16_t size;
} Message_struct;


typedef struct {
    Message_struct* array[MAX_SIZE];
    int front;
    int back;
    int size;
} Queue;

void initializeQueue(Queue* q);

bool isEmpty(Queue* q);

bool isFull(Queue* q);

int enqueue(Queue* q, Message_struct* msg);

Message_struct* dequeue(Queue* q);

Message_struct* peak(Queue* q);

#endif