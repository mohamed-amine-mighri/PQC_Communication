#include "queue.h"
#include <stdio.h>

void initializeQueue(Queue* q) {
    q->back = 0;
    q->front = 0;
    q->size = 0;
}

bool isEmpty(Queue* q) {
    if (q->size == 0) return true;
    return false;
}

bool isFull(Queue* q) {
    if(q->size >= MAX_SIZE) return true;
    return false;
}

int enqueue(Queue* q, Message_struct* msg) {
    if(isFull(q)) {
        printf("Queue full\n");
        return -1;
    }
    q->size++;
    q->array[q->back] = msg;
    q->back = (q->back + 1) % MAX_SIZE;
    return 0;
}

Message_struct* dequeue(Queue* q) {
    if (isEmpty(q)) {
        printf("Queue empty\n");
        return NULL;
    }

    q->size--;
    Message_struct* msg = q->array[q->front];
    q->front = (q->front + 1) % MAX_SIZE;
    return msg;
}

Message_struct* peak(Queue* q) {
    if (isEmpty(q)) {
        printf("Queue empty\n");
        return NULL;
    }

    return q->array[q->front];
}