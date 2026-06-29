#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "queue.h"

extern Queue receiving_queue;
extern pthread_mutex_t queue_lock;

int setup(void);
int send_message(const uint8_t* data, size_t len);
int receive_message(uint8_t* data, size_t len);
void* receive_task(void* arg);
void destroy(void);

void transport_set_role(bool is_alice);

#endif