// transport_mqtt.c
// Minimal MQTT transport layer built on libmosquitto, with
// blocking reads, round-trip ACK helper, and monotonic timing.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <mosquitto.h>

#include "transport_mqtt.h"

#ifndef likely
#  define likely(x)   __builtin_expect(!!(x),1)
#  define unlikely(x) __builtin_expect(!!(x),0)
#endif

// ---------- Monotonic clock & sleep ----------
uint64_t now_ns(void) {
    struct timespec ts;
#if defined(CLOCK_MONOTONIC_RAW)
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
void msleep(unsigned ms) {
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {}
}

// ---------- Internal client state ----------
struct ringbuf {
    uint8_t *data;
    size_t   size;   // allocated
    size_t   used;   // bytes stored
};

struct mqtt_client {
    struct mosquitto *m;
    char *topic_sub;
    char *topic_pub;

    // Incoming data buffer (non-ACK frames)
    struct ringbuf     rb;
    pthread_mutex_t    rb_mu;
    pthread_cond_t     rb_cv;

    // ACK waiting area
    bool               ack_waiting;
    uint32_t           ack_wait_seq;
    bool               ack_ready;
    ack_t              ack;

    pthread_mutex_t    ack_mu;
    pthread_cond_t     ack_cv;
};

// ---------- Ring buffer helpers (simple growable FIFO) ----------
static void rb_init(struct ringbuf *rb) {
    rb->data = NULL; rb->size = 0; rb->used = 0;
}
static void rb_free(struct ringbuf *rb) {
    free(rb->data); rb->data = NULL; rb->size = rb->used = 0;
}
static void rb_push(struct ringbuf *rb, const uint8_t *src, size_t len) {
    if (len == 0) return;
    if (rb->size - rb->used < len) {
        size_t need = rb->used + len;
        size_t cap  = rb->size ? rb->size : 1024;
        while (cap < need) cap *= 2;
        rb->data = (uint8_t*)realloc(rb->data, cap);
        rb->size = cap;
    }
    memcpy(rb->data + rb->used, src, len);
    rb->used += len;
}
static size_t rb_pop(struct ringbuf *rb, uint8_t *dst, size_t want) {
    if (rb->used == 0 || want == 0) return 0;
    size_t take = (want < rb->used) ? want : rb->used;
    memcpy(dst, rb->data, take);
    // shift remaining
    memmove(rb->data, rb->data + take, rb->used - take);
    rb->used -= take;
    return take;
}

// ---------- Mosquitto callbacks ----------
static void on_message(struct mosquitto *m, void *userdata,
                       const struct mosquitto_message *msg)
{
    (void)m;
    struct mqtt_client *c = (struct mqtt_client*)userdata;
    if (!c || !msg || !msg->payload || msg->payloadlen <= 0) return;

    // Heuristic: if payload matches an ack_t size, treat as ACK frame.
    if ((size_t)msg->payloadlen == sizeof(ack_t)) {
        ack_t ack;
        memcpy(&ack, msg->payload, sizeof(ack));
        pthread_mutex_lock(&c->ack_mu);
        if (c->ack_waiting && ack.seq == c->ack_wait_seq) {
            c->ack = ack;
            c->ack_ready = true;
            c->ack_waiting = false;
            pthread_cond_broadcast(&c->ack_cv);
            pthread_mutex_unlock(&c->ack_mu);
            return;
        }
        pthread_mutex_unlock(&c->ack_mu);
        // Fall through: if it's not our pending ACK, let consumer treat it as data.
    }

    // Otherwise store in raw RX buffer
    pthread_mutex_lock(&c->rb_mu);
    rb_push(&c->rb, (const uint8_t*)msg->payload, (size_t)msg->payloadlen);
    pthread_cond_broadcast(&c->rb_cv);
    pthread_mutex_unlock(&c->rb_mu);
}

static void on_connect(struct mosquitto *m, void *userdata, int rc) {
    (void)m; (void)userdata;
    if (rc == MOSQ_ERR_SUCCESS) {
        // ok
    } else {
        fprintf(stderr, "[mqtt] connect failed: rc=%d\n", rc);
    }
}

// ---------- Public API ----------
struct mqtt_client* mqtt_connect_simple(const char *client_id,
                                        const char *host, int port,
                                        const char *topic_sub,
                                        const char *topic_pub)
{
    static bool lib_inited = false;
    if (!lib_inited) { mosquitto_lib_init(); lib_inited = true; }

    struct mqtt_client *c = (struct mqtt_client*)calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->m = mosquitto_new(client_id, true, c);
    if (!c->m) { free(c); return NULL; }

    mosquitto_connect_callback_set(c->m, on_connect);
    mosquitto_message_callback_set(c->m, on_message);

    int rc = mosquitto_connect(c->m, host, port, /*keepalive*/60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[mqtt] connect %s:%d failed: %s\n", host, port, mosquitto_strerror(rc));
        mosquitto_destroy(c->m); free(c); return NULL;
    }

    if (topic_sub) c->topic_sub = strdup(topic_sub);
    if (topic_pub) c->topic_pub = strdup(topic_pub);

    rb_init(&c->rb);
    pthread_mutex_init(&c->rb_mu, NULL);
    pthread_cond_init(&c->rb_cv, NULL);

    pthread_mutex_init(&c->ack_mu, NULL);
    pthread_cond_init(&c->ack_cv, NULL);
    c->ack_waiting = false; c->ack_ready = false;

    // Start network loop
    rc = mosquitto_loop_start(c->m);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[mqtt] loop_start failed: %s\n", mosquitto_strerror(rc));
        mqtt_disconnect_simple(c);
        return NULL;
    }

    if (c->topic_sub) {
        rc = mosquitto_subscribe(c->m, NULL, c->topic_sub, /*qos*/0);
        if (rc != MOSQ_ERR_SUCCESS) {
            fprintf(stderr, "[mqtt] subscribe '%s' failed: %s\n", c->topic_sub, mosquitto_strerror(rc));
            mqtt_disconnect_simple(c);
            return NULL;
        }
    }

    return c;
}

void mqtt_disconnect_simple(struct mqtt_client* c)
{
    if (!c) return;
    if (c->m) {
        mosquitto_loop_stop(c->m, true);
        mosquitto_disconnect(c->m);
        mosquitto_destroy(c->m);
    }
    free(c->topic_sub);
    free(c->topic_pub);

    pthread_mutex_destroy(&c->rb_mu);
    pthread_cond_destroy(&c->rb_cv);
    rb_free(&c->rb);

    pthread_mutex_destroy(&c->ack_mu);
    pthread_cond_destroy(&c->ack_cv);

    free(c);
}

int mqtt_pub_raw(struct mqtt_client* c, const void* buf, size_t len)
{
    if (!c || !c->m || !c->topic_pub || !buf || len == 0) return -1;
    int rc = mosquitto_publish(c->m, NULL, c->topic_pub,
                               (int)len, buf, /*qos*/0, /*retain*/false);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[mqtt] publish failed: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    return 0;
}

int mqtt_read_raw(struct mqtt_client* c, void* out, size_t want_len, int timeout_ms)
{
    if (!c || !out || want_len == 0) return -1;

    uint8_t *dst = (uint8_t*)out;
    size_t copied = 0;
    uint64_t deadline = (timeout_ms >= 0) ? now_ns() + (uint64_t)timeout_ms * 1000000ull : 0;

    pthread_mutex_lock(&c->rb_mu);
    while (copied < want_len) {
        // Attempt to pop what's available
        size_t got = rb_pop(&c->rb, dst + copied, want_len - copied);
        copied += got;
        if (copied >= want_len) break;

        // Wait for more
        if (timeout_ms >= 0) {
            uint64_t now = now_ns();
            if (now >= deadline) break;
            // Convert remaining time to timespec
            uint64_t rem_ns = deadline - now;
            struct timespec ts;
            ts.tv_sec  = rem_ns / 1000000000ull;
            ts.tv_nsec = rem_ns % 1000000000ull;
            int rc = 0;
            rc = pthread_cond_timedwait(&c->rb_cv, &c->rb_mu, &ts);
            if (rc == ETIMEDOUT) break;
        } else {
            pthread_cond_wait(&c->rb_cv, &c->rb_mu);
        }
    }
    pthread_mutex_unlock(&c->rb_mu);

    return (copied == want_len) ? (int)copied : -2; // -2 indicates timeout/short read
}

// Helper that assumes peer will publish an ack_t (binary) on topic_sub.
// We use 'seq' to match the response.
int mqtt_tx_roundtrip(struct mqtt_client* c,
                      const uint8_t* payload, size_t len,
                      uint32_t seq, int ack_timeout_ms,
                      ack_t* ack_out)
{
    if (!c || !payload || len == 0 || !ack_out) return -1;
    if (!c->topic_pub || !c->topic_sub) {
        fprintf(stderr, "[mqtt] roundtrip requires both pub and sub topics\n");
        return -1;
    }

    // Publish request
    int rc = mosquitto_publish(c->m, NULL, c->topic_pub,
                               (int)len, payload, /*qos*/0, /*retain*/false);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[mqtt] publish failed: %s\n", mosquitto_strerror(rc));
        return -1;
    }

    // Wait for ACK with matching seq
    uint64_t deadline = (ack_timeout_ms >= 0) ? now_ns() + (uint64_t)ack_timeout_ms * 1000000ull : 0;

    pthread_mutex_lock(&c->ack_mu);
    c->ack_waiting  = true;
    c->ack_wait_seq = seq;
    c->ack_ready    = false;

    while (!c->ack_ready) {
        if (ack_timeout_ms >= 0) {
            uint64_t now = now_ns();
            if (now >= deadline) { c->ack_waiting = false; break; }
            uint64_t rem_ns = deadline - now;
            struct timespec ts;
            ts.tv_sec  = rem_ns / 1000000000ull;
            ts.tv_nsec = rem_ns % 1000000000ull;
            int wrc = pthread_cond_timedwait(&c->ack_cv, &c->ack_mu, &ts);
            if (wrc == ETIMEDOUT) { c->ack_waiting = false; break; }
        } else {
            pthread_cond_wait(&c->ack_cv, &c->ack_mu);
        }
    }

    if (c->ack_ready) {
        *ack_out = c->ack;
        c->ack_ready = false;
        pthread_mutex_unlock(&c->ack_mu);
        return 0;
    } else {
        pthread_mutex_unlock(&c->ack_mu);
        return -2; // timeout
    }
}
