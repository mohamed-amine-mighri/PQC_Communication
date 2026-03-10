#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Simple ACK structure used by mqtt_tx_roundtrip().
   If you already have a different definition, keep yours and remove this. */
typedef struct {
    uint32_t seq;          /* sequence echoed by peer */
    uint32_t code;         /* application-specific status */
    uint64_t t_ns;         /* optional timestamp (e.g., send/recv time) */
    uint32_t t_unmask_us;  /* optional: Bob's unmask time in microseconds */
    uint32_t reserved;     /* keep 0; future use / alignment */
} ack_t;

/* Opaque MQTT client handle */
struct mqtt_client;

/* Connect and bind default subscribe/publish topics.
   - client_id : MQTT client identifier
   - host, port: broker address
   - topic_sub : default topic to read from (may be NULL if unused)
   - topic_pub : default topic to publish to (may be NULL if unused)
*/
struct mqtt_client* mqtt_connect_simple(const char *client_id,
                                        const char *host, int port,
                                        const char *topic_sub,
                                        const char *topic_pub);

/* Stop loop, disconnect and free resources */
void mqtt_disconnect_simple(struct mqtt_client* c);

/* Monotonic clock and sleep helpers (exported by transport) */
uint64_t now_ns(void);
void     msleep(unsigned ms);

/* Round-trip helper with ACK (existing API) */
int mqtt_tx_roundtrip(struct mqtt_client* c,
                      const uint8_t* payload, size_t len,
                      uint32_t seq, int ack_timeout_ms,
                      ack_t* ack_out);

/* New: raw publish/receive on the default topics set at connect */
int mqtt_pub_raw (struct mqtt_client* c, const void* buf, size_t len);
/* Blocking read of exactly want_len bytes from topic_sub (timeout ms) */
int mqtt_read_raw(struct mqtt_client* c, void* out, size_t want_len, int timeout_ms);

#ifdef __cplusplus
}
#endif
