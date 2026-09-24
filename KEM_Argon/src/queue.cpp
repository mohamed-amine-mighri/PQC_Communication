// Thread-safe queue abstraction for Particle Argon
#include "transport.h"
#include <queue>
#include <mutex>
#include <atomic>
#include "Particle.h"

static std::queue<message_struct_t> msg_queue;
static std::mutex queue_mutex;
volatile bool initialized = false;

extern "C" {
    void receive_queue_push(message_struct_t *msg) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        msg_queue.push(*msg);
    }

    bool receive_queue_get(message_struct_t *msg, uint32_t timeout_ms) {
        unsigned long start = millis();
        while (true) {
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                if (!msg_queue.empty()) {
                    *msg = msg_queue.front();
                    msg_queue.pop();
                    return true;
                }
            }
            if (timeout_ms == 0) return false;
            unsigned long elapsed = millis() - start;
            if (elapsed > timeout_ms) return false;
            delay(10);
        }
    }
}
