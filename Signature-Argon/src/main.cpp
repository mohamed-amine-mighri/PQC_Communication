#include "Particle.h"
#include "bench_local.h"

SYSTEM_MODE(MANUAL);
SYSTEM_THREAD(ENABLED);

Thread *benchThread = nullptr;

void run_local_benchmark() {
    Serial.println("==================================");
    Serial.println(" Particle Argon PQC Local Benchmark");
    Serial.println("==================================");

    run_bench_local();
}

void bench_task(void *) {
    Serial.println("[ARGON] bench thread started");
    run_local_benchmark();
    Serial.println("[ARGON] bench thread finished");
}

void setup() {
    Serial.begin(115200);
    waitUntil(Serial.isConnected);
    delay(1000);

    Serial.printf("[ARGON] reset reason = %d\n", (int)System.resetReason());

    benchThread = new Thread(
        "bench",
        bench_task,
        NULL,
        OS_THREAD_PRIORITY_DEFAULT,
        65536
    );
}

void loop() {
}