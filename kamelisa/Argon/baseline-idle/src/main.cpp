#include "Particle.h"

// ============================================================
//  IDLE BASELINE FIRMWARE for PPK2 current measurement
//  - Joins WiFi (same radio state as the real Bob test)
//  - Does NO crypto, NO MQTT, NO ML-KEM rounds
//  - Just sits connected and idle so the PPK2 records the
//    board's baseline current draw.
//  Subtract this baseline from your active FALCON/ML-KEM run.
// ============================================================

SYSTEM_MODE(MANUAL);           // do NOT connect to WiFi or cloud
SYSTEM_THREAD(ENABLED);

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n=== IDLE BASELINE FIRMWARE (WiFi OFF) ===");
    Serial.println("No WiFi, no crypto, no MQTT. Pure MCU idle baseline.");

    // Force the WiFi radio fully off so we see the bare board draw.
    WiFi.off();

    Serial.println("Radio off. Read the PPK2 average current as your baseline.");
}

void loop() {
    // Do absolutely nothing — this is the baseline.
    delay(1000);
}
