#include "Particle.h"
#include "../inc/dsa.h"

SYSTEM_MODE(SEMI_AUTOMATIC);
SYSTEM_THREAD(ENABLED);

void setup() {
    Serial.begin(9600);
    delay(2000);
    
    Serial.println("=== Argon RSA Test Starting ===");
    
    // Test RSA
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    size_t pk_len, sk_len, sig_len;
    
    Serial.println("1. Allocation...");
    alloc_space_for_dsa(&pk, &sk, &pk_len, &sk_len, &sig_len);
    
    if (pk && sk) {
        Serial.printf("   OK: pk=%d, sk=%d, sig_max=%d\n", pk_len, sk_len, sig_len);
        
        Serial.println("2. Génération des clés...");
        int ret = dsa_keygen(pk, sk);
        Serial.printf("   Résultat: %d\n", ret);
        
        Serial.println("3. Signature...");
        uint8_t msg[32] = {0};
        uint8_t sig[256];
        size_t sig_out_len = 0;
        
        for(int i = 0; i < 32; i++) msg[i] = i;
        
        ret = dsa_signature(sig, &sig_out_len, msg, 32, sk);
        Serial.printf("   Signature: %d bytes, ret=%d\n", sig_out_len, ret);
        
        Serial.println("4. Vérification...");
        ret = dsa_verify(sig, sig_out_len, msg, 32, pk);
        Serial.printf("   Vérification: %s\n", ret == 0 ? "OK" : "ECHEC");
        
        Serial.println("5. Libération...");
        free_space_for_dsa(pk, sk);
    } else {
        Serial.println("   ERREUR: allocation échouée");
    }
    
    Serial.println("=== Test Complete ===");
}

void loop() {
    delay(1000);
}
