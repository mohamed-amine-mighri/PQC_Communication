<!-- PQC Signature Implementation Prompt for ML-KEM-IOT Project -->

# PQC Signature Testing on Particle Argon via MQTT

## Objective
Implement a PQC signature scheme (ML-DSA) using the same MQTT communication pattern established for ML-KEM key exchange. Test message signing and verification across two Argon devices.

## Architecture & Design Principles

### Reuse Existing MQTT Logic
- **DO NOT** create new transport mechanisms—reuse `transport.h` and `MQTT_communication.cpp`
- **DO NOT** change broker configuration (192.168.0.11:1883) or queue abstractions
- Leverage the working message queue system and byte-stream handling
- Use the same threading model (receiveThread, mainThread)

### Protocol Pattern (Mirror ML-KEM)
1. **Handshake**: READY/ACK negotiation (existing pattern)
2. **Key Generation** (Signer/Server):
   - Generate signing keypair (public key + secret key)
   - Send public key to verifier
3. **Message Signing** (Signer):
   - Receive message from verifier
   - Sign the message
   - Send signature back
4. **Verification** (Verifier/Client):
   - Request public key from signer
   - Send message to be signed
   - Receive signature
   - Verify signature against message
5. **Result Exchange**:
   - Send verification result (pass/fail) back to signer

### Message Topics (New)
```
signature/client_send   → Client sends requests (PK request, message to sign)
signature/server_send   → Server sends responses (public key, signature, verification result)
```

### Data Wire Format
All cryptographic payloads use **2-byte length header** (same as ML-KEM):
```
[high_byte][low_byte][...crypto data...]
```

## Implementation Steps

### Step 1: Determine Signature Variant
- [ ] Choose ML-DSA variant (512, 768, or 1024)
- [ ] Verify availability in `components/mlkem/` or external PQC library
- [ ] Document variant selection rationale

### Step 2: Create Signature-Specific Headers
- [ ] `src/signature_transport.h` - Function declarations (mirror transport.h pattern)
- [ ] `src/signature_mqtt.cpp` - MQTT topic subscriptions & callback routing
- [ ] `src/benchmark_signature.h` - Optional benchmark declarations

### Step 3: Implement Signature Exchange Logic
- [ ] `src/signature_main.cpp` OR update `main.cpp` with `#define SIGNATURE_MODE`
  - Signer flow: keygen → wait message → sign → send signature
  - Verifier flow: request pk → send message → receive signature → verify
- [ ] Use `receive_queue_get()` for synchronous message handling (proven robust)
- [ ] Implement 2-byte header packing/unpacking for crypto payloads

### Step 4: Benchmarking (Conditional)
If benchmarking is desired:
- [ ] `src/benchmark_signature.cpp` - Measure signing/verification times
- [ ] Include memory usage, latency per operation
- [ ] Use same JSON output format as existing benchmarks
- [ ] **Optional**: `scripts/capture_signature_results.py` for result capture

### Step 5: Code Cleanup
- [ ] **CRITICAL**: Remove all unused benchmarking code:
  - Dead code in `benchmark.cpp` that's never called
  - Unused benchmark flags or macros
  - Obsolete counter variables or timing structs
  - Comment out or delete unused script files
- [ ] Verify compilation with no warnings

### Step 6: Testing & Documentation
- [ ] Create `SIGNATURE_GUIDE.md` with usage instructions
- [ ] Document compile/flash/run steps with signature mode enabled
- [ ] Add test scenario to README.md

## Code Style & Requirements

### Must Follow
- Particle Device OS APIs only (no FreeRTOS, no ESP-IDF)
- Thread-safe message queue (use existing receive_queue interface)
- Explicit thread stacks to prevent hard-faults
- Serial logging at key milestones (READY, ACK, keygen done, signature verified, etc.)
- 2-byte length headers on all cryptographic messages

### Must NOT Do
- Create new MQTT client or change broker config
- Add blocking delays in receive_task
- Modify existing transport.h interface
- Use malloc/free without corresponding cleanup
- Add dependencies not in components/ or lib/

### Preferred Patterns
```cpp
// Good: Reuse existing queue pattern
message_struct_t msg;
if (receive_queue_get(&msg, 5000)) {
    // Process msg.content (size = msg.size)
    free(msg.content);
}

// Good: Reuse send pattern with 2-byte header
send_message(signature, MLPKCS_SIGNATUREBYTES);

// BAD: Don't create parallel MQTT client
MQTT alt_client(...);

// BAD: Don't block main thread
while(!done) delay(1000);  // Use queue timeouts instead
```

## Cleanup Checklist

### Benchmarking Code to Remove
- [ ] Unused benchmark functions in `benchmark.cpp`
- [ ] Dead benchmark flags (`BENCHMARK_ITERATIONS`, etc.) if not used for signatures
- [ ] Obsolete timing variables or measurement structs
- [ ] Script files that are no longer called (`capture_benchmark.py`, if unused)
- [ ] Test results or sample outputs no longer relevant

### Validation
- [ ] `particle compile .` with no errors
- [ ] No compiler warnings for unused variables/functions
- [ ] Build output size reduced (if applicable)
- [ ] Serial output clean (no debug spam from old code)

## Success Criteria

✅ Two Argon devices exchange signed messages via MQTT  
✅ Signer generates keypair, receives message, produces signature  
✅ Verifier retrieves public key, sends message, verifies signature  
✅ All crypto payloads use 2-byte length header (consistent with ML-KEM)  
✅ No unused benchmarking code remains  
✅ Documentation explains the signature protocol flow  
✅ Code compiles without warnings

## Reference Architecture (Existing ML-KEM)

See these files as the pattern to follow:
- `src/transport.h` - Message queue abstraction
- `src/MQTT_communication.cpp` - Topic subscription & routing
- `src/main.cpp` (sections marked `#elif defined(client)` / `#elif defined(server)`)
- `src/benchmark_mqtt.cpp` - If benchmarking is added

---

**Note**: This prompt guides implementation of **PQC signatures ONLY**. Do not mix with ML-KEM key exchange logic unless explicitly extending a combined protocol.
