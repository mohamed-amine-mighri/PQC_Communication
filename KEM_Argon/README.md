# ML-KEM Argon Project

This project implements ML-KEM post-quantum cryptography with MQTT-based key exchange on the Particle Argon platform (nRF52840 + ESP32 WiFi coprocessor) using Particle Device OS.

## Features
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key encapsulation and shared secret exchange
- MQTT communication for secure handshake
- UART/Serial diagnostics
- WiFi connectivity via Particle Device OS
- Dynamic key size handling (client auto-detects variant from server)
- Chunked receive for large key payloads
- Thread-safe queue for inter-thread MQTT message delivery
- Automatic shared secret comparison and validation

## Project Structure
```
src/
  ├── main.cpp                 # Client handshake logic & entry point
  ├── MQTT_communication.cpp   # MQTT transport & publish/subscribe
  ├── queue.cpp               # Thread-safe message queue
  ├── transport.h             # Transport layer interface
  ├── mlkem.h                 # ML-KEM wrapper definitions
  └── UART_communication.cpp  # Serial diagnostics

components/
  └── mlkem/
      ├── clean512/           # ML-KEM-512 reference implementation
      ├── clean768/           # ML-KEM-768 (included)
      ├── clean1024/          # ML-KEM-1024 (included)
      └── include/mlkem.h     # Common header
```

## Prerequisites
- **Particle Argon** device with USB connection
- **Particle CLI** installed (`npm install -g particle-cli`)
- **MQTT Broker** (Mosquitto, HiveMQ, etc.) running on your network
- **WiFi Network** with known SSID and password

## Setup Instructions

### 1. Configure WiFi on Argon

First, configure the WiFi credentials on your Argon device:

```bash
particle serial wifi --port COM3
```

Follow the prompts to:
- Enter your WiFi **SSID** (network name)
- Enter your WiFi **password**
- Select the **security type** (WPA2, WPA3, Open, etc.)

The device will attempt to connect automatically. Verify connection with:

```bash
particle serial monitor --port COM3
```

You should see:
```
WiFi connected!
Transport initialized!
```

### 2. Set Up MQTT Broker for Testing

#### Option A: Local Testing with Laptop as MQTT Broker

If you're testing with the MQTT broker running on your laptop:

1. **Install Mosquitto** (or your preferred MQTT broker)
   - Windows: Download from [mosquitto.org](https://mosquitto.org/download/)
   - Linux: `sudo apt install mosquitto mosquitto-clients`
   - macOS: `brew install mosquitto`

2. **Start the MQTT Broker**
   ```bash
   mosquitto -p 1883
   ```

3. **Enable Port Forwarding** (so Argon can reach laptop's MQTT)
   
   The Argon currently connects to `192.168.0.14:1883`. Update this to your laptop's IP:
   
   - Edit [src/MQTT_communication.cpp](src/MQTT_communication.cpp) line 45:
   ```cpp
   // OLD:
   MQTT client("192.168.0.14", 1883, MQTT_PACKET_SIZE, mqtt_callback);
   
   // NEW (replace with your laptop's IP):
   MQTT client("192.168.X.X", 1883, MQTT_PACKET_SIZE, mqtt_callback);
   ```
   
   Find your laptop's IP address:
   - **Windows**: `ipconfig` → Look for "IPv4 Address" (e.g., 192.168.1.100)
   - **Linux/macOS**: `ifconfig` → Look for inet address on your WiFi interface

4. **Recompile and Flash**
   ```bash
   particle compile argon .
   particle flash e00fce68e5febe30d84dcf3d argon_firmware_*.bin
   ```

#### Option B: Remote MQTT Broker

Use a cloud MQTT broker (HiveMQ Cloud, Adafruit IO, etc.):
- Update the IP/hostname and port in `src/MQTT_communication.cpp` line 45
- Ensure the Argon has internet connectivity to reach the broker

### 3. Build and Flash the Firmware

```bash
# Compile for Argon
particle compile argon .

# Flash to device (replace with your device ID)
particle flash e00fce68e5febe30d84dcf3d argon_firmware_*.bin

# Monitor serial output
particle serial monitor --port COM3
```

## MQTT Communication Protocol

### Topics
- **Client → Server**: `mlkem/esp32/client_send`
  - Sends: READY (5 bytes) → Ciphertext (768 bytes raw, or 770 bytes framed)
  
- **Server → Client**: `mlkem/esp32/server_send`
  - Sends: ACK (3 bytes) → Public Key (802 bytes framed) → Shared Secret (34 bytes framed)

### Message Format
- **Control Messages**: Plain text (ACK, READY)
- **Data Frames**: 
  - Framed: `[length_hi][length_lo][payload...]`
  - Raw: `[payload...]` (ciphertext only, with 5-second fallback to framed)

## Running the Handshake

### Expected Serial Output

**Client (Argon):**
```
====================
Starting ML-KEM Argon
====================
Reset reason: 70
Waiting for WiFi...
WiFi connected!
Transport initialized!
Starting threads...
Running as client. ML-KEM-512
Sending READY...
Waiting for ACK...
Setup complete!
Got ACK from server! ✓
[HANDSHAKE] Waiting for public key message
[HANDSHAKE] pk_len=800
[HANDSHAKE] Public key received
[HANDSHAKE] Starting encapsulation
[HANDSHAKE] Encapsulation done
[HANDSHAKE] Ciphertext sent (raw)
[HANDSHAKE] Waiting for shared secret message
Shared secrets match!
```

### Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| "WiFi not ready" | No WiFi credentials | Run `particle serial wifi` to configure |
| "Transport init timeout!" | MQTT broker unreachable | Verify broker IP/port, check firewall |
| "No ACK, still waiting..." | Server not sending ACK | Ensure server is running and subscribed to topic |
| "Timeout waiting for public key" | Server not sending public key | Check server logs, verify MQTT connection |
| "Shared secrets do NOT match!" | Protocol mismatch | Ensure both sides use same ML-KEM variant |

## Implementation Notes

- **Thread Safety**: Queue uses `std::mutex` for inter-thread synchronization
- **Memory**: Main task stack allocated 24576 bytes (24KB) — required for Kyber768/1024 encapsulation
- **MQTT Buffer**: Set to 2048 bytes to accommodate all three variant payloads + MQTT overhead
- **Timeouts**: ACK wait = 5s, Public key = 10s, Shared secret = 5-10s (with fallback)
- **ESP-IDF Removed**: Uses only Particle Device OS APIs and C++ STL

## Switching Between ML-KEM Variants (512, 768, 1024)

To run a different Kyber variant, you need to change **three files**. The client automatically handles any key size sent by the server, but it must be compiled with the matching crypto implementation.

### 1. Select the variant in `lib/mlkem/src/mlkem_config.h`

Uncomment the desired variant and comment out the others:

```c
// Uncomment ONE of the following:
//#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME   // Kyber-512
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_ALGNAME    // Kyber-768 (current)
//#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_ALGNAME  // Kyber-1024
```

### 2. Update the implementation includes in `lib/mlkem/src/mlkem_impl.cpp` and `lib/mlkem/src/mlkem_impl.c`

Change all `clean768` paths to match your variant (`clean512`, `clean768`, or `clean1024`):

```cpp
// Example for Kyber-768:
#include "../../../components/mlkem/clean768/params.h"
#include "../../../components/mlkem/clean768/api.h"
// ... all other includes ...
#include "../../../components/mlkem/clean768/verify.c"
```

### 3. Update the wrapper functions in `lib/mlkem/src/mlkem.cpp` and `lib/mlkem/src/mlkem_internal.h`

Change the function name prefix to match the variant:

| Variant | Function prefix |
|---------|----------------|
| ML-KEM-512 | `PQCLEAN_MLKEM512_CLEAN_crypto_kem_*` |
| ML-KEM-768 | `PQCLEAN_MLKEM768_CLEAN_crypto_kem_*` |
| ML-KEM-1024 | `PQCLEAN_MLKEM1024_CLEAN_crypto_kem_*` |

### 4. Update `src/mlkem.h` include path

Change the `api.h` include to the matching variant directory:

```c
#include "../components/mlkem/clean768/api.h"  // Change clean768 to clean512 or clean1024
```

### Key sizes by variant

| Variant | Public Key | Ciphertext | Shared Secret | MQTT Buffer Needed |
|---------|-----------|------------|---------------|-------------------|
| ML-KEM-512 | 800 B | 768 B | 32 B | ~850 B |
| ML-KEM-768 | 1184 B | 1088 B | 32 B | ~1250 B |
| ML-KEM-1024 | 1568 B | 1568 B | 32 B | ~1650 B |

### Changes required for multi-variant support

The following changes were made to enable all three Kyber variants to work:

1. **MQTT buffer size increased** (`src/MQTT_communication.cpp`): Changed from 1200 to **2048 bytes** — the default 1200 was too small for Kyber768 (1186 bytes payload + MQTT overhead = ~1217 bytes, silently dropped by the library).

2. **Main thread stack size increased** (`src/main.cpp`): Changed from 12288 to **24576 bytes (24KB)** — Kyber768/1024 encapsulation uses significantly more stack than Kyber512, causing hard-fault resets.

3. **Dynamic key size handling** (`src/main.cpp`): The client reads the 2-byte length header from the server's message and dynamically allocates the public key and ciphertext buffers based on the received size, rather than using compile-time constants. This allows the same client logic to work with any variant.

4. **Chunked receive** (`src/main.cpp`): Public key and shared secret are received using chunked reads — the client reads header bytes first, then accumulates payload chunks until the full key/secret is received. This handles cases where large messages may arrive in parts.

5. **Ciphertext size derived from public key size** (`src/main.cpp`): The ciphertext buffer size is determined from the received public key size (800→768, 1184→1088, 1568→1568).

6. **Double-free bug fixed** (`src/main.cpp`): Removed a duplicate `free(ss_msg.content)` that caused a crash when processing the shared secret response.

## Future Improvements

- [ ] Add TLS/certificate validation
- [ ] Support other transport protocols (LoRaWAN, BLE)
- [ ] Performance optimization for embedded systems
- [ ] Add error recovery and reconnection logic

## References

- [ML-KEM Specification](https://csrc.nist.gov/pubs/detail/fips/203/final)
- [Particle Device OS Documentation](https://docs.particle.io/)
- [MQTT Protocol](https://mqtt.org/)
- [Mosquitto MQTT Broker](https://mosquitto.org)
