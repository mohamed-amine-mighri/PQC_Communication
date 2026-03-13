# ML-KEM Argon Project

This project implements ML-KEM post-quantum cryptography with MQTT-based key exchange on the Particle Argon platform (nRF52840 + ESP32 WiFi coprocessor) using Particle Device OS.

## Features
- ML-KEM-512 key encapsulation and shared secret exchange
- MQTT communication for secure handshake
- UART/Serial diagnostics
- WiFi connectivity via Particle Device OS
- Dual-format ciphertext transmission (raw + framed fallback)
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
- **Memory**: Main task stack allocated 12288 bytes (ML-KEM ops are stack-heavy)
- **Timeouts**: ACK wait = 5s, Public key = 10s, Shared secret = 5-10s (with fallback)
- **Current ML-KEM Variant**: ML-KEM-512 (800B public key, 768B ciphertext, 32B shared secret)
- **ESP-IDF Removed**: Uses only Particle Device OS APIs and C++ STL

## Future Improvements

- [ ] Implement ML-KEM-768 and ML-KEM-1024 variants
- [ ] Add TLS/certificate validation
- [ ] Support other transport protocols (LoRaWAN, BLE)
- [ ] Performance optimization for embedded systems
- [ ] Add error recovery and reconnection logic

## References

- [ML-KEM Specification](https://csrc.nist.gov/pubs/detail/fips/203/final)
- [Particle Device OS Documentation](https://docs.particle.io/)
- [MQTT Protocol](https://mqtt.org/)
- [Mosquitto MQTT Broker](https://mosquitto.org)
