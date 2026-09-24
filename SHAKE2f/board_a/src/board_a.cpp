#include "Particle.h"
#include "MQTT.h"

extern "C" {
#include "api.h"
}

SYSTEM_MODE(SEMI_AUTOMATIC);
SYSTEM_THREAD(ENABLED);

SerialLogHandler logHandler(LOG_LEVEL_INFO);

void mqttCallback(char* topic, byte* payload, unsigned int length);
void signMessage();

// Buffer sized to fit hex-encoded signature (~4840 chars) + MQTT overhead
MQTT client("test.mosquitto.org", 1883, 5000, mqttCallback);

char clientId[32];

// --------------------------------------------------
// Trigger pins (for scope/logic-analyzer timing)
//
// D2 -> HIGH during key generation
// D3 -> HIGH during signing
// D4 -> HIGH from start of public key send until PK_ACK received
// D5 -> HIGH from start of message send until MSG_ACK received
// D6 -> HIGH from start of signature send until SIG_ACK received
// --------------------------------------------------

#define TRIG_KEYGEN   D2
#define TRIG_SIGN     D3
#define TRIG_PUBKEY   D4
#define TRIG_MSG      D5
#define TRIG_SIG      D6

// --------------------------------------------------
// Cycle state
// --------------------------------------------------

volatile bool cycleActive = false;
volatile bool keysGenerated = false;
volatile bool keygenRequested = false;
volatile bool signingCompleted = false;
volatile bool signRequested = false;
bool publicKeySent = false;
bool ackReceived = false;
bool messageSent = false;
bool msgAckReceived = false;
bool signatureSent = false;
bool sigAckReceived = false;

uint32_t cycleCount = 0;

// key buffers
uint8_t pk[PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t sk[PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];

// Signature buffer
uint8_t sig[PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES];
size_t sigLen = 0;

// Message to be signed
const uint8_t message[] = "hello from board_a";
const size_t messageLen = sizeof(message) - 1;

// Hex buffers for publishing
char pkHex[PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES * 2 + 1];
char sigHex[PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES * 2 + 1];

// --------------------------------------------------
// Signature chunking (sent over MQTT as multiple small messages
// instead of one giant ~34KB message, because the MQTT library's own
// internal receive buffer on board_b cannot hold a message that
// large. Each chunk is tagged "IIII:<hexdata>" with a 4-digit index
// so board_b can place it at the correct offset.
// --------------------------------------------------

#define SIG_CHUNK_HEX_LEN 4700
#define TOTAL_SIG_HEX_LEN (PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES * 2)
#define TOTAL_SIG_CHUNKS ((TOTAL_SIG_HEX_LEN + SIG_CHUNK_HEX_LEN - 1) / SIG_CHUNK_HEX_LEN)
#define SIG_CHUNK_MSG_MAXLEN (4 + 1 + SIG_CHUNK_HEX_LEN + 1) // "IIII:" + hexdata + '\0'

char sigChunkMsgBuf[SIG_CHUNK_MSG_MAXLEN];

// Timestamp tracking
uint32_t pubKeySendTime = 0;
uint32_t msgSendTime = 0;
uint32_t sigSendTime = 0;

// Small buffer only for short control messages (START, PK_ACK, MSG_ACK, SIG_ACK)
#define CONTROL_MAXLEN 32
char controlMsgBuf[CONTROL_MAXLEN];

// Stack size for the dedicated PQC worker thread (keygen + signing).
// NOTE: this board only has ~55-65KB of free heap available at
// runtime, so the stack size has to fit within that budget alongside
// WiFi/MQTT. 16KB was confirmed working; don't raise this without
// re-checking headroom.
#define KEYGEN_THREAD_STACK_SIZE 16384

// --------------------------------------------------
// Helper: bytes -> hex string
// --------------------------------------------------

void bytesToHex(const uint8_t* bytes, size_t len, char* hexOut) {

    const char hexChars[] = "0123456789ABCDEF";

    for (size_t i = 0; i < len; i++) {
        hexOut[i * 2]     = hexChars[(bytes[i] >> 4) & 0x0F];
        hexOut[i * 2 + 1] = hexChars[bytes[i] & 0x0F];
    }

    hexOut[len * 2] = '\0';
}


// --------------------------------------------------
// Reset all per-cycle state so the pipeline runs again from
// key generation.
// --------------------------------------------------

void startNewCycle() {

    cycleCount++;

    keysGenerated = false;
    keygenRequested = false;
    signingCompleted = false;
    signRequested = false;
    publicKeySent = false;
    ackReceived = false;
    messageSent = false;
    msgAckReceived = false;
    signatureSent = false;
    sigAckReceived = false;

    sigLen = 0;

    cycleActive = true;

    digitalWrite(TRIG_KEYGEN, LOW);
    digitalWrite(TRIG_SIGN, LOW);
    digitalWrite(TRIG_PUBKEY, LOW);
    digitalWrite(TRIG_MSG, LOW);
    digitalWrite(TRIG_SIG, LOW);

    Log.info("===== Starting cycle #%lu =====", cycleCount);
}


// --------------------------------------------------
// MQTT Callback
// --------------------------------------------------

void mqttCallback(char* topic, byte* payload, unsigned int length) {

    if (strcmp(topic, "argon/control") == 0) {

        unsigned int copyLen = length;
        if (copyLen >= CONTROL_MAXLEN) {
            copyLen = CONTROL_MAXLEN - 1;
        }

        memcpy(controlMsgBuf, payload, copyLen);
        controlMsgBuf[copyLen] = '\0';

        Log.info("Received on %s: %s", topic, controlMsgBuf);

        if (strcmp(controlMsgBuf, "START") == 0) {

            startNewCycle();

        } else if (strcmp(controlMsgBuf, "PK_ACK") == 0) {

            if (publicKeySent && !ackReceived) {

                ackReceived = true;
                digitalWrite(TRIG_PUBKEY, LOW);
                uint32_t elapsed = millis() - pubKeySendTime;
                Log.info("PK_ACK received");
                Log.info("Public key send time (send -> ack): %lu ms", elapsed);
            }

        } else if (strcmp(controlMsgBuf, "MSG_ACK") == 0) {

            if (messageSent && !msgAckReceived) {

                msgAckReceived = true;
                digitalWrite(TRIG_MSG, LOW);
                uint32_t elapsed = millis() - msgSendTime;
                Log.info("MSG_ACK received");
                Log.info("Message send time (send -> ack): %lu ms", elapsed);
            }

        } else if (strcmp(controlMsgBuf, "SIG_ACK") == 0) {

            if (signatureSent && !sigAckReceived) {

                sigAckReceived = true;
                digitalWrite(TRIG_SIG, LOW);
                uint32_t elapsed = millis() - sigSendTime;
                Log.info("SIG_ACK received");
                Log.info("Signature send time (send -> ack): %lu ms", elapsed);
                Log.info("===== Cycle #%lu complete =====", cycleCount);
                cycleActive = false;
            }
        }

    } else {

        Log.info("Received on unhandled topic %s (%u bytes)", topic, length);
    }
}


// --------------------------------------------------
// WiFi Connection
// --------------------------------------------------

bool connectWiFi() {

    if (WiFi.ready()) {
        return true;
    }

    Log.info("Connecting to WiFi...");

    WiFi.off();
    delay(1000);

    WiFi.on();
       WiFi.setCredentials("Gintonic", "capitainemassime");
    WiFi.connect();

    for (int i = 0; i < 60; i++) {

        if (WiFi.ready()) {
            Log.info("WiFi connected, IP: %s",
                     WiFi.localIP().toString().c_str());
            return true;
        }

        delay(1000);
    }

    Log.error("WiFi failed to connect after 60s timeout");

    WiFi.off();
    delay(3000);

    return false;
}


// --------------------------------------------------
// Key Generation
// --------------------------------------------------

void generateKeys() {

    Log.info("Starting key generation...");

    digitalWrite(TRIG_KEYGEN, HIGH);

    uint32_t startTime = millis();

    int ret = PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);

    uint32_t elapsed = millis() - startTime;

    digitalWrite(TRIG_KEYGEN, LOW);

    if (ret != 0) {
        Log.error("Key generation failed, ret=%d", ret);
        return;
    }

    Log.info("Key generation complete in %lu ms", elapsed);
    Log.info("Public key size: %d bytes",
             PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);
    Log.info("Secret key size: %d bytes",
             PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);

    keysGenerated = true;
}


// --------------------------------------------------
// PQC worker thread (keygen + signing)
// --------------------------------------------------

void pqcThreadFunc() {
    for (;;) {

        if (keygenRequested && !keysGenerated) {

            generateKeys();
            keygenRequested = false;

        } else if (signRequested && !signingCompleted) {

            signMessage();
            signRequested = false;

        } else {

            delay(10);
        }
    }
}


// --------------------------------------------------
// Signing
// --------------------------------------------------

void signMessage() {

    if (!keysGenerated) {
        Log.error("Cannot sign: keys have not been generated");
        return;
    }

    Log.info("Starting signing...");
    Log.info("Message: %s", (const char*)message);
    Log.info("Message size: %d bytes", (int)messageLen);

    digitalWrite(TRIG_SIGN, HIGH);

    uint32_t startTime = millis();

    int ret = PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(
        sig,
        &sigLen,
        message,
        messageLen,
        sk
    );

    uint32_t elapsed = millis() - startTime;

    digitalWrite(TRIG_SIGN, LOW);

    if (ret != 0) {
        Log.error("Signing failed, ret=%d", ret);
        return;
    }

    signingCompleted = true;

    Log.info("Signing completed successfully");
    Log.info("Signing time: %lu ms", elapsed);
    Log.info("Message: %s", (const char*)message);
    Log.info("Message size: %d bytes", (int)messageLen);
    Log.info("Signature size: %d bytes", (int)sigLen);
}


// --------------------------------------------------
// Publish Public Key over MQTT
// --------------------------------------------------

void publishPublicKey() {

    Log.info("Publishing public key...");

    bytesToHex(pk, PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES, pkHex);

    digitalWrite(TRIG_PUBKEY, HIGH);
    pubKeySendTime = millis();

    if (client.publish("argon/pubkey", pkHex)) {

        Log.info("Public key published (%d bytes, %d hex chars)",
                  PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                  (int)strlen(pkHex));

        publicKeySent = true;

    } else {

        Log.error("Failed to publish public key");
        digitalWrite(TRIG_PUBKEY, LOW);
    }
}


// --------------------------------------------------
// Publish Message over MQTT
// --------------------------------------------------

void publishMessage() {

    Log.info("Publishing message...");

    digitalWrite(TRIG_MSG, HIGH);
    msgSendTime = millis();

    if (client.publish("argon/message", (const char*)message)) {

        Log.info("Message published (%d bytes): %s",
                  (int)messageLen, (const char*)message);

        messageSent = true;

    } else {

        Log.error("Failed to publish message");
        digitalWrite(TRIG_MSG, LOW);
    }
}


// --------------------------------------------------
// Publish Signature over MQTT, in chunks
//
// The full signature hex string (34176 chars for SPHINCS+-128f) is
// far too large for the MQTT library's own internal receive buffer
// on board_b to hold in one message, so it's sent as a sequence of
// smaller messages on "argon/signature_chunk", each formatted as
// "IIII:<hexdata>" (4-digit zero-padded chunk index + colon + up to
// SIG_CHUNK_HEX_LEN hex characters). board_b reassembles them using
// the index, so arrival order doesn't matter.
// --------------------------------------------------

void publishSignature() {

    Log.info("Publishing signature...");

    bytesToHex(sig, sigLen, sigHex);

    unsigned int totalHexLen = (unsigned int)strlen(sigHex);

    digitalWrite(TRIG_SIG, HIGH);
    sigSendTime = millis();

    bool allChunksOk = true;

    for (unsigned int idx = 0; idx < TOTAL_SIG_CHUNKS; idx++) {

        unsigned int offset = idx * SIG_CHUNK_HEX_LEN;

        if (offset >= totalHexLen) {
            break;
        }

        unsigned int remaining = totalHexLen - offset;
        unsigned int chunkLen = (remaining < SIG_CHUNK_HEX_LEN) ? remaining : SIG_CHUNK_HEX_LEN;

        int prefixLen = snprintf(sigChunkMsgBuf, sizeof(sigChunkMsgBuf), "%04u:", idx);
        memcpy(sigChunkMsgBuf + prefixLen, sigHex + offset, chunkLen);
        sigChunkMsgBuf[prefixLen + chunkLen] = '\0';

        if (!client.publish("argon/signature_chunk", sigChunkMsgBuf)) {

            Log.error("Failed to publish signature chunk %u", idx);
            allChunksOk = false;
            break;
        }

        // Keep the MQTT connection serviced between chunks and give
        // the broker a moment to process each one.
        client.loop();
        delay(20);
    }

    if (allChunksOk) {

        Log.info("Signature published in %u chunks (%u hex chars total)",
                  (unsigned)TOTAL_SIG_CHUNKS, totalHexLen);

        signatureSent = true;

    } else {

        Log.error("Signature send aborted due to publish failure");
        digitalWrite(TRIG_SIG, LOW);
    }
}


// --------------------------------------------------
// Setup
// --------------------------------------------------

void setup() {

    delay(2000);

    pinMode(TRIG_KEYGEN, OUTPUT);
    pinMode(TRIG_SIGN, OUTPUT);
    pinMode(TRIG_PUBKEY, OUTPUT);
    pinMode(TRIG_MSG, OUTPUT);
    pinMode(TRIG_SIG, OUTPUT);

    digitalWrite(TRIG_KEYGEN, LOW);
    digitalWrite(TRIG_SIGN, LOW);
    digitalWrite(TRIG_PUBKEY, LOW);
    digitalWrite(TRIG_MSG, LOW);
    digitalWrite(TRIG_SIG, LOW);

    String deviceId = System.deviceID();

    snprintf(
        clientId,
        sizeof(clientId),
        "board-a-%s",
        deviceId.substring(deviceId.length() - 6).c_str()
    );

    Log.info("Using MQTT client ID: %s", clientId);

    new Thread("pqc_worker", pqcThreadFunc, OS_THREAD_PRIORITY_DEFAULT,
               KEYGEN_THREAD_STACK_SIZE);

    connectWiFi();

    if (WiFi.ready()) {

        if (client.connect(clientId)) {

            Log.info("MQTT connected");
            client.subscribe("argon/control");
            Log.info("Waiting for START from board_b...");

        } else {

            Log.error("MQTT connect failed");
        }
    }
}


// --------------------------------------------------
// Main Loop
// --------------------------------------------------

void loop() {

    if (!WiFi.ready()) {
        connectWiFi();
        return;
    }

    if (client.isConnected()) {

        client.loop();

        if (cycleActive && !keysGenerated && !keygenRequested) {
            keygenRequested = true;
        }

        if (keysGenerated && !signingCompleted && !signRequested) {
            signRequested = true;
        }

        if (signingCompleted && !publicKeySent) {
            publishPublicKey();
        }

        if (ackReceived && !messageSent) {
            publishMessage();
        }

        if (msgAckReceived && !signatureSent) {
            publishSignature();
        }

    } else {

        Log.info("Attempting MQTT reconnect...");

        if (client.connect(clientId)) {
            Log.info("MQTT reconnected");
            client.subscribe("argon/control");
        }

        delay(2000);
    }
}