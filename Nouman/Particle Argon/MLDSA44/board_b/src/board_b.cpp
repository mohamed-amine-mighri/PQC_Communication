#include "Particle.h"
#include "MQTT.h"

extern "C" {
#include "api.h"
}

SYSTEM_MODE(SEMI_AUTOMATIC);
SYSTEM_THREAD(ENABLED);

SerialLogHandler logHandler(LOG_LEVEL_INFO);

void mqttCallback(char* topic, byte* payload, unsigned int length);

// Buffer sized to fit hex-encoded signature (~4840 chars) + MQTT overhead
MQTT client("test.mosquitto.org", 1883, 5000, mqttCallback);

char clientId[32];

// Buffer to store the received public key (hex string).
// ML-DSA-44 public key is 1312 bytes -> 2624 hex chars + null terminator.
#define PUBKEY_HEX_MAXLEN 2625
char receivedPubKeyHex[PUBKEY_HEX_MAXLEN];
bool publicKeyReceived = false;
bool ackSent = false;

// Buffer to store the received message
#define MESSAGE_MAXLEN 256
char receivedMessageBuf[MESSAGE_MAXLEN];
unsigned int receivedMessageLen = 0;
bool messageReceived = false;
bool msgAckSent = false;

// Buffer to store the received signature (hex string).
// ML-DSA-44 signature is 2420 bytes -> 4840 hex chars + null terminator.
#define SIG_HEX_MAXLEN 4841
char receivedSigHex[SIG_HEX_MAXLEN];
bool signatureReceived = false;
bool sigAckSent = false;

// Small buffer only for short control messages (START, PK_ACK, etc.)
#define CONTROL_MAXLEN 32
char controlMsgBuf[CONTROL_MAXLEN];

// Raw decoded bytes for verification
uint8_t receivedPubKeyBytes[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t receivedSigBytes[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];

bool verificationDone = false;
bool startResent = false;

uint32_t cycleCount = 0;

// Scope/logic-analyzer trigger pin: driven HIGH for the duration of
// PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify() so verification timing
// can be captured externally.
#define VERIFY_TRIGGER_PIN D3


// --------------------------------------------------
// Reset all per-cycle state so board_b is ready to react fresh
// to the next pubkey -> message -> signature sequence from board_a.
// Called right after we send START to kick off the next cycle.
// --------------------------------------------------

void resetCycleState() {

    publicKeyReceived = false;
    ackSent = false;

    messageReceived = false;
    msgAckSent = false;
    receivedMessageLen = 0;

    signatureReceived = false;
    sigAckSent = false;

    verificationDone = false;
    startResent = false;
}


// --------------------------------------------------
// Helper: log a preview of a long buffer instead of the whole thing.
// Printing multi-KB strings through Log.info can overflow the logger's
// own internal formatting buffer, so we only show the first N chars.
// --------------------------------------------------

void logPreview(const char* label, const char* buf, unsigned int fullLength) {

    const int previewLen = 40;
    char preview[previewLen + 1];

    int n = (fullLength < (unsigned int)previewLen) ? fullLength : previewLen;
    memcpy(preview, buf, n);
    preview[n] = '\0';

    Log.info("%s (%u chars): %s%s",
             label, fullLength, preview,
             (fullLength > (unsigned int)previewLen) ? "..." : "");
}


// --------------------------------------------------
// Helper: hex string -> bytes
// --------------------------------------------------

int hexNibble(char c) {

    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

bool hexToBytes(const char* hex, uint8_t* bytesOut, size_t byteLen) {

    for (size_t i = 0; i < byteLen; i++) {

        int hi = hexNibble(hex[i * 2]);
        int lo = hexNibble(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return false;
        }

        bytesOut[i] = (uint8_t)((hi << 4) | lo);
    }

    return true;
}


// --------------------------------------------------
// MQTT Callback
//
// IMPORTANT: do NOT declare a stack buffer sized to `length` here
// (e.g. "char message[length+1]"). For large payloads like the
// signature (~4840 bytes) that overflows the thread's stack and
// resets the device. Instead, copy straight into fixed-size global
// buffers, capped at their max size.
// --------------------------------------------------

void mqttCallback(char* topic, byte* payload, unsigned int length) {

    if (strcmp(topic, "argon/pubkey") == 0) {

        unsigned int copyLen = length;
        if (copyLen >= PUBKEY_HEX_MAXLEN) {
            Log.error("Public key payload too large (%u bytes), truncating", length);
            copyLen = PUBKEY_HEX_MAXLEN - 1;
        }

        memcpy(receivedPubKeyHex, payload, copyLen);
        receivedPubKeyHex[copyLen] = '\0';

        publicKeyReceived = true;

        Log.info("Public key received successfully");
        logPreview("Public key (hex)", receivedPubKeyHex, copyLen);

    } else if (strcmp(topic, "argon/message") == 0) {

        unsigned int copyLen = length;
        if (copyLen >= MESSAGE_MAXLEN) {
            Log.error("Message payload too large (%u bytes), truncating", length);
            copyLen = MESSAGE_MAXLEN - 1;
        }

        memcpy(receivedMessageBuf, payload, copyLen);
        receivedMessageBuf[copyLen] = '\0';
        receivedMessageLen = copyLen;

        messageReceived = true;

        Log.info("Message received successfully");
        Log.info("Message (%u bytes): %s", copyLen, receivedMessageBuf);

    } else if (strcmp(topic, "argon/signature") == 0) {

        unsigned int copyLen = length;
        if (copyLen >= SIG_HEX_MAXLEN) {
            Log.error("Signature payload too large (%u bytes), truncating", length);
            copyLen = SIG_HEX_MAXLEN - 1;
        }

        memcpy(receivedSigHex, payload, copyLen);
        receivedSigHex[copyLen] = '\0';

        signatureReceived = true;

        Log.info("Signature received successfully");
        logPreview("Signature (hex)", receivedSigHex, copyLen);

    } else if (strcmp(topic, "argon/control") == 0) {

        // Control messages (START, PK_ACK, etc.) are always short.
        unsigned int copyLen = length;
        if (copyLen >= CONTROL_MAXLEN) {
            copyLen = CONTROL_MAXLEN - 1;
        }

        memcpy(controlMsgBuf, payload, copyLen);
        controlMsgBuf[copyLen] = '\0';

        Log.info("Received on %s: %s", topic, controlMsgBuf);

    } else {

        Log.info("Received on unhandled topic %s (%u bytes)", topic, length);
    }
}


bool connectWiFi() {
    if (WiFi.ready()) return true;

    Log.info("Connecting to WiFi...");
    WiFi.off();
    delay(1000);
    WiFi.on();
    WiFi.setCredentials("Gintonic", "capitainemassime");
    WiFi.connect();

    for (int i = 0; i < 60; i++) {
        if (WiFi.ready()) {
            Log.info("WiFi connected, IP: %s", WiFi.localIP().toString().c_str());
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
// Send PK_ACK back to board_a
// --------------------------------------------------

void sendPublicKeyAck() {

    if (client.publish("argon/control", "PK_ACK")) {

        Log.info("PK_ACK sent to board_a");
        ackSent = true;

    } else {

        Log.error("Failed to send PK_ACK");
    }
}


// --------------------------------------------------
// Send MSG_ACK back to board_a
// --------------------------------------------------

void sendMessageAck() {

    if (client.publish("argon/control", "MSG_ACK")) {

        Log.info("MSG_ACK sent to board_a");
        msgAckSent = true;

    } else {

        Log.error("Failed to send MSG_ACK");
    }
}


// --------------------------------------------------
// Send SIG_ACK back to board_a
// --------------------------------------------------

void sendSignatureAck() {

    if (client.publish("argon/control", "SIG_ACK")) {

        Log.info("SIG_ACK sent to board_a");
        sigAckSent = true;

    } else {

        Log.error("Failed to send SIG_ACK");
    }
}


// --------------------------------------------------
// Verify the signature using the received public key and message
//
// VERIFY_TRIGGER_PIN (D3) is driven HIGH right before the verify
// call and LOW immediately after, so an external scope/logic
// analyzer can capture exactly how long verification takes.
// --------------------------------------------------

void verifySignature() {

    Log.info("Starting signature verification...");

    if (!hexToBytes(receivedPubKeyHex, receivedPubKeyBytes,
                     PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES)) {

        Log.error("Failed to decode public key hex");
        return;
    }

    if (!hexToBytes(receivedSigHex, receivedSigBytes,
                     PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES)) {

        Log.error("Failed to decode signature hex");
        return;
    }

    digitalWrite(VERIFY_TRIGGER_PIN, HIGH);

    uint32_t startTime = millis();

    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
        receivedSigBytes,
        PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
        (const uint8_t*)receivedMessageBuf,
        receivedMessageLen,
        receivedPubKeyBytes
    );

    uint32_t elapsed = millis() - startTime;

    digitalWrite(VERIFY_TRIGGER_PIN, LOW);

    verificationDone = true;

    if (ret == 0) {

        Log.info("Signature verification SUCCESS");

    } else {

        Log.error("Signature verification FAILED, ret=%d", ret);
    }

    Log.info("Verification time: %lu ms", elapsed);
}


// --------------------------------------------------
// Send START back to board_a after verification, then reset state
// so the next cycle's pubkey/message/signature are handled fresh.
// --------------------------------------------------

void sendStartAgain() {

    if (client.publish("argon/control", "START")) {

        cycleCount++;

        Log.info("START sent to board_a (post-verification)");
        Log.info("===== Cycle #%lu complete, awaiting next cycle =====", cycleCount);

        startResent = true;

        // Reset everything except startResent itself, so the flags
        // above (ackSent, msgAckSent, sigAckSent, verificationDone,
        // publicKeyReceived, etc.) are ready to react to the next
        // pubkey/message/signature from board_a.
        resetCycleState();

    } else {

        Log.error("Failed to send START");
    }
}


void setup() {
    delay(2000);

    pinMode(VERIFY_TRIGGER_PIN, OUTPUT);
    digitalWrite(VERIFY_TRIGGER_PIN, LOW);

    String deviceId = System.deviceID();
    snprintf(clientId, sizeof(clientId), "board-b-%s", deviceId.substring(deviceId.length() - 6).c_str());
    Log.info("Using MQTT client ID: %s", clientId);

    connectWiFi();

    if (WiFi.ready()) {
        if (client.connect(clientId)) {
            Log.info("MQTT connected");
            client.subscribe("argon/data");
            client.subscribe("argon/pubkey");
            client.subscribe("argon/message");
            client.subscribe("argon/signature");
            client.publish("argon/control", "START");
            Log.info("Sent START to board_a");
        } else {
            Log.error("MQTT connect failed");
        }
    }
}


void loop() {
    if (!WiFi.ready()) {
        connectWiFi();
        return;
    }

    if (client.isConnected()) {
        client.loop();

        if (publicKeyReceived && !ackSent) {
            sendPublicKeyAck();
        }

        if (messageReceived && !msgAckSent) {
            sendMessageAck();
        }

        if (signatureReceived && !sigAckSent) {
            sendSignatureAck();
        }

        if (sigAckSent && !verificationDone) {
            verifySignature();
        }

        if (verificationDone && !startResent) {
            sendStartAgain();
        }

    } else {
        Log.info("Attempting MQTT reconnect...");
        if (client.connect(clientId)) {
            Log.info("MQTT reconnected");
            client.subscribe("argon/data");
            client.subscribe("argon/pubkey");
            client.subscribe("argon/message");
            client.subscribe("argon/signature");
            client.publish("argon/control", "START");
            Log.info("Sent START to board_a");
        }
        delay(2000);
    }
}
