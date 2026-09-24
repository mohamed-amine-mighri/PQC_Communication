#include "Particle.h"
#include "MQTT.h"

extern "C" {
#include "api.h"
}

SYSTEM_MODE(SEMI_AUTOMATIC);
SYSTEM_THREAD(ENABLED);

SerialLogHandler logHandler(LOG_LEVEL_INFO);

void mqttCallback(char* topic, byte* payload, unsigned int length);

MQTT client("test.mosquitto.org", 1883, 5000, mqttCallback);

char clientId[32];

// Buffer to store the received public key (hex string).
#define PUBKEY_HEX_MAXLEN (PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES * 2 + 1)
char receivedPubKeyHex[PUBKEY_HEX_MAXLEN];
bool publicKeyReceived = false;
bool ackSent = false;

// Buffer to store the received message
#define MESSAGE_MAXLEN 256
char receivedMessageBuf[MESSAGE_MAXLEN];
unsigned int receivedMessageLen = 0;
bool messageReceived = false;
bool msgAckSent = false;

// Buffer to store the received signature (hex string), reassembled
// from chunks. Sized for the full signature -- this is fine as a
// static buffer; the earlier problem was the MQTT library's own
// internal *receive* buffer, not this one.
#define SIG_HEX_MAXLEN (PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES * 2 + 1)
char receivedSigHex[SIG_HEX_MAXLEN];
bool signatureReceived = false;
bool sigAckSent = false;

// --------------------------------------------------
// Signature chunk reassembly
//
// board_a sends the signature hex as multiple small messages on
// "argon/signature_chunk", each formatted "IIII:<hexdata>" (4-digit
// zero-padded chunk index + colon + up to SIG_CHUNK_HEX_LEN hex
// chars). We write each chunk directly into receivedSigHex at the
// offset implied by its index, so arrival order doesn't matter, and
// track how many distinct chunks have arrived so we know when the
// whole signature is complete.
// --------------------------------------------------

#define SIG_CHUNK_HEX_LEN 1024
#define TOTAL_SIG_HEX_LEN (PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES * 2)
#define TOTAL_SIG_CHUNKS ((TOTAL_SIG_HEX_LEN + SIG_CHUNK_HEX_LEN - 1) / SIG_CHUNK_HEX_LEN)
#define SIG_CHUNK_MSG_MAXLEN (4 + 1 + SIG_CHUNK_HEX_LEN + 1) // "IIII:" + hexdata + '\0'

bool sigChunkReceived[TOTAL_SIG_CHUNKS];
unsigned int sigChunksReceivedCount = 0;
char sigChunkTemp[SIG_CHUNK_MSG_MAXLEN];

// Small buffer only for short control messages (START, PK_ACK, etc.)
#define CONTROL_MAXLEN 32
char controlMsgBuf[CONTROL_MAXLEN];

// Raw decoded bytes for verification
uint8_t receivedPubKeyBytes[PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t receivedSigBytes[PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES];

bool verificationDone = false;
bool verificationOk = false;
bool startResent = false;

uint32_t cycleCount = 0;

#define VERIFY_TRIGGER_PIN D3


// --------------------------------------------------
// Reset all per-cycle state so board_b is ready to react fresh
// to the next pubkey -> message -> signature sequence from board_a.
// --------------------------------------------------

void resetCycleState() {

    publicKeyReceived = false;
    ackSent = false;

    messageReceived = false;
    msgAckSent = false;
    receivedMessageLen = 0;

    signatureReceived = false;
    sigAckSent = false;

    memset(sigChunkReceived, 0, sizeof(sigChunkReceived));
    sigChunksReceivedCount = 0;

    verificationDone = false;
    verificationOk = false;
    startResent = false;
}


// --------------------------------------------------
// Helper: log a preview of a long buffer instead of the whole thing.
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
            Log.error("Hex decode failed at byte index %u", (unsigned)i);
            return false;
        }

        bytesOut[i] = (uint8_t)((hi << 4) | lo);
    }

    return true;
}


// --------------------------------------------------
// MQTT Callback
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

    } else if (strcmp(topic, "argon/signature_chunk") == 0) {

        unsigned int copyLen = length;
        if (copyLen >= SIG_CHUNK_MSG_MAXLEN) {
            Log.error("Signature chunk payload too large (%u bytes), dropping", length);
            return;
        }

        memcpy(sigChunkTemp, payload, copyLen);
        sigChunkTemp[copyLen] = '\0';

        char* colon = strchr(sigChunkTemp, ':');
        if (colon == nullptr) {
            Log.error("Malformed signature chunk (no ':' found)");
            return;
        }

        *colon = '\0';
        int idx = atoi(sigChunkTemp);
        const char* hexData = colon + 1;
        unsigned int hexDataLen = (unsigned int)strlen(hexData);

        if (idx < 0 || idx >= TOTAL_SIG_CHUNKS) {
            Log.error("Signature chunk index %d out of range (0..%d)", idx, TOTAL_SIG_CHUNKS - 1);
            return;
        }

        unsigned int offset = (unsigned int)idx * SIG_CHUNK_HEX_LEN;

        if (offset + hexDataLen > TOTAL_SIG_HEX_LEN) {
            Log.error("Signature chunk %d would overflow buffer (offset=%u len=%u)",
                      idx, offset, hexDataLen);
            return;
        }

        memcpy(receivedSigHex + offset, hexData, hexDataLen);

        if (!sigChunkReceived[idx]) {
            sigChunkReceived[idx] = true;
            sigChunksReceivedCount++;
        }

        if (sigChunksReceivedCount == TOTAL_SIG_CHUNKS) {

            receivedSigHex[TOTAL_SIG_HEX_LEN] = '\0';
            signatureReceived = true;

            Log.info("All %u signature chunks received (%u hex chars total)",
                      (unsigned)TOTAL_SIG_CHUNKS, (unsigned)TOTAL_SIG_HEX_LEN);
        }

    } else if (strcmp(topic, "argon/control") == 0) {

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
    WiFi.setCredentials("pqctest", "12345678");
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


void sendPublicKeyAck() {

    if (client.publish("argon/control", "PK_ACK")) {
        Log.info("PK_ACK sent to board_a");
        ackSent = true;
    } else {
        Log.error("Failed to send PK_ACK");
    }
}


void sendMessageAck() {

    if (client.publish("argon/control", "MSG_ACK")) {
        Log.info("MSG_ACK sent to board_a");
        msgAckSent = true;
    } else {
        Log.error("Failed to send MSG_ACK");
    }
}


void sendSignatureAck() {

    if (client.publish("argon/control", "SIG_ACK")) {
        Log.info("SIG_ACK sent to board_a");
        sigAckSent = true;
    } else {
        Log.error("Failed to send SIG_ACK");
    }
}


// --------------------------------------------------
// Verify the signature using the received public key and message.
// verificationDone is set on every exit path (success or failure) so
// loop() never gets stuck retrying forever.
// --------------------------------------------------

void verifySignature() {

    Log.info("Starting signature verification...");

    if (!hexToBytes(receivedPubKeyHex, receivedPubKeyBytes,
                     PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES)) {

        Log.error("Failed to decode public key hex");
        verificationDone = true;
        verificationOk = false;
        return;
    }

    if (!hexToBytes(receivedSigHex, receivedSigBytes,
                     PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES)) {

        Log.error("Failed to decode signature hex");
        verificationDone = true;
        verificationOk = false;
        return;
    }

    digitalWrite(VERIFY_TRIGGER_PIN, HIGH);

    uint32_t startTime = millis();

    int ret = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(
        receivedSigBytes,
        PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES,
        (const uint8_t*)receivedMessageBuf,
        receivedMessageLen,
        receivedPubKeyBytes
    );

    uint32_t elapsed = millis() - startTime;

    digitalWrite(VERIFY_TRIGGER_PIN, LOW);

    verificationDone = true;

    if (ret == 0) {
        Log.info("Signature verification SUCCESS");
        verificationOk = true;
    } else {
        Log.error("Signature verification FAILED, ret=%d", ret);
        verificationOk = false;
    }

    Log.info("Verification time: %lu ms", elapsed);
}


void sendStartAgain() {

    if (client.publish("argon/control", "START")) {

        cycleCount++;

        Log.info("START sent to board_a (post-verification)");
        Log.info("===== Cycle #%lu complete (verification %s), awaiting next cycle =====",
                  cycleCount, verificationOk ? "OK" : "FAILED");

        startResent = true;

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
            client.subscribe("argon/pubkey");
            client.subscribe("argon/message");
            client.subscribe("argon/signature_chunk");
            client.subscribe("argon/control");
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
            client.subscribe("argon/pubkey");
            client.subscribe("argon/message");
            client.subscribe("argon/signature_chunk");
            client.subscribe("argon/control");
            client.publish("argon/control", "START");
            Log.info("Sent START to board_a");
        }
        delay(2000);
    }
}