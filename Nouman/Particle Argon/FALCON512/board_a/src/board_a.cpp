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
void publishSignatureSize();

// ============================================================
// MQTT
// ============================================================

MQTT client("test.mosquitto.org", 1883, 2048, mqttCallback);

char clientId[32];

// ============================================================
// Trigger pins
//
// D2 -> HIGH during key generation
// D3 -> HIGH during signing
// D4 -> HIGH from public key send until PK_ACK
// D5 -> HIGH from message send until MSG_ACK
// D6 -> HIGH from signature send until SIG_ACK
//
// Signature-size transmission intentionally has NO trigger,
// NO timing measurement, and NO ACK.
// ============================================================

#define TRIG_KEYGEN   D2
#define TRIG_SIGN     D3
#define TRIG_PUBKEY   D4
#define TRIG_MSG      D5
#define TRIG_SIG      D6

// ============================================================
// Cycle state
// ============================================================

volatile bool cycleActive = false;

volatile bool keysGenerated = false;
volatile bool keygenRequested = false;

volatile bool signingCompleted = false;
volatile bool signRequested = false;

bool signatureSizeSent = false;

bool publicKeySent = false;
bool ackReceived = false;

bool messageSent = false;
bool msgAckReceived = false;

bool signatureSent = false;
bool sigAckReceived = false;

uint32_t cycleCount = 0;

// ============================================================
// Falcon-512 key buffers
// ============================================================

uint8_t pk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
uint8_t sk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];

// Signature buffer
uint8_t sig[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
size_t sigLen = 0;

// ============================================================
// Message
// ============================================================

const uint8_t message[] = "hello from board_a";
const size_t messageLen = sizeof(message) - 1;

// ============================================================
// Hex buffers
// ============================================================

char pkHex[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES * 2 + 1];
char sigHex[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES * 2 + 1];

// ============================================================
// Signature chunking
// ============================================================

#define SIG_CHUNK_HEX_LEN 1800

#define TOTAL_SIG_HEX_LEN \
    (PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES * 2)

#define TOTAL_SIG_CHUNKS \
    ((TOTAL_SIG_HEX_LEN + SIG_CHUNK_HEX_LEN - 1) / SIG_CHUNK_HEX_LEN)

#define SIG_CHUNK_MSG_MAXLEN \
    (4 + 1 + SIG_CHUNK_HEX_LEN + 1)

char sigChunkMsgBuf[SIG_CHUNK_MSG_MAXLEN];

// ============================================================
// Timestamp tracking
// ============================================================

uint32_t pubKeySendTime = 0;
uint32_t msgSendTime = 0;
uint32_t sigSendTime = 0;

// ============================================================
// MQTT control buffer
// ============================================================

#define CONTROL_MAXLEN 32
char controlMsgBuf[CONTROL_MAXLEN];

// ============================================================
// Signature-size buffer
// ============================================================

#define SIG_SIZE_MSG_MAXLEN 16
char sigSizeMsgBuf[SIG_SIZE_MSG_MAXLEN];

// ============================================================
// PQC worker stack
//
// IMPORTANT:
// Falcon-512 signing required the larger 48 KB stack.
// Keep this at 49152.
// ============================================================

#define KEYGEN_THREAD_STACK_SIZE 49152

// ============================================================
// Helper: bytes -> hex
// ============================================================

void bytesToHex(
    const uint8_t* bytes,
    size_t len,
    char* hexOut
) {
    const char hexChars[] = "0123456789ABCDEF";

    for (size_t i = 0; i < len; i++) {

        hexOut[i * 2] =
            hexChars[(bytes[i] >> 4) & 0x0F];

        hexOut[i * 2 + 1] =
            hexChars[bytes[i] & 0x0F];
    }

    hexOut[len * 2] = '\0';
}

// ============================================================
// Start new cycle
// ============================================================

void startNewCycle() {

    cycleCount++;

    keysGenerated = false;
    keygenRequested = false;

    signingCompleted = false;
    signRequested = false;

    signatureSizeSent = false;

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

    Log.info(
        "===== Starting cycle #%lu =====",
        (unsigned long)cycleCount
    );
}

// ============================================================
// MQTT callback
// ============================================================

void mqttCallback(
    char* topic,
    byte* payload,
    unsigned int length
) {

    if (strcmp(topic, "argon/control") == 0) {

        unsigned int copyLen = length;

        if (copyLen >= CONTROL_MAXLEN) {
            copyLen = CONTROL_MAXLEN - 1;
        }

        memcpy(
            controlMsgBuf,
            payload,
            copyLen
        );

        controlMsgBuf[copyLen] = '\0';

        Log.info(
            "Received on %s: %s",
            topic,
            controlMsgBuf
        );

        // ====================================================
        // START
        // ====================================================

        if (strcmp(controlMsgBuf, "START") == 0) {

            startNewCycle();
        }

        // ====================================================
        // PUBLIC KEY ACK
        // ====================================================

        else if (
            strcmp(controlMsgBuf, "PK_ACK") == 0
        ) {

            if (
                publicKeySent &&
                !ackReceived
            ) {

                ackReceived = true;

                digitalWrite(
                    TRIG_PUBKEY,
                    LOW
                );

                uint32_t elapsed =
                    millis() - pubKeySendTime;

                Log.info("PK_ACK received");

                Log.info(
                    "Public key send time (send -> ack): %lu ms",
                    (unsigned long)elapsed
                );
            }
        }

        // ====================================================
        // MESSAGE ACK
        // ====================================================

        else if (
            strcmp(controlMsgBuf, "MSG_ACK") == 0
        ) {

            if (
                messageSent &&
                !msgAckReceived
            ) {

                msgAckReceived = true;

                digitalWrite(
                    TRIG_MSG,
                    LOW
                );

                uint32_t elapsed =
                    millis() - msgSendTime;

                Log.info("MSG_ACK received");

                Log.info(
                    "Message send time (send -> ack): %lu ms",
                    (unsigned long)elapsed
                );
            }
        }

        // ====================================================
        // SIGNATURE ACK
        // ====================================================

        else if (
            strcmp(controlMsgBuf, "SIG_ACK") == 0
        ) {

            if (
                signatureSent &&
                !sigAckReceived
            ) {

                sigAckReceived = true;

                digitalWrite(
                    TRIG_SIG,
                    LOW
                );

                uint32_t elapsed =
                    millis() - sigSendTime;

                Log.info("SIG_ACK received");

                Log.info(
                    "Signature send time (send -> ack): %lu ms",
                    (unsigned long)elapsed
                );

                Log.info(
                    "===== Cycle #%lu complete =====",
                    (unsigned long)cycleCount
                );

                cycleActive = false;
            }
        }
    }

    else {

        Log.info(
            "Received on unhandled topic %s (%u bytes)",
            topic,
            length
        );
    }
}

// ============================================================
// WiFi connection
// ============================================================

bool connectWiFi() {

    if (WiFi.ready()) {
        return true;
    }

    Log.info("Connecting to WiFi...");

    WiFi.off();

    delay(1000);

    WiFi.on();

    WiFi.setCredentials(
        "Gintonic",
        "capitainemassime"
    );

    WiFi.connect();

    for (int i = 0; i < 60; i++) {

        if (WiFi.ready()) {

            Log.info(
                "WiFi connected, IP: %s",
                WiFi.localIP()
                    .toString()
                    .c_str()
            );

            return true;
        }

        delay(1000);
    }

    Log.error(
        "WiFi failed to connect after 60s timeout"
    );

    WiFi.off();

    delay(3000);

    return false;
}

// ============================================================
// Falcon-512 key generation
// ============================================================

void generateKeys() {

    Log.info(
        "===================================="
    );

    Log.info(
        "Starting Falcon-512 key generation..."
    );

    digitalWrite(
        TRIG_KEYGEN,
        HIGH
    );

    uint32_t startTime =
        millis();

    int ret =
        PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
            pk,
            sk
        );

    uint32_t elapsed =
        millis() - startTime;

    digitalWrite(
        TRIG_KEYGEN,
        LOW
    );

    if (ret != 0) {

        Log.error(
            "Key generation failed, ret=%d",
            ret
        );

        return;
    }

    Log.info(
        "Key generation completed successfully"
    );

    Log.info(
        "Key generation time: %lu ms",
        (unsigned long)elapsed
    );

    Log.info(
        "Public key size: %d bytes",
        PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
    );

    Log.info(
        "Secret key size: %d bytes",
        PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES
    );

    keysGenerated = true;

    Log.info(
        "===================================="
    );
}

// ============================================================
// Falcon-512 signing
// ============================================================

void signMessage() {

    if (!keysGenerated) {

        Log.error(
            "Cannot sign: keys have not been generated"
        );

        return;
    }

    Log.info(
        "===================================="
    );

    Log.info(
        "Starting Falcon-512 signing..."
    );

    Log.info(
        "Message: %s",
        (const char*)message
    );

    Log.info(
        "Message size: %d bytes",
        (int)messageLen
    );

    digitalWrite(
        TRIG_SIGN,
        HIGH
    );

    uint32_t startTime =
        millis();

    int ret =
        PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
            sig,
            &sigLen,
            message,
            messageLen,
            sk
        );

    uint32_t elapsed =
        millis() - startTime;

    digitalWrite(
        TRIG_SIGN,
        LOW
    );

    if (ret != 0) {

        Log.error(
            "Signing failed, ret=%d",
            ret
        );

        return;
    }

    signingCompleted = true;

    Log.info(
        "Signing completed successfully"
    );

    Log.info(
        "Signing time: %lu ms",
        (unsigned long)elapsed
    );

    Log.info(
        "Message: %s",
        (const char*)message
    );

    Log.info(
        "Message size: %d bytes",
        (int)messageLen
    );

    Log.info(
        "Signature size: %d bytes",
        (int)sigLen
    );

    Log.info(
        "===================================="
    );
}

// ============================================================
// PQC worker thread
// ============================================================

void pqcThreadFunc() {

    for (;;) {

        if (
            keygenRequested &&
            !keysGenerated
        ) {

            generateKeys();

            keygenRequested = false;
        }

        else if (
            signRequested &&
            !signingCompleted
        ) {

            signMessage();

            signRequested = false;
        }

        else {

            delay(10);
        }
    }
}

// ============================================================
// Send signature size
//
// IMPORTANT:
// - Sent BEFORE public key
// - No trigger pin
// - No timing measurement
// - No ACK expected
// - Public key is allowed to send immediately afterward
//
// Topic:
// argon/signature_size
//
// Payload example:
// 654
// ============================================================

void publishSignatureSize() {

    snprintf(
        sigSizeMsgBuf,
        sizeof(sigSizeMsgBuf),
        "%u",
        (unsigned int)sigLen
    );

    if (
        client.publish(
            "argon/signature_size",
            sigSizeMsgBuf
        )
    ) {

        Log.info(
            "Signature size sent: %u bytes",
            (unsigned int)sigLen
        );

        signatureSizeSent = true;
    }

    else {

        Log.error(
            "Failed to send signature size"
        );
    }
}

// ============================================================
// Publish public key
// ============================================================

void publishPublicKey() {

    Log.info(
        "Publishing public key..."
    );

    bytesToHex(
        pk,
        PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
        pkHex
    );

    digitalWrite(
        TRIG_PUBKEY,
        HIGH
    );

    pubKeySendTime =
        millis();

    if (
        client.publish(
            "argon/pubkey",
            pkHex
        )
    ) {

        Log.info(
            "Public key published (%d bytes, %d hex chars)",
            PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
            (int)strlen(pkHex)
        );

        publicKeySent = true;
    }

    else {

        Log.error(
            "Failed to publish public key"
        );

        digitalWrite(
            TRIG_PUBKEY,
            LOW
        );
    }
}

// ============================================================
// Publish message
// ============================================================

void publishMessage() {

    Log.info(
        "Publishing message..."
    );

    digitalWrite(
        TRIG_MSG,
        HIGH
    );

    msgSendTime =
        millis();

    if (
        client.publish(
            "argon/message",
            (const char*)message
        )
    ) {

        Log.info(
            "Message published (%d bytes): %s",
            (int)messageLen,
            (const char*)message
        );

        messageSent = true;
    }

    else {

        Log.error(
            "Failed to publish message"
        );

        digitalWrite(
            TRIG_MSG,
            LOW
        );
    }
}

// ============================================================
// Publish signature in chunks
// ============================================================

void publishSignature() {

    Log.info(
        "Publishing signature..."
    );

    bytesToHex(
        sig,
        sigLen,
        sigHex
    );

    unsigned int totalHexLen =
        (unsigned int)strlen(sigHex);

    unsigned int actualChunks =
        (totalHexLen +
         SIG_CHUNK_HEX_LEN - 1) /
        SIG_CHUNK_HEX_LEN;

    Log.info(
        "Signature hex length: %u chars",
        totalHexLen
    );

    Log.info(
        "Signature requires %u MQTT chunk(s)",
        actualChunks
    );

    digitalWrite(
        TRIG_SIG,
        HIGH
    );

    sigSendTime =
        millis();

    bool allChunksOk = true;

    for (
        unsigned int idx = 0;
        idx < TOTAL_SIG_CHUNKS;
        idx++
    ) {

        unsigned int offset =
            idx * SIG_CHUNK_HEX_LEN;

        if (offset >= totalHexLen) {
            break;
        }

        unsigned int remaining =
            totalHexLen - offset;

        unsigned int chunkLen =
            (remaining < SIG_CHUNK_HEX_LEN)
                ? remaining
                : SIG_CHUNK_HEX_LEN;

        int prefixLen =
            snprintf(
                sigChunkMsgBuf,
                sizeof(sigChunkMsgBuf),
                "%04u:",
                idx
            );

        memcpy(
            sigChunkMsgBuf + prefixLen,
            sigHex + offset,
            chunkLen
        );

        sigChunkMsgBuf[
            prefixLen + chunkLen
        ] = '\0';

        Log.info(
            "Publishing signature chunk %u/%u (%u hex chars)",
            idx + 1,
            actualChunks,
            chunkLen
        );

        if (
            !client.publish(
                "argon/signature_chunk",
                sigChunkMsgBuf
            )
        ) {

            Log.error(
                "Failed to publish signature chunk %u",
                idx
            );

            allChunksOk = false;

            break;
        }

        client.loop();

        delay(20);
    }

    if (allChunksOk) {

        Log.info(
            "Signature published successfully"
        );

        Log.info(
            "Total signature: %u hex chars",
            totalHexLen
        );

        signatureSent = true;
    }

    else {

        Log.error(
            "Signature send aborted due to publish failure"
        );

        digitalWrite(
            TRIG_SIG,
            LOW
        );
    }
}

// ============================================================
// Setup
// ============================================================

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

    String deviceId =
        System.deviceID();

    snprintf(
        clientId,
        sizeof(clientId),
        "board-a-%s",
        deviceId
            .substring(
                deviceId.length() - 6
            )
            .c_str()
    );

    Log.info(
        "Using MQTT client ID: %s",
        clientId
    );

    // ========================================================
    // Create PQC worker with 48 KB stack.
    // This is required for Falcon-512 signing.
    // ========================================================

    new Thread(
        "pqc_worker",
        pqcThreadFunc,
        OS_THREAD_PRIORITY_DEFAULT,
        KEYGEN_THREAD_STACK_SIZE
    );

    // ========================================================
    // WiFi
    // ========================================================

    connectWiFi();

    if (WiFi.ready()) {

        if (
            client.connect(
                clientId
            )
        ) {

            Log.info(
                "MQTT connected"
            );

            client.subscribe(
                "argon/control"
            );

            Log.info(
                "Waiting for START from board_b..."
            );
        }

        else {

            Log.error(
                "MQTT connect failed"
            );
        }
    }
}

// ============================================================
// Main loop
// ============================================================

void loop() {

    // ========================================================
    // WiFi recovery
    // ========================================================

    if (!WiFi.ready()) {

        Log.warn(
            "WiFi not ready - reconnecting..."
        );

        connectWiFi();

        return;
    }

    // ========================================================
    // MQTT
    // ========================================================

    if (client.isConnected()) {

        client.loop();

        // ====================================================
        // 1. KEY GENERATION
        // ====================================================

        if (
            cycleActive &&
            !keysGenerated &&
            !keygenRequested
        ) {

            Log.info(
                "Requesting key generation..."
            );

            keygenRequested = true;
        }

        // ====================================================
        // 2. SIGNING
        // ====================================================

        if (
            keysGenerated &&
            !signingCompleted &&
            !signRequested
        ) {

            Log.info(
                "Requesting signing..."
            );

            signRequested = true;
        }

        // ====================================================
        // 3. SEND SIGNATURE SIZE
        //
        // NO ACK.
        // NO TIMER.
        // ====================================================

        if (
            signingCompleted &&
            !signatureSizeSent
        ) {

            publishSignatureSize();
        }

        // ====================================================
        // 4. SEND PUBLIC KEY IMMEDIATELY AFTER SIGNATURE SIZE
        //
        // We do NOT wait for an ACK for signature size.
        // ====================================================

        if (
            signingCompleted &&
            signatureSizeSent &&
            !publicKeySent
        ) {

            publishPublicKey();
        }

        // ====================================================
        // 5. WAIT PK_ACK -> SEND MESSAGE
        // ====================================================

        if (
            ackReceived &&
            !messageSent
        ) {

            publishMessage();
        }

        // ====================================================
        // 6. WAIT MSG_ACK -> SEND SIGNATURE
        // ====================================================

        if (
            msgAckReceived &&
            !signatureSent
        ) {

            publishSignature();
        }
    }

    // ========================================================
    // MQTT reconnect
    // ========================================================

    else {

        Log.info(
            "Attempting MQTT reconnect..."
        );

        if (
            client.connect(
                clientId
            )
        ) {

            Log.info(
                "MQTT reconnected"
            );

            client.subscribe(
                "argon/control"
            );
        }

        delay(2000);
    }
}