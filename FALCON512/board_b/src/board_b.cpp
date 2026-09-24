#include "Particle.h"
#include "MQTT.h"

extern "C" {
#include "api.h"
}

SYSTEM_MODE(SEMI_AUTOMATIC);
SYSTEM_THREAD(ENABLED);

SerialLogHandler logHandler(LOG_LEVEL_INFO);

void mqttCallback(char* topic, byte* payload, unsigned int length);

// ============================================================
// MQTT
//
// Must match Board A's MQTT buffer arrangement.
// ============================================================

MQTT client("test.mosquitto.org", 1883, 2048, mqttCallback);

char clientId[32];

// ============================================================
// PUBLIC KEY
// ============================================================

#define PUBKEY_HEX_MAXLEN \
    (PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES * 2 + 1)

char receivedPubKeyHex[PUBKEY_HEX_MAXLEN];

bool publicKeyReceived = false;
bool ackSent = false;

// ============================================================
// MESSAGE
// ============================================================

#define MESSAGE_MAXLEN 256

char receivedMessageBuf[MESSAGE_MAXLEN];

unsigned int receivedMessageLen = 0;

bool messageReceived = false;
bool msgAckSent = false;

// ============================================================
// SIGNATURE SIZE
//
// Board A sends the ACTUAL Falcon signature size before
// sending the public key.
//
// Topic:
//      argon/signature_size
//
// Example:
//      "654"
//
// No ACK is sent for this.
// ============================================================

size_t expectedSignatureSize = 0;

unsigned int expectedSignatureHexLen = 0;
unsigned int expectedSignatureChunks = 0;

bool signatureSizeReceived = false;

// ============================================================
// SIGNATURE BUFFER
//
// Allocate for Falcon's maximum possible signature size,
// but only the number of bytes specified by
// expectedSignatureSize will actually be used.
// ============================================================

#define SIG_HEX_MAXLEN \
    (PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES * 2 + 1)

char receivedSigHex[SIG_HEX_MAXLEN];

bool signatureReceived = false;
bool sigAckSent = false;

// ============================================================
// SIGNATURE CHUNKING
//
// IMPORTANT:
// Must exactly match Board A.
//
// Board A:
// #define SIG_CHUNK_HEX_LEN 1800
//
// Format:
//
//      IIII:<hexdata>
//
// Example:
//
//      0000:ABCDEF...
//      0001:123456...
//
// Falcon signature length is variable, so expected chunk
// count is calculated dynamically after receiving sig size.
// ============================================================

#define SIG_CHUNK_HEX_LEN 1800

#define MAX_SIG_HEX_LEN \
    (PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES * 2)

#define MAX_SIG_CHUNKS \
    ((MAX_SIG_HEX_LEN + SIG_CHUNK_HEX_LEN - 1) / \
     SIG_CHUNK_HEX_LEN)

#define SIG_CHUNK_MSG_MAXLEN \
    (4 + 1 + SIG_CHUNK_HEX_LEN + 1)

bool sigChunkReceived[MAX_SIG_CHUNKS];

unsigned int sigChunksReceivedCount = 0;

char sigChunkTemp[SIG_CHUNK_MSG_MAXLEN];

// ============================================================
// CONTROL BUFFER
// ============================================================

#define CONTROL_MAXLEN 32

char controlMsgBuf[CONTROL_MAXLEN];

// ============================================================
// RAW DECODED DATA
// ============================================================

uint8_t receivedPubKeyBytes[
    PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
];

uint8_t receivedSigBytes[
    PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES
];

// ============================================================
// Verification state
// ============================================================

bool verificationDone = false;
bool verificationOk = false;
bool startResent = false;

uint32_t cycleCount = 0;

// ============================================================
// Verification trigger
// ============================================================

#define VERIFY_TRIGGER_PIN D3

// ============================================================
// RESET CYCLE
// ============================================================

void resetCycleState() {

    // --------------------------------------------------------
    // Signature size
    // --------------------------------------------------------

    expectedSignatureSize = 0;
    expectedSignatureHexLen = 0;
    expectedSignatureChunks = 0;

    signatureSizeReceived = false;

    // --------------------------------------------------------
    // Public key
    // --------------------------------------------------------

    publicKeyReceived = false;
    ackSent = false;

    // --------------------------------------------------------
    // Message
    // --------------------------------------------------------

    messageReceived = false;
    msgAckSent = false;

    receivedMessageLen = 0;

    // --------------------------------------------------------
    // Signature
    // --------------------------------------------------------

    signatureReceived = false;
    sigAckSent = false;

    memset(
        sigChunkReceived,
        0,
        sizeof(sigChunkReceived)
    );

    sigChunksReceivedCount = 0;

    // Clear signature buffer
    memset(
        receivedSigHex,
        0,
        sizeof(receivedSigHex)
    );

    // --------------------------------------------------------
    // Verification
    // --------------------------------------------------------

    verificationDone = false;
    verificationOk = false;
    startResent = false;
}

// ============================================================
// LOG PREVIEW
// ============================================================

void logPreview(
    const char* label,
    const char* buf,
    unsigned int fullLength
) {

    const int previewLen = 40;

    char preview[previewLen + 1];

    int n =
        (fullLength < (unsigned int)previewLen)
            ? fullLength
            : previewLen;

    memcpy(
        preview,
        buf,
        n
    );

    preview[n] = '\0';

    Log.info(
        "%s (%u chars): %s%s",
        label,
        fullLength,
        preview,
        (fullLength > (unsigned int)previewLen)
            ? "..."
            : ""
    );
}

// ============================================================
// HEX NIBBLE
// ============================================================

int hexNibble(char c) {

    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}

// ============================================================
// HEX -> BYTES
// ============================================================

bool hexToBytes(
    const char* hex,
    uint8_t* bytesOut,
    size_t byteLen
) {

    for (size_t i = 0; i < byteLen; i++) {

        int hi =
            hexNibble(
                hex[i * 2]
            );

        int lo =
            hexNibble(
                hex[i * 2 + 1]
            );

        if (
            hi < 0 ||
            lo < 0
        ) {

            Log.error(
                "Hex decode failed at byte index %u",
                (unsigned)i
            );

            return false;
        }

        bytesOut[i] =
            (uint8_t)(
                (hi << 4) | lo
            );
    }

    return true;
}

// ============================================================
// MQTT CALLBACK
// ============================================================

void mqttCallback(
    char* topic,
    byte* payload,
    unsigned int length
) {

    // ========================================================
    // SIGNATURE SIZE
    //
    // This should arrive FIRST from Board A.
    // ========================================================

    if (
        strcmp(
            topic,
            "argon/signature_size"
        ) == 0
    ) {

        // Signature size is only a few ASCII characters,
        // e.g. "654".

        char sizeBuf[16];

        unsigned int copyLen = length;

        if (
            copyLen >= sizeof(sizeBuf)
        ) {

            Log.error(
                "Signature size payload too large"
            );

            return;
        }

        memcpy(
            sizeBuf,
            payload,
            copyLen
        );

        sizeBuf[copyLen] = '\0';

        unsigned long receivedSize =
            strtoul(
                sizeBuf,
                nullptr,
                10
            );

        // ----------------------------------------------------
        // Validate received size
        // ----------------------------------------------------

        if (
            receivedSize == 0 ||
            receivedSize >
                PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES
        ) {

            Log.error(
                "Invalid signature size received: %lu bytes",
                receivedSize
            );

            return;
        }

        expectedSignatureSize =
            (size_t)receivedSize;

        expectedSignatureHexLen =
            (unsigned int)(
                expectedSignatureSize * 2
            );

        expectedSignatureChunks =
            (
                expectedSignatureHexLen +
                SIG_CHUNK_HEX_LEN -
                1
            ) /
            SIG_CHUNK_HEX_LEN;

        // Safety check
        if (
            expectedSignatureChunks == 0 ||
            expectedSignatureChunks >
                MAX_SIG_CHUNKS
        ) {

            Log.error(
                "Calculated signature chunk count invalid: %u",
                expectedSignatureChunks
            );

            return;
        }

        signatureSizeReceived = true;

        Log.info(
            "Signature size received: %u bytes",
            (unsigned int)expectedSignatureSize
        );

        Log.info(
            "Expected signature hex length: %u chars",
            expectedSignatureHexLen
        );

        Log.info(
            "Expected signature chunks: %u",
            expectedSignatureChunks
        );
    }

    // ========================================================
    // PUBLIC KEY
    // ========================================================

    else if (
        strcmp(
            topic,
            "argon/pubkey"
        ) == 0
    ) {

        unsigned int copyLen =
            length;

        if (
            copyLen >=
                PUBKEY_HEX_MAXLEN
        ) {

            Log.error(
                "Public key payload too large (%u bytes), truncating",
                length
            );

            copyLen =
                PUBKEY_HEX_MAXLEN - 1;
        }

        memcpy(
            receivedPubKeyHex,
            payload,
            copyLen
        );

        receivedPubKeyHex[
            copyLen
        ] = '\0';

        publicKeyReceived = true;

        Log.info(
            "Public key received successfully"
        );

        logPreview(
            "Public key (hex)",
            receivedPubKeyHex,
            copyLen
        );
    }

    // ========================================================
    // MESSAGE
    // ========================================================

    else if (
        strcmp(
            topic,
            "argon/message"
        ) == 0
    ) {

        unsigned int copyLen =
            length;

        if (
            copyLen >=
                MESSAGE_MAXLEN
        ) {

            Log.error(
                "Message payload too large (%u bytes), truncating",
                length
            );

            copyLen =
                MESSAGE_MAXLEN - 1;
        }

        memcpy(
            receivedMessageBuf,
            payload,
            copyLen
        );

        receivedMessageBuf[
            copyLen
        ] = '\0';

        receivedMessageLen =
            copyLen;

        messageReceived = true;

        Log.info(
            "Message received successfully"
        );

        Log.info(
            "Message (%u bytes): %s",
            copyLen,
            receivedMessageBuf
        );
    }

    // ========================================================
    // SIGNATURE CHUNK
    // ========================================================

    else if (
        strcmp(
            topic,
            "argon/signature_chunk"
        ) == 0
    ) {

        // ----------------------------------------------------
        // We MUST know the signature size first.
        // ----------------------------------------------------

        if (!signatureSizeReceived) {

            Log.error(
                "Signature chunk received before signature size"
            );

            return;
        }

        unsigned int copyLen =
            length;

        if (
            copyLen >=
                SIG_CHUNK_MSG_MAXLEN
        ) {

            Log.error(
                "Signature chunk payload too large (%u bytes), dropping",
                length
            );

            return;
        }

        memcpy(
            sigChunkTemp,
            payload,
            copyLen
        );

        sigChunkTemp[
            copyLen
        ] = '\0';

        // ----------------------------------------------------
        // Find separator:
        //
        // 0000:ABCDEF...
        //     ^
        // ----------------------------------------------------

        char* colon =
            strchr(
                sigChunkTemp,
                ':'
            );

        if (
            colon == nullptr
        ) {

            Log.error(
                "Malformed signature chunk (no ':' found)"
            );

            return;
        }

        *colon = '\0';

        int idx =
            atoi(
                sigChunkTemp
            );

        const char* hexData =
            colon + 1;

        unsigned int hexDataLen =
            (unsigned int)
                strlen(hexData);

        // ----------------------------------------------------
        // Validate chunk index against ACTUAL expected chunks
        // ----------------------------------------------------

        if (
            idx < 0 ||
            (unsigned int)idx >=
                expectedSignatureChunks
        ) {

            Log.error(
                "Signature chunk index %d out of range (expected 0..%u)",
                idx,
                expectedSignatureChunks - 1
            );

            return;
        }

        // ----------------------------------------------------
        // Calculate destination offset
        // ----------------------------------------------------

        unsigned int offset =
            (unsigned int)idx *
            SIG_CHUNK_HEX_LEN;

        // ----------------------------------------------------
        // Determine exactly how many hex chars this particular
        // chunk SHOULD contain.
        //
        // All chunks except the last one should contain 1800.
        // Last chunk contains the remaining characters.
        // ----------------------------------------------------

        unsigned int remainingExpected =
            expectedSignatureHexLen -
            offset;

        unsigned int expectedChunkHexLen =
            (
                remainingExpected >
                SIG_CHUNK_HEX_LEN
            )
                ? SIG_CHUNK_HEX_LEN
                : remainingExpected;

        // ----------------------------------------------------
        // Check actual chunk length
        // ----------------------------------------------------

        if (
            hexDataLen !=
                expectedChunkHexLen
        ) {

            Log.error(
                "Signature chunk %d has wrong length: expected %u, received %u",
                idx,
                expectedChunkHexLen,
                hexDataLen
            );

            return;
        }

        // ----------------------------------------------------
        // Final buffer protection
        // ----------------------------------------------------

        if (
            offset +
            hexDataLen >
            expectedSignatureHexLen
        ) {

            Log.error(
                "Signature chunk %d would exceed expected signature length",
                idx
            );

            return;
        }

        // ----------------------------------------------------
        // Copy chunk directly into correct location
        // ----------------------------------------------------

        memcpy(
            receivedSigHex + offset,
            hexData,
            hexDataLen
        );

        // ----------------------------------------------------
        // Count each chunk only once
        // ----------------------------------------------------

        if (
            !sigChunkReceived[idx]
        ) {

            sigChunkReceived[idx] =
                true;

            sigChunksReceivedCount++;
        }

        Log.info(
            "Signature chunk %d received (%u/%u)",
            idx,
            sigChunksReceivedCount,
            expectedSignatureChunks
        );

        // ----------------------------------------------------
        // Signature complete?
        // ----------------------------------------------------

        if (
            sigChunksReceivedCount ==
            expectedSignatureChunks
        ) {

            receivedSigHex[
                expectedSignatureHexLen
            ] = '\0';

            signatureReceived =
                true;

            Log.info(
                "Complete signature received"
            );

            Log.info(
                "Signature size: %u bytes",
                (unsigned int)
                    expectedSignatureSize
            );

            Log.info(
                "Signature hex length: %u chars",
                expectedSignatureHexLen
            );

            Log.info(
                "All %u signature chunks received",
                expectedSignatureChunks
            );
        }
    }

    // ========================================================
    // CONTROL
    // ========================================================

    else if (
        strcmp(
            topic,
            "argon/control"
        ) == 0
    ) {

        unsigned int copyLen =
            length;

        if (
            copyLen >=
                CONTROL_MAXLEN
        ) {

            copyLen =
                CONTROL_MAXLEN - 1;
        }

        memcpy(
            controlMsgBuf,
            payload,
            copyLen
        );

        controlMsgBuf[
            copyLen
        ] = '\0';

        Log.info(
            "Received on %s: %s",
            topic,
            controlMsgBuf
        );
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
// WiFi
// ============================================================

bool connectWiFi() {

    if (WiFi.ready()) {
        return true;
    }

    Log.info(
        "Connecting to WiFi..."
    );

    WiFi.off();

    delay(1000);

    WiFi.on();

    WiFi.setCredentials(
        "Gintonic",
        "capitainemassime"
    );

    WiFi.connect();

    for (
        int i = 0;
        i < 60;
        i++
    ) {

        if (
            WiFi.ready()
        ) {

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
// SEND PUBLIC KEY ACK
// ============================================================

void sendPublicKeyAck() {

    if (
        client.publish(
            "argon/control",
            "PK_ACK"
        )
    ) {

        Log.info(
            "PK_ACK sent to board_a"
        );

        ackSent = true;
    }

    else {

        Log.error(
            "Failed to send PK_ACK"
        );
    }
}

// ============================================================
// SEND MESSAGE ACK
// ============================================================

void sendMessageAck() {

    if (
        client.publish(
            "argon/control",
            "MSG_ACK"
        )
    ) {

        Log.info(
            "MSG_ACK sent to board_a"
        );

        msgAckSent = true;
    }

    else {

        Log.error(
            "Failed to send MSG_ACK"
        );
    }
}

// ============================================================
// SEND SIGNATURE ACK
// ============================================================

void sendSignatureAck() {

    if (
        client.publish(
            "argon/control",
            "SIG_ACK"
        )
    ) {

        Log.info(
            "SIG_ACK sent to board_a"
        );

        sigAckSent = true;
    }

    else {

        Log.error(
            "Failed to send SIG_ACK"
        );
    }
}

// ============================================================
// VERIFY SIGNATURE
//
// IMPORTANT:
// We now decode and verify exactly expectedSignatureSize
// bytes, NOT PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES.
// ============================================================

void verifySignature() {

    Log.info(
        "Starting signature verification..."
    );

    // --------------------------------------------------------
    // Sanity checks
    // --------------------------------------------------------

    if (
        !signatureSizeReceived ||
        expectedSignatureSize == 0
    ) {

        Log.error(
            "Cannot verify: valid signature size not received"
        );

        verificationDone = true;
        verificationOk = false;

        return;
    }

    if (!signatureReceived) {

        Log.error(
            "Cannot verify: signature is incomplete"
        );

        verificationDone = true;
        verificationOk = false;

        return;
    }

    // --------------------------------------------------------
    // Decode public key
    // --------------------------------------------------------

    if (
        !hexToBytes(
            receivedPubKeyHex,
            receivedPubKeyBytes,
            PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
        )
    ) {

        Log.error(
            "Failed to decode public key hex"
        );

        verificationDone = true;
        verificationOk = false;

        return;
    }

    // --------------------------------------------------------
    // Decode ONLY actual received signature bytes
    // --------------------------------------------------------

    if (
        !hexToBytes(
            receivedSigHex,
            receivedSigBytes,
            expectedSignatureSize
        )
    ) {

        Log.error(
            "Failed to decode signature hex"
        );

        verificationDone = true;
        verificationOk = false;

        return;
    }

    Log.info(
        "Verifying signature using %u-byte signature",
        (unsigned int)expectedSignatureSize
    );

    // --------------------------------------------------------
    // Verification timing starts HERE
    // --------------------------------------------------------

    digitalWrite(
        VERIFY_TRIGGER_PIN,
        HIGH
    );

    uint32_t startTime =
        millis();

    int ret =
        PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
            receivedSigBytes,

            // IMPORTANT:
            // Actual Falcon signature size received from Board A
            expectedSignatureSize,

            (const uint8_t*)
                receivedMessageBuf,

            receivedMessageLen,

            receivedPubKeyBytes
        );

    uint32_t elapsed =
        millis() -
        startTime;

    digitalWrite(
        VERIFY_TRIGGER_PIN,
        LOW
    );

    verificationDone =
        true;

    if (
        ret == 0
    ) {

        Log.info(
            "Signature verification SUCCESS"
        );

        verificationOk =
            true;
    }

    else {

        Log.error(
            "Signature verification FAILED, ret=%d",
            ret
        );

        verificationOk =
            false;
    }

    Log.info(
        "Verification time: %lu ms",
        (unsigned long)elapsed
    );
}

// ============================================================
// SEND START AGAIN
// ============================================================

void sendStartAgain() {

    if (
        client.publish(
            "argon/control",
            "START"
        )
    ) {

        cycleCount++;

        Log.info(
            "START sent to board_a (post-verification)"
        );

        Log.info(
            "===== Cycle #%lu complete (verification %s), awaiting next cycle =====",
            (unsigned long)cycleCount,
            verificationOk
                ? "OK"
                : "FAILED"
        );

        startResent =
            true;

        resetCycleState();
    }

    else {

        Log.error(
            "Failed to send START"
        );
    }
}

// ============================================================
// SETUP
// ============================================================

void setup() {

    delay(2000);

    pinMode(
        VERIFY_TRIGGER_PIN,
        OUTPUT
    );

    digitalWrite(
        VERIFY_TRIGGER_PIN,
        LOW
    );

    String deviceId =
        System.deviceID();

    snprintf(
        clientId,
        sizeof(clientId),
        "board-b-%s",
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

    connectWiFi();

    if (
        WiFi.ready()
    ) {

        if (
            client.connect(
                clientId
            )
        ) {

            Log.info(
                "MQTT connected"
            );

            // =================================================
            // IMPORTANT:
            // Subscribe to signature size.
            // =================================================

            client.subscribe(
                "argon/signature_size"
            );

            client.subscribe(
                "argon/pubkey"
            );

            client.subscribe(
                "argon/message"
            );

            client.subscribe(
                "argon/signature_chunk"
            );

            client.subscribe(
                "argon/control"
            );

            // =================================================
            // Trigger Board A
            // =================================================

            client.publish(
                "argon/control",
                "START"
            );

            Log.info(
                "Sent START to board_a"
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
// MAIN LOOP
// ============================================================

void loop() {

    // ========================================================
    // WiFi recovery
    // ========================================================

    if (
        !WiFi.ready()
    ) {

        connectWiFi();

        return;
    }

    // ========================================================
    // MQTT
    // ========================================================

    if (
        client.isConnected()
    ) {

        client.loop();

        // ====================================================
        // Public key ACK
        // ====================================================

        if (
            publicKeyReceived &&
            !ackSent
        ) {

            sendPublicKeyAck();
        }

        // ====================================================
        // Message ACK
        // ====================================================

        if (
            messageReceived &&
            !msgAckSent
        ) {

            sendMessageAck();
        }

        // ====================================================
        // Signature ACK
        //
        // Only happens when ALL expected signature chunks
        // based on received signature size have arrived.
        // ====================================================

        if (
            signatureReceived &&
            !sigAckSent
        ) {

            sendSignatureAck();
        }

        // ====================================================
        // Verification
        // ====================================================

        if (
            sigAckSent &&
            !verificationDone
        ) {

            verifySignature();
        }

        // ====================================================
        // Start next cycle
        // ====================================================

        if (
            verificationDone &&
            !startResent
        ) {

            sendStartAgain();
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

            // Re-subscribe to ALL topics
            client.subscribe(
                "argon/signature_size"
            );

            client.subscribe(
                "argon/pubkey"
            );

            client.subscribe(
                "argon/message"
            );

            client.subscribe(
                "argon/signature_chunk"
            );

            client.subscribe(
                "argon/control"
            );

            client.publish(
                "argon/control",
                "START"
            );

            Log.info(
                "Sent START to board_a"
            );
        }

        delay(2000);
    }
}