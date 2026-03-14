/*
 * ============================================================
 *   ESP32 IoT Patient Health Monitor — SECURE EDITION
 *   MAX30102 + AD8232 ECG + SSD1306 OLED Display
 *   Security: AES-256-CBC Encryption + SHA-256 HMAC Signature
 *   Ledger  : Consortium Blockchain (hash-chained blocks)
 *   Transport: AWS IoT Core via MQTT (TLS/mTLS)
 *   TinyML  : Rule-Based Anomaly + Cyber Attack Detection
 *             (No external TFLite library required)
 *
 *  I2C Addresses (no conflict):
 *      MAX30102  → 0x57
 *      SSD1306   → 0x3C
 *
 *  MQTT Topics published:
 *      esp32/health/data        ← encrypted vitals + blockchain + ML result
 *      esp32/health/status      ← device heartbeat every 30s
 *      esp32/health/alerts      ← TinyML anomaly/attack alerts (immediate)
 *
 *  MQTT Topic subscribed:
 *      esp32/health/commands    ← receive commands from cloud
 * ============================================================
 */

#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>

// MAX30102 — SparkFun library
#include "MAX30105.h"
#include "heartRate.h"
#include "spo2_algorithm.h"

// OLED — Adafruit SSD1306
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// mbedTLS — built into ESP32 Arduino core (no extra install)
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"

// ============================================================
//  USER CONFIGURATION — WiFi
// ============================================================
const char* WIFI_SSID     = "your wifi name";
const char* WIFI_PASSWORD = "your wifi password";
const char* DEVICE_ID     = "ESP32_HEALTH_01";
const char* PATIENT_ID    = "Patient_1";

// ============================================================
//  AWS IoT Core Configuration
// ============================================================
const char* AWS_IOT_ENDPOINT = ".amazonaws.com";
const int   AWS_IOT_PORT     = 8883;

// MQTT Topics
const char* TOPIC_PUBLISH_DATA    = "esp32/health/data";
const char* TOPIC_PUBLISH_STATUS  = "esp32/health/status";
const char* TOPIC_PUBLISH_ALERTS  = "esp32/health/alerts";
const char* TOPIC_SUBSCRIBE_CMD   = "esp32/health/commands";

// ============================================================
//  AWS IoT Certificates
// ============================================================

const char AWS_CERT_CA[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----
)EOF";

const char AWS_CERT_CRT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----
)EOF";

const char AWS_CERT_PRIVATE[] PROGMEM = R"EOF(
-----BEGIN RSA PRIVATE KEY-----

-----END RSA PRIVATE KEY-----
)EOF";

// ============================================================
//  SECURITY KEYS — AES-256 + HMAC-SHA256
// ============================================================
const uint8_t AES_KEY[32] = {
  0x2B,0x7E,0x15,0x16, 0x28,0xAE,0xD2,0xA6,
  0xAB,0xF7,0x15,0x88, 0x09,0xCF,0x4F,0x3C,
  0x76,0x2E,0x71,0x60, 0xF3,0x8B,0x4D,0xA5,
  0x6A,0x78,0x4D,0x90, 0x45,0x19,0x0C,0xFE
};

const uint8_t HMAC_KEY[32] = {
  0x60,0x3D,0xEB,0x10, 0x15,0xCA,0x71,0xBE,
  0x2B,0x73,0xAE,0xF0, 0x85,0x7D,0x77,0x81,
  0x1F,0x35,0x2C,0x07, 0x3B,0x61,0x08,0xD7,
  0x2D,0x98,0x10,0xA3, 0x09,0x14,0xDF,0xF4
};

// ── Pin Definitions ─────────────────────────────────────────
#define ECG_PIN              34
#define I2C_SDA              21
#define I2C_SCL              22
#define SEND_INTERVAL_MS     5000
#define STATUS_INTERVAL_MS   30000
#define ML_INTERVAL_MS       2000

// ── OLED Configuration ───────────────────────────────────────
#define SCREEN_WIDTH   128
#define SCREEN_HEIGHT   64
#define OLED_RESET      -1
#define OLED_ADDRESS  0x3C

// ── MAX30102 SpO2 buffer ─────────────────────────────────────
#define BUFFER_LENGTH 100

// ── TinyML Thresholds ────────────────────────────────────────
#define ML_ANOMALY_THRESHOLD  0.50f
#define ML_ATTACK_THRESHOLD   0.50f

// ============================================================
//  BLOCKCHAIN CONFIGURATION
// ============================================================
#define MAX_CHAIN_LENGTH 20

struct Block {
  uint32_t index;
  uint64_t timestamp;
  int      heartRate;
  int      spO2;
  int      ecgValue;
  char     previousHash[65];
  char     blockHash[65];
  char     signature[65];
  bool     valid;
};

Block    blockchain[MAX_CHAIN_LENGTH];
uint32_t chainLength = 0;
uint32_t blockIndex  = 0;
char     lastBlockHash[65] =
  "0000000000000000000000000000000000000000000000000000000000000000";

// ============================================================
//  TINYML RESULT STRUCTURE
// ============================================================
struct MLResult {
  float anomalyScore;
  float attackScore;
  bool  anomalyDetected;
  bool  attackDetected;
  char  anomalyLabel[32];
  char  attackLabel[32];
  bool  modelReady;
};

MLResult mlResult = {0.0f, 0.0f, false, false, "NORMAL", "CLEAN", false};

// ============================================================
//  GLOBALS
// ============================================================
MAX30105           particleSensor;
Adafruit_SSD1306   display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

WiFiClientSecure   wifiClientSecure;
PubSubClient       mqttClient(wifiClientSecure);

bool sensorFound   = false;
bool oledFound     = false;
bool wifiConnected = false;
bool awsConnected  = false;

int heartRate = 0;
int spO2      = 0;
int ecgValue  = 0;

uint32_t irBuffer[BUFFER_LENGTH];
uint32_t redBuffer[BUFFER_LENGTH];
int32_t  spo2Raw   = 0;
int8_t   spo2Valid = 0;
int32_t  hrRaw     = 0;
int8_t   hrValid   = 0;

const byte RATE_SIZE = 4;
byte  rates[RATE_SIZE];
byte  rateSpot       = 0;
long  lastBeat       = 0;
float beatsPerMinute = 0;
int   beatAvg        = 0;

bool heartBlink = false;

unsigned long lastSendTime   = 0;
unsigned long lastStatusTime = 0;
unsigned long lastReportTime = 0;
unsigned long lastSpO2Calc   = 0;
unsigned long lastOledUpdate = 0;
unsigned long lastMLTime     = 0;

// ============================================================
//  PROTOTYPES
// ============================================================
void connectWiFi();
void connectAWS();
void mqttCallback(char* topic, byte* payload, unsigned int length);
void publishHealthData();
void publishStatusHeartbeat();
void publishMLAlert();
void initMAX30102();
void initOLED();
void scanI2C();
void updateOLED();
void oledSplash();
void oledWifiStatus(bool connecting);
void oledAwsStatus(bool connecting);
void printBanner();

// Security
void bytesToHex(const uint8_t* bytes, size_t len, char* hexOut);
void computeSHA256(const uint8_t* data, size_t len, char* hexOut);
void computeHMAC_SHA256(const uint8_t* data, size_t len, char* hexOut);
bool encryptAES256CBC(const char* plaintext, char* b64Out, size_t b64OutLen);

// Blockchain
void   computeBlockHash(Block& b, char* hashOut);
void   signBlock(Block& b);
Block  createBlock(int hr, int spo2, int ecg);
bool   addBlock(int hr, int spo2, int ecg);
bool   verifyChain();
String blockToJson(const Block& b);

// TinyML
bool     initTinyML();
MLResult runMLInference(int hr, int spo2, int ecg);

// ============================================================
//  SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(1000);
  printBanner();

  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.setClock(400000);
  delay(100);
  Serial.println("[I2C]    ✓ I2C initialized at 400kHz");

  scanI2C();
  initOLED();
  oledSplash();
  initMAX30102();

  pinMode(ECG_PIN, INPUT);
  Serial.println("[SENSOR] ✓ AD8232 ECG on GPIO34");

  // Genesis block
  Serial.println("[CHAIN]  Creating Genesis Block...");
  addBlock(0, 0, 0);
  Serial.println("[CHAIN]  ✓ Blockchain initialized");

  // TinyML init
  Serial.println("\n=========================================");
  Serial.println("[TINYML] Initializing rule-based ML engine...");
  if (initTinyML()) {
    mlResult.modelReady = true;
    Serial.println("[TINYML] ✅ ML engine ready!");
    Serial.println("[TINYML]   Anomaly threshold : " + String(ML_ANOMALY_THRESHOLD));
    Serial.println("[TINYML]   Attack  threshold : " + String(ML_ATTACK_THRESHOLD));
  }
  Serial.println("=========================================\n");

  // WiFi
  oledWifiStatus(true);
  connectWiFi();
  oledWifiStatus(false);

  // AWS IoT Core
  if (wifiConnected) {
    oledAwsStatus(true);
    connectAWS();
    oledAwsStatus(false);
  }

  Serial.println("[INIT]   ✓ All systems ready!\n=========================================\n");
}

// ============================================================
//  LOOP
// ============================================================
void loop() {
  unsigned long now = millis();

  // Keep MQTT alive
  if (awsConnected) {
    if (!mqttClient.connected()) {
      Serial.println("[MQTT]   ⚠️  Disconnected — reconnecting...");
      awsConnected = false;
      connectAWS();
    } else {
      mqttClient.loop();
    }
  }

  // Always read ECG
  ecgValue = analogRead(ECG_PIN);

  // MAX30102 continuous beat detection
  if (sensorFound) {
    long irValue = particleSensor.getIR();

    if (irValue > 50000) {
      if (checkForBeat(irValue)) {
        long delta     = millis() - lastBeat;
        lastBeat       = millis();
        beatsPerMinute = 60.0 / (delta / 1000.0);
        heartBlink     = !heartBlink;

        if (beatsPerMinute >= 20 && beatsPerMinute <= 255) {
          rates[rateSpot++] = (byte)beatsPerMinute;
          rateSpot %= RATE_SIZE;
          beatAvg = 0;
          for (byte x = 0; x < RATE_SIZE; x++) beatAvg += rates[x];
          beatAvg /= RATE_SIZE;
          Serial.printf("[♥]      Beat! BPM=%.1f  Avg=%d bpm\n",
                        beatsPerMinute, beatAvg);
        }
      }
    } else {
      beatAvg = 0; beatsPerMinute = 0; rateSpot = 0;
      memset(rates, 0, sizeof(rates));
      heartBlink = false;
    }

    // SpO2 calculation every 4 seconds
    if (now - lastSpO2Calc >= 4000) {
      lastSpO2Calc = now;
      for (byte i = 0; i < BUFFER_LENGTH; i++) {
        while (!particleSensor.available()) particleSensor.check();
        redBuffer[i] = particleSensor.getRed();
        irBuffer[i]  = particleSensor.getIR();
        particleSensor.nextSample();
      }
      maxim_heart_rate_and_oxygen_saturation(
        irBuffer, BUFFER_LENGTH, redBuffer,
        &spo2Raw, &spo2Valid, &hrRaw, &hrValid
      );
    }
  }

  // Validated readings
  heartRate = (hrValid   && hrRaw   >= 30 && hrRaw   <= 200) ? hrRaw   :
              (beatAvg   >= 30 && beatAvg  <= 200)            ? beatAvg : 0;
  spO2      = (spo2Valid && spo2Raw >= 70 && spo2Raw <= 100) ? spo2Raw : 0;

  // WiFi watchdog
  if (WiFi.status() != WL_CONNECTED) {
    if (wifiConnected) {
      Serial.println("\n[WIFI]   ⚠️  Lost connection! Reconnecting...");
      wifiConnected = false;
      awsConnected  = false;
    }
    connectWiFi();
    if (wifiConnected && !awsConnected) connectAWS();
  }

  // ── TinyML Inference every 2 seconds ─────────────────────
  if (mlResult.modelReady && (now - lastMLTime >= ML_INTERVAL_MS)) {
    lastMLTime = now;

    mlResult = runMLInference(heartRate, spO2, ecgValue);

    Serial.printf("[TINYML] HR=%d SpO2=%d ECG=%d → Anomaly=%s(%.2f) Attack=%s(%.2f)\n",
                  heartRate, spO2, ecgValue,
                  mlResult.anomalyLabel, mlResult.anomalyScore,
                  mlResult.attackLabel,  mlResult.attackScore);

    // Immediate alert if attack or anomaly detected
    if (awsConnected && (mlResult.anomalyDetected || mlResult.attackDetected)) {
      publishMLAlert();
    }
  }
  // ─────────────────────────────────────────────────────────

  // Every 5 seconds: add block + publish health data
  if (now - lastSendTime >= SEND_INTERVAL_MS) {
    lastSendTime = now;
    addBlock(heartRate, spO2, ecgValue);
    if (awsConnected) {
      publishHealthData();
    } else {
      Serial.println("[ERROR]  ✗ Cannot publish — AWS IoT not connected!");
    }
  }

  // Every 30 seconds: publish status heartbeat
  if (awsConnected && (now - lastStatusTime >= STATUS_INTERVAL_MS)) {
    lastStatusTime = now;
    publishStatusHeartbeat();
  }

  // OLED update every 500ms
  if (oledFound && (now - lastOledUpdate >= 500)) {
    lastOledUpdate = now;
    updateOLED();
  }

  // Serial report every 5 seconds
  if (now - lastReportTime >= 5000) {
    lastReportTime = now;
    Serial.println("─────────────────────────────────────────");
    Serial.printf("[READING] HR: %d bpm | SpO2: %d%% | ECG: %d\n",
                  heartRate, spO2, ecgValue);
    Serial.printf("[CHAIN]   Blocks: %u | Valid: %s\n",
                  blockIndex, verifyChain() ? "✅ YES" : "❌ TAMPERED");
    Serial.printf("[MQTT]    AWS: %s\n", awsConnected ? "✅ Connected" : "❌ Offline");
    Serial.printf("[TINYML]  Anomaly: %s(%.2f) | Attack: %s(%.2f)\n",
                  mlResult.anomalyLabel, mlResult.anomalyScore,
                  mlResult.attackLabel,  mlResult.attackScore);
    if (!sensorFound)
      Serial.println("[WARN]    MAX30102 not detected on I2C bus!");
    Serial.println("─────────────────────────────────────────");
  }

  delay(10);
}

// ============================================================
//  TINYML — Initialize engine
// ============================================================
bool initTinyML() {
  // Rule-based engine — always succeeds, no model file or library needed
  Serial.println("[TINYML] ✓ Rule-based inference engine ready (no library needed)");
  return true;
}

// ============================================================
//  TINYML — Run Inference
//  Detects vital anomalies and cyber attack patterns
//  using clinical thresholds and sensor consistency checks.
// ============================================================
MLResult runMLInference(int hr, int spo2, int ecg) {
  MLResult result;
  result.modelReady = true;

  // ── VITAL ANOMALY DETECTION (clinical thresholds) ─────────
  // Bradycardia: HR < 50 bpm
  bool hrLow    = (hr   > 0 && hr   < 50);
  // Tachycardia: HR > 120 bpm
  bool hrHigh   = (hr   > 0 && hr   > 120);
  // Hypoxia: SpO2 below safe threshold
  bool spo2Low  = (spo2 > 0 && spo2 < 94);
  // ECG out of normal mid-rail range (AD8232 on 3.3V → ~1000–3000 at rest)
  bool ecgAnom  = (ecg  > 0 && (ecg < 800 || ecg > 3300));

  int anomalyCount       = (int)hrLow + (int)hrHigh + (int)spo2Low + (int)ecgAnom;
  result.anomalyScore    = (float)anomalyCount / 4.0f;
  result.anomalyDetected = (result.anomalyScore >= ML_ANOMALY_THRESHOLD);

  // ── CYBER ATTACK / SENSOR TAMPERING DETECTION ─────────────
  // ADC rail clamping: signal forced to 0 or 4095 (injection attack)
  bool ecgRail   = (ecg <= 50 || ecg >= 4050);
  // Extreme ECG spike beyond physical possibility
  bool ecgJump   = (ecg > 0   && (ecg < 100  || ecg > 4000));
  // Sensor frozen: MAX30102 detected but no HR or beat for a while
  bool frozenHR  = (sensorFound && hr == 0 && beatAvg == 0);
  // Impossible SpO2 values — spoofed/replayed data
  bool spo2Spoof = (spo2 > 100 || (spo2 > 0 && spo2 < 50));

  int attackCount       = (int)ecgRail + (int)ecgJump + (int)frozenHR + (int)spo2Spoof;
  result.attackScore    = (float)attackCount / 4.0f;
  result.attackDetected = (result.attackScore >= ML_ATTACK_THRESHOLD);

  // ── ANOMALY LABEL ──────────────────────────────────────────
  if (!result.anomalyDetected) {
    strncpy(result.anomalyLabel, "NORMAL",   sizeof(result.anomalyLabel));
  } else if (result.anomalyScore >= 0.75f) {
    strncpy(result.anomalyLabel, "CRITICAL", sizeof(result.anomalyLabel));
  } else {
    strncpy(result.anomalyLabel, "WARNING",  sizeof(result.anomalyLabel));
  }

  // ── ATTACK LABEL ───────────────────────────────────────────
  if (!result.attackDetected) {
    strncpy(result.attackLabel, "CLEAN",       sizeof(result.attackLabel));
  } else if (result.attackScore >= 0.5f) {
    strncpy(result.attackLabel, "ATTACK_HIGH", sizeof(result.attackLabel));
  } else {
    strncpy(result.attackLabel, "ATTACK_LOW",  sizeof(result.attackLabel));
  }

  return result;
}

// ============================================================
//  TINYML — Publish ML Alert via MQTT
//  Fires immediately on esp32/health/alerts when detected
// ============================================================
void publishMLAlert() {
  StaticJsonDocument<400> doc;
  doc["device_id"]      = DEVICE_ID;
  doc["patient_id"]     = PATIENT_ID;
  doc["alert_type"]     = (mlResult.attackDetected && mlResult.anomalyDetected) ? "BOTH" :
                           mlResult.attackDetected  ? "CYBER_ATTACK" : "VITAL_ANOMALY";
  doc["anomaly_score"]  = mlResult.anomalyScore;
  doc["attack_score"]   = mlResult.attackScore;
  doc["anomaly_label"]  = mlResult.anomalyLabel;
  doc["attack_label"]   = mlResult.attackLabel;
  doc["heart_rate"]     = heartRate;
  doc["spo2"]           = spO2;
  doc["ecg_value"]      = ecgValue;
  doc["block_index"]    = blockIndex - 1;
  doc["chain_valid"]    = verifyChain();
  doc["timestamp_ms"]   = (unsigned long)millis();
  doc["ml_engine"]      = "RuleBased-TinyML";

  String payload;
  serializeJson(doc, payload);

  bool ok = mqttClient.publish(TOPIC_PUBLISH_ALERTS, payload.c_str(), false);
  Serial.printf("[TINYML] 🚨 Alert → %s : %s | Type: %s\n",
                TOPIC_PUBLISH_ALERTS,
                ok ? "OK" : "FAILED",
                doc["alert_type"].as<const char*>());
  if (!ok) awsConnected = false;
}

// ============================================================
//  AWS IoT Core — Connect via MQTT/TLS (mTLS)
// ============================================================
void connectAWS() {
  Serial.println("\n=========================================");
  Serial.printf("[AWS]    🔄 Connecting to AWS IoT Core...\n");
  Serial.printf("[AWS]    Endpoint: %s:%d\n", AWS_IOT_ENDPOINT, AWS_IOT_PORT);

  wifiClientSecure.setCACert(AWS_CERT_CA);
  wifiClientSecure.setCertificate(AWS_CERT_CRT);
  wifiClientSecure.setPrivateKey(AWS_CERT_PRIVATE);

  mqttClient.setServer(AWS_IOT_ENDPOINT, AWS_IOT_PORT);
  mqttClient.setCallback(mqttCallback);
  mqttClient.setBufferSize(2048);
  mqttClient.setKeepAlive(60);

  int attempts = 0;
  while (!mqttClient.connected() && attempts < 5) {
    attempts++;
    Serial.printf("[AWS]    Attempt %d/5 — ClientID: %s\n", attempts, DEVICE_ID);

    if (mqttClient.connect(DEVICE_ID)) {
      awsConnected = true;
      Serial.println("[AWS]    ✅ Connected to AWS IoT Core!");
      mqttClient.subscribe(TOPIC_SUBSCRIBE_CMD);
      Serial.printf("[AWS]    📥 Subscribed: %s\n", TOPIC_SUBSCRIBE_CMD);
      Serial.printf("[AWS]    📤 Publishing to: %s\n", TOPIC_PUBLISH_DATA);
      Serial.printf("[AWS]    📤 Publishing to: %s\n", TOPIC_PUBLISH_STATUS);
      Serial.printf("[AWS]    📤 Publishing to: %s\n", TOPIC_PUBLISH_ALERTS);

      Serial.println("╔════════════════════════════════════════╗");
      Serial.println("║  ✅ AWS IoT Core CONNECTED!            ║");
      Serial.println("║  🔒 TLS 1.2 mTLS Authentication        ║");
      Serial.println("║  🔒 AES-256-CBC Payload Encryption     ║");
      Serial.println("║  ✍️  HMAC-SHA256 Signed                 ║");
      Serial.println("║  ⛓  Blockchain Ledger Active           ║");
      Serial.println("║  🧠 TinyML Rule Engine Active          ║");
      Serial.println("╚════════════════════════════════════════╝");
      break;
    } else {
      Serial.printf("[AWS]    ✗ Failed (state=%d), retrying in 3s...\n",
                    mqttClient.state());
      delay(3000);
    }
  }

  if (!awsConnected) {
    Serial.println("[AWS]    ✗ Could not connect to AWS IoT Core.");
    Serial.println("[AWS]      Check endpoint, certificates, and policy.");
  }
  Serial.println("=========================================\n");
}

// ============================================================
//  MQTT — Incoming message callback
// ============================================================
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  Serial.printf("[MQTT]   📥 Message on [%s] (%u bytes)\n", topic, length);

  char msg[256] = {0};
  size_t copyLen = min((unsigned int)(sizeof(msg) - 1), length);
  memcpy(msg, payload, copyLen);
  msg[copyLen] = '\0';
  Serial.printf("[MQTT]   Payload: %s\n", msg);

  StaticJsonDocument<256> cmdDoc;
  if (deserializeJson(cmdDoc, msg) == DeserializationError::Ok) {
    const char* cmd = cmdDoc["command"] | "";
    Serial.printf("[CMD]    Command received: %s\n", cmd);

    if (strcmp(cmd, "reset_chain") == 0) {
      chainLength = 0;
      blockIndex  = 0;
      strcpy(lastBlockHash,
        "0000000000000000000000000000000000000000000000000000000000000000");
      addBlock(0, 0, 0);
      Serial.println("[CMD]    ✓ Blockchain reset");
    } else if (strcmp(cmd, "status") == 0) {
      publishStatusHeartbeat();
    } else if (strcmp(cmd, "ml_status") == 0) {
      publishMLAlert();
      Serial.println("[CMD]    ✓ ML status published");
    } else {
      Serial.printf("[CMD]    Unknown command: %s\n", cmd);
    }
  }
}

// ============================================================
//  MQTT — Publish Health Data
// ============================================================
void publishHealthData() {
  Serial.println("\n=========================================");
  Serial.printf("[MQTT]   📤 Publishing to: %s\n", TOPIC_PUBLISH_DATA);

  StaticJsonDocument<300> rawDoc;
  rawDoc["device_id"]     = DEVICE_ID;
  rawDoc["patient_id"]    = PATIENT_ID;
  rawDoc["heart_rate"]    = heartRate;
  rawDoc["spo2"]          = spO2;
  rawDoc["ecg_value"]     = ecgValue;
  rawDoc["device_status"] = "ONLINE";
  rawDoc["attack_mode"]   = mlResult.attackDetected;
  rawDoc["block_index"]   = blockIndex - 1;
  String rawPayload;
  serializeJson(rawDoc, rawPayload);

  char encryptedB64[600] = {0};
  bool encOk = encryptAES256CBC(rawPayload.c_str(), encryptedB64, sizeof(encryptedB64));
  Serial.printf("[MQTT]   🔒 AES-256 : %s\n", encOk ? "OK" : "FAILED");

  char payloadHash[65];
  computeSHA256((uint8_t*)rawPayload.c_str(), rawPayload.length(), payloadHash);
  Serial.printf("[MQTT]   #  SHA-256 : %.24s...\n", payloadHash);

  char digitalSig[65];
  computeHMAC_SHA256((uint8_t*)payloadHash, strlen(payloadHash), digitalSig);
  Serial.printf("[MQTT]   ✍️  HMAC-Sig: %.24s...\n", digitalSig);

  uint32_t latestSlot = (blockIndex - 1) % MAX_CHAIN_LENGTH;
  String blockJson    = blockToJson(blockchain[latestSlot]);
  StaticJsonDocument<512> blockDoc;
  deserializeJson(blockDoc, blockJson);

  StaticJsonDocument<1400> secureDoc;
  secureDoc["device_id"]      = DEVICE_ID;
  secureDoc["patient_id"]     = PATIENT_ID;
  secureDoc["encrypted_data"] = encOk ? encryptedB64 : rawPayload.c_str();
  secureDoc["payload_hash"]   = payloadHash;
  secureDoc["signature"]      = digitalSig;
  secureDoc["encrypted"]      = encOk;
  secureDoc["algorithm"]      = "AES-256-CBC + HMAC-SHA256";
  secureDoc["chain_valid"]    = verifyChain();
  secureDoc["chain_length"]   = blockIndex;

  JsonObject blk      = secureDoc.createNestedObject("blockchain_block");
  blk["index"]        = blockDoc["index"];
  blk["blockHash"]    = blockDoc["blockHash"];
  blk["previousHash"] = blockDoc["previousHash"];
  blk["signature"]    = blockDoc["signature"];
  blk["timestamp"]    = blockDoc["timestamp"];
  blk["node_id"]      = DEVICE_ID;

  secureDoc["heart_rate"]    = heartRate;
  secureDoc["spo2"]          = spO2;
  secureDoc["ecg_value"]     = ecgValue;
  secureDoc["device_status"] = "ONLINE";
  secureDoc["attack_mode"]   = mlResult.attackDetected;

  // TinyML results embedded in every health payload
  JsonObject ml           = secureDoc.createNestedObject("tinyml");
  ml["anomaly_score"]     = mlResult.anomalyScore;
  ml["attack_score"]      = mlResult.attackScore;
  ml["anomaly_label"]     = mlResult.anomalyLabel;
  ml["attack_label"]      = mlResult.attackLabel;
  ml["anomaly_detected"]  = mlResult.anomalyDetected;
  ml["attack_detected"]   = mlResult.attackDetected;
  ml["engine"]            = "RuleBased-TinyML";

  secureDoc["transport"]  = "MQTT";
  secureDoc["timestamp"]  = (unsigned long)millis();

  String finalPayload;
  serializeJson(secureDoc, finalPayload);

  Serial.printf("[MQTT]   ⛓  Block #%u | Chain: %s\n",
                blockIndex - 1, verifyChain() ? "✅ Valid" : "❌ Tampered");
  Serial.printf("[MQTT]   🧠 ML: Anomaly=%s(%.2f) Attack=%s(%.2f)\n",
                mlResult.anomalyLabel, mlResult.anomalyScore,
                mlResult.attackLabel,  mlResult.attackScore);
  Serial.printf("[MQTT]   📦 Payload size: %u bytes\n", finalPayload.length());

  bool pubOk = mqttClient.publish(
    TOPIC_PUBLISH_DATA,
    (const uint8_t*)finalPayload.c_str(),
    finalPayload.length(),
    false
  );

  if (pubOk) {
    Serial.println("[MQTT]   ✅ Published successfully!");
  } else {
    Serial.println("[MQTT]   ✗ Publish FAILED — check buffer size / connection");
    awsConnected = false;
  }
  Serial.println("=========================================\n");
}

// ============================================================
//  MQTT — Publish Status Heartbeat
// ============================================================
void publishStatusHeartbeat() {
  StaticJsonDocument<400> doc;
  doc["device_id"]    = DEVICE_ID;
  doc["patient_id"]   = PATIENT_ID;
  doc["status"]       = "ONLINE";
  doc["uptime_ms"]    = (unsigned long)millis();
  doc["heart_rate"]   = heartRate;
  doc["spo2"]         = spO2;
  doc["ecg_value"]    = ecgValue;
  doc["chain_length"] = blockIndex;
  doc["chain_valid"]  = verifyChain();
  doc["wifi_rssi"]    = WiFi.RSSI();
  doc["transport"]    = "MQTT";
  doc["ml_anomaly"]   = mlResult.anomalyLabel;
  doc["ml_attack"]    = mlResult.attackLabel;

  String payload;
  serializeJson(doc, payload);

  bool ok = mqttClient.publish(TOPIC_PUBLISH_STATUS, payload.c_str());
  Serial.printf("[MQTT]   💓 Heartbeat → %s : %s\n",
                TOPIC_PUBLISH_STATUS, ok ? "OK" : "FAILED");
}

// ============================================================
//  I2C Scanner
// ============================================================
void scanI2C() {
  Serial.println("\n[I2C]    Scanning I2C bus...");
  int found = 0;
  for (byte addr = 1; addr < 127; addr++) {
    Wire.beginTransmission(addr);
    if (Wire.endTransmission() == 0) {
      Serial.printf("[I2C]    ✓ Device at 0x%02X", addr);
      if (addr == 0x57) Serial.print("  ← MAX30102");
      if (addr == 0x3C) Serial.print("  ← SSD1306 OLED");
      Serial.println();
      found++;
    }
  }
  if (!found) {
    Serial.println("[I2C]    ✗ No devices found!");
    Serial.println("[I2C]      Check VCC=3.3V, GND, SDA=GPIO21, SCL=GPIO22");
  } else {
    Serial.printf("[I2C]    Total: %d device(s) found\n", found);
  }
  Serial.println();
}

// ============================================================
//  Initialize OLED
// ============================================================
void initOLED() {
  Serial.println("[OLED]   Initializing SSD1306 at 0x3C...");
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
    Serial.println("[OLED]   ✗ SSD1306 not found! Check wiring.");
    oledFound = false;
    return;
  }
  oledFound = true;
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.display();
  Serial.println("[OLED]   ✓ OLED initialized successfully!");
}

// ============================================================
//  OLED — Splash Screen
// ============================================================
void oledSplash() {
  if (!oledFound) return;
  display.clearDisplay();
  display.drawRect(0, 0, 128, 26, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(8, 4);
  display.print("HEALTH MONITORING");
  display.setCursor(32, 14);
  display.print("SYSTEM");
  display.drawLine(0, 27, 128, 27, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(10, 32);
  display.print("ESP32 Secure Node");
  display.setCursor(12, 44);
  display.print("MAX30102 + AD8232");
  display.setCursor(22, 56);
  display.print("Initializing...");
  display.display();
  delay(2500);
}

// ============================================================
//  OLED — WiFi Status
// ============================================================
void oledWifiStatus(bool connecting) {
  if (!oledFound) return;
  display.clearDisplay();
  display.fillRect(0, 0, 128, 14, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK);
  display.setTextSize(1);
  display.setCursor(14, 3);
  display.print("HEALTH MONITORING");
  display.setTextColor(SSD1306_WHITE);
  display.drawLine(0, 15, 128, 15, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 20);
  if (connecting) {
    display.print("WiFi Connecting...");
    display.setCursor(0, 34);
    display.print("SSID:");
    display.setCursor(0, 44);
    display.print(WIFI_SSID);
  } else {
    if (wifiConnected) {
      display.print("WiFi Connected!");
      display.setCursor(0, 34);
      display.print("IP:");
      display.setCursor(0, 44);
      display.print(WiFi.localIP().toString());
    } else {
      display.print("WiFi FAILED!");
      display.setCursor(0, 34);
      display.print("Retrying later...");
    }
  }
  display.display();
  if (!connecting) delay(2000);
}

// ============================================================
//  OLED — AWS IoT Status
// ============================================================
void oledAwsStatus(bool connecting) {
  if (!oledFound) return;
  display.clearDisplay();
  display.fillRect(0, 0, 128, 14, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK);
  display.setTextSize(1);
  display.setCursor(14, 3);
  display.print("AWS IoT Core");
  display.setTextColor(SSD1306_WHITE);
  display.drawLine(0, 15, 128, 15, SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 20);
  if (connecting) {
    display.print("Connecting MQTT...");
    display.setCursor(0, 34);
    display.print("TLS mTLS Auth");
    display.setCursor(0, 44);
    display.print(AWS_IOT_ENDPOINT);
  } else {
    if (awsConnected) {
      display.print("AWS IoT Connected!");
      display.setCursor(0, 34);
      display.print("MQTT TLS OK");
      display.setCursor(0, 44);
      display.print("Publishing active");
    } else {
      display.print("AWS MQTT FAILED!");
      display.setCursor(0, 34);
      display.print("Check certs/policy");
    }
  }
  display.display();
  if (!connecting) delay(2000);
}

// ============================================================
//  OLED — Main monitoring screen (called every 500ms)
// ============================================================
void updateOLED() {
  if (!oledFound) return;
  display.clearDisplay();

  display.fillRect(0, 0, 128, 13, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK);
  display.setTextSize(1);
  display.setCursor(2, 3);
  display.print("HEALTH MONITORING SYS");
  display.setTextColor(SSD1306_WHITE);
  display.drawLine(0, 14, 128, 14, SSD1306_WHITE);

  // Heart Rate
  if (heartBlink && heartRate > 0) {
    display.fillCircle(6, 22, 4, SSD1306_WHITE);
  } else {
    display.drawCircle(6, 22, 4, SSD1306_WHITE);
  }
  display.setTextSize(1);
  display.setCursor(13, 17);
  display.print("HR:");
  display.setTextSize(2);
  display.setCursor(33, 15);
  if (heartRate > 0) display.printf("%3d", heartRate);
  else display.print("---");
  display.setTextSize(1);
  display.setCursor(81, 17);
  display.print("bpm");
  display.setCursor(104, 17);
  display.print(wifiConnected ? "W" : "w");
  display.setCursor(116, 17);
  display.print(awsConnected  ? "A" : "a");
  display.drawLine(0, 29, 128, 29, SSD1306_WHITE);

  // SpO2
  display.setTextSize(1);
  display.setCursor(0, 32);
  display.print("O2 SpO2:");
  display.setTextSize(2);
  display.setCursor(54, 31);
  if (spO2 > 0) display.printf("%3d", spO2);
  else display.print("---");
  display.setTextSize(1);
  display.setCursor(102, 33);
  display.print("%");
  display.drawLine(0, 44, 128, 44, SSD1306_WHITE);

  // ECG + Blockchain
  display.setTextSize(1);
  display.setCursor(0, 47);
  display.print("ECG:");
  display.setCursor(26, 47);
  display.printf("%4d", ecgValue);
  display.setCursor(66, 47);
  display.printf("Blk:%u", blockIndex > 0 ? blockIndex - 1 : 0);
  display.setCursor(110, 47);
  display.print(verifyChain() ? "OK" : "ER");
  display.drawLine(0, 56, 128, 56, SSD1306_WHITE);

  // Bottom row — TinyML status
  display.setCursor(0, 58);
  if (mlResult.attackDetected) {
    display.print("ML:ATTACK DETECTED!");
  } else if (mlResult.anomalyDetected) {
    display.print("ML:ANOMALY DETECTED!");
  } else if (!sensorFound) {
    display.print("Sensor not found!");
  } else if (heartRate == 0) {
    display.print("Place finger flat...");
  } else {
    display.print("ML:OK Monitoring");
    static byte dot = 0;
    dot = (dot + 1) % 4;
    for (byte d = 0; d < dot; d++) display.print(".");
  }

  display.display();
}

// ============================================================
//  Initialize MAX30102
// ============================================================
void initMAX30102() {
  Serial.println("[SENSOR] Initializing MAX30102 (SparkFun library)...");
  for (int attempt = 1; attempt <= 3; attempt++) {
    Serial.printf("[SENSOR] Attempt %d/3...\n", attempt);
    if (particleSensor.begin(Wire, I2C_SPEED_FAST)) {
      particleSensor.setup(60, 4, 2, 100, 411, 4096);
      particleSensor.setPulseAmplitudeRed(0x3C);
      particleSensor.setPulseAmplitudeIR(0x3C);
      particleSensor.setPulseAmplitudeGreen(0);
      sensorFound = true;
      Serial.println("[SENSOR] ✓✓✓ MAX30102 initialized successfully!");
      Serial.println("[SENSOR]   Place finger FLAT and STILL on sensor");
      Serial.println("[SENSOR]   Wait 10-15 seconds for stable readings");
      return;
    }
    Serial.printf("[SENSOR] ✗ Attempt %d failed, retrying...\n", attempt);
    delay(500);
  }
  sensorFound = false;
  Serial.println("[SENSOR] ✗ MAX30102 FAILED after 3 attempts!");
  Serial.println("[SENSOR]   1. VCC must be 3.3V (NOT 5V)");
  Serial.println("[SENSOR]   2. SDA=GPIO21, SCL=GPIO22");
  Serial.println("[SENSOR]   3. Common GND with ESP32");
}

// ============================================================
//  SECURITY — Bytes to hex string
// ============================================================
void bytesToHex(const uint8_t* bytes, size_t len, char* hexOut) {
  for (size_t i = 0; i < len; i++) {
    sprintf(hexOut + (i * 2), "%02x", bytes[i]);
  }
  hexOut[len * 2] = '\0';
}

// ============================================================
//  SECURITY — SHA-256 Hash
// ============================================================
void computeSHA256(const uint8_t* data, size_t len, char* hexOut) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  bytesToHex(hash, 32, hexOut);
}

// ============================================================
//  SECURITY — HMAC-SHA256 Digital Signature
// ============================================================
void computeHMAC_SHA256(const uint8_t* data, size_t len, char* hexOut) {
  uint8_t hmac[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, HMAC_KEY, 32);
  mbedtls_md_hmac_update(&ctx, data, len);
  mbedtls_md_hmac_finish(&ctx, hmac);
  mbedtls_md_free(&ctx);
  bytesToHex(hmac, 32, hexOut);
}

// ============================================================
//  SECURITY — AES-256-CBC Encrypt → Base64
// ============================================================
bool encryptAES256CBC(const char* plaintext, char* b64Out, size_t b64OutLen) {
  uint8_t iv[16];
  esp_fill_random(iv, 16);

  size_t ptLen    = strlen(plaintext);
  size_t padLen   = 16 - (ptLen % 16);
  size_t totalLen = ptLen + padLen;

  uint8_t* padded = (uint8_t*)malloc(totalLen);
  if (!padded) return false;
  memcpy(padded, plaintext, ptLen);
  memset(padded + ptLen, (uint8_t)padLen, padLen);

  uint8_t* encrypted = (uint8_t*)malloc(totalLen);
  if (!encrypted) { free(padded); return false; }

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 256);

  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, totalLen, iv_copy, padded, encrypted);
  mbedtls_aes_free(&aes);

  size_t combinedLen = 16 + totalLen;
  uint8_t* combined  = (uint8_t*)malloc(combinedLen);
  if (!combined) { free(padded); free(encrypted); return false; }
  memcpy(combined, iv, 16);
  memcpy(combined + 16, encrypted, totalLen);

  size_t b64Len = 0;
  mbedtls_base64_encode(
    (uint8_t*)b64Out, b64OutLen, &b64Len, combined, combinedLen
  );
  b64Out[b64Len] = '\0';

  free(padded); free(encrypted); free(combined);
  return true;
}

// ============================================================
//  BLOCKCHAIN — Compute block hash
// ============================================================
void computeBlockHash(Block& b, char* hashOut) {
  char raw[256];
  snprintf(raw, sizeof(raw), "%u|%llu|%d|%d|%d|%s",
    b.index, b.timestamp, b.heartRate, b.spO2, b.ecgValue, b.previousHash);
  computeSHA256((uint8_t*)raw, strlen(raw), hashOut);
}

// ============================================================
//  BLOCKCHAIN — Sign block
// ============================================================
void signBlock(Block& b) {
  char sigInput[160];
  snprintf(sigInput, sizeof(sigInput), "%s|%s|%u",
    b.blockHash, DEVICE_ID, b.index);
  computeHMAC_SHA256((uint8_t*)sigInput, strlen(sigInput), b.signature);
}

// ============================================================
//  BLOCKCHAIN — Create block
// ============================================================
Block createBlock(int hr, int spo2, int ecg) {
  Block b;
  memset(&b, 0, sizeof(Block));
  b.index     = blockIndex;
  b.timestamp = (uint64_t)millis();
  b.heartRate = hr;
  b.spO2      = spo2;
  b.ecgValue  = ecg;
  b.valid     = true;
  strncpy(b.previousHash, lastBlockHash, 64);
  b.previousHash[64] = '\0';
  computeBlockHash(b, b.blockHash);
  signBlock(b);
  return b;
}

// ============================================================
//  BLOCKCHAIN — Add block
// ============================================================
bool addBlock(int hr, int spo2, int ecg) {
  Block nb         = createBlock(hr, spo2, ecg);
  uint32_t slot    = blockIndex % MAX_CHAIN_LENGTH;
  blockchain[slot] = nb;
  strncpy(lastBlockHash, nb.blockHash, 64);
  lastBlockHash[64] = '\0';
  if (chainLength < MAX_CHAIN_LENGTH) chainLength++;
  blockIndex++;
  Serial.printf("[CHAIN]  ⛓  #%u | Hash: %.16s... | Sig: %.16s...\n",
                nb.index, nb.blockHash, nb.signature);
  return true;
}

// ============================================================
//  BLOCKCHAIN — Verify chain
// ============================================================
bool verifyChain() {
  if (chainLength < 2) return true;
  uint32_t count = min(chainLength, (uint32_t)MAX_CHAIN_LENGTH);

  for (uint32_t i = 1; i < count; i++) {
    uint32_t currSlot = (blockIndex - count + i)     % MAX_CHAIN_LENGTH;
    uint32_t prevSlot = (blockIndex - count + i - 1) % MAX_CHAIN_LENGTH;

    Block& cb = blockchain[currSlot];
    Block& pb = blockchain[prevSlot];

    char reHash[65];
    computeBlockHash(cb, reHash);
    if (strcmp(reHash, cb.blockHash) != 0) {
      Serial.printf("[CHAIN]  ❌ Block %u: hash tampered!\n", cb.index);
      return false;
    }
    if (strcmp(cb.previousHash, pb.blockHash) != 0) {
      Serial.printf("[CHAIN]  ❌ Block %u: chain broken!\n", cb.index);
      return false;
    }
    char expectedSig[65], sigInput[160];
    snprintf(sigInput, sizeof(sigInput), "%s|%s|%u",
      cb.blockHash, DEVICE_ID, cb.index);
    computeHMAC_SHA256((uint8_t*)sigInput, strlen(sigInput), expectedSig);
    if (strcmp(expectedSig, cb.signature) != 0) {
      Serial.printf("[CHAIN]  ❌ Block %u: signature invalid!\n", cb.index);
      return false;
    }
  }
  return true;
}

// ============================================================
//  BLOCKCHAIN — Block to JSON
// ============================================================
String blockToJson(const Block& b) {
  StaticJsonDocument<512> doc;
  doc["index"]        = b.index;
  doc["timestamp"]    = (unsigned long)b.timestamp;
  doc["heart_rate"]   = b.heartRate;
  doc["spo2"]         = b.spO2;
  doc["ecg_value"]    = b.ecgValue;
  doc["previousHash"] = b.previousHash;
  doc["blockHash"]    = b.blockHash;
  doc["signature"]    = b.signature;
  doc["node_id"]      = DEVICE_ID;
  String out;
  serializeJson(doc, out);
  return out;
}

// ============================================================
//  Connect to WiFi
// ============================================================
void connectWiFi() {
  Serial.println("\n=========================================");
  Serial.printf("[WIFI]   🔄 Connecting to: %s\n", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print(".");
    attempts++;
    if (attempts % 10 == 0) Serial.println();
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.println("[WIFI]   ✅ Connected!");
    Serial.printf("[WIFI]   📱 IP     : %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("[WIFI]   🌐 Gateway: %s\n", WiFi.gatewayIP().toString().c_str());
    Serial.printf("[WIFI]   📶 Signal : %d dBm\n", WiFi.RSSI());
  } else {
    wifiConnected = false;
    Serial.println("[WIFI]   ✗ FAILED — will retry next cycle.");
  }
  Serial.println("=========================================\n");
}

// ============================================================
//  Startup Banner
// ============================================================
void printBanner() {
  Serial.println("\n╔═══════════════════════════════════════════╗");
  Serial.println("║   ESP32 Secure Patient Health Monitor     ║");
  Serial.println("║   Sensor   : MAX30102 + AD8232 ECG        ║");
  Serial.println("║   Display  : SSD1306 OLED 128x64          ║");
  Serial.println("║   Encrypt  : AES-256-CBC                  ║");
  Serial.println("║   Sign     : HMAC-SHA256                  ║");
  Serial.println("║   Ledger   : Consortium Blockchain        ║");
  Serial.println("║   Transport: AWS IoT Core (MQTT/TLS)      ║");
  Serial.println("║   TinyML   : Rule-Based Anomaly+Attack    ║");
  Serial.println("╚═══════════════════════════════════════════╝");
  Serial.printf("\n  📱 Device  : %s\n", DEVICE_ID);
  Serial.printf("  👤 Patient : %s\n", PATIENT_ID);
  Serial.printf("  ☁️  AWS IoT : %s\n", AWS_IOT_ENDPOINT);
  Serial.printf("  🔌 MQTT Port: %d\n", AWS_IOT_PORT);
  Serial.println("  ⏱️  Data Interval : 5 seconds");
  Serial.println("  🧠 ML   Interval : 2 seconds");
  Serial.println("\n  📌 Wiring:");
  Serial.println("     MAX30102 → SDA=GPIO21, SCL=GPIO22, VCC=3.3V  [0x57]");
  Serial.println("     SSD1306  → SDA=GPIO21, SCL=GPIO22, VCC=3.3V  [0x3C]");
  Serial.println("     AD8232   → OUTPUT=GPIO34");
  Serial.println("\n=========================================\n");
}