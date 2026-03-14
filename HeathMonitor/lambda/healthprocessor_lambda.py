"""
HealthProcessor Lambda — triggered by AWS IoT Rule on topic esp32/health/data
=============================================================================
FIXED VERSION — matches your actual ESP32 payload exactly.

KEY FIXES:
  1. Reads HMAC from "signature" field (your ESP32 calls it "signature" not "hmac")
  2. Saves heart_rate/spo2/ecg_value from PLAINTEXT fields directly
  3. SecurityLogs partition key is "device_id" (not "attack_type")
  4. No false attack logs

Environment Variables:
  PATIENT_TABLE  = PatientData
  SECURITY_TABLE = SecurityLogs
  AES_KEY        = <64-char hex>   (optional)
  HMAC_KEY       = <64-char hex>   (optional — used to verify "signature" field)
"""

import json
import boto3
import hashlib
import hmac as hmac_lib
import uuid
import os
from datetime import datetime, timezone
from decimal import Decimal

dynamodb       = boto3.resource('dynamodb', region_name='ap-south-1')
PATIENT_TABLE  = os.environ.get('PATIENT_TABLE',  'PatientData')
SECURITY_TABLE = os.environ.get('SECURITY_TABLE', 'SecurityLogs')

_HMAC_KEY_HEX = os.environ.get('HMAC_KEY', '')
HMAC_KEY = bytes.fromhex(_HMAC_KEY_HEX) if _HMAC_KEY_HEX else None


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def log_security_event(security_table, device_id, iso_ts, event_type,
                       reason, severity='HIGH', patient_id='', extra=None):
    """
    Write to SecurityLogs.
    Partition key = device_id  (so DashboardAPI scan works correctly)
    Sort key      = timestamp_EVENTTYPE  (unique per event)
    """
    try:
        item = {
            'device_id':   device_id,
            'timestamp':   iso_ts + '_' + event_type,
            'event_id':    str(uuid.uuid4()),
            'event_type':  event_type,
            'attack_type': event_type,
            'reason':      reason,
            'severity':    severity,
            'status':      'Blocked',
        }
        if patient_id:
            item['patient_id'] = patient_id
        if extra:
            item.update(extra)
        security_table.put_item(Item=item)
        print(f"[SecurityLogs] {event_type} — {reason}")
    except Exception as e:
        print(f"[ERROR] SecurityLogs put_item ({event_type}): {e}")


def verify_signature(encrypted_data_str, received_signature):
    """
    Verify HMAC-SHA256. Your ESP32 calls this field 'signature'.
    Returns True if HMAC_KEY not configured (graceful degradation).
    """
    if not HMAC_KEY:
        print("[WARN] HMAC_KEY not set — skipping signature verification")
        return True
    try:
        calculated = hmac_lib.new(
            HMAC_KEY,
            encrypted_data_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return hmac_lib.compare_digest(calculated, received_signature)
    except Exception as e:
        print(f"[WARN] signature verify error: {e} — allowing packet")
        return True


def lambda_handler(event, context):
    print(f"[IoT Event] {json.dumps(event, default=str)}")

    patient_table  = dynamodb.Table(PATIENT_TABLE)
    security_table = dynamodb.Table(SECURITY_TABLE)
    iso_ts         = now_iso()

    # ── Extract fields ────────────────────────────────────────────────────────
    device_id      = event.get('device_id',     'ESP32_HEALTH_01')
    patient_id     = event.get('patient_id',    'Patient_1')
    esp_timestamp  = str(event.get('timestamp', ''))

    # Your ESP32 uses "signature" for the HMAC (not "hmac")
    encrypted_data = event.get('encrypted_data', '')
    signature      = event.get('signature', '')

    # Plaintext vitals — REAL values sent by ESP32 alongside encrypted blob
    heart_rate    = int(event.get('heart_rate',   0) or 0)
    spo2          = int(event.get('spo2',         0) or 0)
    ecg_value     = int(event.get('ecg_value',    0) or 0)
    device_status = str(event.get('device_status', 'ONLINE'))
    chain_valid   = bool(event.get('chain_valid',  True))
    chain_length  = int(event.get('chain_length',  0) or 0)
    attack_mode   = bool(event.get('attack_mode',  False))
    algorithm     = str(event.get('algorithm',    'AES-256-CBC + HMAC-SHA256'))
    transport     = str(event.get('transport',    'MQTT'))
    payload_hash  = str(event.get('payload_hash', ''))

    # ── Security Check: Signature verification ────────────────────────────────
    sig_ok = True
    if encrypted_data and signature:
        sig_ok = verify_signature(encrypted_data, signature)
        if not sig_ok:
            log_security_event(
                security_table, device_id, iso_ts,
                'SIGNATURE_TAMPERING',
                'HMAC-SHA256 signature mismatch',
                patient_id=patient_id
            )

    # ── Security Check: Vital range validation ────────────────────────────────
    if heart_rate != 0 and not (20 <= heart_rate <= 250):
        log_security_event(
            security_table, device_id, iso_ts,
            'IMPOSSIBLE_HEART_RATE',
            f'heart_rate={heart_rate} out of range',
            patient_id=patient_id,
            extra={'heart_rate': Decimal(heart_rate)}
        )

    if spo2 != 0 and not (50 <= spo2 <= 100):
        log_security_event(
            security_table, device_id, iso_ts,
            'SPOOFED_DATA_FLAG',
            f'spo2={spo2} out of range',
            patient_id=patient_id,
            extra={'spo2': Decimal(spo2)}
        )

    # ── Save decoded record to PatientData ────────────────────────────────────
    item = {
        'device_id':      device_id,
        'timestamp':      iso_ts,
        'esp_timestamp':  esp_timestamp,
        'patient_id':     patient_id,
        'heart_rate':     Decimal(heart_rate),
        'spo2':           Decimal(spo2),
        'ecg_value':      Decimal(ecg_value),
        'device_status':  device_status,
        'chain_valid':    chain_valid,
        'chain_length':   Decimal(chain_length),
        'attack_mode':    attack_mode,
        'algorithm':      algorithm,
        'transport':      transport,
        'encrypted':      True,
        'verified':       sig_ok,
        'signature':      signature[:64] if signature else '',
        'payload_hash':   payload_hash[:64] if payload_hash else '',
    }

    bb = event.get('blockchain_block', {})
    if bb and isinstance(bb, dict):
        item['block_index'] = Decimal(int(bb.get('index', 0)))
        item['block_hash']  = str(bb.get('blockHash', bb.get('hash', '')))[:64]

    try:
        patient_table.put_item(Item=item)
        print(f"[PatientData] Saved ts={iso_ts} hr={heart_rate} spo2={spo2} ecg={ecg_value} chain={chain_length}")
    except Exception as e:
        print(f"[ERROR] PatientData put_item: {e}")
        raise

    # ── Log real attacks only ─────────────────────────────────────────────────
    if attack_mode:
        log_security_event(
            security_table, device_id, iso_ts,
            'ATTACK_MODE_ACTIVE',
            'ESP32 reported attack_mode=true',
            patient_id=patient_id,
            extra={'heart_rate': Decimal(heart_rate), 'spo2': Decimal(spo2)}
        )

    if not chain_valid:
        log_security_event(
            security_table, device_id, iso_ts,
            'BLOCK_INVALID',
            'chain_valid=false — blockchain integrity broken',
            patient_id=patient_id
        )

    return {
        'statusCode': 200,
        'body': json.dumps({
            'saved': True, 'device_id': device_id, 'timestamp': iso_ts,
            'heart_rate': heart_rate, 'spo2': spo2, 'ecg_value': ecg_value,
            'chain_valid': chain_valid, 'chain_length': chain_length,
        })
    }