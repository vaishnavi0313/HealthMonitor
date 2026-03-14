"""
DashboardAPI Lambda — GET /dashboard
=====================================
Reads PatientData table (which now has decoded fields saved by HealthProcessor)
and returns the full dashboard JSON for the S3 frontend.

DynamoDB PatientData schema (after HealthProcessor fix):
  device_id    (PK String)
  timestamp    (SK String, ISO format: 2026-02-22T06:50:00.000Z)
  heart_rate   (Number)
  spo2         (Number)
  ecg_value    (Number)
  device_status (String)
  chain_valid  (Boolean)
  chain_length (Number)
  attack_mode  (Boolean)
  algorithm    (String)
  transport    (String)

SecurityLogs schema:
  device_id   (PK String)
  timestamp   (SK String)
  event_type  (String) — only written for real attacks
"""

import json
import boto3
import os
from boto3.dynamodb.conditions import Key
from decimal import Decimal
from datetime import datetime, timezone, timedelta

dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')

PATIENT_TABLE   = os.environ.get('PATIENT_TABLE',   'PatientData')
SECURITY_TABLE  = os.environ.get('SECURITY_TABLE',  'SecurityLogs')

# Device is OFFLINE if last record is older than this many seconds
OFFLINE_THRESHOLD_SEC = 60

def dec(val, default=0):
    """Safely convert DynamoDB Decimal/None to int."""
    try:
        if val is None:
            return default
        return int(Decimal(str(val)))
    except Exception:
        return default

def cors():
    return {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,OPTIONS',
        'Content-Type': 'application/json'
    }

def respond(status, body):
    return {
        'statusCode': status,
        'headers': cors(),
        'body': json.dumps(body, default=str)
    }

def get_latest_records(device_id='ESP32_HEALTH_01', limit=20):
    """
    Query PatientData for latest records using sort key descending.
    Returns list newest-first.
    """
    try:
        table = dynamodb.Table(PATIENT_TABLE)
        resp  = table.query(
            KeyConditionExpression=Key('device_id').eq(device_id),
            ScanIndexForward=False,
            Limit=limit
        )
        return resp.get('Items', [])
    except Exception as e:
        print(f"[ERROR] query PatientData: {e}")
        # Fallback: scan
        try:
            table = dynamodb.Table(PATIENT_TABLE)
            resp  = table.scan()
            items = resp.get('Items', [])
            items.sort(key=lambda x: str(x.get('timestamp', '')), reverse=True)
            return items[:limit]
        except Exception as e2:
            print(f"[ERROR] scan PatientData fallback: {e2}")
            return []

def get_security_events(limit=150):
    """Scan SecurityLogs with pagination to get all items."""
    try:
        table = dynamodb.Table(SECURITY_TABLE)
        items = []

        # First scan
        resp = table.scan()
        items.extend(resp.get('Items', []))

        # Keep scanning if there are more pages
        while 'LastEvaluatedKey' in resp:
            resp = table.scan(ExclusiveStartKey=resp['LastEvaluatedKey'])
            items.extend(resp.get('Items', []))

        items.sort(key=lambda x: str(x.get('timestamp', '')), reverse=True)
        print(f"[SecurityLogs] Total items fetched: {len(items)}")
        return items[:limit]
    except Exception as e:
        print(f"[ERROR] scan SecurityLogs: {e}")
        return []

def check_online(latest_record):
    """
    Returns True if the latest DynamoDB record is fresh (within OFFLINE_THRESHOLD_SEC).
    The timestamp is an ISO string set by HealthProcessor when it saves the record.
    """
    if not latest_record:
        return False

    ts_str = str(latest_record.get('timestamp', ''))
    # Try ISO format written by HealthProcessor
    for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ']:
        try:
            ts_dt = datetime.strptime(ts_str[:23], fmt[:len(fmt)])
            ts_dt = ts_dt.replace(tzinfo=timezone.utc)
            age   = (datetime.now(timezone.utc) - ts_dt).total_seconds()
            print(f"[Online check] last record age: {age:.1f}s, threshold: {OFFLINE_THRESHOLD_SEC}s")
            return age < OFFLINE_THRESHOLD_SEC
        except ValueError:
            continue

    # If timestamp can't be parsed, trust device_status field
    return str(latest_record.get('device_status', '')).upper() == 'ONLINE'

def build_history(records):
    """
    records: list of DynamoDB items, newest-first.
    Returns dict with arrays for charts, oldest-first (left→right).
    """
    ordered = list(reversed(records))
    history = { 'timestamps': [], 'heart_rate': [], 'spo2': [], 'ecg': [] }

    for r in ordered:
        ts    = str(r.get('timestamp', ''))
        label = ts[11:19] if len(ts) >= 19 else ts  # HH:MM:SS
        history['timestamps'].append(label)
        history['heart_rate'].append(dec(r.get('heart_rate',  0)))
        history['spo2'].append(      dec(r.get('spo2',        0)))
        history['ecg'].append(       dec(r.get('ecg_value',   0)))

    return history

def build_security_stats(records, sec_events):
    """
    Compute security metrics from PatientData records + SecurityLogs.
    ✅ FIX: invalid_signatures is 0 unless chain_valid=False (not based on SecurityLogs count)
    """
    total        = len(records)
    chain_valids = [r for r in records if r.get('chain_valid', True)]
    valid_sigs   = len(chain_valids)
    invalid_sigs = total - valid_sigs   # only count actually invalid chains

    # Max chain length seen across all records
    chain_lengths = [dec(r.get('chain_length', 0)) for r in records]
    max_chain     = max(chain_lengths) if chain_lengths else 0

    # Real attacks = SecurityLogs entries with attack event types
    real_attack_types = {
        'ATTACK_MODE_ACTIVE', 'BLOCK_INVALID', 'SIGNATURE_TAMPERING',
        'IMPOSSIBLE_HEART_RATE', 'SPOOFED_DATA_FLAG', 'RAPID_VALUE_CHANGE'
    }
    attacks = len([e for e in sec_events if e.get('event_type', e.get('attack_type', '')) in real_attack_types])

    return {
        'total_requests':      total,
        'valid_signatures':    valid_sigs,
        'invalid_signatures':  invalid_sigs,
        'valid_blocks':        max_chain,
        'attacks_detected':    attacks,
        'decryption_failures': 0,
        'encrypted_requests':  total,    # all ESP32 packets are encrypted
    }

def lambda_handler(event, context):
    print(f"[Event] path={event.get('rawPath','')} method={event.get('requestContext',{}).get('http',{}).get('method','GET')}")

    method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')

    # CORS pre-flight
    if method == 'OPTIONS':
        return {'statusCode': 200, 'headers': cors(), 'body': ''}

    device_id = 'ESP32_HEALTH_01'

    # ── 1. Get latest 20 records from PatientData ─────────────────────────
    records    = get_latest_records(device_id, limit=20)
    sec_events = get_security_events(limit=150)

    print(f"[DynamoDB] PatientData records fetched: {len(records)}")
    print(f"[DynamoDB] SecurityLogs events fetched: {len(sec_events)}")

    latest = records[0] if records else {}
    print(f"[Latest] {json.dumps(latest, default=str)}")

    # ── 2. ONLINE check based on record freshness ─────────────────────────
    online        = check_online(latest)
    device_status = 'ONLINE' if online else 'OFFLINE'
    print(f"[Status] {device_status} (online={online})")

    # ── 3. Extract latest vitals ──────────────────────────────────────────
    hr        = dec(latest.get('heart_rate',  0))
    spo2      = dec(latest.get('spo2',        0))
    ecg       = dec(latest.get('ecg_value',   0))
    chain_len = dec(latest.get('chain_length',0))
    chain_ok  = bool(latest.get('chain_valid', True))
    last_ts   = str(latest.get('timestamp', ''))
    algorithm = latest.get('algorithm', 'AES-256-CBC + HMAC-SHA256')
    transport = latest.get('transport',  'MQTT')

    # ── 4. Build response ─────────────────────────────────────────────────
    response = {
        'device_id':     device_id,
        'patient_id':    latest.get('patient_id', 'Patient_1'),
        'device_status': device_status,
        'heart_rate':    hr,
        'spo2':          spo2,
        'ecg_value':     ecg,
        'last_update':   last_ts,
        'algorithm':     algorithm,
        'transport':     transport,
        'chain_valid':   chain_ok,
        'chain_length':  chain_len,
        'total_records': len(records),
        'history':       build_history(records),
        'security_stats': build_security_stats(records, sec_events),
        'security_events': [
            {
                'timestamp':  str(e.get('timestamp', '')),
                'event_type': str(e.get('event_type', e.get('attack_type', 'UNKNOWN'))),
                'device_id':  str(e.get('device_id', device_id)),
                'patient_id': str(e.get('patient_id', 'Patient_1')),
                'reason':     str(e.get('reason', '—')),
                'severity':   str(e.get('severity', 'HIGH')),
                'status':     str(e.get('status', 'Blocked')),
            }
            for e in sec_events
        ]
    }

    print(f"[Response] status={device_status} hr={hr} spo2={spo2} ecg={ecg} chain={chain_len}")
    return respond(200, response)