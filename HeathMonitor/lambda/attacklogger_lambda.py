import json, boto3, uuid
from datetime import datetime, timezone

dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
table = dynamodb.Table('SecurityLogs')

sns = boto3.client('sns', region_name='ap-south-1')
SNS_TOPIC_ARN = 'arn:aws:sns:ap-south-1:490841876684:Notification'

def lambda_handler(event, context):
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Content-Type': 'application/json'
    }
    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    try:
        body = json.loads(event.get('body', '{}'))
    except:
        return {'statusCode': 400, 'headers': headers, 'body': json.dumps({'error': 'Invalid JSON'})}

    attack_type = body.get('attack_type', 'INVALID_DATA')
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    unique_ts = f"{ts}_{uuid.uuid4().hex[:6]}"

    # ── 1. Write to DynamoDB (unchanged) ──
    table.put_item(Item={
        'attack_type': attack_type,
        'timestamp':   unique_ts,
        'device_id':   body.get('device_id', 'ESP32_HEALTH_01'),
        'patient_id':  body.get('patient_id', 'Patient_1'),
        'reason':      body.get('reason', 'Attack from demo script'),
        'severity':    body.get('severity', 'High'),
        'status':      'Blocked',
        'source_ip':   body.get('source_ip', 'unknown'),
        'source':      body.get('source', 'demo_script')
    })

    # ── 2. Send ONE SNS email only when frontend requests it ──
    # The frontend sets "notify_sns": true only on the FIRST packet of an attack wave.
    # This prevents 100 emails for 100 packets — you get exactly 1 email per attack.
    if body.get('notify_sns', False):
        attack_label = attack_type.replace('_', ' ')
        device_id    = body.get('device_id', 'ESP32_HEALTH_01')
        patient_id   = (body.get('patient_id', 'Patient_1')).replace('_', ' ')
        severity     = body.get('severity', 'High')
        reason       = body.get('reason', 'Security violation detected')
        total_pkts   = body.get('total_packets', 1)

        subject = f"SECURITY ALERT: {attack_label} Detected — MediCore Health"

        message = f"""
=== MEDICORE HEALTH PLATFORM — SECURITY ALERT ===

An attack has been detected and blocked on your health monitoring system.

Attack Type  : {attack_label}
Device ID    : {device_id}
Patient      : {patient_id}
Severity     : {severity}
Time (UTC)   : {ts}
Reason       : {reason}
Packets Sent : {total_pkts}
Status       : BLOCKED

All packets have been blocked by the security layer.
AES-256 encryption and HMAC-SHA256 signature validation are active.

Please log in to the MediCore dashboard to review the Security Centre.

— MediCore Health Automated Alert System
""".strip()

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )

    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps({'success': True, 'logged': attack_type, 'timestamp': unique_ts})
    }