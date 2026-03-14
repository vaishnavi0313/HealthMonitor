Table 1: PatientData

Partition Key: device_id (String)
Sort Key: timestamp (String)

Attributes:
- algorithm
- attack_mode
- block_hash
- block_index

Table 2: SecurityLogs

Partition Key: attack_type (String)
Sort Key: timestamp (String)

Attributes:
- timestamp
- device_id
- event_id
- event_type
- heart_rate
- patient_id
- reason
- severity
- source
- source_ip
- spo2
- status