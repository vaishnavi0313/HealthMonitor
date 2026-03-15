🏥 Smart IoT-Based Patient Health Monitoring & Cyber-Attack Detection System

🌐 Overview

This project presents a secure IoT-enabled healthcare monitoring platform that continuously collects patient health data while simultaneously detecting potential cyber-attacks targeting the monitoring system.

Modern hospitals increasingly rely on IoT devices for real-time patient monitoring, but these systems can be vulnerable to cyber threats. This solution integrates IoT devices, cloud computing, cybersecurity techniques, TinyML intelligence, and blockchain-based validation to ensure that medical data remains accurate, trusted, and tamper-proof.

⚠️ Problem Statement

Healthcare systems are rapidly adopting wireless IoT technologies to monitor patient conditions in real time. While these technologies improve response time and efficiency, they also expose sensitive medical data to cyber threats such as:

Data manipulation

Spoofing attacks

Replay attacks

Unauthorized access

If attackers alter or inject fake health data, healthcare professionals may make incorrect treatment decisions, putting patient safety at risk. Most existing monitoring systems focus only on data visualization and lack mechanisms for security monitoring and attack detection.

💡 Proposed Solution

This project introduces a secure and intelligent IoT healthcare monitoring architecture that protects patient data while providing real-time monitoring.

Patient health data is collected through IoT-based monitoring devices and transmitted securely to the cloud. A cloud-based backend processes the data and displays it through a live web dashboard.

To ensure data security and authenticity, the system uses:

🔐 Encryption and hashing to protect data during transmission

🧠 TinyML edge intelligence to detect abnormal or fake data patterns

📊 Cloud-based analysis to monitor system integrity

🔗 Consortium blockchain to store verified data hashes and security logs

If suspicious activity occurs, the system detects the event and displays important information such as attacker IP address, attack type, and timestamp on the monitoring dashboard.

🚀 Key Capabilities

✔ Real-time IoT patient monitoring
✔ Cyber-attack detection and alerting
✔ Secure data transmission using cryptographic techniques
✔ TinyML-based anomaly detection
✔ Blockchain-supported data integrity verification
✔ Live monitoring dashboard for patient data and security status

☁️ System Architecture
IoT Sensors (ESP32)
        ↓
AWS IoT Core
        ↓
AWS Lambda Processing
        ↓
Amazon DynamoDB
        ↓
API Gateway
        ↓
CloudFront Web Dashboard
🛠 Technologies Used
Hardware

ESP32 Microcontroller

Health Monitoring Sensors

Cloud Services

AWS IoT Core

AWS Lambda

Amazon DynamoDB

API Gateway

Amazon S3

CloudFront

Software

Python

HTML

CSS

JavaScript

Security Technologies

Encryption

Cryptographic hashing

Digital signatures

Consortium blockchain

Intelligence Layer

TinyML anomaly detection

📊 Live Dashboard

The system includes a real-time monitoring dashboard that visualizes patient health data and security status.

🌍 Live Demo
CloudFront Dashboard URL:
https://d23u3a6vyhs3yb.cloudfront.net/

🎯 Expected Impact

This system strengthens the reliability of IoT healthcare infrastructure by ensuring that medical decisions rely only on verified and secure data. It improves patient safety, data integrity, and cybersecurity awareness within healthcare monitoring networks.

👩‍💻 Author

Vaishnavi 

CyberSecurity Student
