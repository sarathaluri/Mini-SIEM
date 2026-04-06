# 🛡️ Mini SIEM System (Advanced SOC Tool)

## 📌 Overview
This project is a Python-based mini SIEM (Security Information and Event Management) system designed to simulate real-world SOC (Security Operations Center) workflows.

It ingests log data, performs event correlation, detects security threats, and generates structured alerts with severity classification and timeline analysis.

---

## 🚀 Key Features

### 🔍 Log Ingestion
- Parses structured log files
- Extracts IP addresses, timestamps, and events

### ⚠️ Threat Detection
- Brute-force attack detection (multiple failed logins)
- Suspicious activity detection
- Multi-level severity classification:
  - **CRITICAL**
  - **HIGH**
  - **MEDIUM**

### 🔗 Event Correlation (Core SIEM Feature)
- Detects **account compromise patterns**
  - Failed logins followed by successful login
- Identifies complex attack behavior across events

### ⏱️ Timeline Analysis
- Tracks **first seen** and **last seen** timestamps
- Enables understanding of attack duration and behavior

### 📊 Alert Dashboard
- Structured alert output with:
  - Alert ID
  - Severity level
  - Attack type
  - Timestamp range
  - Number of attempts

### 📁 Structured Output
- Exports alerts in **JSON format**
- Suitable for further processing or integration

---

## 🛠️ Tech Stack
- Python
- File Handling
- Data Structures (Dictionary, List)
- JSON Processing

---

## ▶️ Usage

```bash
python siem.py logs.txt
