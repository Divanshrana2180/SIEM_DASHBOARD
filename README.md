# SIEM_DASHBOARD
A real-time SIEM Dashboard built with the ELK Stack that simulates 17+ cyber threats using Python-generated logs. Logstash processes and enriches logs, Elasticsearch indexes them, and Kibana provides interactive dashboards for real-time security monitoring and threat analysis.

# SIEM Dashboard with ELK Stack
A real-time Security Information and Event Management (SIEM) solution built with the Elastic Stack (Elasticsearch, Logstash, Kibana) for automated threat detection and security monitoring.

![SIEM Dashboard](https://img.shields.io/badge/SIEM-ELK%20Stack-blue)
![Docker](https://img.shields.io/badge/Docker-Containerized-green)
![Python](https://img.shields.io/badge/Python-3.8+-yellow)
![License](https://img.shields.io/badge/License-MIT-orange)

## 🎯 Overview

This project implements a comprehensive SIEM dashboard that ingests, parses, and visualizes security events in real-time. It includes an automated log generator simulating 17+ cyber threat types, enabling dynamic security monitoring without requiring production infrastructure.

## 🏗️ Architecture
┌─────────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │ Log Generator │────▶│ Logstash │────▶│ Elasticsearch│────▶│ Kibana │ │ (Python) │ │ (Parse/ETL) │ │ (Store) │ │ (Visualize) │ └─────────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │ ▼ ┌─────────────┐ │ GeoIP + │ │Threat Tagging│ └─────────────┘

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Real-Time Log Generation** | Python script generates 17+ threat types continuously |
| **Multi-Format Parsing** | JSON and Apache combined log format support |
| **Threat Detection** | Pattern-based detection for brute force, SQL injection, XSS, malware |
| **ML Anomaly Scoring** | Behavioral analysis with threat severity classification |
| **Interactive Dashboard** | Live charts, maps, and counters with 5-second auto-refresh |
| **Geographic Analysis** | GeoIP enrichment for attack source visualization |
| **Containerized Deployment** | Docker Compose for easy setup |

## 🛠️ Technologies

- **Elasticsearch 8.11** — Distributed search and analytics engine
- **Logstash 8.11** — Data processing pipeline
- **Kibana 8.11** — Data visualization platform
- **Docker & Docker Compose** — Container orchestration
- **Python 3.8+** — Log generation and ML simulation

## 📁 Project Structure
siem-dashboard/ ├── docker-compose.yml # ELK stack configuration ├── logstash/ │ └── pipeline/ │ └── logstash.conf # Log parsing and enrichment rules ├── logs/ │ ├── sample-logs.log # Generated JSON logs │ └── apache-logs.log # Generated Apache logs ├── log_generator_advanced.py # Real-time threat simulator ├── ml_anomaly_detector.py # ML-based anomaly detection ├── start_siem.bat # One-click startup script └── README.md # This file


## ⚡ Quick Start

### Prerequisites
- Windows 10/11 (64-bit)
- Docker Desktop with WSL2
- Python 3.8+
- 8GB+ RAM recommended

### Installation
 **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/siem-dashboard.git
   cd siem-dashboard
```
1.Start the ELK stack
```Bash
docker-compose up -d
```
2.Run the log generator
```Bash
python log_generator_advanced.py
```
3.Access the dashboard
> Open
 http://localhost:5601
> Create index pattern: siem-logs-*
> Navigate to Dashboard → SIEM Security Dashboard

## One-Click Start (Windows)
### Double-click start_siem.bat to automatically:
> Start Docker containers
> Initialize Elasticsearch
> Launch log generator
> Open Kibana in browser
## 📊 Dashboard Components
Visualization 	| Purpose
Critical Alerts Counter|	Real-time high-severity threat count
Failed Login Timeline	|Brute force attack pattern detection
Top Attack IPs	| Source IP frequency analysis
Threat Type Distribution	| Attack category breakdown
Events by Severity	| Severity level comparison
Attack Origins Map 	| Geographic threat visualization
## 🔍 Detected Threat Types
Brute Force — Repeated failed login attempts
SQL Injection — Malicious database query patterns
XSS Attack — Cross-site scripting attempts
Malware/Ransomware — Suspicious file activity
Privilege Escalation — Unauthorized permission elevation
Credential Stuffing — Automated credential reuse
Port Scanning — Network reconnaissance
Data Exfiltration — Unauthorized data transfer
Insider Threat — Abnormal user behavior
Command & Control — Botnet communication

## 🔧 Configuration
### Logstash Pipeline
Edit logstash/pipeline/logstash.conf to customize:
Input sources (files, TCP, Beats)
Filter rules (Grok patterns, GeoIP)
Output destinations
### Log Generator
Modify log_generator_advanced.py to adjust:
> Threat generation frequency
> Attack type distribution
> IP address ranges
> ML anomaly scoring thresholds
### 🌐 API Endpoints
Service	  |  URL   |	Description
Elasticsearch	|  http://localhost:9200 |  REST API for search
Kibana	|   http://localhost:5601 | Web interface
Logstash |	http://localhost:9600 | Monitoring API
### 📝 License
This project is licensed under the MIT License - see the
LICENSE
file for details.
### 🙏 Acknowledgments
Elastic Stack for the open-source SIEM foundation
GeoLite2 for IP geolocation data
Python community for logging and data generation libraries
