# SOCForge

### Enterprise Security Telemetry & Attack Simulation Platform

**SOCForge** is an open-source enterprise security telemetry engine and cyber range simulator. It generates realistic, multi-stage, high-fidelity security logs, alerts, and timelines mapping to the MITRE ATT&CK framework. It is designed to train SOC analysts, validate SIEM rules (Wazuh, Splunk, Elastic, Sentinel), and support detection engineering workflows without requiring massive, costly real-world enterprise infrastructure.

---

## Key Features

- **Multi-Company Topology Generator:** Generate realistic organization layouts, Active Directory structures, departments (Sales, HR, Finance, IT, Security, etc.), employee details, and workstation/server endpoints.
- **Normal Office Activity Simulation:** Simulates normal baseline behavior (logins, file access, DNS queries, network flows, web proxy traffic) mapped to office schedules (08:00 - 18:00).
- **Threat Simulation Engine:** Exposes 8 realistic, multi-stage scenarios:
  1. Brute Force Actions (Failed authentication streams & lockouts)
  2. Phishing Campaign (Ingress emails, URL clicks, credential harvesting)
  3. Persistence (Registry additions, scheduled task hooks, service install)
  4. Privilege Escalation (Token elevation, admin localgroup additions)
  5. Lateral Movement (RDP/SSH pivoting, admin share mounts)
  6. Insider Threat (Sensitive document access, high volume exfiltration)
  7. Ransomware Attack (Shadow copy deletions, rapid file encryption)
  8. Multi-Stage APT Campaign (Comprehensive chain from entry to exfil)
- **MITRE ATT&CK Mapping:** All generated malicious traces automatically tag their corresponding ATT&CK technique IDs (e.g. T1110, T1566, T1486) for easy mapping.
- **SIEM Detection Validation:** Every event includes ground-truth tags. You can test your SIEM detection accuracy and query coverage metrics automatically.
- **Log Exporters:** Convert generated telemetry to standard **JSON**, **NDJSON**, **CSV**, **RFC5424 Syslog**, and **Elastic Common Schema (ECS)** formats.
- **Real-Time Streaming Engine:** Stream simulation events directly over WebSockets with execution controls (Play, Pause, Resume, Accelerate speed).

---

## Folder Structure

```text
SOCForge/
├── docker/
│   ├── backend.Dockerfile
│   └── docker-compose.yml
├── src/
│   ├── app/
│   │   ├── api/             # API Router layout
│   │   ├── core/            # Environment, Business activity, Threat simulations & timelines
│   │   ├── telemetry/       # OS format logs (Windows, Linux, Network, Cloud)
│   │   ├── alert/           # Alert generation logic
│   │   ├── detection/       # Sigma, Wazuh, Splunk rules & validator scoring
│   │   ├── db/              # SQLAlchemy schemas and connectors
│   │   └── config.py        # System configuration
│   └── tests/               # Test suites
├── requirements.txt
└── README.md
```

---

## Local Setup

### Prerequisite
Ensure Python 3.10+ is installed on your machine.

### Installation
1. Clone the repository and navigate to the directory:
   ```bash
   cd SOCForge
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   uvicorn src.app.main:app --reload
   ```
4. Access API Documentation at `http://127.0.0.1:8000/docs`.

---

## Running with Docker

Spin up the platform instantly using docker-compose:
```bash
docker-compose -f docker/docker-compose.yml up --build
```

---

## REST API Reference

| Endpoint | Method | Params | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/companies` | `POST` | `name`, `industry`, `size` | Create corporate topology |
| `/api/v1/companies/{company_id}/topology` | `GET` | - | Get generated host/user information |
| `/api/v1/simulations/generate` | `POST` | `company_id`, `scenario`, `duration_hours`, `format` | Export simulated datasets |
| `/api/v1/detections/rules` | `GET` | `technique_id` | Get detection rules (Sigma, Wazuh, Splunk) |
| `/api/v1/stream/{simulation_run_id}` | `WS` | - | WebSocket real-time telemetry stream |
| `/api/v1/simulations/{simulation_run_id}/control` | `POST` | `action`, `value` | Control running stream (pause/resume/speed) |

---

## Verification & Testing
Execute the test suite using pytest:
```bash
python -m pytest
```
