# Changelog: SOCForge

All notable changes to this project will be documented in this file.

---

## [1.0.0] - 2026-06-19
This release represents the initial stable v1.0.0 build of the **SOCForge Cyber Range Engine**. Development has been frozen to focus on packaging, stability, CI/CD integrations, and release testing.

### Added
- **Telemetry Generation Engine**: Dynamic generation of high-fidelity endpoint security telemetry including Windows (Event Log, Sysmon XML/JSON), Linux (Syslog, auth.log, SSH, sudo), Network (DNS queries, Firewall proxy access, VPN, IDS alerts), and Cloud/Identity logs (AWS CloudTrail, Entra ID / MFA events).
- **AD & Identity Topology Simulation**: Generates an Active Directory Forest schema with Organizational Units (OUs), domain controllers, workstations, and employee mapping profiles.
- **Dynamic Threat Simulation**: 8 pre-packaged attack scenarios mapping directly to MITRE ATT&CK techniques:
  - Initial Access (Phishing)
  - Privilege Escalation (UAC Bypass, Sudo manipulation)
  - Persistence (Scheduled tasks, Registry run keys)
  - Lateral Movement (WMI, SSH)
  - AD Specific Attacks (Kerberoasting, DCSync, MFA Fatigue)
  - Cloud / Container escapes (AWS Key Leakage, Kubernetes escape and mining)
  - Ransomware deployment.
- **Ground Truth Engine**: Each simulated attack action generates explicit structural tracking metadata (`ground_truth`, `attacker`, `victim`, `mitre`, `attack_stage`, `confidence`).
- **Detection Evaluator CLI**: Evaluates detection rules (e.g. Sigma) against simulated log volumes, returning performance metrics (Precision, Recall, False Positives/Negatives, and Technique Coverage).
- **Web UI & Streaming API**: Dark-themed dashboard built with FastAPI, WebSockets real-time playback, and attack graph visualization.
- **Performance Benchmarking Suite**: Proportional telemetry scaling benchmarked across 100, 1000, 5000, and 10000 simulated users.
- **Production Orchestration Config**: Pre-configured multi-container setups using PostgreSQL, Redis, Celery, and Nginx SSL proxying.
- **CI/CD Actions Workflow**: Automatic unit testing, coverage reporting, and container builds on push.
