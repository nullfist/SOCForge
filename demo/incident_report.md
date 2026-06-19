# SOCForge Incident Response & Evidence Package
**Generated At:** 2026-06-19T10:19:03.623480
**Overall Severity:** HIGH

## Executive Summary
SOCForge simulated an active threat scenario across your corporate environment. A total of **8** malicious actions were logged, triggering **8** automated alerts.

## Impact Overview
- **Impacted Hosts:** FIN-DC-01, FIN-WS-001
- **Compromised Identities:** Administrator, mmartin, SYSTEM
- **MITRE Techniques Observed:** T1114, T1078, T1566, T1053, T1021, T1048

## Forensic Timeline
1. `[2026-06-15T22:19:03.584020]` **FIN-WS-001** - mmartin: http://malicious-update.com/payload.exe (Tactic: Initial Access)
2. `[2026-06-15T22:34:03.584020]` **FIN-WS-001** - SYSTEM: schtasks /create /tn "WindowsUpdater" /tr "C:\Windows\Temp\payload.exe" /sc hourly (Tactic: Persistence)
3. `[2026-06-15T23:34:03.584020]` **FIN-WS-001** - SYSTEM: powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\privesc.ps1 (Tactic: Privilege Escalation)
4. `[2026-06-15T23:44:03.584020]` **FIN-WS-001** - SYSTEM: net group "domain admins" /domain (Tactic: Discovery)
5. `[2026-06-16T01:44:03.584020]` **FIN-WS-001** - mmartin: Adversary Action (Tactic: Lateral Movement)
6. `[2026-06-16T01:44:03.584020]` **FIN-DC-01** - Administrator: Adversary Action (Tactic: Lateral Movement)
7. `[2026-06-16T02:14:03.584020]` **FIN-DC-01** - Administrator: ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds" q q (Tactic: Collection)
8. `[2026-06-16T02:24:03.584020]` **FIN-DC-01** - Administrator: Adversary Action (Tactic: Exfiltration)

## Recommended Containment Actions
1. **Isolate Hosts:** Immediately quarantine the affected workstations from the local network segment.
2. **Revoke Credentials:** Reset Active Directory domain credentials and invalidate OAuth tokens/MFA devices for compromised users.
3. **Inspect Shadow Copies:** Restore volume shadow copies if a Ransomware encryption stage was executed.