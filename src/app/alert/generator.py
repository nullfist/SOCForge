import uuid
from datetime import datetime
from typing import Dict, Any, List
from src.app.mitre.mapping import get_mitre_mapping

def generate_alerts_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Inspects a list of events and creates corresponding SOC Alerts for malicious activities."""
    alerts = []
    
    for event in events:
        if not event.get("ground_truth"):
            continue
            
        mitre_id = event.get("mitre")
        if not mitre_id:
            continue
            
        mitre_info = get_mitre_mapping(mitre_id)
        if not mitre_info:
            continue
            
        rule_name = f"SOCForge Detected: {mitre_info['name']}"
        severity = mitre_info["severity"]
        description = mitre_info["description"]
        
        event_type = event.get("event_type")
        if event_type == "Authentication" and event.get("status") == "FAILED":
            continue
        elif event_type == "AccountLockout":
            rule_name = "SOCForge Detected: Account Lockout after Brute Force"
            severity = "High"
            description = f"User account {event.get('username')} locked out on host {event.get('host')}."
        elif event_type == "ProcessCreation" and "vssadmin" in event.get("command_line", ""):
            rule_name = "SOCForge Detected: Volume Shadow Copy Deletion"
            severity = "Critical"
            description = f"Adversary deleted volume shadow copies on {event.get('host')} using vssadmin."
        elif event_type == "ProcessCreation" and "schtasks" in event.get("command_line", ""):
            rule_name = "SOCForge Detected: Scheduled Task Persistence"
            severity = "Medium"
            description = f"Persistence scheduled task created on {event.get('host')}."
            
        alert = {
            "alert_id": str(uuid.uuid4()),
            "rule_name": rule_name,
            "timestamp": event.get("timestamp"),
            "host": event.get("host"),
            "user": event.get("username"),
            "severity": severity,
            "description": description,
            "mitre_mapping": mitre_info
        }
        alerts.append(alert)
        
    return alerts

def generate_analyst_cases(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups malicious events into distinct analyst cases with structured investigation questions."""
    cases = []
    malicious_events = [e for e in events if e.get("ground_truth")]
    
    # Group by scenario name
    scenarios = {}
    for e in malicious_events:
        sc = e.get("scenario", "Generic Incident")
        if sc not in scenarios:
            scenarios[sc] = []
        scenarios[sc].append(e)
        
    for sc_name, sc_events in scenarios.items():
        if not sc_events:
            continue
            
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        host = sc_events[0].get("host")
        user = sc_events[0].get("username")
        
        evidence_timeline = []
        for e in sc_events[:10]: # limit to first 10 evidence lines
            evidence_timeline.append({
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "details": e.get("command_line") or e.get("url") or e.get("file_name") or "Incident Action Detected"
            })
            
        case = {
            "case_id": case_id,
            "title": f"Incident Investigation - Suspicious {sc_name} Activity",
            "severity": "High" if sc_name in ["APT Campaign", "Ransomware"] else "Medium",
            "host": host,
            "impacted_user": user,
            "timeline": evidence_timeline,
            "questions": [
                "1. Identify the initial point of entry or command execution context.",
                f"2. What MITRE ATT&CK techniques were associated with this {sc_name} event?",
                "3. What hosts and users were directly impacted by the adversary?",
                "4. Draft a containment plan to isolate the threat vector."
            ]
        }
        cases.append(case)
        
    return cases

def generate_incident_report(events: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> str:
    """Generates a complete, structured incident response evidence package in Markdown."""
    malicious = [e for e in events if e.get("ground_truth")]
    hosts = list(set(e.get("host") for e in malicious if e.get("host")))
    users = list(set(e.get("username") for e in malicious if e.get("username")))
    techniques = list(set(e.get("mitre") for e in malicious if e.get("mitre")))
    
    report = []
    report.append("# SOCForge Incident Response & Evidence Package")
    report.append(f"**Generated At:** {datetime.now().isoformat()}")
    report.append(f"**Overall Severity:** HIGH")
    report.append("\n## Executive Summary")
    report.append(f"SOCForge simulated an active threat scenario across your corporate environment. A total of **{len(malicious)}** malicious actions were logged, triggering **{len(alerts)}** automated alerts.")
    
    report.append("\n## Impact Overview")
    report.append(f"- **Impacted Hosts:** {', '.join(hosts) if hosts else 'None'}")
    report.append(f"- **Compromised Identities:** {', '.join(users) if users else 'None'}")
    report.append(f"- **MITRE Techniques Observed:** {', '.join(techniques) if techniques else 'None'}")
    
    report.append("\n## Forensic Timeline")
    for idx, e in enumerate(malicious[:20]): # limit to top 20 events
        detail = e.get("command_line") or e.get("url") or e.get("file_name") or "Adversary Action"
        report.append(f"{idx+1}. `[{e.get('timestamp')}]` **{e.get('host')}** - {e.get('username')}: {detail} (Tactic: {e.get('attack_stage')})")
        
    report.append("\n## Recommended Containment Actions")
    report.append("1. **Isolate Hosts:** Immediately quarantine the affected workstations from the local network segment.")
    report.append("2. **Revoke Credentials:** Reset Active Directory domain credentials and invalidate OAuth tokens/MFA devices for compromised users.")
    report.append("3. **Inspect Shadow Copies:** Restore volume shadow copies if a Ransomware encryption stage was executed.")
    
    return "\n".join(report)

