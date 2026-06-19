import json
import csv
import io
from typing import List, Dict, Any

def export_to_ndjson(events: List[Dict[str, Any]]) -> str:
    """Exports events as newline-delimited JSON."""
    return "\n".join(json.dumps(e) for e in events)

def export_to_csv(events: List[Dict[str, Any]]) -> str:
    """Exports events as a CSV string."""
    if not events:
        return ""
    
    # Extract keys as headers
    headers = set()
    for e in events:
        headers.update(e.keys())
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=sorted(list(headers)))
    writer.writeheader()
    for e in events:
        writer.writerow(e)
    return output.getvalue()

def export_to_syslog(events: List[Dict[str, Any]]) -> str:
    """Converts events into RFC5424-style syslog formatted strings."""
    lines = []
    for idx, e in enumerate(events):
        timestamp = e.get("timestamp", "")
        host = e.get("host", "unknown-host")
        app = e.get("event_type", "security-log")
        msg = json.dumps(e)
        lines.append(f"<13>1 {timestamp} {host} {app} {idx} - - {msg}")
    return "\n".join(lines)

def export_to_ecs(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Converts events into Elastic Common Schema (ECS) style dictionary lists."""
    ecs_logs = []
    for e in events:
        ecs_event = {
            "@timestamp": e.get("timestamp"),
            "host": {
                "name": e.get("host"),
                "ip": e.get("ip_address")
            },
            "user": {
                "name": e.get("username"),
                "roles": [e.get("user_role")] if e.get("user_role") else []
            },
            "event": {
                "category": [e.get("event_type", "").lower()],
                "outcome": e.get("status", "success").lower()
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": e.get("mitre"),
                    "name": e.get("scenario")
                } if e.get("mitre") else {}
            }
        }
        ecs_logs.append(ecs_event)
    return ecs_logs
