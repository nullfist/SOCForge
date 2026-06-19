import json
import hashlib
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from src.app.db.session import get_db
from src.app.db.models import Company
from src.app.core.timeline_engine import generate_timeline
from src.app.telemetry.windows import format_windows_event
from src.app.telemetry.linux import format_linux_event
from src.app.telemetry.network import format_network_event
from src.app.telemetry.cloud import format_cloud_event
from src.app.telemetry.edr import format_edr_event
from src.app.alert.generator import generate_alerts_from_events, generate_analyst_cases
from src.app.detection.rules import get_rules_for_scenario
from src.app.detection.validation import calculate_validation_score
from src.app.export.engine import export_to_ndjson, export_to_csv, export_to_syslog, export_to_ecs

router = APIRouter()

def compile_attack_graph(events: list) -> dict:
    nodes = []
    links = []
    seen_nodes = set()
    seen_links = set()
    
    for e in events:
        if e.get("ground_truth"):
            attacker = e.get("attacker")
            victim = e.get("victim") or e.get("host")
            action = e.get("attack_stage", "Attack Step")
            
            if attacker and attacker not in seen_nodes:
                seen_nodes.add(attacker)
                nodes.append({"id": attacker, "label": attacker, "type": "attacker"})
                
            if victim and victim not in seen_nodes:
                seen_nodes.add(victim)
                nodes.append({"id": victim, "label": victim, "type": "victim" if "DC" not in victim else "domain_controller"})
                
            if attacker and victim:
                link_key = (attacker, victim, action)
                if link_key not in seen_links:
                    seen_links.add(link_key)
                    links.append({"source": attacker, "target": victim, "label": action})
                    
    return {"nodes": nodes, "links": links}

@router.post("/simulations/generate")
def generate_dataset(
    company_id: str,
    scenario: str = Query("APT Campaign", description="Scenarios: Brute Force, Phishing, Persistence, Privilege Escalation, Lateral Movement, Insider Threat, Ransomware, APT Campaign, Kerberoasting, DCSync, MFA Fatigue, Cloud Breach, Kubernetes Abuse"),
    duration_hours: int = 24,
    format: str = Query("json", description="json, ndjson, csv, syslog, ecs, edr"),
    db: Session = Depends(get_db)
):
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
        
    try:
        dataset = generate_timeline(db, company, scenario, duration_hours)
        events = dataset["events"]
        
        formatted_events = []
        for e in events:
            if format == "edr":
                formatted_events.append(format_edr_event(e))
            elif e.get("os_type") == "Windows":
                formatted_events.append(format_windows_event(e))
            elif e.get("os_type") == "Linux":
                formatted_events.append(format_linux_event(e))
            elif e.get("event_type") in ["ProxyAccess", "NetworkConnection", "VPNConnection", "DNSQuery", "IDSAlert"]:
                formatted_events.append(format_network_event(e))
            else:
                formatted_events.append(format_cloud_event(e))
                
        alerts = generate_alerts_from_events(events)
        validation = calculate_validation_score(events, alerts)
        graph = compile_attack_graph(events)
        cases = generate_analyst_cases(events)
        
        # Serialize data based on format
        if format == "ndjson":
            exported_data = export_to_ndjson(formatted_events)
        elif format == "csv":
            exported_data = export_to_csv(formatted_events)
        elif format == "syslog":
            exported_data = export_to_syslog(formatted_events)
        elif format == "ecs":
            exported_data = json.dumps(export_to_ecs(formatted_events), indent=2)
        else:
            exported_data = json.dumps(formatted_events, indent=2)
            
        # Cryptographic Dataset Signing (SHA256 signature verification)
        sha256_hash = hashlib.sha256(exported_data.encode("utf-8")).hexdigest()
            
        return {
            "scenario": scenario,
            "duration_hours": duration_hours,
            "format": format,
            "sha256_signature": sha256_hash,
            "validation_report": validation,
            "attack_graph": graph,
            "cases": cases,
            "total_alerts": len(alerts),
            "alerts": alerts,
            "data": exported_data if format in ["ndjson", "csv", "syslog"] else formatted_events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/detections/rules")
def get_detection_rules(technique_id: str):
    rules = get_rules_for_scenario(technique_id)
    return {
        "technique_id": technique_id,
        "rules": rules
    }
