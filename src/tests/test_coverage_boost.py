import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.app.db.session import Base
from src.app.core.environment_generator import generate_company_environment
from src.app.core.timeline_engine import generate_timeline
from src.app.telemetry.windows import format_windows_event
from src.app.telemetry.linux import format_linux_event
from src.app.telemetry.network import format_network_event
from src.app.telemetry.cloud import format_cloud_event
from src.app.telemetry.edr import format_edr_event
from src.app.export.engine import export_to_ndjson, export_to_csv, export_to_syslog, export_to_ecs
from src.app.detection.validation import evaluate_detections_cli, validate_sigma_rule
from src.app.detection.rules import get_rules_for_scenario

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_coverage.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="module")
def shared_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    company = generate_company_environment(db, "CoverageCorp", "Technology", "small")
    yield db, company
    db.close()
    Base.metadata.drop_all(bind=engine)

def test_all_scenarios(shared_db):
    db, company = shared_db
    scenarios = [
        "Brute Force", "Phishing", "Persistence", "Privilege Escalation",
        "Lateral Movement", "Insider Threat", "Ransomware", "APT Campaign",
        "Kerberoasting", "DCSync", "MFA Fatigue", "Cloud Breach", "Kubernetes Abuse"
    ]
    for scenario in scenarios:
        result = generate_timeline(db, company, scenario, duration_hours=1)
        assert result["scenario"] == scenario
        assert len(result["events"]) > 0

def test_telemetry_formatters():
    mock_event = {
        "event_id": "evt-123",
        "timestamp": "2026-06-19T10:00:00",
        "host": "TEST-WS-01",
        "ip_address": "10.0.2.15",
        "username": "jdoe",
        "user_role": "Analyst",
        "os_type": "Windows",
        "event_type": "ProcessCreation",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "parent_process": "explorer.exe",
        "ground_truth": True,
        "scenario": "Ransomware",
        "mitre": "T1059.003",
        "attacker": "APT-TEST",
        "victim": "TEST-WS-01",
        "confidence": 100
    }
    
    # 1. Windows Event
    win = format_windows_event(mock_event)
    assert win["EventID"] == 1
    
    # 2. Linux Event
    mock_event["os_type"] = "Linux"
    mock_event["event_type"] = "Authentication"
    lin = format_linux_event(mock_event)
    assert "jdoe" in lin["message"]
    
    # 3. Network Events
    net_types = ["DNSQuery", "NetworkConnection", "ProxyAccess", "VPNConnection", "IDSAlert"]
    for nt in net_types:
        mock_event["event_type"] = nt
        net_log = format_network_event(mock_event)
        assert net_log["event_id"] == "evt-123"
        
    # 4. Cloud Events
    cloud_types = ["CloudAuthentication", "CloudStorageAccess", "CloudIAMChange"]
    for ct in cloud_types:
        mock_event["event_type"] = ct
        mock_event["host"] = "aws-cloudtrail"
        cloud_log = format_cloud_event(mock_event)
        assert cloud_log["event_id"] == "evt-123"
        
    # 5. EDR Events
    mock_event["event_type"] = "ProcessCreation"
    cs_edr = format_edr_event(mock_event, provider="CrowdStrike")
    assert cs_edr["agent_provider"] == "CrowdStrike"
    
    ms_edr = format_edr_event(mock_event, provider="Defender")
    assert ms_edr["agent_provider"] == "Defender"

def test_exporters():
    events = [
        {"timestamp": "2026-06-19T10:00:00", "host": "WS-01", "event_type": "DNSQuery", "username": "admin"}
    ]
    ndjson_out = export_to_ndjson(events)
    assert "DNSQuery" in ndjson_out
    
    csv_out = export_to_csv(events)
    assert "DNSQuery" in csv_out
    
    syslog_out = export_to_syslog(events)
    assert "WS-01" in syslog_out
    
    ecs_out = export_to_ecs(events)
    assert ecs_out[0]["host"]["name"] == "WS-01"

def test_rules_and_validation():
    # 1. Detection evaluator CLI
    alerts = [{"mitre_mapping": {"id": "T1566"}, "rule_name": "Phishing Alert"}]
    timeline = [{"mitre_technique": "T1566"}]
    eval_res = evaluate_detections_cli(alerts, timeline)
    assert eval_res["precision"] == 100.0
    
    # 2. Rules pack fetch
    pack = get_rules_for_scenario("T1110")
    assert "sigma" in pack
    
    # 3. Dynamic Sigma rule validator syntax error handling
    invalid_sigma = "invalid: yaml: : :"
    res = validate_sigma_rule(invalid_sigma, [])
    assert res["status"] == "error"
