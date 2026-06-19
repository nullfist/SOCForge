import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.app.db.session import Base, get_db
from src.app.main import app
from src.app.core.environment_generator import generate_company_environment
from src.app.core.timeline_engine import generate_timeline
from src.app.alert.generator import generate_alerts_from_events, generate_incident_report
from src.app.detection.validation import validate_sigma_rule

# In-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

client = TestClient(app)

def test_company_generation():
    db = TestingSessionLocal()
    company = generate_company_environment(db, "TestCorp", "Finance", "small")
    assert company.name == "TestCorp"
    assert len(company.hosts) >= 5
    assert len(company.departments) == 6
    db.close()

def test_timeline_generation():
    db = TestingSessionLocal()
    company = generate_company_environment(db, "TestCorp", "Finance", "small")
    result = generate_timeline(db, company, "Brute Force", 2)
    assert result["scenario"] == "Brute Force"
    assert result["total_events"] > 0
    db.close()

def test_api_endpoints():
    # 1. Test create company
    resp = client.post("/api/v1/companies?name=TestCorpAPI&industry=Tech&size=small")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    company_id = data["company_id"]

    # 2. Test topology endpoint
    resp = client.get(f"/api/v1/companies/{company_id}/topology")
    assert resp.status_code == 200
    topology = resp.json()
    assert "hosts" in topology
    assert "active_directory_model" in topology

    # 3. Test log generation endpoint
    resp = client.post(f"/api/v1/simulations/generate?company_id={company_id}&scenario=Phishing&duration_hours=1&format=json")
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["scenario"] == "Phishing"
    assert "validation_report" in res_data
    assert "sha256_signature" in res_data

def test_e2e_platform_flow():
    # Phase 1: Bootstrapping target company via API
    resp = client.post("/api/v1/companies?name=E2ECorp&size=small")
    assert resp.status_code == 200
    company_id = resp.json()["company_id"]

    # Phase 2: Validate Active Directory topology mappings
    resp = client.get(f"/api/v1/companies/{company_id}/topology")
    assert resp.status_code == 200
    topo = resp.json()
    assert topo["active_directory_model"]["forest_name"] == "e2ecorp.local"

    # Phase 3: Launch Ransomware scenario
    resp = client.post(f"/api/v1/simulations/generate?company_id={company_id}&scenario=Ransomware&duration_hours=12&format=json")
    assert resp.status_code == 200
    sim_data = resp.json()
    assert "sha256_signature" in sim_data
    assert sim_data["total_alerts"] > 0

    # Phase 4: Submit custom Sigma rule via validation API
    sigma_rule = """
title: Volume Shadow Copy Deletion via VSSAdmin
detection:
    selection:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains: 'delete shadows'
    condition: selection
tags:
    - attack.T1486
"""
    # Trigger dynamic rule matching
    resp = client.post(
        "/api/v1/validation/sigma",
        json={
            "rule_yaml": sigma_rule,
            "company_id": company_id,
            "scenario": "Ransomware"
        }
    )
    assert resp.status_code == 200
    eval_result = resp.json()
    assert eval_result["status"] == "success"
    # The rule must successfully match the generated vssadmin command execution
    assert eval_result["true_positives"] >= 1
