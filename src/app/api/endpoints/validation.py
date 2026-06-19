from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from src.app.db.session import get_db
from src.app.db.models import Company
from src.app.core.timeline_engine import generate_timeline
from src.app.telemetry.windows import format_windows_event
from src.app.telemetry.linux import format_linux_event
from src.app.telemetry.network import format_network_event
from src.app.telemetry.cloud import format_cloud_event
from src.app.detection.validation import validate_sigma_rule

router = APIRouter()

class SigmaValidationRequest(BaseModel):
    rule_yaml: str
    company_id: str
    scenario: str = "APT Campaign"

@router.post("/validation/sigma")
def evaluate_sigma(
    request: SigmaValidationRequest,
    db: Session = Depends(get_db)
):
    company = db.query(Company).filter(Company.id == request.company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    try:
        dataset = generate_timeline(db, company, request.scenario, 24)
        events = dataset["events"]
        
        formatted_events = []
        for e in events:
            if e.get("os_type") == "Windows":
                formatted_events.append(format_windows_event(e))
            elif e.get("os_type") == "Linux":
                formatted_events.append(format_linux_event(e))
            elif e.get("event_type") in ["ProxyAccess", "NetworkConnection", "VPNConnection", "DNSQuery", "IDSAlert"]:
                formatted_events.append(format_network_event(e))
            else:
                formatted_events.append(format_cloud_event(e))
                
        result = validate_sigma_rule(request.rule_yaml, formatted_events)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
