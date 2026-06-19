from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from src.app.db.session import get_db
from src.app.db.models import Company, Host, Employee
from src.app.core.environment_generator import generate_company_environment

router = APIRouter()

@router.post("/companies")
def create_company(
    name: str = Query(..., description="Name of the company to simulate"),
    industry: str = Query("Finance", description="Company industry (Finance, Healthcare, Tech, etc.)"),
    size: str = Query("medium", description="Company network size (small, medium, large)"),
    db: Session = Depends(get_db)
):
    try:
        company = generate_company_environment(db, name, industry, size)
        return {
            "status": "success",
            "company_id": company.id,
            "company_name": company.name,
            "domain": company.domain,
            "total_departments": len(company.departments),
            "total_hosts": len(company.hosts)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/companies/{company_id}/topology")
def get_company_topology(company_id: str, db: Session = Depends(get_db)):
    company = db.query(Company).filter(Company.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
        
    hosts = db.query(Host).filter(Host.company_id == company_id).all()
    employees = db.query(Employee).join(Employee.department).filter(Employee.department.has(company_id=company_id)).all()
    
    ad_forest = {
        "forest_name": company.domain,
        "root_domain": company.domain,
        "organizational_units": [
            {
                "ou_name": "OU=Domain Controllers,DC=" + company.domain.replace(".", ",DC="),
                "objects": [h.hostname for h in hosts if h.role == "DomainController"]
            },
            {
                "ou_name": "OU=Servers,DC=" + company.domain.replace(".", ",DC="),
                "objects": [h.hostname for h in hosts if h.role == "FileServer" or h.role == "WebServer"]
            },
            {
                "ou_name": "OU=Workstations,DC=" + company.domain.replace(".", ",DC="),
                "objects": [h.hostname for h in hosts if h.role == "Workstation"]
            },
            {
                "ou_name": "OU=User Accounts,DC=" + company.domain.replace(".", ",DC="),
                "objects": [e.username for e in employees]
            }
        ],
        "groups": [
            {
                "group_name": "Domain Admins",
                "members": [e.username for e in employees if e.role_profile in ["SysAdmin", "Security_Analyst"]]
            },
            {
                "group_name": "Domain Users",
                "members": [e.username for e in employees]
            }
        ],
        "gpos": [
            {"name": "Default Domain Policy", "status": "Enabled"},
            {"name": "Audit Process Creation Policy", "status": "Enabled"},
            {"name": "Disable Defender GPO Policy", "status": "Disabled"}
        ]
    }
    
    return {
        "company_name": company.name,
        "domain": company.domain,
        "active_directory_model": ad_forest,
        "hosts": [{"hostname": h.hostname, "ip_address": h.ip_address, "os": h.os_type, "role": h.role} for h in hosts],
        "employees": [{"username": e.username, "email": e.email, "role": e.role_profile} for e in employees]
    }
