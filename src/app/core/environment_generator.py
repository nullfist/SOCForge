import random
from faker import Faker
from sqlalchemy.orm import Session
from src.app.db.models import Company, Department, Employee, Host

fake = Faker()

DEPARTMENTS_TEMPLATE = [
    {"name": "Executive Board", "code": "EXEC", "roles": ["Executive", "Assistant"]},
    {"name": "Human Resources", "code": "HR", "roles": ["HR_Specialist", "HR_Manager"]},
    {"name": "Finance & Accounting", "code": "FIN", "roles": ["Accountant", "Finance_Analyst", "CFO"]},
    {"name": "Sales & Marketing", "code": "SALES", "roles": ["Sales_Rep", "Marketing_Specialist"]},
    {"name": "Information Technology", "code": "IT", "roles": ["SysAdmin", "Network_Admin", "Helpdesk"]},
    {"name": "Security Operations", "code": "SEC", "roles": ["Security_Analyst", "Incident_Responder"]}
]

def generate_company_environment(db: Session, company_name: str, industry: str, size: str = "medium", num_employees: int = None, num_hosts: int = None) -> Company:
    # 1. Create Company
    domain = company_name.lower().replace(" ", "").replace("&", "") + ".local"
    company = Company(
        name=company_name,
        industry=industry,
        domain=domain
    )
    db.add(company)
    db.flush()

    # Determine scaling sizes
    if num_employees is not None and num_hosts is not None:
        emp_count_range = (num_employees, num_employees)
        host_count_range = (num_hosts, num_hosts)
    elif size == "small":
        emp_count_range = (5, 10)
        host_count_range = (5, 10)
    elif size == "large":
        emp_count_range = (40, 100)
        host_count_range = (30, 80)
    else: # medium
        emp_count_range = (15, 30)
        host_count_range = (15, 30)

    # 2. Generate Departments
    created_depts = []
    for dept_t in DEPARTMENTS_TEMPLATE:
        dept = Department(
            company_id=company.id,
            name=dept_t["name"],
            code=dept_t["code"]
        )
        db.add(dept)
        created_depts.append((dept, dept_t["roles"]))
    db.flush()

    # 3. Generate Employees
    employees = []
    num_employees = random.randint(*emp_count_range)
    
    # Ensure at least one sysadmin and exec
    for i in range(num_employees):
        dept_item, roles = random.choice(created_depts)
        role = random.choice(roles)
        
        first_name = fake.first_name()
        last_name = fake.last_name()
        username = f"{first_name[0].lower()}{last_name.lower()}"
        email = f"{username}@{company.domain.replace('.local', '.com')}"
        
        emp = Employee(
            department_id=dept_item.id,
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            role_profile=role
        )
        db.add(emp)
        employees.append(emp)
    db.flush()

    # 4. Generate Hosts & Network Topography
    # Base IP ranges based on company
    subnet_third_octet = random.randint(10, 250)
    ip_base = f"10.{subnet_third_octet}."

    # Domain Controller
    dc_host = Host(
        company_id=company.id,
        hostname=f"{company.name[:3].upper()}-DC-01",
        ip_address=f"{ip_base}1.10",
        os_type="Windows",
        role="DomainController",
        has_sysmon=True
    )
    db.add(dc_host)

    # File Server
    fs_host = Host(
        company_id=company.id,
        hostname=f"{company.name[:3].upper()}-SRV-FILE",
        ip_address=f"{ip_base}1.20",
        os_type="Windows",
        role="FileServer",
        has_sysmon=True
    )
    db.add(fs_host)

    # Mail Server or Linux Web Server
    web_host = Host(
        company_id=company.id,
        hostname=f"{company.name[:3].upper()}-SRV-WEB",
        ip_address=f"{ip_base}1.30",
        os_type="Linux",
        role="WebServer",
        has_sysmon=False
    )
    db.add(web_host)

    # User Workstations
    num_workstations = random.randint(*host_count_range)
    for i in range(1, num_workstations + 1):
        # Match with employee if possible
        emp = employees[i % len(employees)]
        
        # 80% Windows workstations, 20% Linux workstations
        os_choice = "Windows" if random.random() < 0.8 else "Linux"
        hostname = f"{company.name[:3].upper()}-WS-{i:03d}"
        role = "Workstation"
        
        workstation = Host(
            company_id=company.id,
            hostname=hostname,
            ip_address=f"{ip_base}2.{50 + i}",
            os_type=os_choice,
            role=role,
            has_sysmon=True if os_choice == "Windows" else False
        )
        db.add(workstation)

    db.commit()
    db.refresh(company)
    return company
