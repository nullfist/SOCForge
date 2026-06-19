import random
import uuid
from datetime import datetime, time
from typing import Dict, Any, List
from src.app.db.models import Employee, Host

NORMAL_APPS = {
    "Windows": ["chrome.exe", "outlook.exe", "excel.exe", "word.exe", "teams.exe", "notepad.exe", "explorer.exe"],
    "Linux": ["bash", "firefox", "thunderbird", "libreoffice", "git", "curl", "ssh"]
}

NORMAL_DOMAINS = [
    "google.com", "outlook.office365.com", "github.com", "slack.com", "zoom.us",
    "stackoverflow.com", "wikipedia.org", "linkedin.com", "internal-wiki.local",
    "salesforce.com", "jira.atlassian.net", "aws.amazon.com", "nytimes.com"
]

FINANCE_SITES = ["banking-portal.internal", "sec.gov", "stripe.com", "quickbooks.com"]
HR_SITES = ["workday.com", "linkedin.com/talent", "ADP-payroll.internal", "resumes-share.local"]
IT_SITES = ["github.com", "stackoverflow.com", "aws.amazon.com", "docker.com", "kubernetes.io"]

def is_business_hours(dt: datetime) -> bool:
    """Check if the given datetime is within business hours (08:00 - 18:00, Mon-Fri)."""
    if dt.weekday() >= 5: # Saturday & Sunday
        return False
    current_time = dt.time()
    # Lunch break dip (12:00 - 13:00)
    if time(12, 0) <= current_time <= time(13, 0):
        return random.random() < 0.15 # 15% activity during lunch
    return time(8, 0) <= current_time <= time(18, 0)

def generate_normal_event(employee: Employee, host: Host, timestamp: datetime) -> Dict[str, Any]:
    """Generates a single normal business activity event based on user profile, host OS, and calendar behavior."""
    
    # 1. Sick days / Vacation check (deterministic based on username hash)
    user_hash = hash(employee.username)
    if user_hash % 20 == 0:  # 5% chance user is on vacation/sick
        # Gaps of zero activity during mid-week
        if timestamp.weekday() in [1, 2, 3]: # Tue-Thu
            return None
            
    # 2. Adjust activity chance based on business hours
    if is_business_hours(timestamp):
        activity_chance = 0.9
    else:
        # Weekend rare work or late night check
        if timestamp.weekday() >= 5:
            activity_chance = 0.02 # 2% chance of weekend work
        else:
            activity_chance = 0.08 # 8% chance of after-hours work
            
    if random.random() > activity_chance:
        return None

    role = employee.role_profile
    os_type = host.os_type
    
    # Expand event types to include Printer and USB insertions
    event_type = random.choice([
        "Authentication", "ProcessCreation", "FileAccess", "DNSQuery", 
        "NetworkConnection", "USBInsert", "PrintJob"
    ])
    
    event = {
        "event_id": f"evt-normal-{random.randint(100000, 999999)}",
        "timestamp": timestamp.isoformat(),
        "company_id": host.company_id,
        "host": host.hostname,
        "ip_address": host.ip_address,
        "username": employee.username,
        "user_role": role,
        "os_type": os_type,
        "ground_truth": False,
        "scenario": None,
        "mitre": None,
        "attacker": None,
        "victim": None,
        "confidence": 0
    }
    
    if event_type == "Authentication":
        # Random password resets
        is_pw_reset = random.random() < 0.01 # 1% chance
        event.update({
            "event_type": "Authentication",
            "action": "PasswordReset" if is_pw_reset else ("Login" if random.random() < 0.95 else "Logout"),
            "status": "SUCCESS",
            "source_ip": f"10.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(2,254)}" if random.random() < 0.2 else host.ip_address,
            "logon_type": 2 if os_type == "Windows" else "interactive"
        })
        
    elif event_type == "ProcessCreation":
        apps = NORMAL_APPS.get(os_type, ["bash"])
        process = random.choice(apps)
        if "Finance" in role and os_type == "Windows":
            process = random.choice(["excel.exe", "qb-client.exe"])
        elif "HR" in role and os_type == "Windows":
            process = random.choice(["word.exe", "resumes-viewer.exe"])
        elif "SysAdmin" in role or "Security" in role:
            process = "powershell.exe" if os_type == "Windows" else "ssh"
            
        event.update({
            "event_type": "ProcessCreation",
            "process_name": process,
            "command_line": f"C:\\Windows\\System32\\{process}" if os_type == "Windows" else f"/usr/bin/{process}",
            "parent_process": "explorer.exe" if os_type == "Windows" else "systemd"
        })
        
    elif event_type == "FileAccess":
        ext = "xlsx" if "Finance" in role else ("docx" if "HR" in role else "txt")
        file_path = f"C:\\Users\\{employee.username}\\Documents\\report.{ext}" if os_type == "Windows" else f"/home/{employee.username}/documents/report.{ext}"
        event.update({
            "event_type": "FileAccess",
            "file_name": f"report.{ext}",
            "file_path": file_path,
            "action": random.choice(["Read", "Write", "Open"])
        })
        
    elif event_type == "DNSQuery":
        domain = random.choice(NORMAL_DOMAINS)
        if "Finance" in role:
            domain = random.choice(FINANCE_SITES + NORMAL_DOMAINS)
        elif "HR" in role:
            domain = random.choice(HR_SITES + NORMAL_DOMAINS)
        elif "SysAdmin" in role:
            domain = random.choice(IT_SITES + NORMAL_DOMAINS)
            
        event.update({
            "event_type": "DNSQuery",
            "query": domain,
            "record_type": "A",
            "resolved_ip": f"192.168.{random.randint(10,250)}.{random.randint(2,254)}"
        })
        
    elif event_type == "NetworkConnection":
        event.update({
            "event_type": "NetworkConnection",
            "destination_ip": f"192.168.{random.randint(10,250)}.{random.randint(2,254)}",
            "destination_port": random.choice([443, 80]),
            "direction": "Outbound",
            "protocol": "TCP"
        })
        
    elif event_type == "USBInsert" and os_type == "Windows":
        event.update({
            "event_type": "USBInsert",
            "device_id": f"USBSTOR\\DISK&VEN_SANDISK&PROD_CRUZER\\{uuid.uuid4()}",
            "drive_letter": random.choice(["E:", "F:", "G:"])
        })
        
    elif event_type == "PrintJob":
        event.update({
            "event_type": "PrintJob",
            "document_name": "Monthly_Review.pdf",
            "printer_name": "PRN-OFFICE-COLOR-01",
            "pages": random.randint(1, 10)
        })
        
    else:
        return None

    return event
