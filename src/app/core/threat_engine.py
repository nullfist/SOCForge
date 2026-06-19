import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
from src.app.db.models import Employee, Host
from src.app.mitre.mapping import get_mitre_mapping

# Global counter for sequential event IDs
_event_counter = 100000

def _get_next_event_id() -> str:
    global _event_counter
    _event_counter += 1
    return f"evt-{_event_counter}"

def make_threat_event(
    timestamp: datetime,
    event_type: str,
    host: str,
    ip_address: str,
    username: str,
    attack_stage: str,
    scenario: str,
    mitre: str,
    attacker: str,
    victim: str,
    confidence: int = 100,
    **kwargs
) -> Dict[str, Any]:
    """Factory to create threat events with standardized ground truth metadata."""
    host_lower = host.lower()
    os_type = kwargs.get("os_type")
    if not os_type:
        if "web" in host_lower or "mail" in host_lower or "kube" in host_lower or "linux" in host_lower:
            os_type = "Linux"
        elif "ws" in host_lower or "dc" in host_lower or "file" in host_lower or "win" in host_lower:
            os_type = "Windows"
        else:
            os_type = "Cloud"

    event = {
        "event_id": _get_next_event_id(),
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "host": host,
        "ip_address": ip_address,
        "username": username,
        "os_type": os_type,
        "ground_truth": True,
        "attack_stage": attack_stage,
        "scenario": scenario,
        "mitre": mitre,
        "attacker": attacker,
        "victim": victim,
        "confidence": confidence
    }
    event.update(kwargs)
    return event

def simulate_brute_force(attacker_ip: str, victim_emp: Employee, victim_host: Host, start_time: datetime, scenario: str = "RansomCrew") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    for i in range(10):
        current_time += timedelta(seconds=random.randint(1, 3))
        events.append(make_threat_event(
            timestamp=current_time,
            event_type="Authentication",
            host=victim_host.hostname,
            ip_address=victim_host.ip_address,
            username=victim_emp.username,
            attack_stage="Credential Access",
            scenario=scenario,
            mitre="T1110",
            attacker=attacker_ip,
            victim=victim_host.hostname,
            status="FAILED",
            logon_type=3
        ))
    current_time += timedelta(seconds=1)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="AccountLockout",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=victim_emp.username,
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1110",
        attacker=attacker_ip,
        victim=victim_host.hostname
    ))
    current_time += timedelta(minutes=5)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="Authentication",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=victim_emp.username,
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1110",
        attacker=attacker_ip,
        victim=victim_host.hostname,
        status="SUCCESS",
        logon_type=3
    ))
    return events

def simulate_phishing(attacker_domain: str, victim_emp: Employee, victim_host: Host, start_time: datetime, scenario: str = "APT29") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="EmailReceived",
        host="MailServer",
        ip_address="10.150.1.30",
        username=victim_emp.username,
        attack_stage="Initial Access",
        scenario=scenario,
        mitre="T1566",
        attacker=attacker_domain,
        victim=victim_emp.email,
        sender=f"billing-update@{attacker_domain}",
        recipient=victim_emp.email,
        subject="ACTION REQUIRED: Update Billing Information",
        has_link=True
    ))
    current_time += timedelta(minutes=random.randint(2, 5))
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProxyAccess",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=victim_emp.username,
        attack_stage="Initial Access",
        scenario=scenario,
        mitre="T1566",
        attacker=attacker_domain,
        victim=victim_host.hostname,
        method="GET",
        url=f"http://{attacker_domain}/login.html",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/103.0.0.0",
        status_code=200
    ))
    current_time += timedelta(seconds=30)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProxyAccess",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=victim_emp.username,
        attack_stage="Initial Access",
        scenario=scenario,
        mitre="T1566",
        attacker=attacker_domain,
        victim=victim_host.hostname,
        method="POST",
        url=f"http://{attacker_domain}/login.php"
    ))
    return events

def simulate_persistence(victim_emp: Employee, victim_host: Host, start_time: datetime, scenario: str = "APT29") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=victim_emp.username,
        attack_stage="Persistence",
        scenario=scenario,
        mitre="T1053",
        attacker=f"{scenario}-Actor",
        victim=victim_host.hostname,
        command_line="schtasks /create /tn \"UpdateCheck\" /tr \"C:\\Users\\Public\\update.exe\" /sc daily /st 12:00"
    ))
    current_time += timedelta(seconds=15)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ServiceCreation",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username="SYSTEM",
        attack_stage="Persistence",
        scenario=scenario,
        mitre="T1053",
        attacker=f"{scenario}-Actor",
        victim=victim_host.hostname,
        service_name="SOCForgeUpdateService",
        image_path="C:\\Windows\\temp\\updater.exe"
    ))
    return events

def simulate_privilege_escalation(victim_emp: Employee, victim_host: Host, start_time: datetime, scenario: str = "APT29") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username="SYSTEM",
        attack_stage="Privilege Escalation",
        scenario=scenario,
        mitre="T1078",
        attacker=f"{scenario}-Actor",
        victim=victim_host.hostname,
        command_line="cmd.exe /c net localgroup administrators backup_admin /add"
    ))
    current_time += timedelta(seconds=5)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="RegistryModification",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username="SYSTEM",
        attack_stage="Privilege Escalation",
        scenario=scenario,
        mitre="T1078",
        attacker=f"{scenario}-Actor",
        victim=victim_host.hostname,
        target_object="HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\backup_admin",
        details="User elevated to administrator local group"
    ))
    return events

def simulate_lateral_movement(victim_emp: Employee, src_host: Host, dest_host: Host, start_time: datetime, scenario: str = "APT29") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="NetworkConnection",
        host=src_host.hostname,
        ip_address=src_host.ip_address,
        username=victim_emp.username,
        attack_stage="Lateral Movement",
        scenario=scenario,
        mitre="T1021",
        attacker=src_host.hostname,
        victim=dest_host.hostname,
        destination_ip=dest_host.ip_address,
        destination_port=3389 if dest_host.os_type == "Windows" else 22,
        protocol="TCP"
    ))
    current_time += timedelta(seconds=2)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="Authentication",
        host=dest_host.hostname,
        ip_address=dest_host.ip_address,
        username=victim_emp.username,
        attack_stage="Lateral Movement",
        scenario=scenario,
        mitre="T1021",
        attacker=src_host.ip_address,
        victim=dest_host.hostname,
        status="SUCCESS",
        logon_type=10 if dest_host.os_type == "Windows" else "remote"
    ))
    return events

def simulate_insider_threat(insider_emp: Employee, victim_host: Host, start_time: datetime, scenario: str = "InsiderThreat") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="FileAccess",
        host="FinanceServer",
        ip_address="10.150.1.20",
        username=insider_emp.username,
        attack_stage="Collection",
        scenario=scenario,
        mitre="T1114",
        attacker=insider_emp.username,
        victim="FinanceServer",
        file_name="q4_salaries_and_layoffs.xlsx",
        file_path="D:\\Shares\\Finance\\q4_salaries_and_layoffs.xlsx",
        action="Read"
    ))
    current_time += timedelta(minutes=5)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="NetworkConnection",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=insider_emp.username,
        attack_stage="Exfiltration",
        scenario=scenario,
        mitre="T1048",
        attacker=victim_host.hostname,
        victim="82.165.12.99",
        destination_ip="82.165.12.99",
        destination_port=443,
        bytes_sent=542000000
    ))
    return events

def simulate_ransomware(victim_emp: Employee, victim_host: Host, start_time: datetime, scenario: str = "RansomCrew") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=victim_emp.username,
        attack_stage="Impact",
        scenario=scenario,
        mitre="T1486",
        attacker=f"{scenario}-RansomActor",
        victim=victim_host.hostname,
        command_line="vssadmin.exe delete shadows /all /quiet"
    ))
    for i in range(15):
        current_time += timedelta(milliseconds=200)
        events.append(make_threat_event(
            timestamp=current_time,
            event_type="FileAccess",
            host=victim_host.hostname,
            ip_address=victim_host.ip_address,
            username=victim_emp.username,
            attack_stage="Impact",
            scenario=scenario,
            mitre="T1486",
            attacker=f"{scenario}-RansomActor",
            victim=victim_host.hostname,
            file_name=f"document_{i}.docx.locked",
            file_path=f"C:\\Users\\{victim_emp.username}\\Documents\\document_{i}.docx.locked",
            action="Write"
        ))
    return events

def simulate_apt_campaign(victim_emp: Employee, ws_host: Host, dc_host: Host, start_time: datetime, scenario: str = "APT29") -> List[Dict[str, Any]]:
    events = []
    current_time = start_time
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProxyAccess",
        host=ws_host.hostname,
        ip_address=ws_host.ip_address,
        username=victim_emp.username,
        attack_stage="Initial Access",
        scenario=scenario,
        mitre="T1566",
        attacker=f"{scenario}-MalDomain",
        victim=ws_host.hostname,
        method="GET",
        url="http://malicious-update.com/payload.exe"
    ))
    current_time += timedelta(minutes=15)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=ws_host.hostname,
        ip_address=ws_host.ip_address,
        username="SYSTEM",
        attack_stage="Persistence",
        scenario=scenario,
        mitre="T1053",
        attacker=f"{scenario}-Actor",
        victim=ws_host.hostname,
        command_line="schtasks /create /tn \"WindowsUpdater\" /tr \"C:\\Windows\\Temp\\payload.exe\" /sc hourly"
    ))
    current_time += timedelta(hours=1)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=ws_host.hostname,
        ip_address=ws_host.ip_address,
        username="SYSTEM",
        attack_stage="Privilege Escalation",
        scenario=scenario,
        mitre="T1078",
        attacker=f"{scenario}-Actor",
        victim=ws_host.hostname,
        command_line="powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\privesc.ps1"
    ))
    current_time += timedelta(minutes=10)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=ws_host.hostname,
        ip_address=ws_host.ip_address,
        username="SYSTEM",
        attack_stage="Discovery",
        scenario=scenario,
        mitre="T1078",
        attacker=f"{scenario}-Actor",
        victim=ws_host.hostname,
        command_line="net group \"domain admins\" /domain"
    ))
    current_time += timedelta(hours=2)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="NetworkConnection",
        host=ws_host.hostname,
        ip_address=ws_host.ip_address,
        username=victim_emp.username,
        attack_stage="Lateral Movement",
        scenario=scenario,
        mitre="T1021",
        attacker=ws_host.hostname,
        victim=dc_host.hostname,
        destination_ip=dc_host.ip_address,
        destination_port=445,
        protocol="TCP"
    ))
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="Authentication",
        host=dc_host.hostname,
        ip_address=dc_host.ip_address,
        username="Administrator",
        attack_stage="Lateral Movement",
        scenario=scenario,
        mitre="T1021",
        attacker=ws_host.ip_address,
        victim=dc_host.hostname,
        status="SUCCESS",
        logon_type=3
    ))
    current_time += timedelta(minutes=30)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=dc_host.hostname,
        ip_address=dc_host.ip_address,
        username="Administrator",
        attack_stage="Collection",
        scenario=scenario,
        mitre="T1114",
        attacker=f"{scenario}-Actor",
        victim=dc_host.hostname,
        command_line="ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\temp\\ntds\" q q"
    ))
    current_time += timedelta(minutes=10)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="NetworkConnection",
        host=dc_host.hostname,
        ip_address=dc_host.ip_address,
        username="Administrator",
        attack_stage="Exfiltration",
        scenario=scenario,
        mitre="T1048",
        attacker=dc_host.hostname,
        victim="203.0.113.50",
        destination_ip="203.0.113.50",
        destination_port=443,
        bytes_sent=45000000
    ))
    return events

# NEW ADVANCED ACTIVE DIRECTORY & IDENTITY ATTACKS

def simulate_kerberoasting(victim_emp: Employee, victim_host: Host, dc_host: Host, start_time: datetime, scenario: str = "FIN7") -> List[Dict[str, Any]]:
    """Simulates Kerberoasting attack (T1558.003 - requesting TGS tickets for offline cracking)."""
    events = []
    current_time = start_time
    
    # 1. SPN query (Discovery)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=victim_host.hostname,
        ip_address=victim_host.ip_address,
        username=victim_emp.username,
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1558.003",
        attacker=victim_host.hostname,
        victim=dc_host.hostname,
        command_line="setspn.exe -Q */*"
    ))
    
    # 2. TGS request log on Domain Controller
    current_time += timedelta(seconds=5)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="Authentication",
        host=dc_host.hostname,
        ip_address=dc_host.ip_address,
        username=victim_emp.username,
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1558.003",
        attacker=victim_host.ip_address,
        victim="Active Directory",
        ticket_options="0x40810000",
        ticket_encryption_type="0x17",  # RC4 (highly vulnerable to Kerberoasting)
        service_name="MSSQLSvc/sql-production.corp.local:1433"
    ))
    
    return events

def simulate_dcsync(victim_emp: Employee, dc_host: Host, start_time: datetime, scenario: str = "APT29") -> List[Dict[str, Any]]:
    """Simulates DCSync replication request to dump domain database (T1003.006)."""
    events = []
    current_time = start_time
    
    # 1. Mimikatz or DSInternals replication RPC call on DC
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host=dc_host.hostname,
        ip_address=dc_host.ip_address,
        username=victim_emp.username,
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1003.006",
        attacker="RemoteActor",
        victim=dc_host.hostname,
        command_line="mimikatz.exe \"lsadump::dcsync /domain:corp.local /user:krbtgt\" exit"
    ))
    
    # 2. Directory service replication audit event
    current_time += timedelta(seconds=1)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="Authentication",
        host=dc_host.hostname,
        ip_address=dc_host.ip_address,
        username=victim_emp.username,
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1003.006",
        attacker="DSReplicationAPI",
        victim="corp.local"
    ))
    return events

def simulate_mfa_fatigue(victim_emp: Employee, start_time: datetime, scenario: str = "Lapsus$") -> List[Dict[str, Any]]:
    """Simulates MFA fatigue / push bombing attack."""
    events = []
    current_time = start_time
    
    # Generate 15 pushes
    for i in range(15):
        current_time += timedelta(seconds=random.randint(2, 5))
        events.append(make_threat_event(
            timestamp=current_time,
            event_type="CloudAuthentication",
            host="Entra ID",
            ip_address="104.244.42.1",
            username=victim_emp.username,
            attack_stage="Credential Access",
            scenario=scenario,
            mitre="T1621", # Multi-Factor Authentication Request Generation
            attacker="198.51.100.45",
            victim=victim_emp.email,
            status="Push notification sent - ignored/denied"
        ))
        
    # Accept on 16th push
    current_time += timedelta(seconds=10)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="CloudAuthentication",
        host="Entra ID",
        ip_address="104.244.42.1",
        username=victim_emp.username,
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1621",
        attacker="198.51.100.45",
        victim=victim_emp.email,
        status="Push notification accepted (MFA fatigue successful)"
    ))
    return events

def simulate_cloud_breach(victim_emp: Employee, start_time: datetime, scenario: str = "APT29") -> List[Dict[str, Any]]:
    """Simulates cloud breach (Access Key Leak -> Privilege Escalation -> S3 Enumeration -> Exfiltration)."""
    events = []
    current_time = start_time
    
    # 1. AWS Access Key Leak
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="CloudAuthentication",
        host="AWS Console",
        ip_address="54.210.12.3",
        username=victim_emp.username,
        attack_stage="Initial Access",
        scenario=scenario,
        mitre="T1078",
        attacker="198.51.100.45",
        victim=victim_emp.username,
        status="Success (Access Key Leak)"
    ))
    
    # 2. AWS IAM Privilege Escalation
    current_time += timedelta(minutes=5)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="CloudIAMChange",
        host="AWS Console",
        ip_address="54.210.12.3",
        username=victim_emp.username,
        attack_stage="Privilege Escalation",
        scenario=scenario,
        mitre="T1078",
        attacker="198.51.100.45",
        victim="AWS IAM",
        target_user=victim_emp.username,
        policy="AdministratorAccess"
    ))
    
    # 3. S3 Bucket Enumeration
    current_time += timedelta(minutes=2)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="CloudStorageAccess",
        host="AWS S3",
        ip_address="54.210.12.3",
        username=victim_emp.username,
        attack_stage="Discovery",
        scenario=scenario,
        mitre="T1048",
        attacker="198.51.100.45",
        victim="s3://customer-db-backups",
        resource="s3://customer-db-backups/clients.sql"
    ))
    return events

def simulate_kubernetes_abuse(victim_emp: Employee, start_time: datetime, scenario: str = "CryptoCrew") -> List[Dict[str, Any]]:
    """Simulates Container Escape, Kube API Abuse, and Crypto Mining."""
    events = []
    current_time = start_time
    
    # 1. Container Escape (nsenter run)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host="Kube-Node-01",
        ip_address="10.244.0.5",
        username="root",
        attack_stage="Execution",
        scenario=scenario,
        mitre="T1611",  # Escape to Host
        attacker="PodShell",
        victim="Kube-Node-01",
        command_line="nsenter --mount=/proc/1/ns/mnt -- sh -c 'echo escaped'"
    ))
    
    # 2. Kube API Abuse (dump secrets)
    current_time += timedelta(seconds=15)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="NetworkConnection",
        host="Kube-Node-01",
        ip_address="10.244.0.5",
        username="root",
        attack_stage="Credential Access",
        scenario=scenario,
        mitre="T1611",
        attacker="10.244.0.5",
        victim="10.96.0.1",
        destination_ip="10.96.0.1",
        destination_port=443,
        protocol="TCP"
    ))
    
    # 3. Crypto miner launch
    current_time += timedelta(minutes=1)
    events.append(make_threat_event(
        timestamp=current_time,
        event_type="ProcessCreation",
        host="Kube-Node-01",
        ip_address="10.244.0.5",
        username="root",
        attack_stage="Impact",
        scenario=scenario,
        mitre="T1496",  # Resource Hijacking (Mining)
        attacker="escaped-shell",
        victim="Kube-Node-01",
        command_line="./xmrig -o pool.minexmr.com:443 -u 4ABc..."
    ))
    return events
