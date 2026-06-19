import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from src.app.db.models import Company, Employee, Host
from src.app.core.business_simulator import generate_normal_event
from src.app.core.threat_engine import (
    simulate_brute_force, simulate_phishing, simulate_persistence,
    simulate_privilege_escalation, simulate_lateral_movement,
    simulate_insider_threat, simulate_ransomware, simulate_apt_campaign,
    simulate_kerberoasting, simulate_dcsync, simulate_mfa_fatigue,
    simulate_cloud_breach, simulate_kubernetes_abuse
)

def generate_timeline(
    db: Session,
    company: Company,
    scenario_name: str,
    duration_hours: int = 24
) -> Dict[str, Any]:
    """Generates a complete chronological baseline + threat simulation timeline."""
    
    start_time = datetime.now() - timedelta(hours=duration_hours)
    events = []
    
    # 1. Fetch Company Employees & Hosts
    employees = db.query(Employee).join(Employee.department).filter(Employee.department.has(company_id=company.id)).all()
    hosts = db.query(Host).filter(Host.company_id == company.id).all()
    
    if not employees or not hosts:
        raise ValueError("Company environment must be initialized with employees and hosts first.")
        
    # Divide hosts by OS
    win_hosts = [h for h in hosts if h.os_type == "Windows"]
    lin_hosts = [h for h in hosts if h.os_type == "Linux"]
    dc_host = next((h for h in hosts if h.role == "DomainController"), hosts[0])
    
    # 2. Generate baseline events over the duration
    current_time = start_time
    time_step_seconds = 30  # evaluate events every 30 seconds
    
    # Scale log generation volume dynamically by employee count.
    # Target: ~120 events per employee over 24 hours (~5 events/employee/hour).
    # Since each step is 30 seconds (120 steps/hour), rate per employee per step is 5 / 120 = 0.0416.
    events_per_step_rate = len(employees) * 0.0416
    
    while current_time < datetime.now():
        num_events = int(events_per_step_rate)
        if random.random() < (events_per_step_rate - num_events):
            num_events += 1
            
        for _ in range(num_events):
            emp = random.choice(employees)
            hst = random.choice(hosts)
            norm_event = generate_normal_event(emp, hst, current_time)
            if norm_event:
                events.append(norm_event)
                
        current_time += timedelta(seconds=time_step_seconds)
        
    # 3. Inject Threat Scenario Events at specific points in the timeline
    threat_start_time = start_time + timedelta(hours=duration_hours // 2)
    threat_events = []
    
    # Select threat targets
    target_emp = random.choice(employees)
    target_host = next((h for h in win_hosts if h.role == "Workstation"), hosts[0])
    
    if scenario_name == "Brute Force":
        threat_events = simulate_brute_force("198.51.100.45", target_emp, target_host, threat_start_time)
    elif scenario_name == "Phishing":
        threat_events = simulate_phishing("account-billing-alert.com", target_emp, target_host, threat_start_time)
    elif scenario_name == "Persistence":
        threat_events = simulate_persistence(target_emp, target_host, threat_start_time)
    elif scenario_name == "Privilege Escalation":
        threat_events = simulate_privilege_escalation(target_emp, target_host, threat_start_time)
    elif scenario_name == "Lateral Movement":
        dest_host = next((h for h in win_hosts if h.hostname != target_host.hostname), hosts[0])
        threat_events = simulate_lateral_movement(target_emp, target_host, dest_host, threat_start_time)
    elif scenario_name == "Insider Threat":
        threat_events = simulate_insider_threat(target_emp, target_host, threat_start_time)
    elif scenario_name == "Ransomware":
        threat_events = simulate_ransomware(target_emp, target_host, threat_start_time)
    elif scenario_name == "APT Campaign":
        threat_events = simulate_apt_campaign(target_emp, target_host, dc_host, threat_start_time)
    elif scenario_name == "Kerberoasting":
        threat_events = simulate_kerberoasting(target_emp, target_host, dc_host, threat_start_time)
    elif scenario_name == "DCSync":
        threat_events = simulate_dcsync(target_emp, dc_host, threat_start_time)
    elif scenario_name == "MFA Fatigue":
        threat_events = simulate_mfa_fatigue(target_emp, threat_start_time)
    elif scenario_name == "Cloud Breach":
        threat_events = simulate_cloud_breach(target_emp, threat_start_time)
    elif scenario_name == "Kubernetes Abuse":
        threat_events = simulate_kubernetes_abuse(target_emp, threat_start_time)
        
    events.extend(threat_events)
    
    # 4. Sort all events chronologically
    events.sort(key=lambda x: x["timestamp"])
    
    return {
        "scenario": scenario_name,
        "duration_hours": duration_hours,
        "total_events": len(events),
        "events": events
    }
