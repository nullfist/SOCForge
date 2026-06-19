import os
import sys
import json
import yaml
import time
import argparse
import tracemalloc
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from src.app.db.session import engine, SessionLocal, Base
from src.app.core.environment_generator import generate_company_environment
from src.app.core.timeline_engine import generate_timeline
from src.app.telemetry.windows import format_windows_event
from src.app.telemetry.linux import format_linux_event
from src.app.telemetry.network import format_network_event
from src.app.telemetry.cloud import format_cloud_event
from src.app.alert.generator import generate_alerts_from_events, generate_analyst_cases, generate_incident_report
from src.app.mitre.mapping import MITRE_ATTACK_DB, generate_navigator_layer
from src.app.detection.validation import evaluate_detections_cli, validate_sigma_rule

Base.metadata.create_all(bind=engine)

def generate_demo():
    print("[*] Initializing Demo Workspace...")
    db = SessionLocal()
    os.makedirs("demo", exist_ok=True)
    
    print("[*] Generating company 'FinanceCorp' (250 users, 120 endpoints topology simulation)...")
    company = generate_company_environment(db, "FinanceCorp", "Finance", "large")
    
    print("[*] Compiling 7-day attack timeline (Phishing -> PrivEsc -> Lateral Movement -> Ransomware)...")
    dataset = generate_timeline(db, company, "APT Campaign", 168)
    
    events = dataset["events"]
    print(f"[+] Total generated logs: {len(events)}")
    
    print("[*] Formatting and exporting telemetry to demo/logs.ndjson...")
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
            
    with open("demo/logs.ndjson", "w") as f:
        for fmt_e in formatted_events:
            f.write(json.dumps(fmt_e) + "\n")
            
    print("[*] Triggering Alert Framework and saving to demo/alerts.json...")
    alerts = generate_alerts_from_events(events)
    with open("demo/alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
        
    print("[*] Creating high-level timeline narrative in demo/timeline.json...")
    timeline_narrative = []
    for e in events:
        if e.get("ground_truth"):
            timeline_narrative.append({
                "timestamp": e.get("timestamp"),
                "host": e.get("host"),
                "username": e.get("username"),
                "action": e.get("event_type"),
                "mitre_technique": e.get("mitre"),
                "scenario": e.get("scenario")
            })
    with open("demo/timeline.json", "w") as f:
        json.dump(timeline_narrative, f, indent=2)
        
    print("[*] Generating MITRE ATT&CK coverage heatmap mapping to demo/mitre.json...")
    with open("demo/mitre.json", "w") as f:
        json.dump(MITRE_ATTACK_DB, f, indent=2)

    print("[*] Generating MITRE ATT&CK Navigator layer to demo/navigator_layer.json...")
    simulated_techs = list(set(e.get("mitre") for e in events if e.get("mitre")))
    alerted_techs = list(set(a.get("mitre_mapping", {}).get("id") for a in alerts if a.get("mitre_mapping")))
    nav_layer = generate_navigator_layer(simulated_techs, alerted_techs)
    with open("demo/navigator_layer.json", "w") as f:
        json.dump(nav_layer, f, indent=2)
        
    print("[*] Creating SOC Analyst training scenarios in demo/cases.json...")
    cases = generate_analyst_cases(events)
    with open("demo/cases.json", "w") as f:
        json.dump(cases, f, indent=2)

    print("[*] Evaluating detection performance and exporting to demo/evaluation.json...")
    eval_report = evaluate_detections_cli(alerts, timeline_narrative)
    with open("demo/evaluation.json", "w") as f:
        json.dump(eval_report, f, indent=2)

    print("[*] Generating Incident Response & Evidence Package to demo/incident_report.md...")
    report_md = generate_incident_report(events, alerts)
    with open("demo/incident_report.md", "w") as f:
        f.write(report_md)
        
    db.close()
    print("[+] Demo generation complete! All assets saved under the 'demo/' directory.")

def replay_logs(filepath: str, speed: float):
    if not os.path.exists(filepath):
        print(f"[-] Error: Log file '{filepath}' not found.")
        sys.exit(1)
        
    print(f"[*] Replaying '{filepath}' at {speed}x speed...")
    
    with open(filepath, "r") as f:
        last_time = None
        for line in f:
            log = json.loads(line.strip())
            log_time_str = log.get("TimeCreated") or log.get("timestamp") or log.get("event_time")
            
            if log_time_str:
                clean_time_str = log_time_str.split(".")[0].replace("Z", "")
                try:
                    current_time = datetime.strptime(clean_time_str, "%Y-%m-%dT%H:%M:%S")
                    if last_time:
                        delta = (current_time - last_time).total_seconds()
                        if delta > 0:
                            time.sleep(delta / speed)
                    last_time = current_time
                except Exception:
                    pass
            print(json.dumps(log))

def run_scenario(yaml_path: str):
    if not os.path.exists(yaml_path):
        print(f"[-] Error: Scenario file '{yaml_path}' not found.")
        sys.exit(1)
        
    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)
        
    print(f"[*] Compiling custom scenario '{config.get('name')}'...")
    db = SessionLocal()
    
    comp_cfg = config.get("company", {})
    print(f"[*] Bootstrapping custom company '{comp_cfg.get('name')}'...")
    company = generate_company_environment(
        db, 
        comp_cfg.get("name", "CustomCorp"), 
        comp_cfg.get("industry", "Technology"), 
        comp_cfg.get("size", "medium")
    )
    
    duration = config.get("duration_hours", 24)
    output_dir = config.get("output_dir", "output")
    os.makedirs(output_dir, exist_ok=True)
    
    all_events = []
    steps = config.get("steps", ["APT Campaign"])
    
    for step in steps:
        print(f"[*] Executing simulation stage: {step}...")
        dataset = generate_timeline(db, company, step, duration)
        all_events.extend(dataset["events"])
        
    all_events.sort(key=lambda x: x["timestamp"])
    
    formatted = []
    for e in all_events:
        if e.get("os_type") == "Windows":
            formatted.append(format_windows_event(e))
        elif e.get("os_type") == "Linux":
            formatted.append(format_linux_event(e))
        elif e.get("event_type") in ["ProxyAccess", "NetworkConnection", "VPNConnection", "DNSQuery", "IDSAlert"]:
            formatted.append(format_network_event(e))
        else:
            formatted.append(format_cloud_event(e))
            
    log_file = os.path.join(output_dir, "scenario_logs.ndjson")
    with open(log_file, "w") as f:
        for fmt_e in formatted:
            f.write(json.dumps(fmt_e) + "\n")
            
    print(f"[+] Scenario execution successful! Generated {len(formatted)} events.")
    print(f"[+] Telemetry saved to: {log_file}")
    db.close()

def evaluate_files(alerts_path: str, timeline_path: str):
    if not os.path.exists(alerts_path) or not os.path.exists(timeline_path):
        print("[-] Error: Alerts file or Timeline file not found.")
        sys.exit(1)
        
    with open(alerts_path, "r") as f:
        alerts = json.load(f)
    with open(timeline_path, "r") as f:
        timeline = json.load(f)
        
    report = evaluate_detections_cli(alerts, timeline)
    
    print("\n" + "="*40)
    print("      SOCFORGE DETECTION EVALUATION")
    print("="*40)
    print(f"Precision:         {report['precision']}%")
    print(f"Recall:            {report['recall']}%")
    print(f"Coverage:          {report['coverage']}%")
    print(f"True Positives:    {report['true_positives']}")
    print(f"False Positives:   {report['false_positives']}")
    print(f"False Negatives:   {report['false_negatives']}")
    print("\nDetected Techniques:")
    for t in report['detected_techniques']:
        print(f"  [+] {t}")
    print("\nMissed Techniques:")
    for t in report['missed_techniques']:
        print(f"  [-] {t}")
    print("="*40 + "\n")

def evaluate_custom_sigma(sigma_path: str, logs_path: str):
    if not os.path.exists(sigma_path) or not os.path.exists(logs_path):
        print("[-] Error: Sigma rule file or NDJSON logs file not found.")
        sys.exit(1)
        
    with open(sigma_path, "r") as f:
        sigma_content = f.read()
        
    logs = []
    with open(logs_path, "r") as f:
        for line in f:
            if line.strip():
                logs.append(json.loads(line.strip()))
                
    result = validate_sigma_rule(sigma_content, logs)
    
    if result["status"] == "error":
        print(f"[-] Error: {result['message']}")
        return
        
    print("\n" + "="*45)
    print("      DETECTION-AS-CODE: SIGMA EVALUATION")
    print("="*45)
    print(f"Rule Title:       {result['rule_title']}")
    print(f"Evaluated Logs:   {result['total_evaluated_logs']}")
    print(f"Matches Found:    {result['matches_found']}")
    print(f"True Positives:   {result['true_positives']}")
    print(f"False Positives:  {result['false_positives']}")
    print(f"False Negatives:  {result['false_negatives']}")
    print(f"Precision Score:  {result['precision_percentage']}%")
    print(f"Recall Score:     {result['recall_percentage']}%")
    print("="*45 + "\n")

def generate_custom_report(logs_path: str, alerts_path: str, output_md_path: str):
    if not os.path.exists(logs_path) or not os.path.exists(alerts_path):
        print("[-] Error: Logs file or Alerts file not found.")
        sys.exit(1)
        
    logs = []
    with open(logs_path, "r") as f:
        for line in f:
            if line.strip():
                logs.append(json.loads(line.strip()))
                
    with open(alerts_path, "r") as f:
        alerts = json.load(f)
        
    report = generate_incident_report(logs, alerts)
    with open(output_md_path, "w") as f:
        f.write(report)
        
    print(f"[+] Incident report successfully written to: {output_md_path}")

def run_performance_benchmark():
    print("\n" + "="*50)
    print("     SOCFORGE PERFORMANCE BENCHMARK SUITE")
    print("="*50)
    import psutil
    db = SessionLocal()
    
    user_scales = [100, 1000, 5000, 10000]
    for num_users in user_scales:
        tracemalloc.start()
        start_time = time.time()
        
        # Track CPU times
        proc = psutil.Process(os.getpid())
        cpu_start = proc.cpu_times()
        
        # 1. Bootstrapping Company Environment
        # Host count scales proportionally (approx 80% of user count)
        num_hosts = int(num_users * 0.8)
        company = generate_company_environment(
            db, 
            company_name=f"Bench-{num_users}", 
            industry="Finance", 
            size="custom",
            num_employees=num_users,
            num_hosts=num_hosts
        )
        
        # 2. Timelined Campaign Compilation (24 hours)
        dataset = generate_timeline(db, company, "APT Campaign", 24)
        events = dataset["events"]
        
        end_time = time.time()
        cpu_end = proc.cpu_times()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        elapsed = end_time - start_time
        peak_mb = peak / (1024 * 1024)
        
        cpu_time_spent = (cpu_end.user - cpu_start.user) + (cpu_end.system - cpu_start.system)
        cpu_percentage = (cpu_time_spent / elapsed) * 100 if elapsed > 0 else 0.0
        
        print(f"Users:      {num_users}")
        print(f"Hosts:      {num_hosts}")
        print(f"Events:     {len(events)}")
        print(f"Time:       {elapsed:.2f} seconds")
        print(f"RAM Peak:   {peak_mb:.2f} MB")
        print(f"CPU Usage:  {cpu_percentage:.1f}%")
        print(f"Throughput: {len(events)/elapsed:.1f} events/sec")
        print("-"*50)
        
    db.close()
    print("="*50 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCForge Cyber Range Command-line Interface")
    subparsers = parser.add_subparsers(dest="command")
    
    subparsers.add_parser("generate-demo", help="Generate a pre-packaged 7-day showcase enterprise attack timeline")
    subparsers.add_parser("benchmark", help="Execute scalability and throughput performance benchmarks")
    
    replay_parser = subparsers.add_parser("replay", help="Replay a generated NDJSON log dataset dynamically")
    replay_parser.add_argument("file", type=str, help="Path to NDJSON log file")
    replay_parser.add_argument("--speed", type=float, default=100.0, help="Replay speed multiplier (default: 100.0)")
    
    scenario_parser = subparsers.add_parser("run-scenario", help="Compile and execute a scenario from a YAML configuration")
    scenario_parser.add_argument("yaml_file", type=str, help="Path to scenario YAML configuration")
    
    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate detection precision and recall mapping metrics")
    evaluate_parser.add_argument("alerts_file", type=str, help="Path to triggered alerts JSON file")
    evaluate_parser.add_argument("timeline_file", type=str, help="Path to simulation ground truth timeline JSON file")

    sigma_parser = subparsers.add_parser("evaluate-sigma", help="Evaluate custom Sigma detection rule against generated logs")
    sigma_parser.add_argument("sigma_file", type=str, help="Path to Sigma YAML rule file")
    sigma_parser.add_argument("logs_file", type=str, help="Path to NDJSON logs file")
    
    report_parser = subparsers.add_parser("generate-report", help="Compile simulation logs into a structured forensic incident report")
    report_parser.add_argument("logs_file", type=str, help="Path to NDJSON logs file")
    report_parser.add_argument("alerts_file", type=str, help="Path to alerts JSON file")
    report_parser.add_argument("output_file", type=str, help="Path to output markdown report file")
    
    args = parser.parse_args()
    
    if args.command == "generate-demo":
        generate_demo()
    elif args.command == "benchmark":
        run_performance_benchmark()
    elif args.command == "replay":
        replay_logs(args.file, args.speed)
    elif args.command == "run-scenario":
        run_scenario(args.yaml_file)
    elif args.command == "evaluate":
        evaluate_files(args.alerts_file, args.timeline_file)
    elif args.command == "evaluate-sigma":
        evaluate_custom_sigma(args.sigma_file, args.logs_file)
    elif args.command == "generate-report":
        generate_custom_report(args.logs_file, args.alerts_file, args.output_file)
    else:
        parser.print_help()
