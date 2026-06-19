from typing import Dict, Any

def format_linux_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Formats standard SOCForge events into syslog or auth.log format."""
    event_type = event.get("event_type")
    timestamp = event.get("timestamp")
    host = event.get("host")
    username = event.get("username")
    
    linux_event = {
        "log_source": "syslog",
        "Computer": host,
        "TimeCreated": timestamp,
        "event_id": event.get("event_id"),
        "ground_truth": event.get("ground_truth", False),
        "attack_stage": event.get("attack_stage"),
        "scenario": event.get("scenario"),
        "mitre": event.get("mitre"),
        "attacker": event.get("attacker"),
        "victim": event.get("victim"),
        "confidence": event.get("confidence")
    }

    if event_type == "Authentication":
        status = event.get("status")
        source_ip = event.get("source_ip", "192.168.1.1")
        if status == "SUCCESS":
            message = f"sshd[4102]: Accepted publickey for {username} from {source_ip} port {random_port()} ssh2"
        else:
            message = f"sshd[4102]: Failed password for invalid user {username} from {source_ip} port {random_port()} ssh2"
        
        linux_event.update({
            "log_source": "auth.log",
            "message": f"{timestamp} {host} {message}"
        })
        
    elif event_type == "SudoExecution":
        command = event.get("command_line", "apt-get update")
        linux_event.update({
            "log_source": "auth.log",
            "message": f"{timestamp} {host} sudo:   {username} : TTY=pts/0 ; PWD=/home/{username} ; USER=root ; COMMAND={command}"
        })
        
    elif event_type == "CronExecution":
        job = event.get("job_command", "/usr/local/bin/backup.sh")
        linux_event.update({
            "log_source": "syslog",
            "message": f"{timestamp} {host} CRON[1245]: (root) CMD ({job})"
        })
        
    elif event_type == "PackageInstall":
        package = event.get("package_name", "curl")
        linux_event.update({
            "log_source": "dpkg.log",
            "message": f"{timestamp} install {package}:amd64 <none> 7.81.0-1ubuntu1"
        })
        
    else:
        # Default Syslog output
        linux_event.update({
            "log_source": "syslog",
            "message": f"{timestamp} {host} systemd[1]: Started SOCForge Simulated Activity."
        })
        
    return linux_event

def random_port() -> int:
    import random
    return random.randint(49152, 65535)
