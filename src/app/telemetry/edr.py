from typing import Dict, Any

def format_edr_event(event: Dict[str, Any], provider: str = "CrowdStrike") -> Dict[str, Any]:
    """Formats standard events into EDR-style telemetry logs resembling CrowdStrike Falcon or Defender."""
    event_type = event.get("event_type")
    
    edr_log = {
        "agent_provider": provider,
        "agent_id": f"aid-{hash(event.get('host', '')) % 1000000}",
        "computer_name": event.get("host"),
        "local_ip": event.get("ip_address"),
        "timestamp": event.get("timestamp"),
        "user_sid": f"S-1-5-21-{hash(event.get('username', '')) % 100000}",
        "user_name": event.get("username"),
        "ground_truth": event.get("ground_truth", False),
        "scenario": event.get("scenario"),
        "mitre": event.get("mitre"),
        "attack_stage": event.get("attack_stage")
    }

    if provider == "CrowdStrike":
        if event_type == "ProcessCreation":
            edr_log.update({
                "event_simpleName": "ProcessRollup2",
                "CommandLine": event.get("command_line", ""),
                "ImageFileName": event.get("process_name", "cmd.exe"),
                "ParentImageFileName": event.get("parent_process", "explorer.exe"),
                "SHA256HashData": f"{hash(event.get('command_line', '')) % 10**64:x}".zfill(64),
                "IntegrityLevel": "SYSTEM" if event.get("username") == "SYSTEM" else "High"
            })
        elif event_type == "NetworkConnection":
            edr_log.update({
                "event_simpleName": "NetworkConnectIP4",
                "RemoteIP": event.get("destination_ip"),
                "RemotePort": event.get("destination_port"),
                "Protocol": event.get("protocol", "TCP"),
                "ConnectionDirection": "Outbound"
            })
        else:
            edr_log.update({
                "event_simpleName": "SyntheticAgentAudit",
                "Message": f"Behavior audit: {event_type} on host"
            })
            
    else: # Microsoft Defender for Endpoint
        if event_type == "ProcessCreation":
            edr_log.update({
                "ActionType": "AntivirusDetectionEvent" if event.get("ground_truth") else "ProcessCreated",
                "FileName": event.get("process_name", "cmd.exe"),
                "ProcessCommandLine": event.get("command_line", ""),
                "InitiatingProcessFileName": event.get("parent_process", "explorer.exe"),
                "InitiatingProcessCommandLine": "C:\\Windows\\explorer.exe"
            })
        elif event_type == "NetworkConnection":
            edr_log.update({
                "ActionType": "NetworkConnectionInitiated",
                "RemoteIP": event.get("destination_ip"),
                "RemotePort": event.get("destination_port"),
                "Protocol": event.get("protocol", "TCP")
            })
        else:
            edr_log.update({
                "ActionType": "DeviceEvents",
                "AdditionalFields": event
            })

    return edr_log
