from typing import Dict, Any

def format_windows_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Converts a standard SOCForge event into a realistic Windows Event Log or Sysmon format."""
    event_type = event.get("event_type")
    
    # Base Windows XML / EVTX representation fields
    win_event = {
        "Source": "Microsoft-Windows-Security-Auditing" if "Sysmon" not in event_type else "Microsoft-Windows-Sysmon",
        "ProviderName": "Microsoft-Windows-Security-Auditing" if "Sysmon" not in event_type else "Microsoft-Windows-Sysmon",
        "Computer": event.get("host"),
        "TimeCreated": event.get("timestamp"),
        "Channel": "Security" if "Sysmon" not in event_type else "Microsoft-Windows-Sysmon/Operational",
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
        if event.get("status") == "SUCCESS":
            win_event.update({
                "EventID": 4624,
                "Description": "An account was successfully logged on.",
                "EventData": {
                    "TargetUserName": event.get("username"),
                    "TargetDomainName": "WORKGROUP" if "local" not in event.get("host") else "CORP",
                    "LogonType": event.get("logon_type", 3),
                    "IpAddress": event.get("source_ip", "127.0.0.1"),
                    "IpPort": "0"
                }
            })
        else: # FAILED
            win_event.update({
                "EventID": 4625,
                "Description": "An account failed to log on.",
                "EventData": {
                    "TargetUserName": event.get("username"),
                    "TargetDomainName": "CORP",
                    "LogonType": event.get("logon_type", 3),
                    "IpAddress": event.get("source_ip", "127.0.0.1"),
                    "Status": "0xC000006D",
                    "SubStatus": "0xC000006A"
                }
            })
            
    elif event_type == "ProcessCreation":
        cmd = event.get("command_line", "cmd.exe")
        binary_name = cmd.split(" ")[0].replace("\"", "")
        if not binary_name.lower().endswith(".exe"):
            binary_name += ".exe"
        if "\\" not in binary_name:
            image_path = f"C:\\Windows\\System32\\{binary_name}"
        else:
            image_path = binary_name

        win_event.update({
            "EventID": 1,
            "Source": "Microsoft-Windows-Sysmon",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Description": "Process Create",
            "EventData": {
                "UtcTime": event.get("timestamp"),
                "ProcessGuid": "{A2C21C30-D321-6B65-0000-0010DF6D2000}",
                "ProcessId": 4820,
                "Image": image_path,
                "CommandLine": cmd,
                "CurrentDirectory": "C:\\Windows\\system32\\",
                "User": f"CORP\\{event.get('username')}",
                "ParentProcessGuid": "{A2C21C30-D320-6B65-0000-0010C46D2000}",
                "ParentProcessId": 1024,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\explorer.exe"
            }
        })
        
    elif event_type == "FileAccess":
        # Sysmon Event ID 11 (FileCreated)
        win_event.update({
            "EventID": 11,
            "Source": "Microsoft-Windows-Sysmon",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Description": "File created",
            "EventData": {
                "UtcTime": event.get("timestamp"),
                "ProcessGuid": "{A2C21C30-D321-6B65-0000-0010DF6D2000}",
                "ProcessId": 4820,
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "TargetFilename": event.get("file_path"),
                "CreationUtcTime": event.get("timestamp")
            }
        })
        
    elif event_type == "RegistryModification":
        # Sysmon Event ID 13 (RegistryEvent - Value Set)
        win_event.update({
            "EventID": 13,
            "Source": "Microsoft-Windows-Sysmon",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Description": "Registry value set",
            "EventData": {
                "UtcTime": event.get("timestamp"),
                "EventType": "SetValue",
                "TargetObject": event.get("target_object", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"),
                "Details": event.get("details", "C:\\temp\\malware.exe")
            }
        })
        
    elif event_type == "ServiceCreation":
        # Windows System Event 7045 (New Service Created)
        win_event.update({
            "EventID": 7045,
            "Source": "Service Control Manager",
            "ProviderName": "Service Control Manager",
            "Channel": "System",
            "Description": "A service was installed in the system.",
            "EventData": {
                "ServiceName": event.get("service_name", "MaliciousService"),
                "ImagePath": event.get("image_path", "C:\\Windows\\System32\\cmd.exe /c C:\\temp\\payload.exe"),
                "ServiceType": "user start",
                "StartType": "demand start",
                "AccountName": "LocalSystem"
            }
        })
        
    else:
        # Default fallback
        win_event.update({
            "EventID": 9999,
            "Description": "Generic Windows Log",
            "EventData": event
        })
        
    return win_event
