from typing import Dict, Any

SIGMA_TEMPLATES = {
    "T1110": """title: Brute Force Authentication Attempt
id: 5b6c3d9a-a82f-412e-b6a3-678a10dfb398
status: experimental
description: Detects multiple failed authentication attempts followed by a successful login.
logsource:
    product: windows
    service: security
detection:
    selection_fail:
        EventID: 4625
    selection_success:
        EventID: 4624
    timeframe: 10m
    condition: selection_fail | count() > 10 followed_by selection_success
falsepositives:
    - Administrator scripting or misconfiguration
level: high""",

    "T1053": """title: Scheduled Task Creation for Persistence
id: c48dfa20-410a-4b6a-9cd4-3c6d2df20002
status: experimental
description: Detects creation of scheduled tasks for persistent execution of commands.
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine|contains: 'schtasks /create'
    condition: selection
falsepositives:
    - Normal deployment scripts
level: medium""",

    "T1486": """title: Volume Shadow Copy Deletion via VSSAdmin
id: 8db2a192-3c22-4919-86bd-90cdd90030a1
status: active
description: Detects the deletion of volume shadow copies which is highly indicative of ransomware operations.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains: 'delete shadows'
    condition: selection
falsepositives:
    - Legitimate system administration backup scripts
level: critical"""
}

def get_rules_for_scenario(technique_id: str) -> Dict[str, str]:
    """Returns detection logic in Sigma, Wazuh, and Splunk formats."""
    sigma = SIGMA_TEMPLATES.get(technique_id, "# No Sigma rule template defined for this technique.")
    
    # Generic mapping
    wazuh = f"""<group name="socforge,">{chr(10)}  <rule id="100100" level="10">{chr(10)}    <decoded_as>json</decoded_as>{chr(10)}    <field name="mitre">{technique_id}</field>{chr(10)}    <description>SOCForge simulated attack technique {technique_id} detected</description>{chr(10)}  </rule>{chr(10)}</group>"""
    
    splunk = f"index=security mitre=\"{technique_id}\" | stats count by host, username"
    
    return {
        "sigma": sigma,
        "wazuh": wazuh,
        "splunk": splunk
    }
