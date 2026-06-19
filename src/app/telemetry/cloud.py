from typing import Dict, Any

def format_cloud_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Formats standard events into AWS CloudTrail or Azure Entra ID log standards."""
    event_type = event.get("event_type")
    
    cloud_log = {
        "log_source": "aws_cloudtrail" if "aws" in event.get("host", "").lower() else "azure_entra_id",
        "event_time": event.get("timestamp"),
        "user_identity": event.get("username"),
        "event_id": event.get("event_id"),
        "ground_truth": event.get("ground_truth", False),
        "attack_stage": event.get("attack_stage"),
        "scenario": event.get("scenario"),
        "mitre": event.get("mitre"),
        "attacker": event.get("attacker"),
        "victim": event.get("victim"),
        "confidence": event.get("confidence")
    }

    if event_type == "CloudAuthentication":
        cloud_log.update({
            "event_source": "signin.microsoft.com" if "azure" in cloud_log["log_source"] else "signin.aws.amazon.com",
            "event_name": "UserLogin",
            "source_ip": event.get("source_ip", "104.244.42.1"),
            "status": event.get("status", "Success"),
            "mfa_used": event.get("mfa_used", True)
        })
        
    elif event_type == "CloudStorageAccess":
        cloud_log.update({
            "event_source": "s3.amazonaws.com" if "aws" in cloud_log["log_source"] else "sharepoint.com",
            "event_name": "GetObject" if "aws" in cloud_log["log_source"] else "FileDownloaded",
            "resource_name": event.get("resource", "s3://company-financials/q4_results.xlsx"),
            "source_ip": event.get("source_ip", "192.168.1.10")
        })
        
    elif event_type == "CloudIAMChange":
        cloud_log.update({
            "event_source": "iam.amazonaws.com" if "aws" in cloud_log["log_source"] else "graph.microsoft.com",
            "event_name": "CreateAccessKey" if "aws" in cloud_log["log_source"] else "AddMemberToGroup",
            "target_user": event.get("target_user", "system-admin-temp"),
            "policy_or_group": event.get("policy", "AdministratorAccess")
        })

    return cloud_log
