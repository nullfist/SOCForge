from typing import Dict, Any

def format_network_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Formats standard network events into firewall, DNS, web proxy, or VPN log schemas."""
    event_type = event.get("event_type")
    
    net_log = {
        "log_source": "network_gateway",
        "timestamp": event.get("timestamp"),
        "host": event.get("host"),
        "source_ip": event.get("ip_address"),
        "event_id": event.get("event_id"),
        "ground_truth": event.get("ground_truth", False),
        "attack_stage": event.get("attack_stage"),
        "scenario": event.get("scenario"),
        "mitre": event.get("mitre"),
        "attacker": event.get("attacker"),
        "victim": event.get("victim"),
        "confidence": event.get("confidence")
    }

    if event_type == "DNSQuery":
        net_log.update({
            "log_source": "dns_server",
            "query": event.get("query"),
            "record_type": event.get("record_type", "A"),
            "resolved_ip": event.get("resolved_ip", "0.0.0.0"),
            "response_code": "NOERROR" if event.get("resolved_ip") else "NXDOMAIN"
        })
        
    elif event_type == "NetworkConnection":
        net_log.update({
            "log_source": "firewall",
            "destination_ip": event.get("destination_ip"),
            "destination_port": event.get("destination_port"),
            "protocol": event.get("protocol", "TCP"),
            "action": "ALLOW" if event.get("destination_port") in [80, 443] else "DENY",
            "bytes_sent": event.get("bytes_sent", 1024),
            "bytes_received": event.get("bytes_received", 4096)
        })
        
    elif event_type == "ProxyAccess":
        net_log.update({
            "log_source": "web_proxy",
            "request_method": event.get("method", "GET"),
            "url": event.get("url", "https://google.com"),
            "user_agent": event.get("user_agent", "Mozilla/5.0"),
            "status_code": event.get("status_code", 200)
        })
        
    elif event_type == "VPNConnection":
        net_log.update({
            "log_source": "vpn_gateway",
            "action": event.get("action", "Connect"),
            "client_ip": event.get("client_ip"),
            "user": event.get("username"),
            "duration_seconds": event.get("duration", 3600)
        })
        
    elif event_type == "IDSAlert":
        net_log.update({
            "log_source": "ids_suricata",
            "signature_id": event.get("signature_id", 2000001),
            "signature_name": event.get("signature_name", "ET TROJAN Malicious Callback Detected"),
            "severity": event.get("severity", "High"),
            "category": event.get("category", "Trojan Activity")
        })

    return net_log
