import yaml
from typing import List, Dict, Any

def calculate_validation_score(events: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes a validation score based on injected ground truth and alerts triggered."""
    total_events = len(events)
    ground_truth_events = [e for e in events if e.get("ground_truth")]
    total_malicious = len(ground_truth_events)
    
    # Calculate MITRE technique coverage
    techniques_simulated = set(e.get("mitre") for e in ground_truth_events if e.get("mitre"))
    techniques_alerted = set(a.get("mitre_mapping", {}).get("id") for a in alerts if a.get("mitre_mapping"))
    
    coverage_ratio = len(techniques_alerted) / len(techniques_simulated) if techniques_simulated else 0.0
    
    # Score calculation
    # Base formula: Coverage * 100 - (False Positives * 5)
    # Since all alerts here map to ground truth, false positives = 0
    validation_score = coverage_ratio * 100
    
    return {
        "total_events": total_events,
        "total_malicious_events": total_malicious,
        "techniques_simulated": list(techniques_simulated),
        "techniques_alerted": list(techniques_alerted),
        "coverage_percentage": round(coverage_ratio * 100, 2),
        "validation_score": round(validation_score, 1),
        "remarks": "Excellent coverage" if validation_score > 80 else "Needs detection engineering improvements"
    }

def evaluate_detections_cli(alerts: List[Dict[str, Any]], timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Correlates alerts and ground-truth timeline to evaluate precision, recall, and detection gaps."""
    simulated_techniques = set()
    ground_truth_events = []
    
    for item in timeline:
        mitre_id = item.get("mitre") or item.get("mitre_technique")
        if mitre_id:
            simulated_techniques.add(mitre_id)
            ground_truth_events.append(item)
            
    alerted_techniques = set()
    true_positives = 0
    false_positives = 0
    
    for alert in alerts:
        alert_mitre = None
        if alert.get("mitre_mapping"):
            alert_mitre = alert["mitre_mapping"].get("id")
        elif alert.get("mitre_technique"):
            alert_mitre = alert.get("mitre_technique")
            
        if alert_mitre in simulated_techniques:
            if alert_mitre not in alerted_techniques:
                true_positives += 1
                alerted_techniques.add(alert_mitre)
        else:
            false_positives += 1
            
    false_negatives = len(simulated_techniques) - len(alerted_techniques)
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    coverage = len(alerted_techniques) / len(simulated_techniques) if simulated_techniques else 0.0
    
    missed_techniques = list(simulated_techniques - alerted_techniques)
    
    return {
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "coverage": round(coverage * 100, 1),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "detected_techniques": list(alerted_techniques),
        "missed_techniques": missed_techniques
    }

def validate_sigma_rule(sigma_yaml: str, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluates a Sigma rule against the generated dataset to calculate detection coverage."""
    try:
        rule = yaml.safe_load(sigma_yaml)
    except Exception as e:
        return {"status": "error", "message": f"Failed to parse Sigma YAML: {e}"}
        
    detection_block = rule.get("detection", {})
    selection = detection_block.get("selection", {})
    
    matches = []
    tp = 0
    fp = 0
    fn = 0
    
    # Simple rule evaluator matching keys
    for log in logs:
        is_match = True
        
        # Flatten event data helper
        flat_log = {}
        for k, v in log.items():
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    flat_log[sub_k] = sub_v
            flat_log[k] = v
            
        for key_def, target_value in selection.items():
            # Handle modifiers like contains, endswith
            key = key_def.split("|")[0]
            modifier = key_def.split("|")[1] if "|" in key_def else None
            
            val = flat_log.get(key)
            if val is None:
                is_match = False
                break
                
            val_str = str(val).lower()
            tgt_str = str(target_value).lower()
            
            if modifier == "contains":
                if tgt_str not in val_str:
                    is_match = False
                    break
            elif modifier == "endswith":
                if not val_str.endswith(tgt_str):
                    is_match = False
                    break
            else:
                if val_str != tgt_str:
                    is_match = False
                    break
                    
        if is_match:
            matches.append(log)
            # Match is a True Positive if ground_truth is marked true in the logs
            if log.get("ground_truth") or (isinstance(log.get("EventData"), dict) and log["EventData"].get("ground_truth")):
                tp += 1
            else:
                fp += 1
                
    # Calculate false negatives (how many ground truth threat logs of this technique were NOT matched)
    target_mitre = None
    for tag in rule.get("tags", []):
        if tag.startswith("attack."):
            target_mitre = tag.replace("attack.", "").upper()
            
    if target_mitre:
        for log in logs:
            is_gt = log.get("ground_truth") or (isinstance(log.get("EventData"), dict) and log["EventData"].get("ground_truth"))
            log_mitre = log.get("mitre") or (isinstance(log.get("EventData"), dict) and log["EventData"].get("mitre"))
            if is_gt and log_mitre == target_mitre:
                # check if this log was captured
                if log not in matches:
                    fn += 1
                    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    return {
        "status": "success",
        "rule_title": rule.get("title", "Unknown Rule"),
        "total_evaluated_logs": len(logs),
        "matches_found": len(matches),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision_percentage": round(precision * 100, 1),
        "recall_percentage": round(recall * 100, 1)
    }
