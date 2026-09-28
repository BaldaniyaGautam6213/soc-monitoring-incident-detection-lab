"""
mitre_mapper.py — MITRE ATT&CK technique mapper for SOC Lab
Maps alert data to ATT&CK techniques and generates heatmap data.
"""

import json
from pathlib import Path
from typing import Dict, Any, List

BASE_DIR   = Path(__file__).parent
MITRE_FILE = BASE_DIR / "data" / "mitre_attack.json"


def load_mitre_db() -> Dict:
    with open(MITRE_FILE) as f:
        return json.load(f)


def get_technique(technique_id: str) -> Dict[str, Any]:
    """Get full MITRE technique details by ID."""
    db = load_mitre_db()
    return db["techniques"].get(technique_id, {})


def get_all_tactics() -> Dict[str, str]:
    """Return all MITRE tactics."""
    db = load_mitre_db()
    return db["tactics"]


def map_alert_to_technique(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert with full MITRE ATT&CK context.
    Returns the technique details, tactic, detection advice, and remediation.
    """
    technique_id = alert.get("mitre_technique", "")
    technique    = get_technique(technique_id)

    if not technique:
        return {
            "technique_id":   technique_id,
            "technique_name": "Unknown",
            "tactic":         alert.get("mitre_tactic", "Unknown"),
            "description":    "No ATT&CK mapping found",
            "detection":      "Review logs manually",
            "remediation":    [],
            "severity":       alert.get("severity", "Medium"),
            "mitre_url":      "",
        }

    return {
        "technique_id":   technique["id"],
        "technique_name": technique["name"],
        "tactic":         technique["tactic"],
        "tactic_id":      technique["tactic_id"],
        "description":    technique["description"],
        "detection":      technique["detection"],
        "remediation":    technique["remediation"],
        "severity":       technique["severity"],
        "platforms":      technique.get("platforms", []),
        "data_sources":   technique.get("data_sources", []),
        "mitre_url":      f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
    }


def generate_heatmap_data(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Generate MITRE ATT&CK heatmap data from a list of alerts.
    Returns per-technique detection counts organized by tactic.
    """
    db = load_mitre_db()
    all_techniques = db["techniques"]
    all_tactics    = db["tactics"]

    # Count detections per technique
    detection_counts = {}
    for alert in alerts:
        tid = alert.get("mitre_technique", "")
        if tid:
            detection_counts[tid] = detection_counts.get(tid, 0) + 1

    # Build heatmap entries
    heatmap = []
    for tid, technique in all_techniques.items():
        count = detection_counts.get(tid, 0)
        heatmap.append({
            "technique_id":   technique["id"],
            "technique_name": technique["name"],
            "tactic":         technique["tactic"],
            "tactic_id":      technique["tactic_id"],
            "detection_count": count,
            "severity":       technique["severity"],
            "heat_level":     _heat_level(count),
            "mitre_url":      f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
        })

    return sorted(heatmap, key=lambda x: -x["detection_count"])


def _heat_level(count: int) -> str:
    """Convert detection count to a heat level for the heatmap UI."""
    if count == 0:   return "none"
    if count <= 2:   return "low"
    if count <= 10:  return "medium"
    if count <= 30:  return "high"
    return "critical"


def coverage_summary(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a coverage summary showing which tactics are covered.
    """
    db = load_mitre_db()
    all_tactics = db["tactics"]
    all_techniques = db["techniques"]

    covered_tactics = set()
    covered_techniques = set()

    for alert in alerts:
        tid = alert.get("mitre_technique", "")
        if tid and tid in all_techniques:
            covered_techniques.add(tid)
            covered_tactics.add(all_techniques[tid]["tactic_id"])

    tactic_coverage = []
    for tactic_id, tactic_name in all_tactics.items():
        techniques_in_tactic = [
            t for t in all_techniques.values()
            if t["tactic_id"] == tactic_id
        ]
        detected_in_tactic = [
            t for t in techniques_in_tactic
            if t["id"] in covered_techniques
        ]
        tactic_coverage.append({
            "tactic_id":      tactic_id,
            "tactic_name":    tactic_name,
            "total_techniques": len(techniques_in_tactic),
            "detected_count": len(detected_in_tactic),
            "covered":        len(detected_in_tactic) > 0,
        })

    return {
        "total_techniques_in_db":  len(all_techniques),
        "techniques_with_coverage": len(covered_techniques),
        "total_tactics":           len(all_tactics),
        "tactics_with_coverage":   len(covered_tactics),
        "coverage_percentage":     round(len(covered_techniques) / max(len(all_techniques), 1) * 100, 1),
        "tactic_breakdown":        tactic_coverage,
    }


if __name__ == "__main__":
    # Quick test
    test_alerts = [
        {"mitre_technique": "T1110", "mitre_tactic": "Credential Access", "severity": "High"},
        {"mitre_technique": "T1059.001", "mitre_tactic": "Execution", "severity": "Critical"},
        {"mitre_technique": "T1046", "mitre_tactic": "Discovery", "severity": "Medium"},
        {"mitre_technique": "T1548", "mitre_tactic": "Privilege Escalation", "severity": "Critical"},
    ]

    print("=== HEATMAP DATA ===")
    heatmap = generate_heatmap_data(test_alerts)
    for entry in heatmap:
        if entry["detection_count"] > 0:
            print(f"  {entry['technique_id']} | {entry['technique_name']} | {entry['heat_level']} | {entry['detection_count']} detections")

    print("\n=== COVERAGE SUMMARY ===")
    summary = coverage_summary(test_alerts)
    print(f"  Techniques covered: {summary['techniques_with_coverage']}/{summary['total_techniques_in_db']}")
    print(f"  Tactics covered:    {summary['tactics_with_coverage']}/{summary['total_tactics']}")
    print(f"  Coverage %:         {summary['coverage_percentage']}%")
