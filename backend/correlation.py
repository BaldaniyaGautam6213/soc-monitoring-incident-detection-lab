"""
correlation.py — Alert correlation engine for SOC Lab
Groups related alerts into incidents and builds attack chain storylines.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from detection_engine import get_db, log_analyst_action

# Tactic order for attack chain sorting (MITRE kill-chain inspired)
TACTIC_ORDER = {
    "Initial Access":        1,
    "Execution":             2,
    "Persistence":           3,
    "Privilege Escalation":  4,
    "Defense Evasion":       5,
    "Credential Access":     6,
    "Discovery":             7,
    "Lateral Movement":      8,
    "Collection":            9,
    "Command and Control":   10,
    "Exfiltration":          11,
    "Impact":                12,
}

# Multi-stage attack pattern recognition
ATTACK_CHAINS = [
    {
        "name": "Credential Compromise → Execution → Persistence",
        "scenarios": ["brute_force", "powershell_execution", "persistence"],
        "description": "Adversary performed credential brute-force, then executed malicious PowerShell, then established persistence via registry run key. Indicates a multi-stage intrusion sequence.",
        "severity": "Critical",
    },
    {
        "name": "Phishing → Execution → Privilege Escalation",
        "scenarios": ["malicious_office_macro", "powershell_execution", "privilege_escalation"],
        "description": "Office macro executed a shell, followed by PowerShell payload and privilege escalation. Consistent with phishing-initiated intrusion.",
        "severity": "Critical",
    },
    {
        "name": "Reconnaissance → Credential Attack",
        "scenarios": ["port_scan", "brute_force"],
        "description": "Network port scan followed by brute-force authentication attempts. Indicates active reconnaissance progressing to exploitation.",
        "severity": "High",
    },
    {
        "name": "Full Intrusion Chain",
        "scenarios": ["brute_force", "powershell_execution", "privilege_escalation", "persistence"],
        "description": "Complete multi-stage intrusion detected: credential access, code execution, privilege escalation, and persistence establishment. HIGH PRIORITY.",
        "severity": "Critical",
    },
]


def correlate_alerts(new_alert=None):
    """
    Correlate recent alerts into incidents.
    Called after each new alert is created.
    Returns created/updated incident or None.
    """
    conn = get_db()
    # Get recent open alerts (last 2 hours)
    recent_alerts = [
        dict(r) for r in conn.execute(
            """SELECT id, attack_scenario, mitre_technique, mitre_tactic, severity,
                      created_at, hostname, user, incident_id
               FROM alerts
               WHERE created_at >= datetime('now', '-2 hours')
               ORDER BY created_at ASC"""
        ).fetchall()
    ]
    conn.close()

    if not recent_alerts:
        return None

    # Group by attack scenario presence
    present_scenarios = {a["attack_scenario"] for a in recent_alerts if a["attack_scenario"]}

    for chain in ATTACK_CHAINS:
        required = set(chain["scenarios"])
        if required.issubset(present_scenarios):
            # Check if incident already exists for this chain
            conn  = get_db()
            chain_alerts = [a for a in recent_alerts if a["attack_scenario"] in required]
            alert_ids    = [a["id"] for a in chain_alerts]
            unlinked     = [a for a in chain_alerts if not a.get("incident_id")]

            if not unlinked:
                conn.close()
                continue  # already correlated

            # Build attack chain (ordered by tactic phase)
            chain_steps = sorted(
                [{"scenario": a["attack_scenario"], "technique": a["mitre_technique"],
                  "tactic": a["mitre_tactic"], "time": a["created_at"],
                  "hostname": a["hostname"]} for a in chain_alerts],
                key=lambda x: TACTIC_ORDER.get(x["tactic"], 99)
            )

            incident_id  = str(uuid.uuid4())
            now          = datetime.now().isoformat() + "Z"

            conn.execute("""
                INSERT INTO incidents (id, created_at, title, severity, status, attack_chain, alert_ids, summary, analyst)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                incident_id, now,
                chain["name"],
                chain["severity"],
                "Investigating",
                json.dumps(chain_steps),
                json.dumps(alert_ids),
                chain["description"],
                "SOC Analyst L1"
            ))

            # Link alerts to incident
            for aid in alert_ids:
                conn.execute(
                    "UPDATE alerts SET incident_id=? WHERE id=?",
                    (incident_id, aid)
                )

            conn.commit()
            conn.close()
            return incident_id

    return None


def get_incident(incident_id):
    conn      = get_db()
    incident  = dict(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone() or {})
    conn.close()

    if not incident:
        return None

    # Parse JSON fields
    for field in ("attack_chain", "alert_ids"):
        if isinstance(incident.get(field), str):
            try:
                incident[field] = json.loads(incident[field])
            except Exception:
                incident[field] = []

    return incident


def get_all_incidents(limit=50):
    conn      = get_db()
    incidents = [dict(r) for r in
                 conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]
    conn.close()

    for inc in incidents:
        for field in ("attack_chain", "alert_ids"):
            if isinstance(inc.get(field), str):
                try:
                    inc[field] = json.loads(inc[field])
                except Exception:
                    inc[field] = []

    return incidents


def build_attack_storyline(incident):
    """Build a human-readable attack storyline from an incident."""
    chain = incident.get("attack_chain", [])
    if not chain:
        return []

    storyline = []
    scenario_labels = {
        "brute_force":          "Credential Brute Force",
        "powershell_execution": "Malicious PowerShell Execution",
        "malicious_office_macro": "Malicious Office Macro (Phishing)",
        "suspicious_process":   "Suspicious Process Spawned",
        "port_scan":            "Network Port Scan / Recon",
        "privilege_escalation": "Privilege Escalation / Token Abuse",
        "persistence":          "Persistence Established",
    }

    for step in chain:
        storyline.append({
            "time":        step.get("time", "")[:19].replace("T", " "),
            "scenario":    step.get("scenario", ""),
            "label":       scenario_labels.get(step.get("scenario", ""), step.get("scenario", "")),
            "technique":   step.get("technique", ""),
            "tactic":      step.get("tactic", ""),
            "hostname":    step.get("hostname", ""),
            "tactic_order": TACTIC_ORDER.get(step.get("tactic", ""), 99),
        })

    return sorted(storyline, key=lambda x: x["tactic_order"])
