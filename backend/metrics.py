"""
metrics.py — SOC performance metrics: MTTD, MTTA, MTTR, SLA, FP rate, detection quality.
"""

import json
from datetime import datetime
from detection_engine import get_db


def _parse_dt(iso_str):
    if not iso_str:
        return None
    try:
        return datetime.fromisoformat(iso_str.replace("Z", ""))
    except Exception:
        return None


def _minutes_between(start, end):
    if not start or not end:
        return None
    delta = end - start
    return round(delta.total_seconds() / 60, 1)


def calculate_metrics():
    """Calculate all SOC performance metrics from the database."""
    conn   = get_db()
    alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts").fetchall()]
    actions = [dict(r) for r in conn.execute("SELECT * FROM analyst_actions ORDER BY timestamp ASC").fetchall()]
    conn.close()

    if not alerts:
        return _empty_metrics()

    # ── MTTD (Mean Time to Detect) ──────────────────────────────
    # For simulated data: MTTD ≈ time from first event in scenario to alert creation
    # We approximate with a constant offset per severity for demo purposes
    sev_detect_offset = {"Critical": 0.8, "High": 1.2, "Medium": 2.5, "Low": 5.0}
    mttd_values = [sev_detect_offset.get(a["severity"], 2.0) for a in alerts]
    mttd = round(sum(mttd_values) / len(mttd_values), 1) if mttd_values else 0

    # ── MTTA (Mean Time to Acknowledge / first analyst action) ──
    mtta_values = []
    for alert in alerts:
        created = _parse_dt(alert.get("created_at"))
        # Find first action for this alert
        first_action = next((a for a in actions if a["alert_id"] == alert["id"]), None)
        if first_action:
            acted = _parse_dt(first_action["timestamp"])
            mins  = _minutes_between(created, acted)
            if mins is not None and 0 <= mins <= 1440:
                mtta_values.append(mins)
        elif alert.get("triaged_at"):
            mins = _minutes_between(created, _parse_dt(alert["triaged_at"]))
            if mins is not None and 0 <= mins <= 1440:
                mtta_values.append(mins)

    mtta = round(sum(mtta_values) / len(mtta_values), 1) if mtta_values else None

    # ── MTTR (Mean Time to Respond / close) ─────────────────────
    mttr_values = []
    for alert in alerts:
        if alert.get("closed_at"):
            created = _parse_dt(alert["created_at"])
            closed  = _parse_dt(alert["closed_at"])
            mins    = _minutes_between(created, closed)
            if mins is not None and 0 <= mins <= 10080:
                mttr_values.append(mins)

    mttr = round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None

    # ── SLA Compliance ───────────────────────────────────────────
    from detection_engine import SLA_MINUTES
    sla_compliance = {}
    for severity, sla_min in SLA_MINUTES.items():
        sev_alerts = [a for a in alerts if a["severity"] == severity]
        if not sev_alerts:
            continue
        within  = 0
        breached = 0
        for a in sev_alerts:
            if a.get("closed_at") and a.get("created_at"):
                response_mins = _minutes_between(_parse_dt(a["created_at"]), _parse_dt(a["closed_at"]))
                if response_mins is not None:
                    if response_mins <= sla_min:
                        within += 1
                    else:
                        breached += 1
                else:
                    # Still open — check against deadline
                    deadline = _parse_dt(a.get("sla_deadline"))
                    if deadline and datetime.now() > deadline:
                        breached += 1
                    else:
                        within += 1
            else:
                deadline = _parse_dt(a.get("sla_deadline"))
                if deadline and datetime.now() > deadline:
                    breached += 1
                else:
                    within += 1

        sla_compliance[severity] = {
            "total":         len(sev_alerts),
            "within_sla":    within,
            "breached":      breached,
            "sla_minutes":   sla_min,
            "compliance_pct": round(within / max(len(sev_alerts), 1) * 100, 1),
        }

    # ── False Positive Rate ──────────────────────────────────────
    closed_alerts = [a for a in alerts if a.get("closed_at") or a.get("closure_reason")]
    fp_alerts     = [a for a in closed_alerts if a.get("closure_reason") == "FalsePositive"]
    tp_alerts     = [a for a in closed_alerts if a.get("closure_reason") == "TruePositive"]
    fp_rate = round(len(fp_alerts) / max(len(closed_alerts), 1) * 100, 1)
    tp_rate = round(len(tp_alerts) / max(len(closed_alerts), 1) * 100, 1)

    # ── Detection Quality Per Rule ───────────────────────────────
    rule_quality = {}
    for alert in closed_alerts:
        rid = alert.get("rule_id", "unknown")
        if rid not in rule_quality:
            rule_quality[rid] = {"rule_id": rid, "rule_name": alert.get("rule_name", ""), "tp": 0, "fp": 0, "total": 0}
        rule_quality[rid]["total"] += 1
        if alert.get("closure_reason") == "TruePositive":
            rule_quality[rid]["tp"] += 1
        elif alert.get("closure_reason") == "FalsePositive":
            rule_quality[rid]["fp"] += 1

    for rid, data in rule_quality.items():
        data["fp_rate"] = round(data["fp"] / max(data["total"], 1) * 100, 1)

    # ── ATT&CK Tactic Coverage ───────────────────────────────────
    tactics_detected = {}
    for alert in alerts:
        tactic = alert.get("mitre_tactic", "Unknown")
        if tactic and tactic != "Unknown":
            tactics_detected[tactic] = tactics_detected.get(tactic, 0) + 1

    # ── Alert Volume ─────────────────────────────────────────────
    status_counts = {}
    for alert in alerts:
        s = alert.get("status", "Unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    sla_at_risk = sum(
        1 for a in alerts
        if not a.get("closed_at") and a.get("sla_deadline")
        and 0 < (_parse_dt(a["sla_deadline"]) - datetime.now()).total_seconds() / 60 < 15
        if _parse_dt(a.get("sla_deadline"))
    )

    return {
        "total_alerts":    len(alerts),
        "open_alerts":     status_counts.get("New", 0) + status_counts.get("Triaged", 0) + status_counts.get("Investigating", 0),
        "closed_alerts":   len(closed_alerts),
        "true_positives":  len(tp_alerts),
        "false_positives": len(fp_alerts),
        "fp_rate":         fp_rate,
        "tp_rate":         tp_rate,
        "mttd_minutes":    mttd,
        "mtta_minutes":    mtta,
        "mttr_minutes":    mttr,
        "mttd_display":    _fmt_minutes(mttd),
        "mtta_display":    _fmt_minutes(mtta),
        "mttr_display":    _fmt_minutes(mttr),
        "sla_at_risk":     sla_at_risk,
        "sla_compliance":  sla_compliance,
        "rule_quality":    list(rule_quality.values()),
        "tactics_detected": tactics_detected,
        "status_breakdown": status_counts,
        "severity_breakdown": {
            sev: sum(1 for a in alerts if a["severity"] == sev)
            for sev in ["Critical", "High", "Medium", "Low"]
        },
    }


def _fmt_minutes(minutes):
    """Format minutes into human-readable string."""
    if minutes is None:
        return "N/A"
    if minutes < 1:
        return f"{int(minutes * 60)}s"
    if minutes < 60:
        return f"{int(minutes)}m {int((minutes % 1) * 60)}s"
    hours = int(minutes // 60)
    mins  = int(minutes % 60)
    return f"{hours}h {mins}m"


def _empty_metrics():
    return {
        "total_alerts": 0, "open_alerts": 0, "closed_alerts": 0,
        "true_positives": 0, "false_positives": 0, "fp_rate": 0.0, "tp_rate": 0.0,
        "mttd_minutes": 0, "mtta_minutes": None, "mttr_minutes": None,
        "mttd_display": "N/A", "mtta_display": "N/A", "mttr_display": "N/A",
        "sla_at_risk": 0, "sla_compliance": {}, "rule_quality": [],
        "tactics_detected": {}, "status_breakdown": {}, "severity_breakdown": {},
    }


def get_audit_log(limit=100):
    conn    = get_db()
    actions = [dict(r) for r in
               conn.execute(
                   """SELECT a.*, al.rule_name, al.severity FROM analyst_actions a
                      LEFT JOIN alerts al ON a.alert_id = al.id
                      ORDER BY a.timestamp DESC LIMIT ?""",
                   (limit,)
               ).fetchall()]
    conn.close()
    return actions


if __name__ == "__main__":
    metrics = calculate_metrics()
    print(f"MTTD: {metrics['mttd_display']}")
    print(f"MTTA: {metrics['mtta_display']}")
    print(f"MTTR: {metrics['mttr_display']}")
    print(f"FP Rate: {metrics['fp_rate']}%")
    print(f"SLA At Risk: {metrics['sla_at_risk']}")
