"""
app.py — Upgraded Flask + Flask-SocketIO backend for SOC Lab
Full SOC L1 workflow: Detect → Triage → Investigate → Correlate → Respond → Report → Metrics
"""

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from detection_engine import init_db, get_db, process_scenario, store_events, log_analyst_action, SLA_MINUTES
from ioc_extractor import enrich_iocs
from log_simulator import run_scenario, SCENARIOS
from mitre_mapper import generate_heatmap_data, coverage_summary, map_alert_to_technique
from report_generator import generate_pdf_report
from correlation import correlate_alerts, get_all_incidents, get_incident, build_attack_storyline
from metrics import calculate_metrics, get_audit_log

BASE_DIR    = Path(__file__).parent
REPORTS_DIR = BASE_DIR.parent / "reports"
FRONTEND    = BASE_DIR.parent / "frontend"

app      = Flask(__name__, static_folder=str(FRONTEND))
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

init_db()


# ─── Helpers ─────────────────────────────────────────────────────

def row_to_dict(row):
    if row is None:
        return None
    d = dict(row)
    for field in ("iocs", "event_ids", "matched_conditions", "correlated_ids", "attack_chain", "alert_ids"):
        if isinstance(d.get(field), str):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    return d


def _check_sla_breaches():
    """Mark alerts as SLA-breached if deadline has passed."""
    conn = get_db()
    now  = datetime.now().isoformat() + "Z"
    conn.execute(
        "UPDATE alerts SET sla_breached=1 WHERE sla_deadline < ? AND sla_breached=0 AND closed_at IS NULL",
        (now,)
    )
    conn.commit()
    conn.close()


def get_alerts_from_db(limit=100, offset=0, severity=None, status=None, search=None):
    _check_sla_breaches()
    conn       = get_db()
    conditions = []
    params     = []
    if severity:
        conditions.append("severity=?"); params.append(severity)
    if status:
        conditions.append("status=?"); params.append(status)
    if search:
        conditions.append("(rule_name LIKE ? OR hostname LIKE ? OR user LIKE ? OR source_ip LIKE ?)")
        params.extend([f"%{search}%"] * 4)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows  = conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    total = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
    conn.close()
    return [row_to_dict(r) for r in rows], total


def get_events_for_alert(alert_id):
    conn   = get_db()
    alert  = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    if not alert:
        conn.close()
        return None, []
    scenario = alert.get("attack_scenario", "")
    events   = [row_to_dict(r) for r in
                conn.execute("SELECT * FROM events WHERE attack_scenario=? ORDER BY timestamp ASC", (scenario,)).fetchall()]
    conn.close()
    return alert, events


def _sla_remaining(alert):
    """Returns (seconds_remaining, is_breached, display_string)."""
    deadline = alert.get("sla_deadline")
    if not deadline:
        return None, False, "N/A"
    try:
        dl  = datetime.fromisoformat(deadline.replace("Z", ""))
        now = datetime.now()
        remaining = (dl - now).total_seconds()
        if remaining <= 0:
            return 0, True, "BREACHED"
        h   = int(remaining // 3600)
        m   = int((remaining % 3600) // 60)
        s   = int(remaining % 60)
        disp = f"{h:02d}:{m:02d}:{s:02d}"
        return remaining, False, disp
    except Exception:
        return None, False, "N/A"


# ─── Static file serving ─────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(FRONTEND), "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(str(FRONTEND), filename)


# ─── Health ──────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})


# ─── Stats (dashboard KPIs) ──────────────────────────────────────

@app.route("/api/stats")
def stats():
    _check_sla_breaches()
    conn = get_db()
    total_alerts   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    open_alerts    = conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('New','Triaged','Investigating')").fetchone()[0]
    critical_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'").fetchone()[0]
    high_count     = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'").fetchone()[0]
    medium_count   = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='Medium'").fetchone()[0]
    low_count      = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='Low'").fetchone()[0]
    total_events   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    sla_breached   = conn.execute("SELECT COUNT(*) FROM alerts WHERE sla_breached=1 AND closed_at IS NULL").fetchone()[0]

    # SLA at risk (deadline in next 15 minutes and not closed)
    now_plus_15    = (datetime.now() + timedelta(minutes=15)).isoformat() + "Z"
    sla_at_risk    = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE sla_deadline < ? AND sla_deadline > ? AND closed_at IS NULL",
        (now_plus_15, datetime.now().isoformat() + "Z")
    ).fetchone()[0]

    by_scenario    = {}
    for r in conn.execute("SELECT attack_scenario, COUNT(*) as cnt FROM alerts GROUP BY attack_scenario").fetchall():
        by_scenario[r["attack_scenario"]] = r["cnt"]

    by_status = {}
    for r in conn.execute("SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status").fetchall():
        by_status[r["status"]] = r["cnt"]

    # Incident queue (top 5 open, sorted by severity)
    sev_order = "CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END"
    queue = [row_to_dict(r) for r in conn.execute(
        f"SELECT * FROM alerts WHERE status NOT IN ('Closed') ORDER BY {sev_order}, created_at ASC LIMIT 6"
    ).fetchall()]

    recent_alerts = [row_to_dict(r) for r in
                     conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 5").fetchall()]

    # ATT&CK tactic breakdown
    tactics = {}
    for r in conn.execute("SELECT mitre_tactic, COUNT(*) as cnt FROM alerts GROUP BY mitre_tactic").fetchall():
        if r["mitre_tactic"]:
            tactics[r["mitre_tactic"]] = r["cnt"]

    conn.close()

    # FP/TP stats
    met = calculate_metrics()

    # SLA enrichment on queue
    for alert in queue:
        rem, breached, disp = _sla_remaining(alert)
        alert["sla_remaining_display"] = disp
        alert["sla_at_risk"]           = not breached and rem is not None and rem < 900  # < 15 min

    return jsonify({
        "total_alerts":   total_alerts,
        "open_alerts":    open_alerts,
        "critical_count": critical_count,
        "high_count":     high_count,
        "medium_count":   medium_count,
        "low_count":      low_count,
        "total_events":   total_events,
        "sla_breached":   sla_breached,
        "sla_at_risk":    sla_at_risk,
        "severity_breakdown": {"Critical": critical_count, "High": high_count, "Medium": medium_count, "Low": low_count},
        "by_scenario":    by_scenario,
        "by_status":      by_status,
        "incident_queue": queue,
        "recent_alerts":  recent_alerts,
        "tactics":        tactics,
        "fp_rate":        met["fp_rate"],
        "tp_rate":        met["tp_rate"],
        "mtta_display":   met["mtta_display"],
        "mttr_display":   met["mttr_display"],
        "true_positives": met["true_positives"],
        "false_positives": met["false_positives"],
    })


# ─── Alerts ──────────────────────────────────────────────────────

@app.route("/api/alerts")
def list_alerts():
    limit    = int(request.args.get("limit", 50))
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    status   = request.args.get("status")
    search   = request.args.get("search")
    alerts, total = get_alerts_from_db(limit, offset, severity, status, search)

    # Add SLA display to each alert
    for a in alerts:
        rem, breached, disp = _sla_remaining(a)
        a["sla_remaining_display"] = disp
        a["sla_at_risk"]           = not breached and rem is not None and rem < 900

    return jsonify({"alerts": alerts, "total": total, "limit": limit, "offset": offset})


@app.route("/api/alerts/<alert_id>")
def get_alert(alert_id):
    alert, events = get_events_for_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    ioc_report    = enrich_iocs(events)
    mitre_context = map_alert_to_technique(alert)

    # Asset context
    conn  = get_db()
    asset = row_to_dict(conn.execute("SELECT * FROM assets WHERE hostname=?", (alert.get("hostname",""),)).fetchone())
    # Analyst actions for this alert
    actions = [row_to_dict(r) for r in
               conn.execute("SELECT * FROM analyst_actions WHERE alert_id=? ORDER BY timestamp ASC", (alert_id,)).fetchall()]
    conn.close()

    # SLA
    rem, breached, disp = _sla_remaining(alert)
    alert["sla_remaining_display"] = disp
    alert["sla_at_risk"]           = not breached and rem is not None and rem < 900

    return jsonify({
        "alert":         alert,
        "events":        events[:50],
        "ioc_report":    ioc_report,
        "mitre_context": mitre_context,
        "asset":         asset,
        "actions":       actions,
    })


# ─── Alert lifecycle ─────────────────────────────────────────────

STATUS_FLOW = ["New", "Triaged", "Investigating", "Containment", "Eradication", "Recovery", "Closed"]
STATUS_TIMESTAMP = {
    "Triaged":       "triaged_at",
    "Investigating": "investigated_at",
    "Containment":   "contained_at",
    "Closed":        "closed_at",
}


@app.route("/api/alerts/<alert_id>/status", methods=["PUT"])
def update_status(alert_id):
    data       = request.json or {}
    new_status = data.get("status")
    notes      = data.get("notes", "")

    if new_status not in STATUS_FLOW:
        return jsonify({"error": f"Invalid status. Must be one of: {STATUS_FLOW}"}), 400

    now  = datetime.now().isoformat() + "Z"
    conn = get_db()
    ts_field = STATUS_TIMESTAMP.get(new_status)
    if ts_field:
        conn.execute(f"UPDATE alerts SET status=?, {ts_field}=? WHERE id=?", (new_status, now, alert_id))
    else:
        conn.execute("UPDATE alerts SET status=? WHERE id=?", (new_status, alert_id))
    conn.commit()
    conn.close()

    log_analyst_action(alert_id, f"status_change", f"Status → {new_status}. {notes}")
    socketio.emit("alert_updated", {"alert_id": alert_id, "status": new_status})

    return jsonify({"success": True, "status": new_status})


@app.route("/api/alerts/<alert_id>/note", methods=["POST"])
def add_note(alert_id):
    data    = request.json or {}
    note    = data.get("note", "")
    analyst = data.get("analyst", "SOC Analyst L1")
    if not note:
        return jsonify({"error": "Note is required"}), 400

    conn = get_db()
    existing = conn.execute("SELECT analyst_notes FROM alerts WHERE id=?", (alert_id,)).fetchone()
    old_notes = existing["analyst_notes"] or "" if existing else ""
    now = datetime.now().strftime("%H:%M:%S")
    new_notes = f"[{now}] {analyst}: {note}\n{old_notes}"
    conn.execute("UPDATE alerts SET analyst_notes=? WHERE id=?", (new_notes, alert_id))
    conn.commit()
    conn.close()

    log_analyst_action(alert_id, "note_added", note, analyst)
    return jsonify({"success": True})


@app.route("/api/alerts/<alert_id>/classify", methods=["POST"])
def classify_alert(alert_id):
    data   = request.json or {}
    reason = data.get("closure_reason")  # TruePositive / FalsePositive / Benign / Duplicate
    fp_reason = data.get("fp_reason", "")
    notes  = data.get("notes", "")

    if reason not in ("TruePositive", "FalsePositive", "Benign", "Duplicate"):
        return jsonify({"error": "Invalid closure_reason"}), 400

    now  = datetime.now().isoformat() + "Z"
    conn = get_db()
    conn.execute(
        "UPDATE alerts SET closure_reason=?, fp_reason=?, status='Closed', closed_at=?, analyst_notes=? WHERE id=?",
        (reason, fp_reason, now, notes, alert_id)
    )
    conn.commit()
    conn.close()

    log_analyst_action(alert_id, "classified", f"Classification: {reason}. {fp_reason}. {notes}")
    socketio.emit("alert_updated", {"alert_id": alert_id, "status": "Closed", "closure_reason": reason})
    return jsonify({"success": True, "closure_reason": reason})


# ─── Investigation endpoints ──────────────────────────────────────

@app.route("/api/alerts/<alert_id>/timeline")
def alert_timeline(alert_id):
    alert, events = get_events_for_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    timeline = []
    for i, event in enumerate(events):
        extra = {}
        if isinstance(event.get("extra_data"), str):
            try:
                extra = json.loads(event["extra_data"])
            except Exception:
                pass

        timeline.append({
            "index":      i + 1,
            "timestamp":  event.get("timestamp", "")[:19].replace("T", " "),
            "log_source": event.get("log_source", ""),
            "event_id":   event.get("event_id", ""),
            "event_type": event.get("event_type", ""),
            "hostname":   event.get("hostname", ""),
            "user":       event.get("user", ""),
            "source_ip":  event.get("source_ip", ""),
            "process":    event.get("process_name", ""),
            "narrative":  _narrative(event, extra),
        })

    return jsonify({"timeline": timeline, "total": len(timeline)})


def _narrative(event, extra):
    """Generate a human-readable narrative for a log event."""
    etype = event.get("event_type", "")
    user  = event.get("user", "?")
    host  = event.get("hostname", "?")
    ip    = event.get("source_ip", "?")
    proc  = event.get("process_name", "?")
    parent = extra.get("parent_process", "")
    narratives = {
        "FAILED_LOGIN":      f"Failed authentication attempt — User: {user} | Source: {ip} | Host: {host}",
        "SUCCESSFUL_LOGIN":  f"⚠ SUCCESSFUL LOGIN after repeated failures — User: {user} | Source: {ip}",
        "PROCESS_CREATE":    f"Process spawned: {proc}" + (f" ← parent: {parent}" if parent else "") + f" | User: {user}",
        "NETWORK_CONNECT":   f"Outbound connection from {proc} → {extra.get('dest_ip','?')}:{extra.get('dest_port','?')} | Host: {host}",
        "NETWORK_SCAN":      f"Port scan detected: {ip} → {extra.get('dest_ip','?')}:{extra.get('dest_port','?')}",
        "PRIVILEGE_USE":     f"Sensitive privilege assigned — User: {user} | Privileges: {extra.get('privileges','?')} | Host: {host}",
        "REGISTRY_VALUE_SET": f"Registry modified — Key: {extra.get('registry_key','?')} | Data: {extra.get('registry_data','?')} | Process: {proc}",
        "FILE_CREATE":       f"File created: {extra.get('file_path','?')} | Hash: {extra.get('file_hash','?')} | Process: {proc}",
    }
    return narratives.get(etype, f"{etype} event on {host} by {user}")


@app.route("/api/alerts/<alert_id>/process_tree")
def alert_process_tree(alert_id):
    """Build a process tree from events in the alert's scenario."""
    alert, events = get_events_for_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    process_events = [e for e in events if e.get("event_type") in ("PROCESS_CREATE",)]
    if not process_events:
        return jsonify({"tree": [], "flat": []})

    # Parse extra_data for parent process info
    nodes  = {}
    for event in process_events:
        extra = {}
        if isinstance(event.get("extra_data"), str):
            try:
                extra = json.loads(event["extra_data"])
            except Exception:
                pass

        pid    = extra.get("process_id", str(id(event)))
        parent = extra.get("parent_process", "").split("\\")[-1] if extra.get("parent_process") else None
        ppid   = extra.get("parent_pid", "")

        nodes[pid] = {
            "pid":          pid,
            "name":         event.get("process_name", "unknown"),
            "full_path":    extra.get("image_path", ""),
            "cmd":          event.get("command_line", "")[:120],
            "user":         event.get("user", ""),
            "timestamp":    event.get("timestamp", "")[:19].replace("T", " "),
            "parent_name":  parent,
            "ppid":         ppid,
            "children":     [],
            "suspicious":   _is_suspicious_process(event.get("process_name", ""), parent or ""),
        }

    # Build tree structure (parent → children)
    roots = []
    for pid, node in nodes.items():
        parent_name = node.get("parent_name", "")
        parent_node = next((n for n in nodes.values() if n["name"] == parent_name), None)
        if parent_node and parent_node is not node:
            parent_node["children"].append(node)
        else:
            roots.append(node)

    # Flat list for simple rendering
    flat = []
    def _flatten(node, depth=0):
        flat.append({**node, "depth": depth, "children": []})
        for child in node.get("children", []):
            _flatten(child, depth + 1)
    for root in roots:
        _flatten(root)

    return jsonify({"tree": roots, "flat": flat})


def _is_suspicious_process(proc_name, parent_name):
    suspicious_parents = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "chrome.exe", "firefox.exe"}
    suspicious_children = {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"}
    return parent_name.lower() in suspicious_parents and proc_name.lower() in suspicious_children


@app.route("/api/alerts/<alert_id>/why_fired")
def why_fired(alert_id):
    conn  = get_db()
    alert = row_to_dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
    conn.close()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    # Load the matching rule
    from detection_engine import load_rules
    rules = load_rules()
    rule  = next((r for r in rules if r["rule_id"] == alert.get("rule_id")), None)

    conditions = alert.get("matched_conditions", [])
    if isinstance(conditions, str):
        try:
            conditions = json.loads(conditions)
        except Exception:
            conditions = []

    return jsonify({
        "rule_id":         alert.get("rule_id"),
        "rule_name":       alert.get("rule_name"),
        "confidence":      alert.get("confidence", 70),
        "severity":        alert.get("severity"),
        "matched_conditions": conditions,
        "false_positives": rule.get("false_positives", []) if rule else [],
        "total_conditions": len(conditions),
        "all_matched":     True,  # All conditions must match for rule to fire
    })


@app.route("/api/alerts/<alert_id>/playbook")
def get_playbook(alert_id):
    conn  = get_db()
    alert = row_to_dict(conn.execute("SELECT rule_id FROM alerts WHERE id=?", (alert_id,)).fetchone())
    conn.close()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    rules    = json.loads(open(BASE_DIR / "data" / "detection_rules.json").read())
    playbooks = json.loads(open(BASE_DIR / "data" / "playbooks.json").read())

    rule = next((r for r in rules if r["rule_id"] == alert.get("rule_id")), None)
    if not rule:
        return jsonify({"error": "No playbook found"}), 404

    pb_id    = rule.get("response_playbook_id")
    playbook = playbooks.get(pb_id)
    if not playbook:
        return jsonify({"error": "Playbook not found"}), 404

    # Get completed steps for this alert (from audit log)
    conn     = get_db()
    actions  = [dict(r) for r in
                conn.execute(
                    "SELECT details FROM analyst_actions WHERE alert_id=? AND action_type='playbook_step'",
                    (alert_id,)
                ).fetchall()]
    conn.close()
    completed_steps = {a["details"] for a in actions}

    # Mark completed steps
    for phase, steps in playbook.get("nist_phases", {}).items():
        for step in steps:
            step["completed"] = step["id"] in completed_steps

    return jsonify({"playbook": playbook, "alert_id": alert_id})


@app.route("/api/alerts/<alert_id>/playbook/step", methods=["POST"])
def complete_playbook_step(alert_id):
    data    = request.json or {}
    step_id = data.get("step_id")
    if not step_id:
        return jsonify({"error": "step_id required"}), 400
    log_analyst_action(alert_id, "playbook_step", step_id)
    return jsonify({"success": True, "step_id": step_id})


# ─── Incidents ───────────────────────────────────────────────────

@app.route("/api/incidents")
def list_incidents():
    incidents = get_all_incidents()
    for inc in incidents:
        storyline = build_attack_storyline(inc)
        inc["storyline"] = storyline
    return jsonify({"incidents": incidents, "total": len(incidents)})


@app.route("/api/incidents/<incident_id>")
def get_incident_detail(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    incident["storyline"] = build_attack_storyline(incident)

    # Get linked alerts
    alert_ids = incident.get("alert_ids", [])
    alerts    = []
    if alert_ids:
        conn = get_db()
        for aid in alert_ids:
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
            if row:
                alerts.append(row_to_dict(row))
        conn.close()

    return jsonify({"incident": incident, "alerts": alerts})


# ─── Simulate ────────────────────────────────────────────────────

@app.route("/api/simulate/<scenario>", methods=["POST"])
def simulate_attack(scenario):
    if scenario not in SCENARIOS:
        return jsonify({"error": f"Unknown scenario: {scenario}. Valid: {list(SCENARIOS.keys())}"}), 400

    def run_in_background():
        try:
            socketio.emit("simulation_start", {
                "scenario": scenario,
                "message":  f"Starting simulation: {scenario.replace('_',' ').title()}"
            })
            time.sleep(0.15)

            events, summary = run_scenario(scenario)

            for i, event in enumerate(events):
                socketio.emit("attack_log", {
                    "index":      i + 1,
                    "total":      len(events),
                    "timestamp":  event.get("timestamp", ""),
                    "log_source": event.get("log_source", ""),
                    "event_id":   event.get("event_id", ""),
                    "event_type": event.get("event_type", ""),
                    "hostname":   event.get("hostname", ""),
                    "user":       event.get("user", ""),
                    "source_ip":  event.get("source_ip", ""),
                    "raw_log":    event.get("raw_log", ""),
                    "scenario":   scenario,
                })
                time.sleep(0.04)

            alert = process_scenario(events, summary)
            if alert:
                if isinstance(alert.get("iocs"), str):
                    try:
                        alert["iocs"] = json.loads(alert["iocs"])
                    except Exception:
                        pass

                # SLA info
                from detection_engine import SLA_MINUTES
                sla_mins = SLA_MINUTES.get(alert.get("severity", "Low"), 240)
                alert["sla_remaining_display"] = f"{sla_mins}:00"

                # Try correlation
                incident_id = correlate_alerts(alert)
                if incident_id:
                    alert["incident_id"] = incident_id
                    socketio.emit("incident_created", {
                        "incident_id": incident_id,
                        "message":     "Multi-stage attack chain detected — incident created",
                    })

                socketio.emit("new_alert", {"alert": alert, "summary": summary})
                socketio.emit("simulation_end", {
                    "scenario":  scenario,
                    "alert_id":  alert.get("id"),
                    "severity":  alert.get("severity"),
                    "priority":  alert.get("priority"),
                    "confidence": alert.get("confidence"),
                    "rule_name": alert.get("rule_name"),
                    "message":   f"ALERT FIRED: {alert.get('rule_name')} [{alert.get('severity')}] Confidence: {alert.get('confidence')}%",
                    "success":   True,
                })
            else:
                socketio.emit("simulation_end", {"scenario": scenario, "message": "No detection fired", "success": False})
        except Exception as e:
            socketio.emit("simulation_error", {"scenario": scenario, "error": str(e)})

    threading.Thread(target=run_in_background, daemon=True).start()
    return jsonify({"status": "started", "scenario": scenario})


@app.route("/api/simulate/all", methods=["POST"])
def simulate_all():
    def run_all():
        for scenario in SCENARIOS:
            socketio.emit("simulation_start", {
                "scenario": scenario,
                "message":  f"Starting simulation: {scenario.replace('_',' ').title()}"
            })
            time.sleep(0.1)

            events, summary = run_scenario(scenario)
            for i, event in enumerate(events):
                socketio.emit("attack_log", {
                    "index":      i + 1,
                    "total":      len(events),
                    "raw_log":    event.get("raw_log", ""),
                    "log_source": event.get("log_source", ""),
                    "event_type": event.get("event_type", ""),
                    "hostname":   event.get("hostname", ""),
                    "user":       event.get("user", ""),
                    "source_ip":  event.get("source_ip", ""),
                    "scenario":   scenario,
                })
                time.sleep(0.03)

            alert = process_scenario(events, summary)
            if alert:
                if isinstance(alert.get("iocs"), str):
                    try:
                        alert["iocs"] = json.loads(alert["iocs"])
                    except Exception:
                        pass
                incident_id = correlate_alerts(alert)
                if incident_id:
                    alert["incident_id"] = incident_id
                    socketio.emit("incident_created", {"incident_id": incident_id})
                socketio.emit("new_alert", {"alert": alert, "summary": summary})
                socketio.emit("simulation_end", {
                    "scenario":   scenario,
                    "alert_id":   alert.get("id"),
                    "severity":   alert.get("severity"),
                    "priority":   alert.get("priority"),
                    "confidence": alert.get("confidence"),
                    "rule_name":  alert.get("rule_name"),
                    "message":    f"ALERT FIRED: {alert.get('rule_name')} [{alert.get('severity')}]",
                    "success":    True,
                })
            else:
                socketio.emit("simulation_end", {
                    "scenario": scenario, "message": "No detection fired", "success": False
                })
            time.sleep(0.4)

    threading.Thread(target=run_all, daemon=True).start()
    return jsonify({"status": "started", "scenarios": list(SCENARIOS.keys())})



# ─── MITRE ───────────────────────────────────────────────────────

@app.route("/api/mitre")
def mitre_heatmap():
    alerts, _ = get_alerts_from_db(limit=1000)
    heatmap   = generate_heatmap_data(alerts)
    coverage  = coverage_summary(alerts)
    return jsonify({"heatmap": heatmap, "coverage": coverage})


# ─── Metrics ─────────────────────────────────────────────────────

@app.route("/api/metrics")
def soc_metrics():
    return jsonify(calculate_metrics())


@app.route("/api/audit")
def audit_log():
    limit   = int(request.args.get("limit", 100))
    actions = get_audit_log(limit)
    return jsonify({"actions": actions, "total": len(actions)})


@app.route("/api/assets")
def list_assets():
    conn   = get_db()
    assets = [dict(r) for r in conn.execute("SELECT * FROM assets ORDER BY criticality").fetchall()]
    conn.close()
    return jsonify({"assets": assets})


# ─── Report ──────────────────────────────────────────────────────

@app.route("/api/report/<alert_id>", methods=["POST"])
def generate_report(alert_id):
    import re
    data         = request.json or {}
    analyst_name = data.get("analyst_name", "SOC Analyst L1") or "SOC Analyst L1"
    report_title = data.get("report_title", "").strip()

    # Sanitise the user-supplied title into a safe filename
    if report_title:
        safe_filename = re.sub(r"[^\w\-]", "_", report_title)   # keep letters, digits, _, -
        safe_filename = re.sub(r"_+", "_", safe_filename).strip("_")  # collapse repeated _
    else:
        safe_filename = f"Incident_Report_{alert_id[:8].upper()}"

    if not safe_filename:
        safe_filename = f"Incident_Report_{alert_id[:8].upper()}"

    alert, events = get_events_for_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    try:
        pdf_path = generate_pdf_report(alert, events, analyst_name, report_title=report_title or safe_filename)
        log_analyst_action(alert_id, "report_generated",
                           f"PDF report '{safe_filename}' generated by {analyst_name}")
        return send_file(pdf_path, mimetype="application/pdf", as_attachment=True,
                         download_name=f"{safe_filename}.pdf")
    except ImportError:
        return jsonify({"error": "ReportLab not installed", "install": "pip install reportlab"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scenarios")
def list_scenarios():
    return jsonify({
        "brute_force": {
            "name": "Brute Force Login", "description": "50+ failed auth attempts followed by account compromise",
            "mitre": "T1110.001", "severity": "High", "log_source": "Windows Security 4625/4624",
        },
        "powershell_execution": {
            "name": "Suspicious PowerShell", "description": "Encoded PowerShell with C2 callback via Office parent",
            "mitre": "T1059.001", "severity": "High", "log_source": "Sysmon Event 1, 3",
        },
        "malicious_office_macro": {
            "name": "Malicious Office Macro", "description": "Word→cmd→powershell chain — phishing macro execution",
            "mitre": "T1204.002", "severity": "Critical", "log_source": "Sysmon Event 1",
        },
        "port_scan": {
            "name": "Network Port Scan", "description": "Nmap SYN scan across 1024 ports",
            "mitre": "T1046", "severity": "Medium", "log_source": "Suricata ET SCAN",
        },
        "privilege_escalation": {
            "name": "Access Token Manipulation", "description": "SeDebugPrivilege token + LSASS access",
            "mitre": "T1134", "severity": "Critical", "log_source": "Windows Security 4672/4673",
        },
        "persistence": {
            "name": "Registry Persistence", "description": "Malware added to HKLM Run key",
            "mitre": "T1547.001", "severity": "High", "log_source": "Sysmon Event 13",
        },
    })


# ─── WebSocket ───────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    emit("connected", {"message": "SOC Lab WebSocket connected", "sid": request.sid})

@socketio.on("disconnect")
def on_disconnect():
    pass

@socketio.on("ping_server")
def on_ping(data):
    emit("pong_server", {"time": datetime.now().isoformat()})


# ─── Main ────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  SOC Monitoring & Incident Detection Lab — v2.0")
    print("  Interview-Grade SOC L1 Workflow")
    print("=" * 60)
    print(f"  Dashboard : http://localhost:5000")
    print(f"  API       : http://localhost:5000/api")
    print(f"  Reports   : {REPORTS_DIR}")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
