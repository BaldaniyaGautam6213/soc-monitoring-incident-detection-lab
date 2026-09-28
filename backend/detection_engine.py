"""
detection_engine.py — Upgraded Sigma-style detection rule engine
Includes: alert lifecycle, confidence scoring, SLA, matched conditions, audit log.
"""

import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR   = Path(__file__).parent
RULES_FILE = BASE_DIR / "data" / "detection_rules.json"
DB_FILE    = BASE_DIR / "data" / "soc_lab.db"

# SLA deadlines by severity (minutes)
SLA_MINUTES = {"Critical": 15, "High": 30, "Medium": 240, "Low": 1440}

# Priority mapping by severity (default)
SEVERITY_PRIORITY = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}


def get_db():
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize / migrate the SQLite database schema."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id              TEXT PRIMARY KEY,
            timestamp       TEXT NOT NULL,
            hostname        TEXT,
            log_source      TEXT,
            event_id        TEXT,
            event_type      TEXT,
            user            TEXT,
            source_ip       TEXT,
            process_name    TEXT,
            command_line    TEXT,
            raw_log         TEXT,
            attack_scenario TEXT,
            mitre_technique TEXT,
            extra_data      TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id                  TEXT PRIMARY KEY,
            created_at          TEXT NOT NULL,
            rule_id             TEXT NOT NULL,
            rule_name           TEXT NOT NULL,
            severity            TEXT NOT NULL,
            confidence          INTEGER DEFAULT 70,
            priority            TEXT DEFAULT 'P3',
            status              TEXT DEFAULT 'New',
            assigned_to         TEXT DEFAULT 'SOC Analyst L1',
            sla_deadline        TEXT,
            sla_breached        INTEGER DEFAULT 0,
            hostname            TEXT,
            user                TEXT,
            source_ip           TEXT,
            mitre_technique     TEXT,
            mitre_tactic        TEXT,
            event_ids           TEXT,
            iocs                TEXT,
            summary             TEXT,
            attack_scenario     TEXT,
            matched_conditions  TEXT,
            risk_score          INTEGER DEFAULT 0,
            correlated_ids      TEXT,
            incident_id         TEXT,
            triaged_at          TEXT,
            investigated_at     TEXT,
            contained_at        TEXT,
            closed_at           TEXT,
            closure_reason      TEXT,
            fp_reason           TEXT,
            analyst_notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id              TEXT PRIMARY KEY,
            created_at      TEXT NOT NULL,
            title           TEXT NOT NULL,
            severity        TEXT NOT NULL,
            status          TEXT DEFAULT 'Open',
            attack_chain    TEXT,
            alert_ids       TEXT,
            summary         TEXT,
            analyst         TEXT DEFAULT 'SOC Analyst L1'
        );

        CREATE TABLE IF NOT EXISTS analyst_actions (
            id          TEXT PRIMARY KEY,
            alert_id    TEXT NOT NULL,
            action_type TEXT NOT NULL,
            analyst     TEXT DEFAULT 'SOC Analyst L1',
            timestamp   TEXT NOT NULL,
            details     TEXT
        );

        CREATE TABLE IF NOT EXISTS assets (
            hostname        TEXT PRIMARY KEY,
            ip              TEXT,
            os              TEXT DEFAULT 'Windows Server 2019',
            criticality     TEXT DEFAULT 'Medium',
            owner           TEXT DEFAULT 'IT Operations',
            environment     TEXT DEFAULT 'Production',
            business_svc    TEXT DEFAULT 'Internal'
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_scenario  ON alerts(attack_scenario);
        CREATE INDEX IF NOT EXISTS idx_events_scenario  ON events(attack_scenario);
        CREATE INDEX IF NOT EXISTS idx_actions_alert    ON analyst_actions(alert_id);
    """)
    conn.commit()
    _seed_assets(conn)
    conn.close()


def _seed_assets(conn):
    """Seed realistic asset inventory if empty."""
    count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    if count > 0:
        return
    assets = [
        ("SERVER-DC-01",        "192.168.1.10", "Windows Server 2019", "Critical", "IT Security",      "Production",  "Domain Controller"),
        ("WEB-SERVER-02",       "192.168.1.25", "Windows Server 2022", "Critical", "Dev Team",         "Production",  "Customer Portal"),
        ("DESKTOP-WIN10-01",    "192.168.1.42", "Windows 10 Pro",      "Medium",   "HR Department",    "Production",  "Internal HR System"),
        ("WORKSTATION-HR-07",   "10.0.0.15",    "Windows 10 Pro",      "Medium",   "HR Department",    "Production",  "HR Payroll"),
        ("LAPTOP-DEV-22",       "10.0.0.88",    "Windows 11 Pro",      "Low",      "Dev Team",         "Development", "Internal Dev"),
        ("ubuntu-proxy-01",     "192.168.1.50", "Ubuntu 22.04",        "High",     "Network Team",     "Production",  "Proxy/Gateway"),
        ("kali-sensor-02",      "192.168.1.55", "Kali Linux",          "Low",      "Security Team",    "Lab",         "Security Testing"),
        ("centos-web-03",       "192.168.1.60", "CentOS 8",            "High",     "Dev Team",         "Production",  "Internal API"),
        ("debian-db-04",        "192.168.1.65", "Debian 11",           "Critical", "DB Team",          "Production",  "Customer Database"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO assets (hostname,ip,os,criticality,owner,environment,business_svc) VALUES (?,?,?,?,?,?,?)",
        assets
    )
    conn.commit()


def load_rules():
    with open(RULES_FILE) as f:
        return json.load(f)


def _match_field(event_val, pattern_val):
    return str(event_val).lower() == str(pattern_val).lower()


def _match_regex(event_val, pattern):
    return bool(re.search(pattern, str(event_val), re.IGNORECASE))


def evaluate_rule(rule, events_batch):
    """
    Evaluate a rule against a batch of events.
    Returns (fired, matched_events, conditions_detail).
    """
    field_conditions = rule["conditions"].get("field_matches", {})
    regex_conditions = rule["conditions"].get("regex_matches", {})
    threshold        = rule["conditions"].get("threshold", 1)
    target_event_ids = [str(eid) for eid in rule.get("event_ids", [])]

    matched     = []
    cond_detail = []  # For "Why did this fire?" transparency

    for event in events_batch:
        if target_event_ids and str(event.get("event_id")) not in target_event_ids:
            continue

        field_ok = all(
            _match_field(event.get(field, ""), val)
            for field, val in field_conditions.items()
        )

        regex_results = {}
        if regex_conditions:
            searchable = (
                event.get("command_line", "") + " " +
                event.get("privileges", "") + " " +
                event.get("registry_key", "") + " " +
                event.get("parent_process", "") + " " +
                event.get("process_name", "")
            )
            for field, pattern in regex_conditions.items():
                # Use the specific field value; fall back to searchable blob only
                # if the field doesn't exist on the event
                val = event.get(field) if event.get(field) else searchable
                regex_results[field] = _match_regex(val, pattern)
            # Rules with multiple regex keys require ALL to match (AND semantics)
            # so a parent_process + process_name rule fires only when both match
            regex_ok = all(regex_results.values())
        else:
            regex_ok = True

        if field_ok and regex_ok:
            matched.append(event)

    # Build condition transparency record
    tmpl = rule.get("matched_conditions_template", [])
    first = matched[0] if matched else {}
    for cond in tmpl:
        cond_detail.append(
            cond.format(
                count=len(matched),
                window=rule["conditions"].get("timewindow_seconds", 60),
                rate=round(len(matched) / max(rule["conditions"].get("timewindow_seconds", 60), 1), 1),
                parent_process=first.get("parent_process", "unknown"),
                process_name=first.get("process_name", "unknown"),
                command_line=(first.get("command_line", "")[:80] + "...") if first.get("command_line") else "N/A",
                user=first.get("user", "unknown"),
                privileges=first.get("privileges", "N/A"),
                registry_key=first.get("registry_key", "N/A"),
                registry_value=first.get("registry_value", "N/A"),
                registry_data=first.get("registry_data", "N/A"),
                correlated="Yes (Event 4673 detected)" if len(matched) > 1 else "No",
            )
        )

    return len(matched) >= threshold, matched, cond_detail


def _calculate_risk_score(severity, confidence, asset_criticality="Medium"):
    crit_map = {"Critical": 5, "High": 4, "Medium": 3, "Low": 1}
    sev_map  = {"Critical": 5, "High": 4, "Medium": 3, "Low": 1}
    sev_score   = sev_map.get(severity, 3)
    asset_score = crit_map.get(asset_criticality, 3)
    conf_factor = confidence / 100.0
    raw = (sev_score * asset_score * conf_factor) / (5 * 5) * 100
    return min(100, int(raw))


def _get_asset_criticality(hostname):
    try:
        conn = get_db()
        row  = conn.execute("SELECT criticality FROM assets WHERE hostname=?", (hostname,)).fetchone()
        conn.close()
        return row["criticality"] if row else "Medium"
    except Exception:
        return "Medium"


def create_alert(rule, matched_events, summary_info, cond_detail=None):
    """Create an enriched alert record in the DB."""
    with open(BASE_DIR / "data" / "mitre_attack.json") as f:
        mitre_db = json.load(f)

    technique_id = rule["mitre_technique"]
    technique    = mitre_db["techniques"].get(technique_id, {})
    confidence   = rule.get("confidence", 70)
    severity     = rule["severity"]

    # IOC extraction
    iocs = {
        "source_ips":    list({e.get("source_ip")    for e in matched_events if e.get("source_ip")   and e.get("source_ip")  != "N/A"}),
        "usernames":     list({e.get("user")          for e in matched_events if e.get("user")        and e.get("user")       != "N/A"}),
        "hostnames":     list({e.get("hostname")      for e in matched_events if e.get("hostname")}),
        "processes":     list({e.get("process_name")  for e in matched_events if e.get("process_name") and e.get("process_name") != "N/A"}),
        "file_hashes":   list({e.get("file_hash")    for e in matched_events if e.get("file_hash")}),
        "domains":       list({e.get("dest_domain")  for e in matched_events if e.get("dest_domain")}),
        "registry_keys": list({e.get("registry_key") for e in matched_events if e.get("registry_key")}),
    }
    iocs = {k: [v for v in vals if v] for k, vals in iocs.items()}

    first_event  = matched_events[0] if matched_events else {}
    hostname     = first_event.get("hostname", summary_info.get("victim_host", summary_info.get("target_host", "Unknown")))
    asset_crit   = _get_asset_criticality(hostname)
    risk_score   = _calculate_risk_score(severity, confidence, asset_crit)
    priority     = rule.get("priority_map", {}).get(f"{asset_crit}_asset", SEVERITY_PRIORITY.get(severity, "P3"))

    now          = datetime.now()
    sla_mins     = SLA_MINUTES.get(severity, 240)
    sla_deadline = (now + timedelta(minutes=sla_mins)).isoformat() + "Z"
    alert_id     = str(uuid.uuid4())

    # Build the alert dict — keys must match the INSERT column names
    alert = {
        "id":                 alert_id,
        "created_at":         now.isoformat() + "Z",
        "rule_id":            rule["rule_id"],
        # JSON uses key "name"; we alias it to "rule_name" for the DB column
        "rule_name":          rule.get("name", rule.get("rule_name", "Unknown Rule")),
        "severity":           severity,
        "confidence":         confidence,
        "priority":           priority,
        "status":             "New",
        "assigned_to":        "SOC Analyst L1",
        "sla_deadline":       sla_deadline,
        "sla_breached":       0,
        "hostname":           hostname,
        "user":               first_event.get("user", summary_info.get("target_user", "Unknown")),
        "source_ip":          first_event.get("source_ip", summary_info.get("attacker_ip", "Unknown")),
        "mitre_technique":    technique_id,
        "mitre_tactic":       technique.get("tactic", rule.get("mitre_tactic", "Unknown")),
        "event_ids":          json.dumps([e.get("event_id", "") for e in matched_events[:20]]),
        "iocs":               json.dumps(iocs),
        "summary":            summary_info.get("outcome", rule.get("description", "")),
        "attack_scenario":    first_event.get("attack_scenario", ""),
        "matched_conditions": json.dumps(cond_detail or []),
        "risk_score":         risk_score,
        "correlated_ids":     json.dumps([]),
        "incident_id":        None,
        "triaged_at":         None,
        "investigated_at":    None,
        "contained_at":       None,
        "closed_at":          None,
        "closure_reason":     None,
        "fp_reason":          None,
        "analyst_notes":      None,
    }

    conn = get_db()
    conn.execute("""
        INSERT INTO alerts (
            id, created_at, rule_id, rule_name, severity, confidence, priority, status,
            assigned_to, sla_deadline, sla_breached, hostname, user, source_ip,
            mitre_technique, mitre_tactic, event_ids, iocs, summary, attack_scenario,
            matched_conditions, risk_score, correlated_ids, incident_id,
            triaged_at, investigated_at, contained_at, closed_at,
            closure_reason, fp_reason, analyst_notes
        ) VALUES (
            :id, :created_at, :rule_id, :rule_name, :severity, :confidence, :priority, :status,
            :assigned_to, :sla_deadline, :sla_breached, :hostname, :user, :source_ip,
            :mitre_technique, :mitre_tactic, :event_ids, :iocs, :summary, :attack_scenario,
            :matched_conditions, :risk_score, :correlated_ids, :incident_id,
            :triaged_at, :investigated_at, :contained_at, :closed_at,
            :closure_reason, :fp_reason, :analyst_notes
        )
    """, alert)
    conn.commit()
    conn.close()

    return alert


def log_analyst_action(alert_id, action_type, details="", analyst="SOC Analyst L1"):
    """Write an audit log entry for analyst actions."""
    conn = get_db()
    conn.execute(
        "INSERT INTO analyst_actions (id, alert_id, action_type, analyst, timestamp, details) VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), alert_id, action_type, analyst, datetime.now().isoformat() + "Z", details)
    )
    conn.commit()
    conn.close()


def store_events(events):
    """Persist log events to SQLite."""
    conn = get_db()
    for event in events:
        eid   = str(uuid.uuid4())
        extra = {k: v for k, v in event.items() if k not in (
            "id", "timestamp", "hostname", "log_source", "event_id", "event_type",
            "user", "source_ip", "process_name", "command_line", "raw_log",
            "attack_scenario", "mitre_technique"
        )}
        conn.execute("""
            INSERT OR IGNORE INTO events
            (id, timestamp, hostname, log_source, event_id, event_type,
             user, source_ip, process_name, command_line, raw_log, attack_scenario, mitre_technique, extra_data)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            eid, event.get("timestamp",""), event.get("hostname",""),
            event.get("log_source",""), event.get("event_id",""), event.get("event_type",""),
            event.get("user",""), event.get("source_ip",""), event.get("process_name",""),
            event.get("command_line",""), event.get("raw_log",""),
            event.get("attack_scenario",""), event.get("mitre_technique",""),
            json.dumps(extra),
        ))
    conn.commit()
    conn.close()


def process_scenario(events, summary_info):
    """Full pipeline: store events → match rules → create alert → return alert."""
    import traceback
    store_events(events)
    rules          = load_rules()
    target_rule_id = summary_info.get("rule_id")

    if not target_rule_id:
        print(f"[WARN] process_scenario: no rule_id in summary_info: {summary_info}")
        return None

    matched_rule = next((r for r in rules if r["rule_id"] == target_rule_id), None)
    if not matched_rule:
        print(f"[WARN] process_scenario: rule_id '{target_rule_id}' not found. "
              f"Available: {[r['rule_id'] for r in rules]}")
        return None

    try:
        fired, matched, cond_detail = evaluate_rule(matched_rule, events)
        print(f"[DEBUG] rule={target_rule_id} fired={fired} matched={len(matched)} threshold={matched_rule['conditions'].get('threshold',1)}")
        if fired:
            alert = create_alert(matched_rule, matched if matched else events, summary_info, cond_detail)
            return alert
        return None
    except Exception as e:
        print(f"[ERROR] process_scenario exception for rule {target_rule_id}: {e}")
        traceback.print_exc()
        return None


if __name__ == "__main__":
    init_db()
    print("Database initialized with upgraded schema.")
    print("Tables: events, alerts, incidents, analyst_actions, assets")
    print("Assets seeded with 9 hosts.")
