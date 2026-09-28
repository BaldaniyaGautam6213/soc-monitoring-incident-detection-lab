# SOC Monitoring & Incident Detection Lab

> **Resume Title:** SOC Monitoring & Incident Detection Lab using Wazuh-style Detection Engine and MITRE ATT&CK

A self-contained, interview-grade Security Operations Center (SOC) simulation platform built in Python + Flask. Demonstrates the full **SOC L1 analyst thought process** — from raw telemetry to incident closure.

---

## 🎯 What This Demonstrates

```
Telemetry → Detection → Correlation → Triage → Investigation
         → Enrichment → Decision → Response → Documentation → Metrics
```

Built for cybersecurity job applications to show practical SOC skills **without requiring real infrastructure**.

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask, Flask-SocketIO |
| Detection Engine | Sigma-style rule engine (custom) |
| Database | SQLite |
| Log Simulation | Custom attack scenario generator |
| MITRE ATT&CK | Full technique mapping + heatmap |
| IOC Extraction | Regex + threat intel enrichment |
| Reporting | ReportLab PDF generation |
| Frontend | Vanilla JS, WebSocket (real-time) |
| Correlation | Multi-alert incident grouping |

---

## ⚔️ Attack Scenarios Simulated

| Scenario | MITRE Technique | Log Source |
|---|---|---|
| Brute Force Login | T1110.001 — Password Guessing | Windows Security (4625/4624) |
| Suspicious PowerShell | T1059.001 — PowerShell | Sysmon Event ID 1 |
| Malicious Office Macro | T1204.002 — User Execution | Sysmon Event ID 1 |
| Network Port Scan | T1046 — Network Discovery | Suricata (ET SCAN) |
| Access Token Manipulation | T1134 — Token Manipulation | Windows Security (4672/4673) |
| Registry Persistence | T1547.001 — Run Key | Sysmon Event ID 13 |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Frontend (Browser)                    │
│  Dashboard │ Simulation │ Investigation │ Reports │ MITRE│
└──────────────────────┬──────────────────────────────────┘
                       │ WebSocket (real-time) + REST API
┌──────────────────────▼──────────────────────────────────┐
│                  Flask Backend                          │
│                                                         │
│  log_simulator.py   →   detection_engine.py             │
│  (Attack Generator)     (Sigma-style Rule Evaluator)    │
│                              │                          │
│  ioc_extractor.py   ←────────┤                          │
│  correlation.py     ←────────┤                          │
│  mitre_mapper.py    ←────────┤                          │
│  report_generator.py ←───────┘                          │
│                              │                          │
│                         SQLite DB                       │
│           (events, alerts, incidents, audit trail)      │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
```bash
pip install flask flask-cors flask-socketio reportlab
```

### Run
```bash
cd backend
python app.py
```

Open **http://localhost:5000** in your browser.

### Simulate attacks
1. Go to **Attack Simulation** tab
2. Click any scenario card **or** click **Run All 6 Scenarios**
3. Watch real-time logs stream in the terminal
4. Alerts fire automatically with MITRE mapping, IOC extraction, confidence scoring

---

## 📁 Project Structure

```
soc-lab/
├── backend/
│   ├── app.py                  # Flask server + WebSocket + API routes
│   ├── detection_engine.py     # Sigma-style rule engine, alert lifecycle, SLA
│   ├── log_simulator.py        # Attack scenario generators (6 scenarios)
│   ├── ioc_extractor.py        # IOC extraction + threat intel enrichment
│   ├── correlation.py          # Multi-alert incident correlation
│   ├── mitre_mapper.py         # MITRE ATT&CK technique mapping + heatmap
│   ├── report_generator.py     # PDF incident report generation (ReportLab)
│   ├── metrics.py              # MTTA, MTTR, SLA, detection coverage metrics
│   └── data/
│       ├── detection_rules.json    # Sigma-style detection rules
│       ├── mitre_attack.json       # ATT&CK technique database
│       └── playbooks.json          # NIST IR response playbooks
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   └── js/
│       ├── dashboard.js        # Main dashboard, WebSocket, live feed
│       ├── investigation.js    # Alert investigation console
│       ├── reports.js          # Reports view
│       ├── incidents.js        # Incident management
│       ├── mitre.js            # MITRE ATT&CK heatmap
│       └── metrics.js          # SOC metrics dashboard
└── reports/                    # Generated PDF reports (gitignored)
```

---

## 🔍 Key Features

### Detection Engine (Sigma-style)
- Field matching + regex conditions
- Threshold-based triggering (e.g. 5+ failed logins in 60s)
- Confidence scoring per rule (79–91%)
- SLA deadlines: Critical=15min, High=30min, Medium=4h, Low=24h
- Asset criticality-aware risk scoring

### Investigation Console
- Raw event log viewer
- Process tree visualization
- Attack timeline narrative
- IOC extraction panel
- MITRE ATT&CK technique card
- NIST IR playbook with checkable steps
- "Why Fired?" rule transparency view

### Incident Management
- Multi-alert correlation into incidents
- Full lifecycle: New → Triaged → Investigating → Containment → Eradication → Recovery → Closed
- Audit trail for every analyst action
- PDF export with custom filename

### MITRE ATT&CK Coverage
- Technique heatmap showing which ATT&CK techniques are covered
- Coverage % by tactic
- Per-technique alert counts

---

## 📊 SOC Metrics Tracked

- MTTA (Mean Time to Acknowledge)
- MTTR (Mean Time to Respond)
- SLA compliance rate
- True Positive / False Positive ratio
- Detection coverage by MITRE tactic
- Alerts by severity trend

---

## 🏆 Resume Bullets

> • Built a simulated SOC environment using a custom Sigma-style detection engine, Sysmon-style event simulation, and MITRE ATT&CK mapping to monitor and investigate 6 attack scenarios across Windows/Linux/Network telemetry.
>
> • Developed detection rules for brute-force attacks (T1110.001), suspicious PowerShell execution (T1059.001), malicious Office macros (T1204.002), port scanning (T1046), access token manipulation (T1134), and registry persistence (T1547.001).
>
> • Implemented a full incident response lifecycle (New → Closed) with IOC extraction, threat intel enrichment, asset criticality-aware risk scoring, SLA tracking, and automated PDF incident report generation.
>
> • Built real-time WebSocket telemetry streaming, MITRE ATT&CK heatmap visualization, SOC metrics dashboard (MTTA/MTTR/SLA), and a styled investigation console with analyst audit trail.

---

## ⚠️ Disclaimer

This is a self-contained simulation for educational/portfolio purposes. All attack scenarios generate synthetic log data — no real systems are targeted.

---

## 📄 License

MIT
