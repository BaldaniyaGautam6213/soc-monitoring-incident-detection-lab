/* ================================================================
   dashboard.js — SOC ops dashboard: incident queue, MTTA/MTTR/SLA, live feed
================================================================ */

const API = (window.location.origin.startsWith('http') ? window.location.origin : 'http://localhost:5000') + '/api';
let socket = null;
let openAlertCount = 0;

// ─── WebSocket ────────────────────────────────────────────────

function initWebSocket() {
  const socketUrl = window.location.origin.startsWith('http') ? window.location.origin : 'http://localhost:5000';
  socket = io(socketUrl, {
    transports: ['websocket', 'polling'],
    reconnectionDelay: 1000,
    reconnectionAttempts: 10,
  });

  socket.on('connect', () => {
    setWsStatus('connected');
    appendLog('[ WebSocket connected — Real-time monitoring active ]', 'log-system');
  });

  socket.on('disconnect', () => {
    setWsStatus('disconnected');
    appendLog('[ WebSocket disconnected — attempting to reconnect... ]', 'log-error');
  });

  socket.on('connected', (data) => {
    appendLog(`[ Session: ${data.sid} ]`, 'log-info');
  });

  socket.on('attack_log', (data) => {
    const cls = data.event_type === 'SUCCESSFUL_LOGIN' ? 'log-error'
              : data.event_type === 'PRIVILEGE_USE'    ? 'log-error'
              : data.event_type === 'FAILED_LOGIN'     ? 'log-warning'
              : data.event_type === 'NETWORK_SCAN'     ? 'log-warning'
              : 'log-info';
    appendLog(`[${data.log_source}] ${data.event_type} | ${data.hostname || ''} | ${data.raw_log}`, cls);
    appendTerminal(data.raw_log, 'term-info');
  });

  socket.on('new_alert', (data) => {
    const alert = data.alert;
    openAlertCount++;
    updateAlertBadge(openAlertCount);
    showToast(
      `🚨 ALERT: ${alert.rule_name}`,
      `${alert.severity} | Confidence: ${alert.confidence}% | ${alert.mitre_technique}`,
      alert.severity
    );
    appendLog(`[ALERT] ${alert.rule_name} | ${alert.severity} | Conf: ${alert.confidence}% | ${alert.mitre_technique}`, 'log-alert');
    loadStats();
  });

  socket.on('incident_created', (data) => {
    showToast('🔗 Multi-Stage Attack Detected', 'Correlated alerts grouped into an incident', 'Critical');
    appendLog('[INCIDENT] Multi-stage attack chain correlated — check Incidents view', 'log-error');
  });

  socket.on('simulation_start', (data) => {
    appendTerminal(`\n[+] Launching: ${data.scenario?.toUpperCase()}`, 'term-cmd');
    appendTerminal('[*] Generating telemetry...', 'term-info');
  });

  socket.on('simulation_end', (data) => {
    if (data.success) {
      appendTerminal(`\n[!] DETECTION: ${data.rule_name}`, 'term-alert');
      appendTerminal(`[!] Severity: ${data.severity} | Priority: ${data.priority} | Confidence: ${data.confidence}%`, 'term-alert');
      appendTerminal(`[+] Alert saved | IOCs extracted | MITRE mapped`, 'term-success');
    } else {
      appendTerminal(`[-] No detection fired.`, 'term-warn');
    }
    appendTerminal(`\nroot@soc-lab:~# `, 'term-prompt');
    document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('running'));
    document.getElementById('btn-simulate-all').disabled = false;
  });

  socket.on('simulation_error', (data) => {
    appendTerminal(`[ERROR] ${data.error}`, 'term-error');
  });

  socket.on('alert_updated', () => loadStats());
}

function setWsStatus(state) {
  const dot   = document.getElementById('ws-dot');
  const label = document.getElementById('ws-label');
  dot.className   = `ws-dot ${state}`;
  label.textContent = state === 'connected' ? 'Connected' : 'Disconnected';
}

// ─── Navigation ───────────────────────────────────────────────

window.switchView = function(view) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const viewEl = document.getElementById(`view-${view}`);
  const navEl  = document.getElementById(`nav-${view}`);
  if (viewEl) viewEl.classList.add('active');
  if (navEl)  navEl.classList.add('active');

  const titles = {
    dashboard:     ['Security Operations Center',     'Detection · Triage · Investigation · Response'],
    alerts:        ['Alert Management',               'Investigate and triage security alerts'],
    incidents:     ['Incident Management',            'Correlated multi-stage attack chains'],
    simulate:      ['Attack Simulation Console',      'Simulate real-world attack scenarios with full telemetry'],
    mitre:         ['MITRE ATT&CK Coverage',          'Lab detection coverage across ATT&CK framework'],
    metrics:       ['SOC Performance Metrics',        'MTTD · MTTA · MTTR · SLA · False Positive Rate'],
    reports:       ['Incident Reports',               'Generate and download PDF incident reports'],
    investigation: ['Alert Investigation',            'Deep-dive analyst console'],
  };

  if (titles[view]) {
    document.getElementById('page-title').textContent    = titles[view][0];
    document.getElementById('page-subtitle').textContent = titles[view][1];
  }

  if (view === 'alerts')    loadAlerts();
  if (view === 'incidents') loadIncidentsView();
  if (view === 'mitre')     loadMitreHeatmap();
  if (view === 'simulate')  loadScenarioCards();
  if (view === 'reports')   loadReportsView();
  if (view === 'metrics')   loadMetricsView();
};

document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

// ─── Stats ────────────────────────────────────────────────────

async function loadStats() {
  try {
    const res  = await fetch(`${API}/stats`);
    const data = await res.json();

    // SOC-ops KPIs
    document.getElementById('kpi-open').textContent     = data.open_alerts;
    document.getElementById('kpi-critical').textContent = data.critical_count;
    document.getElementById('kpi-sla-risk').textContent = data.sla_at_risk;
    document.getElementById('kpi-mtta').textContent     = data.mtta_display || 'N/A';
    document.getElementById('kpi-mttr').textContent     = data.mttr_display || 'N/A';
    document.getElementById('kpi-fp-rate').textContent  = (data.fp_rate ?? 0) + '%';

    openAlertCount = data.open_alerts;
    updateAlertBadge(openAlertCount);

    // SLA card color
    const slaCard = document.getElementById('kpi-sla-card');
    if (slaCard) {
      slaCard.style.borderTopColor = data.sla_at_risk > 0 ? 'var(--orange)' : 'var(--border-light)';
    }

    // Severity bars
    const sev   = data.severity_breakdown;
    const total = Math.max(data.total_alerts, 1);
    ['critical','high','medium','low'].forEach(s => {
      const key = s.charAt(0).toUpperCase() + s.slice(1);
      const pct = Math.round((sev[key] / total) * 100);
      const bar = document.getElementById(`bar-${s}`);
      const cnt = document.getElementById(`cnt-${s}`);
      if (bar) bar.style.width = `${pct}%`;
      if (cnt) cnt.textContent  = sev[key];
    });

    // TP/FP quality bars
    const totalClosed = Math.max((data.true_positives || 0) + (data.false_positives || 0), 1);
    const tpPct = Math.round(((data.true_positives || 0) / totalClosed) * 100);
    const fpPct = Math.round(((data.false_positives || 0) / totalClosed) * 100);
    const barTp = document.getElementById('bar-tp');
    const barFp = document.getElementById('bar-fp');
    const tpCnt = document.getElementById('tp-count');
    const fpCnt = document.getElementById('fp-count');
    if (barTp) barTp.style.width = `${tpPct}%`;
    if (barFp) barFp.style.width = `${fpPct}%`;
    if (tpCnt) tpCnt.textContent  = data.true_positives || 0;
    if (fpCnt) fpCnt.textContent  = data.false_positives || 0;

    // Incident queue table
    renderIncidentQueue(data.incident_queue || []);

    // Tactics breakdown
    renderTactics(data.tactics || {});

  } catch(e) {
    console.error('Stats error:', e);
  }
}

// ─── Incident Queue ───────────────────────────────────────────

function renderIncidentQueue(queue) {
  const tbody = document.getElementById('incident-queue-tbody');
  if (!tbody) return;

  if (!queue.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No open alerts. Run a simulation to populate the queue.</td></tr>';
    return;
  }

  tbody.innerHTML = queue.map(a => {
    const slaClass = a.sla_breached ? 'sla-badge-breached'
                   : a.sla_at_risk  ? 'sla-badge-risk'
                   : 'sla-badge-ok';
    return `
      <tr onclick="investigateAlert('${a.id}')" style="cursor:pointer">
        <td><span class="alert-sev-badge badge-${a.severity}">${a.severity}</span></td>
        <td style="font-size:12px;font-weight:500">${escHtml(a.rule_name)}</td>
        <td style="font-family:var(--mono);font-size:11px">${escHtml(a.hostname)}</td>
        <td><span class="status-badge status-${a.status}">${a.status}</span></td>
        <td><span class="priority-badge">${a.priority || 'P2'}</span></td>
        <td><span class="sla-badge ${slaClass}">${escHtml(a.sla_remaining_display || 'N/A')}</span></td>
        <td><button class="btn-sm" onclick="event.stopPropagation();investigateAlert('${a.id}')">Investigate</button></td>
      </tr>
    `;
  }).join('');
}

// ─── Tactics ──────────────────────────────────────────────────

function renderTactics(tactics) {
  const el = document.getElementById('tactics-list');
  if (!el) return;

  if (!tactics || Object.keys(tactics).length === 0) {
    el.innerHTML = '<div class="empty-state-sm">Run simulations to see tactic breakdown</div>';
    return;
  }

  const maxVal = Math.max(...Object.values(tactics), 1);
  const tacticColors = {
    'Credential Access':   'var(--red)',
    'Execution':           'var(--orange)',
    'Persistence':         'var(--purple)',
    'Privilege Escalation':'var(--red)',
    'Discovery':           'var(--yellow)',
    'Defense Evasion':     'var(--electric)',
    'Lateral Movement':    'var(--orange)',
    'Command and Control': 'var(--red)',
  };

  el.innerHTML = Object.entries(tactics).map(([tactic, count]) => `
    <div class="severity-bar-row" style="margin-bottom:8px">
      <span class="sev-label" style="width:160px;font-size:11px;color:var(--text-dim)">${tactic}</span>
      <div class="sev-bar-wrap">
        <div class="sev-bar" style="width:${Math.round((count/maxVal)*100)}%;background:${tacticColors[tactic]||'var(--electric)'}"></div>
      </div>
      <span class="sev-count">${count}</span>
    </div>
  `).join('');
}

// ─── Alerts Table ─────────────────────────────────────────────

let currentPage = 0;
const PAGE_SIZE  = 20;

window.loadAlerts = async function() {
  const search   = document.getElementById('alert-search')?.value  || '';
  const severity = document.getElementById('filter-severity')?.value || '';
  const status   = document.getElementById('filter-status')?.value  || '';
  const params   = new URLSearchParams({ limit: PAGE_SIZE, offset: currentPage * PAGE_SIZE });
  if (search)   params.set('search', search);
  if (severity) params.set('severity', severity);
  if (status)   params.set('status', status);

  try {
    const res  = await fetch(`${API}/alerts?${params}`);
    const data = await res.json();
    renderAlertsTable(data.alerts);
    renderPagination(data.total);
  } catch(e) {
    document.getElementById('alerts-tbody').innerHTML =
      '<tr><td colspan="9" class="table-empty">Failed to load. Is the backend running?</td></tr>';
  }
};

function renderAlertsTable(alerts) {
  const tbody = document.getElementById('alerts-tbody');
  if (!alerts || !alerts.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="table-empty">No alerts found. Run a simulation to generate alerts.</td></tr>';
    return;
  }

  tbody.innerHTML = alerts.map(a => {
    const slaClass = a.sla_breached ? 'sla-badge-breached'
                   : a.sla_at_risk  ? 'sla-badge-risk'
                   : 'sla-badge-ok';
    return `
      <tr onclick="investigateAlert('${a.id}')" style="cursor:pointer">
        <td><span class="alert-sev-badge badge-${a.severity}">${a.severity}</span></td>
        <td style="font-size:12px;max-width:200px">${escHtml(a.rule_name)}</td>
        <td style="font-family:var(--mono);font-size:11px">${escHtml(a.hostname)}</td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">${escHtml(a.source_ip)}</td>
        <td><span class="mitre-badge">${escHtml(a.mitre_technique)}</span></td>
        <td><span class="status-badge status-${a.status}">${a.status}</span></td>
        <td><span class="priority-badge">${a.priority || 'P2'}</span></td>
        <td><span class="sla-badge ${slaClass}">${escHtml(a.sla_remaining_display || 'N/A')}</span></td>
        <td><button class="btn-sm" onclick="event.stopPropagation();investigateAlert('${a.id}')">Investigate</button></td>
      </tr>
    `;
  }).join('');
}

function renderPagination(total) {
  const pages = Math.ceil(total / PAGE_SIZE);
  const pEl   = document.getElementById('alerts-pagination');
  if (!pEl || pages <= 1) { if (pEl) pEl.innerHTML = ''; return; }
  pEl.innerHTML = Array.from({length: pages}, (_, i) =>
    `<button class="page-btn${i === currentPage ? ' active' : ''}" onclick="currentPage=${i};loadAlerts()">${i+1}</button>`
  ).join('');
}

document.getElementById('alert-search')?.addEventListener('input', debounce(loadAlerts, 400));
document.getElementById('filter-severity')?.addEventListener('change', loadAlerts);
document.getElementById('filter-status')?.addEventListener('change', loadAlerts);

// ─── Simulate All ─────────────────────────────────────────────

window.simulateAll = async function() {
  const btn = document.getElementById('btn-simulate-all');
  btn.disabled = true;
  btn.textContent = 'Running all 6 scenarios...';
  appendTerminal('\n[+] Running ALL 6 attack scenarios...', 'term-cmd');

  try {
    await fetch(`${API}/simulate/all`, { method: 'POST' });
  } catch(e) {
    appendTerminal('[ERROR] Backend not reachable', 'term-error');
    btn.disabled = false;
  }

  setTimeout(() => {
    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run All 6 Scenarios`;
  }, 20000);
};

// ─── Log helpers ──────────────────────────────────────────────

function appendLog(msg, cls = 'log-info') {
  const el = document.getElementById('log-stream');
  if (!el) return;
  const line = document.createElement('div');
  line.className   = `log-line ${cls}`;
  line.textContent = msg.length > 220 ? msg.slice(0, 220) + '…' : msg;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
  const lines = el.querySelectorAll('.log-line');
  if (lines.length > 200) lines[0].remove();
}

window.appendTerminal = function(msg, cls = 'term-info') {
  const el = document.getElementById('sim-terminal');
  if (!el) return;
  const line = document.createElement('div');
  line.className   = `term-line ${cls}`;
  line.textContent = msg;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
};

// ─── Toasts ───────────────────────────────────────────────────

window.showToast = function(title, body, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  const cls   = type === 'Critical' ? 'toast-critical'
              : type === 'High'     ? 'toast-high'
              : type === 'success'  ? 'toast-success'
              : 'toast-info';
  toast.className = `toast ${cls}`;
  toast.innerHTML = `
    <div class="toast-title">${escHtml(title)}</div>
    <div class="toast-body">${escHtml(body)}</div>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 6000);
};

// ─── Badge & Clock ────────────────────────────────────────────

function updateAlertBadge(count) {
  const badge = document.getElementById('nav-badge');
  if (badge) { badge.textContent = count; badge.classList.toggle('visible', count > 0); }
}

function updateClock() {
  const el = document.getElementById('topbar-time');
  if (el) el.textContent = new Date().toUTCString().slice(17, 25) + ' UTC';
}

// ─── Utilities ────────────────────────────────────────────────

window.formatTime = function(iso) {
  if (!iso) return '—';
  const d = new Date(iso.replace('Z', ''));
  return d.toLocaleString('en-IN', { hour12: false }).replace(',', '');
};

window.escHtml = function(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
};

function debounce(fn, delay) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}

// ─── Scenario Cards ───────────────────────────────────────────

const MITRE_COLORS = {
  'T1110.001': '#e53935', 'T1059.001': '#fb8c00', 'T1204.002': '#c62828',
  'T1046':     '#f9a825', 'T1134':     '#e53935', 'T1547.001': '#7b1fa2',
};

window.loadScenarioCards = async function() {
  try {
    const res  = await fetch(`${API}/scenarios`);
    const data = await res.json();
    const container = document.getElementById('scenario-cards');
    if (!container) return;

    container.innerHTML = Object.entries(data).map(([key, s]) => `
      <div class="scenario-card" id="sc-${key}" onclick="simulateSingle('${key}')">
        <div class="sc-top">
          <div class="sc-name">${escHtml(s.name)}</div>
          <span class="sc-sev badge-${s.severity}" style="font-size:10px;padding:2px 7px;border-radius:10px;font-weight:700;background:${MITRE_COLORS[s.mitre] || '#444'};color:#fff">${s.severity}</span>
        </div>
        <div class="sc-desc">${escHtml(s.description)}</div>
        <div class="sc-footer">
          <span class="mitre-badge">${escHtml(s.mitre)}</span>
          <span style="font-size:10px;color:var(--text-dim)">${escHtml(s.log_source)}</span>
        </div>
        <div class="sc-run-btn">▶ Run Simulation</div>
      </div>
    `).join('');
  } catch(e) { console.error('Scenario cards error:', e); }
};

window.simulateSingle = async function(scenario) {
  const card = document.getElementById(`sc-${scenario}`);
  if (card) card.classList.add('running');
  appendTerminal(`\nroot@soc-lab:~# ./simulate.py --scenario ${scenario}`, 'term-cmd');

  try {
    const res = await fetch(`${API}/simulate/${scenario}`, { method: 'POST' });
    if (!res.ok) showToast('Error', 'Simulation failed', 'Critical');
  } catch(e) {
    appendTerminal(`[ERROR] ${e.message}`, 'term-error');
    if (card) card.classList.remove('running');
  }
};

// ─── Init ─────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initWebSocket();
  loadStats();
  setInterval(loadStats, 30000);
  setInterval(updateClock, 1000);
  updateClock();
});

window.API    = API;
window.socket = () => socket;
