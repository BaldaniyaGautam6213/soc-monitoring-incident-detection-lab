/* ================================================================
   reports.js — Incident report viewer and PDF generator
================================================================ */

window.loadReportsView = async function() {
  const container = document.getElementById('reports-alert-list');
  container.innerHTML = '<div class="empty-state"><p>Loading...</p></div>';

  try {
    const res  = await fetch(`${API}/alerts?limit=50`);
    const data = await res.json();
    renderReportCards(data.alerts);
  } catch(e) {
    container.innerHTML = '<div class="empty-state"><p>Failed to load alerts. Is the backend running?</p></div>';
  }
};

function renderReportCards(alerts) {
  const container = document.getElementById('reports-alert-list');

  if (!alerts || alerts.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/>
        </svg>
        <p>No alerts yet. Run simulations to generate alerts, then create reports here.</p>
        <button class="btn-primary" onclick="switchView('simulate')">→ Go to Simulation Console</button>
      </div>
    `;
    return;
  }

  container.innerHTML = alerts.map(alert => {
    const iocs = typeof alert.iocs === 'string'
      ? (() => { try { return JSON.parse(alert.iocs); } catch { return {}; } })()
      : (alert.iocs || {});

    const iocCount = (iocs.external_ips?.length || 0) +
                     (iocs.usernames?.length || 0) +
                     (iocs.file_hashes?.length || 0) +
                     (iocs.domains?.length || 0);

    return `
      <div class="report-card">
        <div class="rc-header">
          <div class="rc-title">${escHtml(alert.rule_name)}</div>
          <span class="alert-sev-badge badge-${alert.severity}">${alert.severity}</span>
        </div>
        <div class="rc-meta">
          <div><strong>Alert ID:</strong> INC-${escHtml(alert.id.slice(0,8).toUpperCase())}</div>
          <div><strong>Host:</strong> ${escHtml(alert.hostname)} &nbsp; <strong>User:</strong> ${escHtml(alert.user)}</div>
          <div><strong>MITRE:</strong> <span class="mitre-badge">${escHtml(alert.mitre_technique)}</span></div>
          <div><strong>Status:</strong> <span class="status-badge status-${alert.status}">${alert.status}</span></div>
          <div><strong>Detected:</strong> ${formatTime(alert.created_at)}</div>
          <div><strong>IOCs Extracted:</strong> ${iocCount} indicators</div>
        </div>
        <div class="rc-meta" style="color:var(--text-dim);font-size:10.5px">
          ${escHtml(alert.summary || '')}
        </div>
        <div class="rc-actions">
          <button class="btn-primary" onclick="generateReport('${alert.id}')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            Download PDF
          </button>
          <button class="btn-sm" onclick="investigateAlert('${alert.id}')">
            Investigate →
          </button>
        </div>
      </div>
    `;
  }).join('');
}
