/* ================================================================
   incidents.js — Correlated incident view + attack storyline
================================================================ */

window.loadIncidentsView = async function() {
  const container = document.getElementById('incidents-content');
  container.innerHTML = '<div class="empty-state"><p>Loading incidents...</p></div>';

  try {
    const res  = await fetch(`${API}/incidents`);
    const data = await res.json();
    renderIncidents(data.incidents);
  } catch(e) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load incidents. Is the backend running?</p></div>`;
  }
};

function renderIncidents(incidents) {
  const container = document.getElementById('incidents-content');

  if (!incidents || incidents.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <p>No correlated incidents yet.</p>
        <p style="font-size:12px;color:var(--text-dim);max-width:400px;text-align:center">
          Run multiple attack simulations including brute force, PowerShell, and persistence
          to trigger multi-stage attack chain detection.
        </p>
        <button class="btn-primary" onclick="switchView('simulate')">→ Go to Simulation Console</button>
      </div>
    `;
    return;
  }

  container.innerHTML = incidents.map(inc => renderIncidentCard(inc)).join('');
}

function renderIncidentCard(inc) {
  const chain      = inc.storyline || [];
  const alertCount = (inc.alert_ids || []).length;

  return `
    <div class="incident-card">

      <!-- Header -->
      <div class="inc-header">
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <span class="alert-sev-badge badge-${inc.severity}">${inc.severity}</span>
          <h3 class="inc-title">${escHtml(inc.title)}</h3>
        </div>
        <div style="display:flex;align-items:center;gap:10px">
          <span class="status-badge status-${inc.status}">${inc.status}</span>
          <span style="font-size:11px;color:var(--text-muted)">${formatTime(inc.created_at)}</span>
        </div>
      </div>

      <!-- Warning -->
      <div class="inc-warning">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        Potential multi-stage intrusion detected — ${alertCount} correlated alerts. Analyst investigation required.
      </div>

      <!-- Summary -->
      <div class="inc-summary">${escHtml(inc.summary)}</div>

      <!-- Attack Storyline -->
      ${chain.length > 0 ? `
        <div style="margin-top:16px">
          <div style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px">Attack Storyline</div>
          <div class="attack-chain">
            ${chain.map((step, i) => `
              <div class="chain-step">
                <div class="chain-connector">${i > 0 ? '<div class="chain-arrow">↓</div>' : ''}</div>
                <div class="chain-node chain-${severityFromTactic(step.tactic)}">
                  <div class="chain-time">${step.time || ''}</div>
                  <div class="chain-label">${escHtml(step.label)}</div>
                  <div class="chain-technique">
                    <span class="mitre-badge" style="font-size:10px">${escHtml(step.technique)}</span>
                    <span style="font-size:10px;color:var(--text-dim)">${escHtml(step.tactic)}</span>
                  </div>
                  ${step.hostname ? `<div style="font-size:10px;color:var(--text-dim);margin-top:2px">${escHtml(step.hostname)}</div>` : ''}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <!-- Actions -->
      <div class="inc-actions">
        <span style="font-size:11px;color:var(--text-muted)">${alertCount} correlated alert${alertCount !== 1 ? 's' : ''}</span>
        <button class="btn-primary" onclick="viewIncidentAlerts('${escHtml(inc.id)}')">
          → Investigate All Alerts
        </button>
      </div>

    </div>
  `;
}

function severityFromTactic(tactic) {
  const criticalTactics = ['Credential Access', 'Privilege Escalation', 'Execution'];
  const highTactics     = ['Persistence', 'Defense Evasion', 'Lateral Movement'];
  if (criticalTactics.includes(tactic)) return 'critical';
  if (highTactics.includes(tactic))     return 'high';
  return 'medium';
}

window.viewIncidentAlerts = async function(incidentId) {
  try {
    const res  = await fetch(`${API}/incidents/${incidentId}`);
    const data = await res.json();
    if (data.alerts && data.alerts.length > 0) {
      // Open investigation of the most severe alert
      const sorted = [...data.alerts].sort((a, b) => {
        const order = {Critical:0,High:1,Medium:2,Low:3};
        return (order[a.severity]||4) - (order[b.severity]||4);
      });
      investigateAlert(sorted[0].id);
    }
  } catch(e) {
    showToast('Error', 'Failed to load incident details', 'Critical');
  }
};
