/* ================================================================
   metrics.js — SOC performance metrics: MTTD, MTTA, MTTR, SLA, FP rate
================================================================ */

window.loadMetricsView = async function() {
  const container = document.getElementById('metrics-content');
  container.innerHTML = '<div class="empty-state"><p>Loading metrics...</p></div>';

  try {
    const res  = await fetch(`${API}/metrics`);
    const data = await res.json();
    renderMetrics(data);
  } catch(e) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load metrics. Is the backend running?</p></div>`;
  }
};

function renderMetrics(m) {
  const container = document.getElementById('metrics-content');

  if (m.total_alerts === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <p>No data yet. Run simulations and classify some alerts as True/False Positive to generate metrics.</p>
        <button class="btn-primary" onclick="switchView('simulate')">→ Run Simulations</button>
      </div>`;
    return;
  }

  const slaRows = Object.entries(m.sla_compliance || {}).map(([sev, d]) => `
    <tr>
      <td><span class="alert-sev-badge badge-${sev}">${sev}</span></td>
      <td style="font-family:var(--mono)">${d.sla_minutes < 60 ? d.sla_minutes + 'm' : Math.round(d.sla_minutes/60) + 'h'}</td>
      <td>${d.total}</td>
      <td style="color:var(--green)">${d.within_sla}</td>
      <td style="color:${d.breached > 0 ? 'var(--red)' : 'var(--text-muted)'}">${d.breached}</td>
      <td>
        <div class="sev-bar-wrap" style="width:120px;display:inline-block">
          <div class="sev-bar" style="width:${d.compliance_pct}%;background:${d.compliance_pct >= 80 ? 'var(--green)' : d.compliance_pct >= 50 ? 'var(--orange)' : 'var(--red)'}"></div>
        </div>
        <span style="font-size:11px;color:var(--text-muted);margin-left:6px">${d.compliance_pct}%</span>
      </td>
    </tr>
  `).join('');

  const ruleRows = (m.rule_quality || []).map(r => `
    <tr>
      <td style="font-family:var(--mono);font-size:11px">${escHtml(r.rule_id)}</td>
      <td style="font-size:12px">${escHtml(r.rule_name.slice(0, 40))}${r.rule_name.length > 40 ? '…' : ''}</td>
      <td>${r.total}</td>
      <td style="color:var(--green)">${r.tp}</td>
      <td style="color:${r.fp > 0 ? 'var(--orange)' : 'var(--text-muted)'}">${r.fp}</td>
      <td style="color:${r.fp_rate > 30 ? 'var(--red)' : r.fp_rate > 10 ? 'var(--orange)' : 'var(--green)'}">${r.fp_rate}%</td>
    </tr>
  `).join('');

  const tacticBars = Object.entries(m.tactics_detected || {}).map(([tactic, count]) => `
    <div class="severity-bar-row">
      <span class="sev-label" style="width:180px;color:var(--text-dim)">${escHtml(tactic)}</span>
      <div class="sev-bar-wrap">
        <div class="sev-bar bar-high" style="width:${Math.min(100, count * 15)}%;background:var(--electric)"></div>
      </div>
      <span class="sev-count">${count}</span>
    </div>
  `).join('');

  container.innerHTML = `

    <!-- ─── Time Metrics ─── -->
    <div class="metrics-kpi-row">

      <div class="metric-card">
        <div class="metric-label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          MTTD
          <span class="metric-hint">Mean Time to Detect</span>
        </div>
        <div class="metric-value">${escHtml(m.mttd_display)}</div>
        <div class="metric-desc">First event → alert fired</div>
      </div>

      <div class="metric-card">
        <div class="metric-label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          MTTA
          <span class="metric-hint">Mean Time to Acknowledge</span>
        </div>
        <div class="metric-value ${m.mtta_minutes === null ? 'metric-na' : ''}">${escHtml(m.mtta_display)}</div>
        <div class="metric-desc">Alert created → first analyst action</div>
      </div>

      <div class="metric-card">
        <div class="metric-label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          MTTR
          <span class="metric-hint">Mean Time to Respond</span>
        </div>
        <div class="metric-value ${m.mttr_minutes === null ? 'metric-na' : ''}">${escHtml(m.mttr_display)}</div>
        <div class="metric-desc">Alert created → closed/resolved</div>
      </div>

      <div class="metric-card ${m.fp_rate > 30 ? 'metric-warn' : ''}">
        <div class="metric-label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
          FP Rate
          <span class="metric-hint">False Positive Rate</span>
        </div>
        <div class="metric-value" style="color:${m.fp_rate > 30 ? 'var(--red)' : m.fp_rate > 15 ? 'var(--orange)' : 'var(--green)'}">${m.fp_rate}%</div>
        <div class="metric-desc">Of ${m.closed_alerts} classified alerts</div>
      </div>

      <div class="metric-card">
        <div class="metric-label">TP / FP Split</div>
        <div style="display:flex;gap:16px;align-items:baseline;margin:8px 0">
          <div><span style="font-size:24px;font-weight:800;color:var(--green)">${m.true_positives}</span><span style="font-size:11px;color:var(--text-muted);margin-left:4px">TP</span></div>
          <div style="color:var(--text-dim)">/</div>
          <div><span style="font-size:24px;font-weight:800;color:${m.false_positives > 0 ? 'var(--orange)' : 'var(--text-muted)'}">${m.false_positives}</span><span style="font-size:11px;color:var(--text-muted);margin-left:4px">FP</span></div>
        </div>
        <div class="metric-desc">From ${m.closed_alerts} closed alerts</div>
      </div>

      <div class="metric-card">
        <div class="metric-label">Alert Volume</div>
        <div class="metric-value">${m.total_alerts}</div>
        <div class="metric-desc">${m.open_alerts} open · ${m.closed_alerts} closed</div>
      </div>

    </div>

    <!-- ─── SLA Compliance ─── -->
    <div class="metrics-section">
      <div class="metrics-section-header">
        <h3>SLA Compliance by Severity</h3>
        <span class="metrics-note">Critical=15m · High=30m · Medium=4h · Low=24h</span>
      </div>
      ${slaRows ? `
        <div class="alerts-table-wrap">
          <table class="alerts-table">
            <thead><tr>
              <th>Severity</th><th>SLA Target</th><th>Total</th>
              <th>Within SLA</th><th>Breached</th><th>Compliance</th>
            </tr></thead>
            <tbody>${slaRows}</tbody>
          </table>
        </div>
      ` : '<div class="empty-state-sm">No closed alerts yet — SLA data will appear after alerts are investigated and closed.</div>'}
    </div>

    <!-- ─── Detection Quality Per Rule ─── -->
    <div class="metrics-section">
      <div class="metrics-section-header">
        <h3>Detection Quality by Rule</h3>
        <span class="metrics-note">Classify alerts as True/False Positive to populate this table</span>
      </div>
      ${ruleRows ? `
        <div class="alerts-table-wrap">
          <table class="alerts-table">
            <thead><tr>
              <th>Rule ID</th><th>Rule Name</th><th>Total</th>
              <th>True Positive</th><th>False Positive</th><th>FP Rate</th>
            </tr></thead>
            <tbody>${ruleRows || '<tr><td colspan="6" class="table-empty">No classified alerts yet</td></tr>'}</tbody>
          </table>
        </div>
      ` : '<div class="empty-state-sm">No classified alerts yet.</div>'}
    </div>

    <!-- ─── ATT&CK Tactic Coverage ─── -->
    <div class="metrics-section">
      <div class="metrics-section-header">
        <h3>Lab Detection Coverage by Tactic</h3>
        <span class="metrics-note">Detections observed in this lab environment — not enterprise ATT&CK coverage</span>
      </div>
      ${tacticBars || '<div class="empty-state-sm">Run simulations to see tactic coverage</div>'}
    </div>

  `;
}
