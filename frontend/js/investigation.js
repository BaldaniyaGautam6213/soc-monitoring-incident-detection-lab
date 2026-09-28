/* ================================================================
   investigation.js — Full SOC analyst investigation console
   Tabs: Raw Events | Process Tree | Timeline | IOCs | MITRE | Playbook | Why Fired?
================================================================ */

/* ----------------------------------------------------------------
   showModal(config) — reusable styled modal (replaces prompt())
   config: { title, icon, fields: [{id, label, type, placeholder, value, required}], submitLabel, onSubmit }
---------------------------------------------------------------- */
function showModal(config) {
  // Remove any existing modal
  document.getElementById('soc-modal-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.id = 'soc-modal-overlay';
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:9999;
    background:rgba(0,0,0,0.7);
    backdrop-filter:blur(4px);
    display:flex;align-items:center;justify-content:center;
    animation:fadeIn 0.15s ease;
  `;

  const fieldsHtml = config.fields.map(f => {
    if (f.type === 'textarea') {
      return `
        <div style="margin-bottom:14px">
          <label style="display:block;font-size:11px;font-weight:700;color:var(--text-muted);
                        text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px">${f.label}</label>
          <textarea id="modal-field-${f.id}" placeholder="${f.placeholder || ''}" rows="3"
            style="width:100%;background:var(--surface);border:1px solid var(--border);
                   border-radius:6px;padding:10px 12px;color:var(--text);font-size:13px;
                   font-family:inherit;resize:vertical;box-sizing:border-box;
                   outline:none;transition:border 0.15s"
            onfocus="this.style.borderColor='var(--electric)'"
            onblur="this.style.borderColor='var(--border)'">${f.value || ''}</textarea>
        </div>`;  
    }
    return `
      <div style="margin-bottom:14px">
        <label style="display:block;font-size:11px;font-weight:700;color:var(--text-muted);
                      text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px">
          ${f.label}${f.required ? ' <span style="color:var(--red)">*</span>' : ''}
        </label>
        <input id="modal-field-${f.id}" type="${f.type || 'text'}"
               placeholder="${f.placeholder || ''}" value="${f.value || ''}"
               style="width:100%;background:var(--surface);border:1px solid var(--border);
                      border-radius:6px;padding:10px 12px;color:var(--text);font-size:13px;
                      font-family:inherit;box-sizing:border-box;outline:none;transition:border 0.15s"
               onfocus="this.style.borderColor='var(--electric)'"
               onblur="this.style.borderColor='var(--border)'"/>
      </div>`;
  }).join('');

  overlay.innerHTML = `
    <div id="soc-modal" style="
      background:var(--panel);border:1px solid var(--border);
      border-radius:14px;padding:28px;width:440px;max-width:90vw;
      box-shadow:0 24px 64px rgba(0,0,0,0.6);
      animation:slideIn 0.2s ease;
    ">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:22px">
        <div style="font-size:22px">${config.icon || '📋'}</div>
        <div>
          <div style="font-size:15px;font-weight:700;color:var(--text)">${config.title}</div>
          ${config.subtitle ? `<div style="font-size:12px;color:var(--text-muted);margin-top:2px">${config.subtitle}</div>` : ''}
        </div>
      </div>
      <div id="modal-error" style="display:none;margin-bottom:12px;padding:8px 12px;
            background:rgba(255,51,102,0.1);border:1px solid rgba(255,51,102,0.3);
            border-radius:6px;font-size:12px;color:var(--red)"></div>
      ${fieldsHtml}
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:6px">
        <button onclick="document.getElementById('soc-modal-overlay').remove()"
          style="padding:9px 20px;border-radius:8px;border:1px solid var(--border);
                 background:transparent;color:var(--text-muted);font-size:13px;
                 font-family:inherit;cursor:pointer;transition:all 0.15s"
          onmouseover="this.style.borderColor='var(--electric)';this.style.color='var(--text)'"
          onmouseout="this.style.borderColor='var(--border)';this.style.color='var(--text-muted)'">
          Cancel
        </button>
        <button id="soc-modal-submit"
          style="padding:9px 22px;border-radius:8px;border:none;
                 background:linear-gradient(135deg,var(--electric),var(--purple));
                 color:#000;font-size:13px;font-weight:700;
                 font-family:inherit;cursor:pointer;transition:all 0.15s"
          onmouseover="this.style.opacity='0.85'"
          onmouseout="this.style.opacity='1'">
          ${config.submitLabel || 'Submit'}
        </button>
      </div>
    </div>`;

  document.body.appendChild(overlay);

  // Close on overlay click
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

  // Submit handler
  document.getElementById('soc-modal-submit').addEventListener('click', () => {
    const values = {};
    let valid = true;
    config.fields.forEach(f => {
      const el = document.getElementById(`modal-field-${f.id}`);
      const v = el?.value?.trim() || '';
      if (f.required && !v) {
        valid = false;
        el.style.borderColor = 'var(--red)';
        const err = document.getElementById('modal-error');
        err.style.display = 'block';
        err.textContent = `"${f.label}" is required.`;
      } else {
        values[f.id] = v || f.value || '';
      }
    });
    if (!valid) return;
    overlay.remove();
    config.onSubmit(values);
  });

  // Enter key submits
  overlay.addEventListener('keydown', e => {
    if (e.key === 'Escape') overlay.remove();
    if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
      document.getElementById('soc-modal-submit')?.click();
    }
  });

  // Focus first field
  setTimeout(() => document.getElementById(`modal-field-${config.fields[0]?.id}`)?.focus(), 50);
}


window.investigateAlert = async function(alertId) {
  switchView('investigation');
  const container = document.getElementById('investigation-content');
  container.innerHTML = '<div class="empty-state"><p>Loading investigation...</p></div>';

  try {
    const [alertRes, timelineRes, processRes, playbookRes, whyRes] = await Promise.all([
      fetch(`${API}/alerts/${alertId}`),
      fetch(`${API}/alerts/${alertId}/timeline`),
      fetch(`${API}/alerts/${alertId}/process_tree`),
      fetch(`${API}/alerts/${alertId}/playbook`),
      fetch(`${API}/alerts/${alertId}/why_fired`),
    ]);

    const alertData    = await alertRes.json();
    const timelineData = await timelineRes.json();
    const processData  = await processRes.json();
    const playbookData = playbookRes.ok ? await playbookRes.json() : { playbook: null };
    const whyData      = whyRes.ok ? await whyRes.json() : null;

    renderInvestigation(alertData, timelineData, processData, playbookData, whyData);
  } catch(e) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load alert: ${e.message}</p></div>`;
  }
};

function renderInvestigation(alertData, timelineData, processData, playbookData, whyData) {
  const container = document.getElementById('investigation-content');
  const { alert, events, ioc_report, mitre_context, asset, actions } = alertData;
  const iocs = typeof alert.iocs === 'string' ? safeJson(alert.iocs, {}) : (alert.iocs || {});

  // SLA display
  const slaDisplay = alert.sla_remaining_display || 'N/A';
  const slaClass   = alert.sla_breached ? 'sla-breached' : alert.sla_at_risk ? 'sla-risk' : 'sla-ok';

  container.innerHTML = `

    <!-- ─── Status Bar ─── -->
    <div class="inv-status-bar">
      <div class="inv-status-left">
        <span class="inv-inc-id">INC-${alert.id.slice(0,8).toUpperCase()}</span>
        <span class="alert-sev-badge badge-${alert.severity}">${alert.severity}</span>
        <span class="priority-badge">${alert.priority || 'P2'}</span>
        <span class="status-badge status-${alert.status}">${alert.status}</span>
      </div>
      <div class="inv-status-right">
        <span class="inv-sla ${slaClass}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          SLA: ${escHtml(slaDisplay)}
        </span>
        <span class="inv-analyst">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          ${escHtml(alert.assigned_to || 'SOC Analyst L1')}
        </span>
      </div>
    </div>

    <!-- ─── Lifecycle Stepper ─── -->
    <div class="lifecycle-stepper">
      ${['New','Triaged','Investigating','Containment','Eradication','Recovery','Closed'].map((s, i) => `
        <div class="lifecycle-step ${alert.status === s ? 'step-active' : isStepDone(alert.status, s) ? 'step-done' : 'step-pending'}"
             onclick="advanceStatus('${alert.id}', '${s}')">
          <div class="step-dot"></div>
          <div class="step-label">${s}</div>
        </div>
        ${i < 6 ? '<div class="step-connector"></div>' : ''}
      `).join('')}
    </div>

    <!-- ─── Alert Overview ─── -->
    <div class="inv-overview-grid">
      <div class="inv-panel">
        <div class="inv-header">
          <h2 class="inv-title">${escHtml(alert.rule_name)}</h2>
          <span class="mitre-badge">${escHtml(alert.mitre_technique)}</span>
        </div>
        <div class="inv-body">
          <div class="detail-2col">
            ${dr('Alert ID', `<span style="font-family:var(--mono);font-size:11px">${alert.id}</span>`)}
            ${dr('Detection Rule', alert.rule_id)}
            ${dr('Affected Host', alert.hostname)}
            ${dr('Affected User', alert.user)}
            ${dr('Source IP', alert.source_ip)}
            ${dr('MITRE Tactic', alert.mitre_tactic)}
            ${dr('Confidence', `<span class="conf-badge" style="color:${confColor(alert.confidence)}">${alert.confidence || '?'}%</span>`)}
            ${dr('Risk Score', `<span style="color:${riskColor(alert.risk_score)};font-weight:700">${alert.risk_score}/100</span>`)}
            ${dr('Priority', alert.priority || 'P2')}
            ${dr('Detected', formatTime(alert.created_at))}
          </div>
          <div class="detail-row" style="margin-top:10px">
            <span class="detail-label">Outcome</span>
            <span class="detail-value" style="color:var(--yellow)">${escHtml(alert.summary)}</span>
          </div>
          ${asset ? `
            <div style="margin-top:12px;padding:10px;background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.15);border-radius:6px">
              <div style="font-size:10px;font-weight:700;color:var(--electric);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px">Asset Context</div>
              <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:var(--text-dim)">
                <span>Criticality: <strong style="color:${critColor(asset.criticality)}">${asset.criticality}</strong></span>
                <span>OS: ${asset.os}</span>
                <span>Owner: ${asset.owner}</span>
                <span>Env: ${asset.environment}</span>
                <span>Service: ${asset.business_svc}</span>
              </div>
            </div>
          ` : ''}
        </div>
      </div>

      <!-- Action Buttons -->
      <div class="inv-panel">
        <div class="inv-header"><h3 class="inv-title">Analyst Actions</h3></div>
        <div class="inv-body">
          <div class="action-buttons" style="flex-direction:column;gap:8px">
            ${alert.status === 'New' ? `<button class="btn-primary" onclick="advanceStatus('${alert.id}', 'Triaged')">✓ Triage Alert</button>` : ''}
            ${alert.status === 'Triaged' ? `<button class="btn-primary" onclick="advanceStatus('${alert.id}', 'Investigating')">🔍 Start Investigation</button>` : ''}
            ${alert.status === 'Investigating' ? `<button class="btn-primary" onclick="advanceStatus('${alert.id}', 'Containment')">🛡 Mark Contained</button>` : ''}
            ${alert.status !== 'Closed' ? `
              <button class="btn-success" onclick="classifyAlert('${alert.id}', 'TruePositive')">✓ Confirm True Positive</button>
              <button class="btn-warning" onclick="classifyAlert('${alert.id}', 'FalsePositive')">✗ Mark False Positive</button>
            ` : `<div style="color:var(--green);font-size:13px;font-weight:600">✓ Alert closed — ${escHtml(alert.closure_reason || '')}</div>`}
            <button class="btn-sm" onclick="addNote('${alert.id}')">📝 Add Investigation Note</button>
            <button class="btn-sm" onclick="generateReport('${alert.id}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              Export PDF Report
            </button>
          </div>
          ${actions && actions.length > 0 ? `
            <div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px">
              <div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Audit Trail</div>
              ${actions.slice(0,5).map(a => `
                <div style="font-size:11px;color:var(--text-dim);margin-bottom:4px">
                  <span style="color:var(--electric)">${a.action_type}</span> · ${a.analyst} · ${formatTime(a.timestamp)}
                  ${a.details ? `<br/><span style="color:var(--text-dim);font-size:10px">${escHtml(a.details.slice(0,80))}</span>` : ''}
                </div>
              `).join('')}
            </div>
          ` : ''}
        </div>
      </div>
    </div>

    <!-- ─── Investigation Tabs ─── -->
    <div class="inv-tabs-container">
      <div class="inv-tabs">
        <button class="inv-tab active" data-tab="raw-events" onclick="switchInvTab(this, 'raw-events')">Raw Events</button>
        <button class="inv-tab" data-tab="process-tree"  onclick="switchInvTab(this, 'process-tree')">Process Tree</button>
        <button class="inv-tab" data-tab="timeline"      onclick="switchInvTab(this, 'timeline')">Timeline</button>
        <button class="inv-tab" data-tab="iocs"          onclick="switchInvTab(this, 'iocs')">IOCs</button>
        <button class="inv-tab" data-tab="mitre"         onclick="switchInvTab(this, 'mitre')">MITRE</button>
        <button class="inv-tab" data-tab="playbook"      onclick="switchInvTab(this, 'playbook')">Playbook</button>
        <button class="inv-tab" data-tab="why-fired"     onclick="switchInvTab(this, 'why-fired')">Why Fired?</button>
      </div>

      <!-- Tab: Raw Events -->
      <div class="inv-tab-content active" id="tab-raw-events">
        <div class="raw-log-scroll">
          ${(events || []).slice(0, 30).map((e, i) => `
            <div class="raw-log-entry">
              <span class="raw-log-num">[${i+1}]</span>
              <strong style="color:var(--electric)">[${e.log_source} | ${e.event_type} | EventID ${e.event_id}]</strong><br/>
              <span style="color:var(--text-dim)">${escHtml(e.raw_log)}</span>
            </div>
          `).join('')}
          ${!events || events.length === 0 ? '<div style="color:var(--text-muted);font-size:12px;padding:16px">No raw log events found for this alert.</div>' : ''}
        </div>
      </div>

      <!-- Tab: Process Tree -->
      <div class="inv-tab-content" id="tab-process-tree">
        ${renderProcessTree(processData)}
      </div>

      <!-- Tab: Timeline -->
      <div class="inv-tab-content" id="tab-timeline">
        ${renderTimeline(timelineData)}
      </div>

      <!-- Tab: IOCs -->
      <div class="inv-tab-content" id="tab-iocs">
        ${renderIocs(ioc_report, iocs)}
      </div>

      <!-- Tab: MITRE -->
      <div class="inv-tab-content" id="tab-mitre">
        ${renderMitreContext(mitre_context)}
      </div>

      <!-- Tab: Playbook -->
      <div class="inv-tab-content" id="tab-playbook">
        ${renderPlaybook(playbookData, alert.id)}
      </div>

      <!-- Tab: Why Fired? -->
      <div class="inv-tab-content" id="tab-why-fired">
        ${renderWhyFired(whyData)}
      </div>

    </div>
  `;
}

// ─── Tab switching ────────────────────────────────────────────

window.switchInvTab = function(btn, tabId) {
  document.querySelectorAll('.inv-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.inv-tab-content').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(`tab-${tabId}`)?.classList.add('active');
};

// ─── Lifecycle helpers ────────────────────────────────────────

function isStepDone(currentStatus, stepName) {
  const order = ['New','Triaged','Investigating','Containment','Eradication','Recovery','Closed'];
  return order.indexOf(currentStatus) > order.indexOf(stepName);
}

window.advanceStatus = async function(alertId, status) {
  try {
    const res = await fetch(`${API}/alerts/${alertId}/status`, {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ status }),
    });
    if (!res.ok) { showToast('Error', 'Status update failed', 'Critical'); return; }
    showToast('Status Updated', `Alert → ${status}`, 'success');
    investigateAlert(alertId);
  } catch(e) { showToast('Error', e.message, 'Critical'); }
};

window.classifyAlert = async function(alertId, reason) {
  if (reason === 'FalsePositive') {
    showModal({
      title: 'Mark False Positive',
      icon: '⚠️',
      subtitle: 'Explain why this alert is a false positive so future similar events can be filtered.',
      fields: [
        { id: 'fp_reason', label: 'False Positive Reason', type: 'text', required: true,
          placeholder: 'e.g., Authorized vulnerability scanner, Admin script, Red team activity' },
        { id: 'notes', label: 'Additional Notes (optional)', type: 'textarea',
          placeholder: 'e.g., Confirmed with IT team — this was Nessus scheduled scan on 10.0.0.88' },
      ],
      submitLabel: '✕ Mark False Positive',
      onSubmit: async ({ fp_reason, notes }) => {
        try {
          const res = await fetch(`${API}/alerts/${alertId}/classify`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ closure_reason: 'FalsePositive', fp_reason, notes }),
          });
          if (!res.ok) { showToast('Error', 'Classification failed', 'Critical'); return; }
          showToast('Alert Classified', '✕ Marked False Positive', 'success');
          investigateAlert(alertId);
        } catch(e) { showToast('Error', e.message, 'Critical'); }
      }
    });
  } else {
    showModal({
      title: 'Confirm True Positive',
      icon: '✅',
      subtitle: 'Confirm this is a genuine threat and add investigation notes.',
      fields: [
        { id: 'notes', label: 'Investigation Notes', type: 'textarea', required: true,
          placeholder: 'e.g., Confirmed malicious — attacker IP 77.111.247.143 with 52 failed logins then successful login. Host isolated.' },
      ],
      submitLabel: '✓ Confirm True Positive',
      onSubmit: async ({ notes }) => {
        try {
          const res = await fetch(`${API}/alerts/${alertId}/classify`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ closure_reason: 'TruePositive', fp_reason: '', notes }),
          });
          if (!res.ok) { showToast('Error', 'Classification failed', 'Critical'); return; }
          showToast('Alert Classified', '✓ Confirmed True Positive', 'success');
          investigateAlert(alertId);
        } catch(e) { showToast('Error', e.message, 'Critical'); }
      }
    });
  }
};

window.addNote = async function(alertId) {
  showModal({
    title: 'Add Investigation Note',
    icon: '📝',
    subtitle: 'Notes are added to the audit trail for this alert.',
    fields: [
      { id: 'note', label: 'Investigation Note', type: 'textarea', required: true,
        placeholder: 'e.g., Checked with HR team — john.smith was on leave. Escalating to L2. Initiated host isolation on WORKSTATION-HR-07.' },
    ],
    submitLabel: 'Save Note',
    onSubmit: async ({ note }) => {
      try {
        await fetch(`${API}/alerts/${alertId}/note`, {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ note, analyst: 'SOC Analyst L1' }),
        });
        showToast('Note Added', 'Investigation note saved to audit trail', 'success');
        investigateAlert(alertId);
      } catch(e) { showToast('Error', e.message, 'Critical'); }
    }
  });
};

// ─── Tab content renderers ────────────────────────────────────

function renderProcessTree(processData) {
  const flat = processData?.flat || [];
  if (!flat.length) {
    return `<div class="empty-state-sm">
      No process creation events found for this scenario. Process trees are generated from Sysmon Event ID 1 (ProcessCreate).
    </div>`;
  }

  return `
    <div class="process-tree">
      ${flat.map(node => `
        <div class="proc-node depth-${Math.min(node.depth, 4)}" style="margin-left:${node.depth * 32}px">
          <div class="proc-header">
            <span class="proc-icon ${node.suspicious ? 'proc-icon-danger' : 'proc-icon-normal'}">
              ${node.suspicious ? '⚠' : '▶'}
            </span>
            <span class="proc-name ${node.suspicious ? 'proc-suspicious' : ''}">${escHtml(node.name)}</span>
            ${node.suspicious ? '<span class="proc-flag">SUSPICIOUS</span>' : ''}
          </div>
          ${node.depth > 0 ? `<div class="proc-connector">└─</div>` : ''}
          <div class="proc-details">
            <div class="proc-detail-row">
              <span class="proc-detail-label">PID</span>
              <span class="proc-detail-val">${escHtml(node.pid)}</span>
            </div>
            ${node.user ? `<div class="proc-detail-row"><span class="proc-detail-label">User</span><span class="proc-detail-val">${escHtml(node.user)}</span></div>` : ''}
            ${node.cmd ? `<div class="proc-detail-row"><span class="proc-detail-label">CmdLine</span><span class="proc-detail-val" style="font-family:var(--mono);color:${node.suspicious ? 'var(--orange)' : 'var(--text-dim)'}">${escHtml(node.cmd)}</span></div>` : ''}
            ${node.timestamp ? `<div class="proc-detail-row"><span class="proc-detail-label">Time</span><span class="proc-detail-val">${escHtml(node.timestamp)}</span></div>` : ''}
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderTimeline(timelineData) {
  const events = timelineData?.timeline || [];
  if (!events.length) return `<div class="empty-state-sm">No timeline events available.</div>`;

  return `
    <div class="timeline">
      ${events.map((e, i) => `
        <div class="timeline-entry">
          <div class="tl-marker ${e.event_type === 'SUCCESSFUL_LOGIN' || e.event_type === 'PRIVILEGE_USE' ? 'tl-marker-danger' : 'tl-marker-info'}"></div>
          <div class="tl-content">
            <div class="tl-header">
              <span class="tl-time">${escHtml(e.timestamp)}</span>
              <span class="tl-source">${escHtml(e.log_source)}</span>
              <span class="tl-event-id">EventID ${escHtml(String(e.event_id))}</span>
            </div>
            <div class="tl-narrative">${escHtml(e.narrative)}</div>
          </div>
        </div>
      `).join('')}
      <div class="timeline-conclusion">
        <div class="tl-conclusion-header">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          Analyst Conclusion
        </div>
        <div class="tl-conclusion-body">
          Based on the event timeline above, ${events.length} events were observed over the attack window.
          This sequence is consistent with the detection rule: <strong>${document.querySelector('.inv-title')?.textContent || 'detected pattern'}</strong>.
          Investigation of IOCs, process relationships, and context is required to confirm classification.
        </div>
      </div>
    </div>
  `;
}

function renderIocs(iocReport, rawIocs) {
  if (!iocReport) return '<div class="empty-state-sm">No IOC data available.</div>';

  const buildSection = (title, items, cls) => {
    if (!items || !items.length) return '';
    return `
      <div class="ioc-section">
        <div class="ioc-section-title">${escHtml(title)}</div>
        <div class="ioc-tags">${items.map(v => `<span class="ioc-tag ${cls}">${escHtml(String(v))}</span>`).join('')}</div>
      </div>
    `;
  };

  return `
    <div class="iocs-panel">
      <div class="ioc-summary">
        <span style="color:var(--text-muted);font-size:12px">${iocReport.total_ioc_count || 0} indicators extracted</span>
      </div>
      ${buildSection('External IPs (Threat Intel)', iocReport.external_ips, 'ip')}
      ${buildSection('Internal IPs', iocReport.internal_ips, 'ip')}
      ${buildSection('Usernames', iocReport.usernames, 'user')}
      ${buildSection('File Hashes', iocReport.file_hashes, 'hash')}
      ${buildSection('Registry Keys', iocReport.registry_keys, 'regkey')}
      ${buildSection('Suspicious Privileges', iocReport.suspicious_privileges, 'proc')}
      ${iocReport.domains && Object.keys(iocReport.domains).length > 0 ? `
        <div class="ioc-section">
          <div class="ioc-section-title">Domains</div>
          <div class="ioc-tags">
            ${Object.entries(iocReport.domains).map(([d, info]) => `
              <span class="ioc-tag domain" title="${escHtml(info.reason || '')}" style="cursor:help">
                ${escHtml(d)} [${escHtml(info.verdict || '')}]
              </span>
            `).join('')}
          </div>
        </div>
      ` : ''}
      ${iocReport.flagged_processes && Object.keys(iocReport.flagged_processes).length > 0 ? `
        <div class="ioc-section">
          <div class="ioc-section-title">Flagged Processes</div>
          <div class="ioc-tags">
            ${Object.entries(iocReport.flagged_processes).map(([p, reason]) => `
              <span class="ioc-tag proc" title="${escHtml(reason)}" style="cursor:help">${escHtml(p)}</span>
            `).join('')}
          </div>
        </div>
      ` : ''}
      ${iocReport.total_ioc_count === 0 ? '<div class="empty-state-sm">No IOCs extracted from this alert\'s events.</div>' : ''}
    </div>
  `;
}

function renderMitreContext(mitre) {
  if (!mitre) return '<div class="empty-state-sm">No MITRE context available.</div>';

  return `
    <div class="mitre-context-card" style="max-width:700px">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
        <div class="mitre-tid" style="font-size:20px">${escHtml(mitre.technique_id)}</div>
        <div>
          <div class="mitre-tname" style="font-size:16px">${escHtml(mitre.technique_name)}</div>
          <div class="mitre-tactic-chip">${escHtml(mitre.tactic)}</div>
        </div>
      </div>

      <div class="mitre-field-label">Description</div>
      <div class="mitre-desc">${escHtml(mitre.description)}</div>

      <div class="mitre-field-label" style="margin-top:12px">Detection Guidance</div>
      <div class="mitre-desc">${escHtml(mitre.detection)}</div>

      <div class="mitre-field-label" style="margin-top:12px">Remediation Steps</div>
      <ol class="remediation-list">
        ${(mitre.remediation || []).map(r => `<li>${escHtml(r)}</li>`).join('')}
      </ol>

      <div class="mitre-field-label" style="margin-top:12px">False Positives to Rule Out</div>
      <ul class="remediation-list">
        ${(mitre.false_positives || []).map(fp => `<li style="color:var(--orange)">${escHtml(fp)}</li>`).join('')}
      </ul>

      <div style="margin-top:16px">
        <a href="${escHtml(mitre.mitre_url)}" target="_blank" style="font-size:12px;color:var(--electric);text-decoration:none">
          → View ${escHtml(mitre.technique_id)} on attack.mitre.org ↗
        </a>
      </div>
    </div>
  `;
}

function renderPlaybook(playbookData, alertId) {
  const pb = playbookData?.playbook;
  if (!pb) return `<div class="empty-state-sm">No playbook found for this detection rule.</div>`;

  const phases = pb.nist_phases || {};
  const phaseColors = { Detection:'var(--electric)', Triage:'var(--yellow)', Containment:'var(--orange)', Eradication:'var(--red)', Recovery:'var(--green)' };

  return `
    <div class="playbook">
      <div class="playbook-header">
        <div class="playbook-title">${escHtml(pb.title)}</div>
        <div style="font-size:11px;color:var(--text-muted)">MITRE: ${escHtml(pb.mitre_technique)} · NIST IR Framework</div>
      </div>
      ${Object.entries(phases).map(([phase, steps]) => `
        <div class="playbook-phase">
          <div class="phase-header" style="border-left-color:${phaseColors[phase] || 'var(--text-muted)'}">
            <span class="phase-name" style="color:${phaseColors[phase] || 'var(--text-dim)'}">${phase}</span>
            <span style="font-size:11px;color:var(--text-muted)">${steps.filter(s => s.completed).length}/${steps.length} completed</span>
          </div>
          <div class="phase-steps">
            ${steps.map(step => `
              <div class="playbook-step ${step.completed ? 'step-completed' : ''}" id="pb-step-${step.id}">
                <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">
                  <input type="checkbox" ${step.completed ? 'checked' : ''}
                    onchange="completePlaybookStep('${alertId}', '${step.id}', this)"
                    style="margin-top:2px;accent-color:var(--green)"/>
                  <span class="step-text">${escHtml(step.step)}</span>
                </label>
              </div>
            `).join('')}
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

window.completePlaybookStep = async function(alertId, stepId, checkbox) {
  if (!checkbox.checked) return;
  try {
    await fetch(`${API}/alerts/${alertId}/playbook/step`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ step_id: stepId }),
    });
    const stepEl = document.getElementById(`pb-step-${stepId}`);
    if (stepEl) stepEl.classList.add('step-completed');
    showToast('Step Completed', `Playbook step ${stepId} recorded`, 'success');
  } catch(e) {
    checkbox.checked = false;
    showToast('Error', e.message, 'Critical');
  }
};

function renderWhyFired(why) {
  if (!why) return `<div class="empty-state-sm">No rule transparency data available.</div>`;

  const condCount  = why.matched_conditions?.length || 0;
  const confColor2 = confColor(why.confidence);

  return `
    <div class="why-fired">
      <div class="why-header">
        <div>
          <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:4px">
            Rule: <span style="font-family:var(--mono);color:var(--electric)">${escHtml(why.rule_id)}</span>
          </div>
          <div style="font-size:12px;color:var(--text-dim)">${escHtml(why.rule_name)}</div>
        </div>
        <div class="conf-display">
          <div class="conf-circle" style="--conf:${why.confidence || 70}%;border-color:${confColor2}">
            <span style="color:${confColor2};font-size:18px;font-weight:800">${why.confidence || '?'}%</span>
            <span style="font-size:9px;color:var(--text-muted)">CONFIDENCE</span>
          </div>
        </div>
      </div>

      <div style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px">
        Matched Conditions (${condCount}/${condCount} — all must match)
      </div>

      <div class="condition-list">
        ${(why.matched_conditions || []).map(cond => `
          <div class="condition-item">
            <span class="cond-check">✓</span>
            <span class="cond-text">${escHtml(cond)}</span>
          </div>
        `).join('')}
        ${condCount === 0 ? '<div style="color:var(--text-muted);font-size:12px">Condition details not available for this alert.</div>' : ''}
      </div>

      <div style="margin-top:16px;font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">
        False Positives to Rule Out
      </div>
      <div class="fp-list">
        ${(why.false_positives || []).map(fp => `
          <div class="fp-item">
            <span style="color:var(--orange)">⚠</span>
            <span>${escHtml(fp)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ─── Report generator ─────────────────────────────────────────

window.generateReport = async function(alertId) {
  // Get the alert name for a sensible default filename
  const ruleNameEl = document.querySelector('.inv-title');
  const defaultTitle = ruleNameEl?.textContent?.trim()
    ? ruleNameEl.textContent.trim().slice(0, 40).replace(/[^a-zA-Z0-9\s-]/g, '')
    : `Incident_${alertId.slice(0,8).toUpperCase()}`;

  showModal({
    title: 'Export PDF Incident Report',
    icon: '📄',
    subtitle: 'The report title will be used as the PDF filename.',
    fields: [
      {
        id: 'report_title',
        label: 'Report Name / Filename',
        type: 'text',
        required: true,
        placeholder: 'e.g., Brute_Force_Investigation_2026-09-22',
        value: defaultTitle.replace(/\s+/g, '_'),
      },
      {
        id: 'analyst_name',
        label: 'Analyst Name (appears in report)',
        type: 'text',
        placeholder: 'SOC Analyst L1',
        value: 'SOC Analyst L1',
      },
    ],
    submitLabel: '📥 Download PDF',
    onSubmit: async ({ report_title, analyst_name }) => {
      showToast('Generating Report', 'Creating PDF incident report…', 'info');
      try {
        const res = await fetch(`${API}/report/${alertId}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            analyst_name: analyst_name || 'SOC Analyst L1',
            report_title,
          }),
        });

        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          showToast('Error', err.error || 'Report generation failed', 'Critical');
          return;
        }

        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        // Sanitise filename: replace spaces/special chars with underscores
        const safeFilename = report_title
          .replace(/[^a-zA-Z0-9_\-]/g, '_')
          .replace(/_+/g, '_')
          .replace(/^_|_$/g, '');
        a.download = `${safeFilename}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast('Report Downloaded', `✓ Saved as ${safeFilename}.pdf`, 'success');
      } catch(e) {
        showToast('Error', e.message, 'Critical');
      }
    }
  });
};

// ─── Helpers ─────────────────────────────────────────────────

function dr(label, value) {
  return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value">${value}</span></div>`;
}

function confColor(conf) {
  if (!conf) return 'var(--text-muted)';
  if (conf >= 85) return 'var(--green)';
  if (conf >= 70) return 'var(--yellow)';
  return 'var(--orange)';
}

function riskColor(score) {
  if (!score) return 'var(--text-muted)';
  if (score >= 75) return 'var(--red)';
  if (score >= 50) return 'var(--orange)';
  if (score >= 25) return 'var(--yellow)';
  return 'var(--green)';
}

function critColor(crit) {
  const c = { Critical:'var(--red)', High:'var(--orange)', Medium:'var(--yellow)', Low:'var(--green)' };
  return c[crit] || 'var(--text-muted)';
}

function safeJson(str, fallback) {
  try { return JSON.parse(str); } catch { return fallback; }
}
