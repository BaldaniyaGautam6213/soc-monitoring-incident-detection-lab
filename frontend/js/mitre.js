/* ================================================================
   mitre.js — MITRE ATT&CK heatmap + scenario cards loader
================================================================ */

window.loadMitreHeatmap = async function() {
  try {
    const res  = await fetch(`${API}/mitre`);
    const data = await res.json();
    renderHeatmap(data.heatmap);
    renderCoverage(data.coverage);
  } catch(e) {
    document.getElementById('mitre-heatmap').innerHTML =
      '<div class="empty-state"><p>Failed to load MITRE data. Ensure backend is running.</p></div>';
  }
};

function renderHeatmap(heatmap) {
  const el = document.getElementById('mitre-heatmap');
  if (!heatmap || heatmap.length === 0) {
    el.innerHTML = '<div class="empty-state"><p>No MITRE data yet. Run simulations first.</p></div>';
    return;
  }

  el.innerHTML = heatmap.map(t => `
    <div class="heat-card heat-${t.heat_level}" onclick="window.open('${t.mitre_url}','_blank')" style="cursor:pointer" title="Click to view on attack.mitre.org">
      <div class="heat-tid">${escHtml(t.technique_id)}</div>
      <div class="heat-name">${escHtml(t.technique_name)}</div>
      <div class="heat-tactic">${escHtml(t.tactic)}</div>
      <div style="display:flex;align-items:baseline;gap:6px">
        <span class="heat-count heat-${t.heat_level}">${t.detection_count}</span>
        <span class="heat-count-label">detection${t.detection_count !== 1 ? 's' : ''}</span>
      </div>
    </div>
  `).join('');
}

function renderCoverage(cov) {
  document.getElementById('cov-techniques').textContent = cov.techniques_with_coverage + '/' + cov.total_techniques_in_db;
  document.getElementById('cov-tactics').textContent    = cov.tactics_with_coverage + '/' + cov.total_tactics;
  document.getElementById('cov-percent').textContent    = cov.coverage_percentage + '%';
}

/* ================================================================
   Scenario Cards Loader (for Simulate view)
================================================================ */

window.loadScenarioCards = async function() {
  const container = document.getElementById('scenario-cards');
  if (!container) return;

  try {
    const res  = await fetch(`${API}/scenarios`);
    const data = await res.json();
    renderScenarioCards(data);
  } catch(e) {
    container.innerHTML = renderFallbackCards();
  }
};

function renderScenarioCards(scenarios) {
  const container = document.getElementById('scenario-cards');
  if (!container) return;

  container.innerHTML = Object.entries(scenarios).map(([key, sc]) => `
    <div class="scenario-card sev-${sc.severity}" id="sc-${key}" onclick="runSimulation('${key}')">
      <div class="sc-header">
        <span class="sc-mitre">${escHtml(sc.mitre)}</span>
        <span class="sc-sev badge-${sc.severity}">${escHtml(sc.severity)}</span>
      </div>
      <div class="sc-name">${escHtml(sc.name)}</div>
      <div class="sc-desc">${escHtml(sc.description)}</div>
      <div class="sc-source">${escHtml(sc.log_source)}</div>
    </div>
  `).join('');
}

function renderFallbackCards() {
  const scenarios = [
    { key: 'brute_force',          name: 'Brute Force Login',              mitre: 'T1110',     severity: 'High',     desc: '50+ failed logins followed by account compromise',          src: 'Windows Security 4625' },
    { key: 'powershell_execution', name: 'Suspicious PowerShell',          mitre: 'T1059.001', severity: 'Critical', desc: 'Encoded PowerShell command via Office app with C2 callback', src: 'Sysmon EventID 1, 3' },
    { key: 'suspicious_process',   name: 'Suspicious Process Creation',    mitre: 'T1055',     severity: 'Critical', desc: 'winword.exe spawning cmd.exe — phishing macro payload',      src: 'Sysmon EventID 1' },
    { key: 'port_scan',            name: 'Network Port Scan',              mitre: 'T1046',     severity: 'Medium',   desc: 'Nmap SYN scan across 1024 ports detected by Suricata',      src: 'Suricata ET SCAN' },
    { key: 'privilege_escalation', name: 'Privilege Escalation',           mitre: 'T1548',     severity: 'Critical', desc: 'SeDebugPrivilege token — possible LSASS credential dump',    src: 'Windows Security 4672' },
    { key: 'persistence',          name: 'Registry Persistence',           mitre: 'T1547.001', severity: 'High',     desc: 'Malware dropped and added to HKLM Run key for autostart',   src: 'Sysmon EventID 13' },
  ];

  return scenarios.map(sc => `
    <div class="scenario-card sev-${sc.severity}" id="sc-${sc.key}" onclick="runSimulation('${sc.key}')">
      <div class="sc-header">
        <span class="sc-mitre">${sc.mitre}</span>
        <span class="sc-sev badge-${sc.severity}">${sc.severity}</span>
      </div>
      <div class="sc-name">${sc.name}</div>
      <div class="sc-desc">${sc.desc}</div>
      <div class="sc-source">${sc.src}</div>
    </div>
  `).join('');
}

window.runSimulation = async function(scenario) {
  const card = document.getElementById(`sc-${scenario}`);
  if (card) card.classList.add('running');

  switchView('simulate');
  appendTerminal(`\n$ python log_simulator.py --scenario ${scenario}`, 'term-cmd');

  try {
    await fetch(`${API}/simulate/${scenario}`, { method: 'POST' });
    appendTerminal(`[+] Simulation started — streaming logs via WebSocket...`, 'term-info');
  } catch(e) {
    appendTerminal(`[ERROR] Could not reach backend: ${e.message}`, 'term-error');
    if (card) card.classList.remove('running');
  }
};
