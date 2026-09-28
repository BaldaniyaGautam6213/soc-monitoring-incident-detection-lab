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



