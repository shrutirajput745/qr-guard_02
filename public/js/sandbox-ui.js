/**
 * QR Guard - Behavior Sandbox UI Controller
 * Interactive pre-navigation payload simulation lab.
 */

window.QRSandboxUI = (function() {
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function getVerdictClass(verdict) {
    if (verdict === 'BLOCKED_EXECUTION' || verdict === 'HIGH_RISK_BEHAVIOR') return 'dangerous';
    if (verdict === 'CAUTION_INTERACTIVE_ACTION') return 'suspicious';
    return 'safe';
  }

  function runSimulation(rawPayload) {
    if (!window.QRBehaviorSandbox) return null;
    const sim = window.QRBehaviorSandbox.simulate(rawPayload);
    renderSimulation(sim);
    return sim;
  }

  function renderSimulation(sim) {
    const emptyEl = document.getElementById('sbEmptyState');
    const outEl = document.getElementById('sbResultsContainer');
    if (!outEl) return;

    if (emptyEl) emptyEl.style.display = 'none';
    outEl.style.display = 'block';

    const cls = getVerdictClass(sim.verdict);
    const timelineHtml = sim.timeline.map(step => `
      <div class="sb-step-item sb-step-${escapeHtml(step.status)}">
        <div class="sb-step-num">${step.stage}</div>
        <div>
          <strong>${escapeHtml(step.title)}</strong>
          <p>${escapeHtml(step.action)}</p>
        </div>
      </div>`).join('');

    const permsHtml = sim.permissionsRequested.length > 0
      ? sim.permissionsRequested.map(p => `<span class="ti-cat-chip">${escapeHtml(p)}</span>`).join('')
      : '<span class="ti-cat-chip safe">No Elevated Permissions</span>';

    const hopsHtml = sim.staticRedirectHops.length > 0
      ? sim.staticRedirectHops.map(h => `
          <div class="ti-ind-row">
            <div class="ti-ind-info">
              <span class="ti-sev-dot ${h.isExecutableTarget ? 'high' : 'medium'}"></span>
              <span class="ti-ind-title">Hop ${h.hopNumber}: ${escapeHtml(h.fromHost)} (?${escapeHtml(h.parameter)}) ➔ <code>${escapeHtml(h.target)}</code></span>
            </div>
          </div>`).join('')
      : '<p class="ti-muted-note">No static redirect parameters detected in URL.</p>';

    const effectsHtml = sim.sideEffects.map(e => `<li>${escapeHtml(e)}</li>`).join('');
    const recsHtml = sim.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');

    const chainHtml = sim.timeline.map((step, idx) => `
      ${idx > 0 ? '<span class="sb-chain-arrow"><i class="fa-solid fa-chevron-right"></i></span>' : ''}
      <div class="sb-chain-node node-${escapeHtml(step.status)}">
        <span>Stage ${step.stage}</span>
        <strong>${escapeHtml(step.title)}</strong>
      </div>`).join('');

    let previewHtml = '';
    if (sim.previewData) {
      const entries = Object.entries(sim.previewData).filter(([k]) => k !== 'kind');
      const cells = entries.map(([k, v]) => `
        <div class="ti-forensic-cell">
          <span>${escapeHtml(k.replace(/([A-Z])/g, ' $1'))}</span>
          <code>${escapeHtml(String(v || 'None'))}</code>
        </div>`).join('');
      previewHtml = `
        <div class="card ti-panel-card" style="margin-bottom:18px;">
          <div class="ti-panel-header">
            <h3><i class="fa-solid fa-eye"></i> Simulated ${escapeHtml(sim.previewData.kind.toUpperCase())} Action Preview</h3>
            <span class="ti-panel-badge">Not Executed</span>
          </div>
          <div class="ti-forensics-grid">${cells}</div>
        </div>`;
    }

    outEl.innerHTML = `
      <div class="il-status-banner il-status-${cls}" style="margin-bottom:18px;">
        <div class="il-status-left">
          <div class="il-status-icon"><i class="fa-solid ${cls === 'dangerous' ? 'fa-shield-halved' : (cls === 'suspicious' ? 'fa-triangle-exclamation' : 'fa-circle-check')}"></i></div>
          <div>
            <span class="il-eyebrow">BEHAVIOR SANDBOX VERDICT</span>
            <h3>${escapeHtml(sim.verdictLabel)}</h3>
            <p>Predicted Dispatch Handler: <strong>${escapeHtml(sim.handlerType)}</strong></p>
          </div>
        </div>
        <div class="il-status-metrics">
          <div class="il-metric-pill">
            <span>RISK LEVEL</span>
            <strong>${escapeHtml(sim.riskLevel)}</strong>
          </div>
          <div class="il-metric-pill">
            <span>EXECUTION</span>
            <strong>BLOCKED</strong>
          </div>
        </div>
      </div>

      <div class="sb-chain-wrap" aria-label="Hypothetical Execution Chain">${chainHtml}</div>

      ${previewHtml}

      <div class="ti-report-payload" style="margin-bottom:18px;">
        <span class="ti-sub-label">Simulated Payload (Inert — Zero Network / Zero Script Execution)</span>
        <code>${escapeHtml(sim.input || '(empty)')}</code>
      </div>

      <div class="ti-analytics-grid">
        <div class="card ti-panel-card">
          <div class="ti-panel-header">
            <h3><i class="fa-solid fa-route"></i> Predicted Execution Timeline</h3>
            <span class="ti-panel-badge">Offline Trace</span>
          </div>
          <div class="sb-timeline-list">${timelineHtml}</div>
        </div>

        <div class="card ti-panel-card">
          <div class="ti-panel-header">
            <h3><i class="fa-solid fa-key"></i> Permissions &amp; Static Redirects</h3>
            <span class="ti-panel-badge">Containment Audit</span>
          </div>
          <div style="margin-bottom:14px;">
            <span class="ti-sub-label">Capabilities / Permissions Requested</span>
            <div class="ti-tags-row" style="margin-top:6px;">${permsHtml}</div>
          </div>
          <div>
            <span class="ti-sub-label">Static Redirect Hop Predictor</span>
            <div class="ti-ind-list" style="margin-top:6px;">${hopsHtml}</div>
          </div>
          ${sim.downloadRisk ? `<div class="ti-malformed-alert" style="margin-top:12px;"><i class="fa-solid fa-file-arrow-down"></i> <strong>Download Risk (${escapeHtml(sim.downloadRisk.level)}):</strong> ${escapeHtml(sim.downloadRisk.reason)}</div>` : ''}
        </div>
      </div>

      <div class="ti-analytics-grid" style="margin-top:18px;">
        <div class="card ti-panel-card">
          <div class="ti-panel-header"><h3><i class="fa-solid fa-bolt"></i> Predicted Device Side Effects</h3></div>
          <ul class="sb-bullet-list">${effectsHtml}</ul>
        </div>
        <div class="card ti-panel-card">
          <div class="ti-panel-header"><h3><i class="fa-solid fa-lightbulb"></i> Sandbox Safety Guidance</h3></div>
          <ul class="sb-bullet-list">${recsHtml}</ul>
        </div>
      </div>
    `;
  }

  function init() {
    const inputEl = document.getElementById('sbPayloadInput');
    const runBtn = document.getElementById('sbRunBtn');

    if (runBtn && inputEl) {
      runBtn.addEventListener('click', () => {
        runSimulation(inputEl.value);
      });
      inputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          runSimulation(inputEl.value);
        }
      });
    }

    document.querySelectorAll('.sb-preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const val = btn.getAttribute('data-payload') || '';
        if (inputEl) inputEl.value = val;
        runSimulation(val);
      });
    });
  }

  return {
    init,
    runSimulation
  };
})();
