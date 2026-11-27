/**
 * QR Guard - Threat Intelligence & URL Forensics Dashboard Controller
 * Tracks analyzed URLs, aggregates threat categories & indicator distributions,
 * renders recent suspicious analyses, and drives the detailed forensic investigation view.
 */

window.QRThreatIntel = (function() {
  const STORAGE_KEY = 'qrguard_threat_intel_v1';
  const MAX_RECORDS = 100;

  let activeFilter = 'all';
  let activeSearch = '';
  let selectedRecordId = null;

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function loadRecords() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  function saveRecords(records) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
    } catch (e) {
      console.warn('QR Guard ThreatIntel: Could not persist telemetry:', e);
    }
  }

  function maskPayloadForStorage(result) {
    const raw = typeof result.input === 'string' ? result.input : '';
    if (result.qrType === 'wifi') return raw.replace(/(P:)[^;]*/i, '$1[MASKED]');
    if (result.qrType === 'upi') return raw.replace(/([?&]am=)[^&]*/i, '$1[MASKED]');
    if (result.qrType === 'vcard') return '[vCard contact — masked for privacy]';
    return raw.slice(0, 512);
  }

  /**
   * Record an analyzed QR/URL result into Threat Intelligence telemetry.
   * Tracks URL analyses (and dangerous executable schemes) for threat aggregation.
   */
  function recordAnalysis(result) {
    if (!result || !result.isUrl) return null;

    const records = loadRecords();
    const record = {
      id: Date.now() + '_' + Math.random().toString(36).slice(2, 8),
      timestamp: new Date().toISOString(),
      input: maskPayloadForStorage(result),
      qrType: result.qrType || 'url',
      qrTypeLabel: result.qrTypeLabel || 'Website URL',
      score: typeof result.score === 'number' ? result.score : 0,
      status: result.status || 'Safe',
      threatCategories: Array.isArray(result.threatCategories) ? result.threatCategories : [],
      detectedIndicators: Array.isArray(result.detectedIndicators) ? result.detectedIndicators : [],
      highlightedComponents: Array.isArray(result.highlightedComponents) ? result.highlightedComponents : [],
      forensics: result.forensics || null,
      explanation: result.explanation || '',
      recommendation: result.recommendation || result.advice || ''
    };

    records.unshift(record);
    if (records.length > MAX_RECORDS) {
      records.length = MAX_RECORDS;
    }
    saveRecords(records);
    selectedRecordId = record.id;

    // Re-render if dashboard is mounted
    renderDashboard();
    return record;
  }

  function clearTelemetry() {
    localStorage.removeItem(STORAGE_KEY);
    selectedRecordId = null;
    renderDashboard();
  }

  function investigatePayload(rawInput, recordInHistory = true) {
    const trimmed = typeof rawInput === 'string' ? rawInput.trim() : '';
    if (!trimmed) {
      if (window.showToast) window.showToast('Enter a URL or QR payload to investigate.', 'warning');
      return null;
    }
    if (!window.QRAnalyzer) {
      if (window.showToast) window.showToast('Analyzer engine unavailable.', 'error');
      return null;
    }

    const result = window.QRAnalyzer.analyze(trimmed);

    if (recordInHistory && window.QRHistory) {
      window.QRHistory.addEntry(result);
    }

    if (result.isUrl) {
      const rec = recordAnalysis(result);
      if (rec) selectedRecordId = rec.id;
    } else {
      // Render transient investigation report for non-URL payloads too
      renderInvestigationReport({
        id: 'transient',
        timestamp: new Date().toISOString(),
        input: trimmed,
        qrType: result.qrType,
        qrTypeLabel: result.qrTypeLabel,
        score: result.score,
        status: result.status,
        threatCategories: result.threatCategories || [],
        detectedIndicators: result.detectedIndicators || [],
        highlightedComponents: result.highlightedComponents || [],
        forensics: result.forensics || null,
        explanation: result.explanation || '',
        recommendation: result.recommendation || result.advice || ''
      });
    }

    if (window.showToast) {
      window.showToast(`Forensic Report: ${result.score}/100 (${result.status})`, result.status.toLowerCase());
    }
    return result;
  }

  function getStatusClass(status) {
    if (status === 'Dangerous') return 'dangerous';
    if (status === 'Suspicious') return 'suspicious';
    return 'safe';
  }

  function formatTimestamp(iso) {
    try {
      return new Date(iso).toLocaleString(undefined, {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
      });
    } catch (e) {
      return iso;
    }
  }

  function renderDashboard() {
    const records = loadRecords();

    // 1. Aggregate KPI counts
    const total = records.length;
    const safeCount = records.filter(r => r.status === 'Safe').length;
    const suspiciousCount = records.filter(r => r.status === 'Suspicious').length;
    const dangerousCount = records.filter(r => r.status === 'Dangerous').length;

    const pct = (n) => total > 0 ? Math.round((n / total) * 100) + '%' : '0%';

    setText('tiTotalUrls', String(total));
    setText('tiSafeUrls', String(safeCount));
    setText('tiSafePct', pct(safeCount));
    setText('tiSuspiciousUrls', String(suspiciousCount));
    setText('tiSuspiciousPct', pct(suspiciousCount));
    setText('tiDangerousUrls', String(dangerousCount));
    setText('tiDangerousPct', pct(dangerousCount));

    // 2. Category frequency & indicator distribution
    const categoryCounts = {};
    const indicatorCounts = {};
    const severityCounts = { high: 0, medium: 0, low: 0 };

    records.forEach(rec => {
      (rec.threatCategories || []).forEach(cat => {
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      });
      (rec.detectedIndicators || []).forEach(ind => {
        const key = ind.title || 'Unknown Indicator';
        if (!indicatorCounts[key]) {
          indicatorCounts[key] = { title: key, count: 0, severity: ind.severity || 'medium', points: ind.points || 0 };
        }
        indicatorCounts[key].count++;
        if (ind.severity && severityCounts[ind.severity] !== undefined) {
          severityCounts[ind.severity]++;
        }
      });
    });

    renderCategoryBars(categoryCounts);
    renderIndicatorDistribution(indicatorCounts, severityCounts);
    renderRecentFeed(records);

    // 3. Render selected or latest investigation report
    if (records.length === 0) {
      renderInvestigationEmpty();
    } else {
      const target = records.find(r => r.id === selectedRecordId) || records[0];
      selectedRecordId = target.id;
      renderInvestigationReport(target);
    }
  }

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function renderCategoryBars(categoryCounts) {
    const container = document.getElementById('tiCategoriesChart');
    if (!container) return;

    const sorted = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]).slice(0, 7);
    if (sorted.length === 0) {
      container.innerHTML = '<div class="ti-empty-mini"><i class="fa-solid fa-chart-bar"></i> No threat categories detected yet. Scan or investigate a suspicious URL.</div>';
      return;
    }

    const maxVal = sorted[0][1] || 1;
    container.innerHTML = sorted.map(([cat, count]) => {
      const widthPct = Math.max(8, Math.round((count / maxVal) * 100));
      return `
        <div class="ti-bar-row">
          <div class="ti-bar-meta">
            <span class="ti-bar-label">${escapeHtml(cat)}</span>
            <span class="ti-bar-count">${count} hit${count !== 1 ? 's' : ''}</span>
          </div>
          <div class="ti-bar-track">
            <div class="ti-bar-fill" style="width: ${widthPct}%;"></div>
          </div>
        </div>`;
    }).join('');
  }

  function renderIndicatorDistribution(indicatorCounts, severityCounts) {
    const container = document.getElementById('tiIndicatorsChart');
    if (!container) return;

    const totalInd = severityCounts.high + severityCounts.medium + severityCounts.low;
    const sorted = Object.values(indicatorCounts).sort((a, b) => b.count - a.count).slice(0, 6);

    if (sorted.length === 0) {
      container.innerHTML = '<div class="ti-empty-mini"><i class="fa-solid fa-shield-halved"></i> No triggered threat indicators recorded yet.</div>';
      return;
    }

    const sevBar = totalInd > 0 ? `
      <div class="ti-severity-bar-track" aria-label="Severity distribution">
        <div class="ti-sev-seg high" style="width:${Math.round((severityCounts.high / totalInd) * 100)}%" title="High: ${severityCounts.high}"></div>
        <div class="ti-sev-seg medium" style="width:${Math.round((severityCounts.medium / totalInd) * 100)}%" title="Medium: ${severityCounts.medium}"></div>
        <div class="ti-sev-seg low" style="width:${Math.round((severityCounts.low / totalInd) * 100)}%" title="Low: ${severityCounts.low}"></div>
      </div>
      <div class="ti-severity-summary">
        <span class="ti-sev-pill high"><i class="fa-solid fa-circle-exclamation"></i> High: ${severityCounts.high}</span>
        <span class="ti-sev-pill medium"><i class="fa-solid fa-triangle-exclamation"></i> Medium: ${severityCounts.medium}</span>
        <span class="ti-sev-pill low"><i class="fa-solid fa-circle-info"></i> Low: ${severityCounts.low}</span>
      </div>` : '';

    const itemsHtml = sorted.map(item => `
      <div class="ti-ind-row">
        <div class="ti-ind-info">
          <span class="ti-sev-dot ${escapeHtml(item.severity)}"></span>
          <span class="ti-ind-title">${escapeHtml(item.title)}</span>
        </div>
        <div class="ti-ind-metrics">
          <span class="ti-pts-chip">+${escapeHtml(String(item.points))}</span>
          <span class="ti-count-chip">${item.count}×</span>
        </div>
      </div>`).join('');

    container.innerHTML = sevBar + '<div class="ti-ind-list">' + itemsHtml + '</div>';
  }

  function renderRecentFeed(records) {
    const container = document.getElementById('tiRecentFeed');
    if (!container) return;

    const filtered = records.filter(r => {
      if (activeFilter === 'flagged' && r.status !== 'Dangerous' && r.status !== 'Suspicious') return false;
      if (activeFilter !== 'all' && activeFilter !== 'flagged' && r.status.toLowerCase() !== activeFilter) return false;
      if (activeSearch) {
        const indText = (r.detectedIndicators || []).map(i => `${i.title || ''} ${i.reason || ''}`).join(' ');
        const decodedHost = r.forensics && r.forensics.decodedHostname ? r.forensics.decodedHostname : '';
        const hay = `${r.input} ${decodedHost} ${(r.threatCategories || []).join(' ')} ${indText} ${r.status}`.toLowerCase();
        if (!hay.includes(activeSearch)) return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="ti-empty-mini">
          <i class="fa-solid fa-inbox"></i>
          ${records.length === 0
            ? 'No URLs analyzed yet. Scan a QR code or use the Forensic Investigator above.'
            : 'No URL analyses match the selected severity filter.'}
        </div>`;
      return;
    }

    container.innerHTML = filtered.slice(0, 20).map(r => {
      const cls = getStatusClass(r.status);
      const isSelected = r.id === selectedRecordId;
      const cats = (r.threatCategories || []).slice(0, 3)
        .map(c => `<span class="ti-cat-chip">${escapeHtml(c)}</span>`)
        .join('');

      return `
        <div class="ti-feed-item ti-feed-${cls} ${isSelected ? 'selected' : ''}" data-record-id="${escapeHtml(r.id)}">
          <div class="ti-feed-top">
            <span class="history-risk-badge history-risk-${cls}">${escapeHtml(r.status.toUpperCase())} · ${r.score}/100</span>
            <span class="ti-feed-time">${formatTimestamp(r.timestamp)}</span>
          </div>
          <div class="ti-feed-url">${escapeHtml(r.input)}</div>
          <div class="ti-feed-bottom">
            <div class="ti-feed-cats">${cats || '<span class="ti-cat-chip safe">Clean Structure</span>'}</div>
            <button class="btn btn-sm btn-outline ti-inspect-btn" data-record-id="${escapeHtml(r.id)}">
              <i class="fa-solid fa-microscope"></i> Inspect
            </button>
          </div>
        </div>`;
    }).join('');

    container.querySelectorAll('.ti-inspect-btn, .ti-feed-item').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = el.getAttribute('data-record-id');
        const found = loadRecords().find(r => r.id === id);
        if (found) {
          selectedRecordId = found.id;
          renderDashboard();
        }
      });
    });
  }

  function renderInvestigationEmpty() {
    const panel = document.getElementById('tiInvestigationPanel');
    if (!panel) return;
    panel.innerHTML = `
      <div class="ti-investigation-empty">
        <i class="fa-solid fa-microscope"></i>
        <h4>No URL Selected for Investigation</h4>
        <p>Enter any suspicious URL in the Forensic Investigator bar above, load a threat preset, or scan a QR code in the Universal Scanner.</p>
      </div>`;
  }

  function renderInvestigationReport(rec) {
    const panel = document.getElementById('tiInvestigationPanel');
    if (!panel) return;

    const cls = getStatusClass(rec.status);
    const f = rec.forensics;

    const categoriesHtml = (rec.threatCategories && rec.threatCategories.length > 0)
      ? rec.threatCategories.map(c => `<span class="ti-threat-tag">${escapeHtml(c)}</span>`).join('')
      : '<span class="ti-threat-tag clean">No Threat Categories Triggered</span>';

    const indicatorsHtml = (rec.detectedIndicators && rec.detectedIndicators.length > 0)
      ? rec.detectedIndicators.map(ind => `
          <div class="issue-item ${escapeHtml(ind.severity)}">
            <i class="fa-solid ${ind.severity === 'high' ? 'fa-circle-exclamation' : (ind.severity === 'low' ? 'fa-circle-info' : 'fa-triangle-exclamation')}"></i>
            <div>
              <div class="issue-header-line">
                <strong>${escapeHtml(ind.title)}</strong>
                <span class="pts-badge">+${escapeHtml(String(ind.points))} pts</span>
              </div>
              <p>${escapeHtml(ind.reason)}</p>
            </div>
          </div>`).join('')
      : '<div class="highlight-item"><i class="fa-solid fa-circle-check"></i><div><strong>[Clean]</strong> Zero heuristic threat indicators triggered.</div></div>';

    const componentsHtml = (rec.highlightedComponents && rec.highlightedComponents.length > 0)
      ? rec.highlightedComponents.map(comp => `
          <div class="ti-component-chip sev-${escapeHtml(comp.severity)}">
            <span class="ti-comp-part">${escapeHtml(comp.part)}</span>
            <code class="ti-comp-val">${escapeHtml(comp.value)}</code>
            <span class="ti-comp-reason">${escapeHtml(comp.reason)}</span>
          </div>`).join('')
      : '<p class="ti-muted-note">No suspicious URL components detected.</p>';

    let forensicsHtml = '<p class="ti-muted-note">URL structure decomposition is available for web URLs and executable schemes.</p>';
    if (f) {
      const subdomainsText = (f.subdomains && f.subdomains.length > 0) ? f.subdomains.join('.') : 'None';
      const encodedText = (f.encodedComponents && f.encodedComponents.length > 0) ? f.encodedComponents.join('; ') : 'None';
      const charsText = (f.suspiciousCharacteristics && f.suspiciousCharacteristics.length > 0)
        ? f.suspiciousCharacteristics.map(s => `<span class="ti-char-pill">${escapeHtml(s)}</span>`).join('')
        : '<span class="ti-char-pill clean">No structural anomalies</span>';

      const paramsHtml = (f.queryParams && f.queryParams.length > 0)
        ? `<div class="ti-params-table-wrap">
            <table class="ti-params-table">
              <thead>
                <tr><th>Parameter</th><th>Raw Value</th><th>Decoded Value</th><th>Forensic Flags</th></tr>
              </thead>
              <tbody>
                ${f.queryParams.map(qp => `
                  <tr>
                    <td><code>${escapeHtml(qp.key)}</code></td>
                    <td><code>${escapeHtml(qp.value.slice(0, 80))}</code></td>
                    <td><code>${escapeHtml(qp.decodedValue.slice(0, 80))}</code></td>
                    <td>${qp.flags.length > 0
                      ? qp.flags.map(fl => `<span class="ti-flag-badge">${escapeHtml(fl)}</span>`).join(' ')
                      : '<span class="ti-flag-clean">normal</span>'}</td>
                  </tr>`).join('')}
              </tbody>
            </table>
          </div>`
        : '<p class="ti-muted-note">No query parameters present.</p>';

      forensicsHtml = `
        <div class="ti-forensics-grid">
          <div class="ti-forensic-cell"><span>Protocol</span><code>${escapeHtml(f.protocol || 'N/A')}</code></div>
          <div class="ti-forensic-cell"><span>Hostname (Normalized)</span><code>${escapeHtml(f.hostname || 'N/A')}</code></div>
          <div class="ti-forensic-cell"><span>Raw Hostname</span><code>${escapeHtml(f.rawHostname || 'N/A')}</code></div>
          <div class="ti-forensic-cell"><span>Decoded IDN / Punycode</span><code>${escapeHtml(f.decodedHostname || 'N/A')}${f.punycodeHostname ? ' (' + escapeHtml(f.punycodeHostname) + ')' : ''}</code></div>
          <div class="ti-forensic-cell"><span>Root Domain</span><code>${escapeHtml(f.rootDomain || 'N/A')}</code></div>
          <div class="ti-forensic-cell"><span>Subdomains</span><code>${escapeHtml(subdomainsText)}</code></div>
          <div class="ti-forensic-cell"><span>Port</span><code>${escapeHtml(f.port || 'N/A')}${f.isExplicitPort ? ' (explicit)' : ' (default)'}</code></div>
          <div class="ti-forensic-cell"><span>Path</span><code>${escapeHtml(f.path || '/')}</code></div>
          <div class="ti-forensic-cell"><span>Fragment</span><code>${escapeHtml(f.fragment || 'None')}</code></div>
          <div class="ti-forensic-cell"><span>Encoded Components</span><code>${escapeHtml(encodedText)}</code></div>
        </div>
        ${f.malformed ? `<div class="ti-malformed-alert"><i class="fa-solid fa-bug"></i> <strong>Malformed URL Indicators:</strong> ${escapeHtml((f.malformedReasons || []).join('; '))}</div>` : ''}
        <div class="ti-forensic-subblock">
          <h5><i class="fa-solid fa-fingerprint"></i> Suspicious URL Characteristics</h5>
          <div class="ti-chars-wrap">${charsText}</div>
        </div>
        <div class="ti-forensic-subblock">
          <h5><i class="fa-solid fa-sliders"></i> Query Parameter Decomposition</h5>
          ${paramsHtml}
        </div>`;
    }

    panel.innerHTML = `
      <div class="ti-report-header ti-report-${cls}">
        <div>
          <span class="ti-report-eyebrow">FORENSIC THREAT REPORT</span>
          <h3 class="ti-report-verdict">${escapeHtml(rec.status.toUpperCase())} VERDICT</h3>
        </div>
        <div class="ti-report-score-box">
          <span class="ti-report-score">${rec.score}</span>
          <span class="ti-report-max">/100 RISK</span>
        </div>
      </div>

      <div class="ti-report-payload">
        <span class="ti-sub-label">Target Payload (Defanged — Not Executed)</span>
        <code>${escapeHtml(rec.input)}</code>
      </div>

      <div class="ti-report-section">
        <h5><i class="fa-solid fa-tags"></i> Detected Threat Categories</h5>
        <div class="ti-tags-row">${categoriesHtml}</div>
      </div>

      <div class="ti-report-section">
        <h5><i class="fa-solid fa-triangle-exclamation"></i> Triggered Security Indicators &amp; Weights</h5>
        <div class="issues-list">${indicatorsHtml}</div>
      </div>

      <div class="ti-report-section">
        <h5><i class="fa-solid fa-highlighter"></i> Highlighted Suspicious URL Components</h5>
        <div class="ti-components-grid">${componentsHtml}</div>
      </div>

      <div class="ti-report-section">
        <h5><i class="fa-solid fa-network-wired"></i> URL Structure Forensics Decomposition</h5>
        ${forensicsHtml}
      </div>

      <div class="advice-box advice-${cls}" style="margin: 14px 0 0;">
        <i class="fa-solid ${cls === 'dangerous' ? 'fa-shield-cat' : (cls === 'suspicious' ? 'fa-triangle-exclamation' : 'fa-lightbulb')}"></i>
        <div>
          <strong>Recommended Action:</strong>
          <p>${escapeHtml(rec.recommendation)}</p>
        </div>
      </div>
    `;
  }

  function init() {
    const investigateBtn = document.getElementById('tiInvestigateBtn');
    const investigateInput = document.getElementById('tiInvestigateInput');

    if (investigateBtn && investigateInput) {
      investigateBtn.addEventListener('click', () => {
        investigatePayload(investigateInput.value);
      });
      investigateInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          investigatePayload(investigateInput.value);
        }
      });
    }

    document.querySelectorAll('#page-threat-intel .ti-preset-btn[data-url]').forEach(btn => {
      btn.addEventListener('click', () => {
        const sample = btn.getAttribute('data-url') || '';
        if (investigateInput) investigateInput.value = sample;
        investigatePayload(sample);
      });
    });

    document.querySelectorAll('.ti-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.ti-filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-filter') || 'all';
        renderRecentFeed(loadRecords());
      });
    });

    const searchInput = document.getElementById('tiSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        activeSearch = (e.target.value || '').trim().toLowerCase();
        renderRecentFeed(loadRecords());
      });
    }

    const clearBtn = document.getElementById('tiClearTelemetryBtn');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        if (window.confirm('Clear all Threat Intelligence telemetry records?')) {
          clearTelemetry();
          if (window.showToast) window.showToast('Threat Intelligence telemetry cleared.', 'info');
        }
      });
    }

    renderDashboard();
  }

  return {
    init,
    recordAnalysis,
    investigatePayload,
    renderDashboard,
    clearTelemetry,
    loadRecords
  };
})();
