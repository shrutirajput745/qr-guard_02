/**
 * QR Guard - Main Application Controller
 * Wires together: Universal Scanner, Security Analyzer, Blur Recovery Lab,
 * Scan History, Theme, Page Navigation, Tabs, and Result Rendering.
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── HTML Entity Escaping (XSS Prevention) ──────────────────────────────
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ── Toast Notification ─────────────────────────────────────────────────
  window.showToast = function(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    let icon = 'fa-circle-info';
    if (type === 'success' || type === 'safe') icon = 'fa-circle-check';
    if (type === 'warning' || type === 'suspicious') icon = 'fa-triangle-exclamation';
    if (type === 'error' || type === 'dangerous') icon = 'fa-circle-exclamation';
    toast.innerHTML = `
      <i class="fa-solid ${icon}"></i>
      <span>${escapeHtml(message)}</span>
      <button onclick="this.parentElement.remove()" class="toast-close" aria-label="Close">&times;</button>
    `;
    container.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  };

  // ── Theme Toggle ───────────────────────────────────────────────────────
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  let currentTheme = localStorage.getItem('qrguard_theme') || localStorage.getItem('qrguard2_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);
  updateThemeIcon(currentTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', currentTheme);
      localStorage.setItem('qrguard_theme', currentTheme);
      updateThemeIcon(currentTheme);
      window.showToast(`Switched to ${currentTheme} theme`, 'info');
    });
  }
  function updateThemeIcon(theme) {
    if (themeToggleBtn) {
      themeToggleBtn.innerHTML = theme === 'dark'
        ? '<i class="fa-solid fa-sun"></i>'
        : '<i class="fa-solid fa-moon"></i>';
    }
  }

  // ── Page Navigation ────────────────────────────────────────────────────
  const pageNavBtns = document.querySelectorAll('.page-nav-btn');
  const pageContents = document.querySelectorAll('.page-content');

  pageNavBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetPage = btn.getAttribute('data-page');
      pageNavBtns.forEach(b => b.classList.remove('active'));
      pageContents.forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const activePage = document.getElementById(`page-${targetPage}`);
      if (activePage) activePage.classList.add('active');

      // Stop camera when leaving scanner
      if (targetPage !== 'scanner' && window.QRScanner) {
        window.QRScanner.stopCamera();
      }

      // Render history when navigating to it
      if (targetPage === 'history' && window.QRHistory) {
        window.QRHistory.renderHistory();
      }

      // Initialize Live Demo Lab scenario when navigating to it
      if (targetPage === 'demo' && window.QRLiveDemo) {
        window.QRLiveDemo.selectScenario('safe');
      }

      // Reset or highlight Architecture when navigating to it
      if (targetPage === 'architecture' && window.QRArchitecture) {
        // Ready for inspection
      }

      // Initialize Presentation when navigating to it
      if (targetPage === 'presentation' && window.QRPresentation) {
        // Presentation ready
      }
    });
  });

  // Global helper to switch page programmatically
  window.navigateToPage = function(pageId) {
    const navBtn = document.querySelector(`.page-nav-btn[data-page="${pageId}"]`);
    if (navBtn) navBtn.click();
  };

  // ── Scanner Tab Navigation ─────────────────────────────────────────────
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const activeContent = document.getElementById(`tab-${targetTab}`);
      if (activeContent) activeContent.classList.add('active');
      if (targetTab !== 'camera' && window.QRScanner) window.QRScanner.stopCamera();
    });
  });

  // ── Camera Controls ────────────────────────────────────────────────────
  const startCamBtn = document.getElementById('startCamBtn');
  const stopCamBtn  = document.getElementById('stopCamBtn');
  if (startCamBtn) startCamBtn.addEventListener('click', () => window.QRScanner.startCamera());
  if (stopCamBtn)  stopCamBtn.addEventListener('click',  () => window.QRScanner.stopCamera());

  // ── Initialize Modules ─────────────────────────────────────────────────
  if (window.QRScanner) {
    window.QRScanner.init(
      (decodedText) => processQrData(decodedText),
      (errorMessage) => window.showToast(errorMessage, 'warning')
    );
  }

  if (window.QRSamples) {
    window.QRSamples.init((sampleUrl) => processQrData(sampleUrl));
  }

  if (window.QRRecovery) {
    window.QRRecovery.init((decodedText) => {
      // Route recovered QR through security analyzer
      processQrData(decodedText);
      // Switch back to scanner page to show result
      const scannerNav = document.getElementById('navScanner');
      if (scannerNav) scannerNav.click();
      window.showToast('QR recovered! Analyzing security…', 'info');
    });
  }

  if (window.QRLiveDemo) {
    window.QRLiveDemo.init();
  }

  if (window.QRArchitecture) {
    window.QRArchitecture.init();
  }

  if (window.QRPresentation) {
    window.QRPresentation.init();
  }

  // ── Remove File Button ─────────────────────────────────────────────────
  const removeFileBtn = document.getElementById('removeFileBtn');
  if (removeFileBtn) {
    removeFileBtn.addEventListener('click', () => window.QRScanner.resetUpload());
  }

  // ── Recovery Reset Button ──────────────────────────────────────────────
  const recoveryResetBtn = document.getElementById('recoveryResetBtn');
  if (recoveryResetBtn) {
    recoveryResetBtn.addEventListener('click', () => {
      if (window.QRRecovery) window.QRRecovery.resetRecovery();
    });
  }

  // ── Scan Again Button ──────────────────────────────────────────────────
  const scanAgainBtn = document.getElementById('scanAgainBtn');
  if (scanAgainBtn) {
    scanAgainBtn.addEventListener('click', () => resetResultsView());
  }

  // ── Copy Payload Button ────────────────────────────────────────────────
  const copyBtn = document.getElementById('copyBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const payloadText = document.getElementById('extractedPayload')?.textContent;
      if (!payloadText) return;
      navigator.clipboard.writeText(payloadText).then(() => {
        copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        window.showToast('Copied to clipboard!', 'success');
        setTimeout(() => { copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy'; }, 2000);
      }).catch(() => window.showToast('Could not copy automatically.', 'warning'));
    });
  }

  // ── Open URL Safety Handling ───────────────────────────────────────────
  const openUrlBtn = document.getElementById('openUrlBtn');
  let currentAnalyzedUrl = '';
  let currentAnalyzedStatus = 'Safe';

  if (openUrlBtn) {
    openUrlBtn.addEventListener('click', (e) => {
      if (!currentAnalyzedUrl || currentAnalyzedUrl === '#') {
        e.preventDefault();
        window.showToast('No valid web address to open.', 'warning');
        return;
      }
      if (/^(javascript:|data:|file:|vbscript:)/i.test(currentAnalyzedUrl)) {
        e.preventDefault();
        window.showToast('Execution of script/file schemes is blocked for security.', 'error');
        return;
      }
      if (currentAnalyzedStatus === 'Dangerous') {
        const confirmed = window.confirm(
          'SECURITY ALERT: QR Guard flagged this URL as HIGH RISK / DANGEROUS.\n\n' +
          'Opening it may expose you to phishing, credential theft, or malicious downloads.\n\n' +
          'Are you absolutely sure you want to proceed?'
        );
        if (!confirmed) { e.preventDefault(); return; }
      }
    });
  }

  // ── History Actions ────────────────────────────────────────────────────
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
      if (window.confirm('Clear all scan history? This cannot be undone.')) {
        if (window.QRHistory) {
          window.QRHistory.clearAll();
          window.QRHistory.renderHistory();
          window.showToast('Scan history cleared.', 'info');
        }
      }
    });
  }

  const exportCsvBtn = document.getElementById('exportCsvBtn');
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      if (!window.QRHistory) return;
      const csv = window.QRHistory.exportCSV();
      if (!csv) {
        window.showToast('No history to export.', 'warning');
        return;
      }
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `qr-guard-history-${Date.now()}.csv`;
      link.click();
      URL.revokeObjectURL(link.href);
      window.showToast('History exported as CSV.', 'success');
    });
  }

  // ── Core: Process QR Data ──────────────────────────────────────────────
  function processQrData(rawPayload) {
    showLoading();
    setTimeout(() => {
      if (!window.QRAnalyzer) {
        window.showToast('Analyzer module not loaded.', 'error');
        return;
      }
      const result = window.QRAnalyzer.analyze(rawPayload);

      // Save to history (privacy-aware masking done inside history module)
      if (window.QRHistory) {
        window.QRHistory.addEntry(result);
      }

      renderResults(result);
    }, 350);
  }

  // ── Render Security Results ────────────────────────────────────────────
  function renderResults(result) {
    const emptyState   = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const resultContent = document.getElementById('resultContent');

    if (emptyState)   emptyState.style.display   = 'none';
    if (loadingState) loadingState.style.display = 'none';
    if (resultContent) resultContent.style.display = 'block';

    // 1. QR Type Badge
    const qrTypeBadge = document.getElementById('qrTypeBadge');
    const qrTypeIcon  = document.getElementById('qrTypeIcon');
    const qrTypeLbl   = document.getElementById('qrTypeLabelText');
    if (qrTypeIcon) qrTypeIcon.className = `fa-solid ${result.qrTypeIcon || 'fa-question-circle'}`;
    if (qrTypeLbl)  qrTypeLbl.textContent = result.qrTypeLabel || 'Unknown';

    // 2. Parsed Data Panel (for special QR types)
    renderParsedData(result);

    // 3. Status Banner & Score
    const statusBanner  = document.getElementById('statusBanner');
    const statusIcon    = document.getElementById('statusIcon');
    const statusTitle   = document.getElementById('statusTitle');
    const scoreValue    = document.getElementById('scoreValue');
    const meterBarFill  = document.getElementById('meterBarFill');
    const meterPointer  = document.getElementById('meterPointer');

    if (statusBanner) statusBanner.className = 'status-banner';
    if (meterBarFill) meterBarFill.className = 'meter-bar-fill';
    currentAnalyzedStatus = result.status;

    if (result.status === 'Dangerous') {
      statusBanner?.classList.add('status-dangerous');
      if (statusIcon)  statusIcon.className = 'fa-solid fa-skull-crossbones';
      if (statusTitle) statusTitle.textContent = 'DANGEROUS / HIGH RISK';
      meterBarFill?.classList.add('fill-dangerous');
    } else if (result.status === 'Suspicious') {
      statusBanner?.classList.add('status-suspicious');
      if (statusIcon)  statusIcon.className = 'fa-solid fa-triangle-exclamation';
      if (statusTitle) statusTitle.textContent = 'SUSPICIOUS / MODERATE RISK';
      meterBarFill?.classList.add('fill-suspicious');
    } else {
      statusBanner?.classList.add('status-safe');
      if (statusIcon)  statusIcon.className = 'fa-solid fa-circle-check';
      if (statusTitle) statusTitle.textContent = 'SAFE / LOW RISK';
      meterBarFill?.classList.add('fill-safe');
    }

    animateCounter(scoreValue, 0, result.score, 650);
    setTimeout(() => {
      if (meterBarFill) meterBarFill.style.width  = `${result.score}%`;
      if (meterPointer) meterPointer.style.left   = `${result.score}%`;
    }, 50);

    // 4. Extracted Payload
    const extractedPayload = document.getElementById('extractedPayload');
    const payloadType = document.getElementById('payloadType');
    if (extractedPayload) extractedPayload.textContent = result.input;

    const isExecScheme = /^(javascript:|data:|file:|vbscript:)/i.test(result.input);
    if (result.isUrl && !isExecScheme) {
      if (payloadType) payloadType.innerHTML = '<i class="fa-solid fa-link"></i> Decoded Web URL';
      if (openUrlBtn)  openUrlBtn.style.display = 'inline-flex';
      const validUrl = /^https?:\/\//i.test(result.input) ? result.input : `http://${result.input}`;
      currentAnalyzedUrl = validUrl;
      if (openUrlBtn) openUrlBtn.href = validUrl;
      if (result.status === 'Dangerous') {
        if (openUrlBtn) { openUrlBtn.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Open with Caution (High Risk)'; openUrlBtn.className = 'btn btn-danger btn-lg'; }
      } else if (result.status === 'Suspicious') {
        if (openUrlBtn) { openUrlBtn.innerHTML = '<i class="fa-solid fa-arrow-up-right-from-square"></i> Open Link (Suspicious)'; openUrlBtn.className = 'btn btn-outline btn-lg'; }
      } else {
        if (openUrlBtn) { openUrlBtn.innerHTML = '<i class="fa-solid fa-arrow-up-right-from-square"></i> Open Link Safely'; openUrlBtn.className = 'btn btn-outline btn-lg'; }
      }
    } else {
      currentAnalyzedUrl = '';
      const typeMap = {
        upi:      '<i class="fa-solid fa-indian-rupee-sign"></i> UPI Payment QR',
        wifi:     '<i class="fa-solid fa-wifi"></i> Wi-Fi Network QR',
        vcard:    '<i class="fa-solid fa-address-card"></i> Contact Card (vCard)',
        email:    '<i class="fa-solid fa-envelope"></i> Email Address',
        phone:    '<i class="fa-solid fa-phone"></i> Phone Number',
        sms:      '<i class="fa-solid fa-comment-sms"></i> SMS Message',
        geo:      '<i class="fa-solid fa-location-dot"></i> Geographic Location',
        applink:  '<i class="fa-solid fa-mobile-screen-button"></i> App Download Link',
        social:   '<i class="fa-solid fa-share-nodes"></i> Social Media Link',
        text:     '<i class="fa-solid fa-font"></i> Plain Text',
        dangerous:'<i class="fa-solid fa-triangle-exclamation"></i> Executable Scheme (Blocked)',
      };
      const typeHtml = typeMap[result.qrType] || '<i class="fa-solid fa-font"></i> Decoded Text';
      if (payloadType) payloadType.innerHTML = typeHtml;
      if (openUrlBtn)  openUrlBtn.style.display = 'none';
      if (openUrlBtn)  openUrlBtn.href = '#';
    }

    // 5. Explanation Summary
    const explanationText = document.getElementById('explanationText');
    if (explanationText) explanationText.textContent = result.explanation;

    // 6. Detected Issues List
    const issuesList = document.getElementById('issuesList');
    if (issuesList) {
      issuesList.innerHTML = '';
      if (result.issues.length === 0) {
        issuesList.innerHTML = `
          <div class="issue-item low">
            <i class="fa-solid fa-circle-check"></i>
            <div><strong>[Zero Risk Factors]</strong> No suspicious security indicators detected.</div>
          </div>`;
      } else {
        result.issues.forEach(issue => {
          const item = document.createElement('div');
          item.className = `issue-item ${escapeHtml(issue.severity)}`;
          const icon = issue.severity === 'high' ? 'fa-circle-exclamation' : issue.severity === 'low' ? 'fa-circle-info' : 'fa-triangle-exclamation';
          item.innerHTML = `
            <i class="fa-solid ${icon}"></i>
            <div>
              <div class="issue-header-line">
                <strong>[${escapeHtml(issue.title)}]</strong>
                <span class="pts-badge">+${escapeHtml(String(issue.points))} pts</span>
              </div>
              <p>${escapeHtml(issue.message)}</p>
            </div>`;
          issuesList.appendChild(item);
        });
      }
    }

    // 7. Passed Security Checks
    const highlightsList = document.getElementById('highlightsList');
    if (highlightsList) {
      highlightsList.innerHTML = '';
      if (result.highlights.length === 0) {
        highlightsList.innerHTML = `
          <div class="highlight-item">
            <i class="fa-solid fa-circle-check"></i>
            <div><strong>[Checked]</strong> Heuristic structural validation complete.</div>
          </div>`;
      } else {
        result.highlights.forEach(h => {
          const item = document.createElement('div');
          item.className = 'highlight-item';
          item.innerHTML = `
            <i class="fa-solid fa-circle-check"></i>
            <div><strong>[${escapeHtml(h.title)}]</strong> ${escapeHtml(h.message)}</div>`;
          highlightsList.appendChild(item);
        });
      }
    }

    // 8. Advice Box
    const adviceBox  = document.getElementById('adviceBox');
    const adviceIcon = document.getElementById('adviceIcon');
    const adviceText = document.getElementById('adviceText');
    if (adviceBox) adviceBox.className = 'advice-box';
    if (result.status === 'Dangerous') {
      adviceBox?.classList.add('advice-dangerous');
      if (adviceIcon) adviceIcon.className = 'fa-solid fa-shield-cat';
    } else if (result.status === 'Suspicious') {
      adviceBox?.classList.add('advice-suspicious');
      if (adviceIcon) adviceIcon.className = 'fa-solid fa-triangle-exclamation';
    } else {
      adviceBox?.classList.add('advice-safe');
      if (adviceIcon) adviceIcon.className = 'fa-solid fa-lightbulb';
    }
    if (adviceText) adviceText.textContent = result.advice;

    // 9. Toast
    window.showToast(`Risk Score: ${result.score}/100 (${result.status}) — Type: ${result.qrTypeLabel}`, result.status.toLowerCase());

    // 10. Scroll to results on mobile
    if (window.innerWidth < 960) {
      document.getElementById('resultCard')?.scrollIntoView({ behavior: 'smooth' });
    }
  }

  // ── Render Parsed Data for Special QR Types ────────────────────────────
  function renderParsedData(result) {
    const panel = document.getElementById('parsedDataPanel');
    const grid  = document.getElementById('parsedDataGrid');
    if (!panel || !grid) return;

    const HIDE_TYPES = ['url', 'text', 'unknown', 'dangerous', 'social'];
    if (HIDE_TYPES.includes(result.qrType) || !result.parsedData || Object.keys(result.parsedData).length === 0) {
      panel.style.display = 'none';
      return;
    }

    panel.style.display = 'block';
    grid.innerHTML = '';

    const displayNames = {
      payeeAddress: 'Payee UPI ID', payeeName: 'Payee Name', amount: 'Amount',
      note: 'Note', currency: 'Currency', ssid: 'Network Name (SSID)',
      security: 'Security Type', hidden: 'Hidden Network', password: 'Password',
      name: 'Full Name', phone: 'Phone', email: 'Email', organization: 'Organization',
      to: 'To', subject: 'Subject', body: 'Body', number: 'Number', message: 'Message',
      latitude: 'Latitude', longitude: 'Longitude', store: 'Store', url: 'URL',
      platform: 'Platform', length: 'Length', preview: 'Preview',
      protocol: 'Protocol', host: 'Host', path: 'Path', query: 'Query'
    };

    for (const [key, value] of Object.entries(result.parsedData)) {
      if (value === '' || value === null || value === undefined) continue;
      const label = displayNames[key] || key.charAt(0).toUpperCase() + key.slice(1);
      const keyEl = document.createElement('div');
      keyEl.className = 'parsed-data-key';
      keyEl.textContent = label;
      const valEl = document.createElement('div');
      valEl.className = 'parsed-data-val';
      valEl.textContent = String(value);
      grid.appendChild(keyEl);
      grid.appendChild(valEl);
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────
  function showLoading() {
    const emptyState   = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const resultContent = document.getElementById('resultContent');
    if (emptyState)   emptyState.style.display   = 'none';
    if (resultContent) resultContent.style.display = 'none';
    if (loadingState) loadingState.style.display  = 'flex';
  }

  function resetResultsView() {
    const emptyState   = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const resultContent = document.getElementById('resultContent');
    if (emptyState)   emptyState.style.display   = 'flex';
    if (loadingState) loadingState.style.display = 'none';
    if (resultContent) resultContent.style.display = 'none';
    if (window.QRScanner) { window.QRScanner.resetUpload(); window.QRScanner.stopCamera(); }
    document.getElementById('inputCard')?.scrollIntoView({ behavior: 'smooth' });
    window.showToast('Ready for next scan.', 'info');
  }

  function animateCounter(element, start, end, duration) {
    if (!element) return;
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      element.textContent = Math.floor(progress * (end - start) + start);
      if (progress < 1) window.requestAnimationFrame(step);
    };
    window.requestAnimationFrame(step);
  }

});
