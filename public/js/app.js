/**
 * QR Guide 2 - Main Application Controller
 * Handles user interaction, theme toggling, scanner callbacks, and results rendering.
 */

document.addEventListener('DOMContentLoaded', () => {

  // --- HTML Entity Escaping Helper (Prevents XSS) ---
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // --- Toast Notification Helper ---
  window.showToast = function(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'fa-circle-info';
    if (type === 'success' || type === 'safe') icon = 'fa-circle-check';
    if (type === 'warning' || type === 'suspicious') icon = 'fa-triangle-exclamation';
    if (type === 'error' || type === 'dangerous') icon = 'fa-circle-exclamation';

    const safeMsg = escapeHtml(message);
    toast.innerHTML = `
      <i class="fa-solid ${icon}"></i>
      <span>${safeMsg}</span>
      <button onclick="this.parentElement.remove()" class="toast-close" aria-label="Close Notification">&times;</button>
    `;

    container.appendChild(toast);

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  };

  // --- Theme Toggle ---
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  let currentTheme = localStorage.getItem('qr_guide_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);
  updateThemeIcon(currentTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', currentTheme);
      localStorage.setItem('qr_guide_theme', currentTheme);
      updateThemeIcon(currentTheme);
      window.showToast(`Switched to ${currentTheme} theme`, 'info');
    });
  }

  function updateThemeIcon(theme) {
    if (themeToggleBtn) {
      themeToggleBtn.innerHTML = theme === 'dark' ? '<i class="fa-solid fa-sun"></i>' : '<i class="fa-solid fa-moon"></i>';
    }
  }

  // --- Tab Navigation ---
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

      // Stop camera if navigating away
      if (targetTab !== 'camera' && window.QRScanner) {
        window.QRScanner.stopCamera();
      }
    });
  });

  // --- Camera Controls ---
  const startCamBtn = document.getElementById('startCamBtn');
  const stopCamBtn = document.getElementById('stopCamBtn');
  
  if (startCamBtn) {
    startCamBtn.addEventListener('click', () => {
      window.QRScanner.startCamera();
    });
  }

  if (stopCamBtn) {
    stopCamBtn.addEventListener('click', () => {
      window.QRScanner.stopCamera();
    });
  }

  // --- Initialize Modules ---
  if (window.QRScanner) {
    window.QRScanner.init(
      (decodedText) => {
        processQrData(decodedText);
      },
      (errorMessage) => {
        window.showToast(errorMessage, 'warning');
      }
    );
  }

  if (window.QRSamples) {
    window.QRSamples.init((sampleUrl) => {
      processQrData(sampleUrl);
    });
  }

  // Remove File Button
  const removeFileBtn = document.getElementById('removeFileBtn');
  if (removeFileBtn) {
    removeFileBtn.addEventListener('click', () => {
      window.QRScanner.resetUpload();
    });
  }

  // Scan Again Button
  const scanAgainBtn = document.getElementById('scanAgainBtn');
  if (scanAgainBtn) {
    scanAgainBtn.addEventListener('click', () => {
      resetResultsView();
    });
  }

  // Copy URL Button
  const copyBtn = document.getElementById('copyBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const payloadText = document.getElementById('extractedPayload').textContent;
      navigator.clipboard.writeText(payloadText).then(() => {
        copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        window.showToast('Payload copied to clipboard!', 'success');
        setTimeout(() => {
          copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
        }, 2000);
      }).catch(() => {
        window.showToast('Could not copy to clipboard automatically.', 'warning');
      });
    });
  }

  // Open URL Safety Handling
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

      // Block dangerous schemes from running
      if (/^(javascript:|data:|file:|vbscript:)/i.test(currentAnalyzedUrl)) {
        e.preventDefault();
        window.showToast('Direct execution of script or file schemes is blocked for security.', 'error');
        return;
      }

      // If marked dangerous, confirm with user
      if (currentAnalyzedStatus === 'Dangerous') {
        const confirmed = window.confirm(
          'SECURITY ALERT: QR Guide 2 flagged this URL as HIGH RISK / DANGEROUS.\n\nOpening it may expose you to phishing, credential theft, or malicious downloads.\n\nAre you absolutely sure you want to proceed?'
        );
        if (!confirmed) {
          e.preventDefault();
          return;
        }
      }
    });
  }

  // --- Process Decoded Payload ---
  function processQrData(rawPayload) {
    showLoading();

    setTimeout(() => {
      if (!window.QRAnalyzer) {
        window.showToast('Analyzer module not loaded properly.', 'error');
        return;
      }
      const result = window.QRAnalyzer.analyze(rawPayload);
      renderResults(result);
    }, 350);
  }

  // --- Render Security Results to UI ---
  function renderResults(result) {
    const emptyState = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const resultContent = document.getElementById('resultContent');

    emptyState.style.display = 'none';
    loadingState.style.display = 'none';
    resultContent.style.display = 'block';

    // 1. Status Banner & Score
    const statusBanner = document.getElementById('statusBanner');
    const statusIcon = document.getElementById('statusIcon');
    const statusTitle = document.getElementById('statusTitle');
    const scoreValue = document.getElementById('scoreValue');
    const meterBarFill = document.getElementById('meterBarFill');
    const meterPointer = document.getElementById('meterPointer');

    statusBanner.className = 'status-banner';
    meterBarFill.className = 'meter-bar-fill';

    currentAnalyzedStatus = result.status;

    if (result.status === 'Dangerous') {
      statusBanner.classList.add('status-dangerous');
      statusIcon.className = 'fa-solid fa-skull-crossbones';
      statusTitle.textContent = 'DANGEROUS / HIGH RISK';
      meterBarFill.classList.add('fill-dangerous');
    } else if (result.status === 'Suspicious') {
      statusBanner.classList.add('status-suspicious');
      statusIcon.className = 'fa-solid fa-triangle-exclamation';
      statusTitle.textContent = 'SUSPICIOUS / MODERATE RISK';
      meterBarFill.classList.add('fill-suspicious');
    } else {
      statusBanner.classList.add('status-safe');
      statusIcon.className = 'fa-solid fa-circle-check';
      statusTitle.textContent = 'SAFE / LOW RISK';
      meterBarFill.classList.add('fill-safe');
    }

    // Animate Score Counter
    animateCounter(scoreValue, 0, result.score, 600);

    // Update Risk Bar Position
    setTimeout(() => {
      meterBarFill.style.width = `${result.score}%`;
      meterPointer.style.left = `${result.score}%`;
    }, 50);

    // 2. Extracted Payload Code Block
    const extractedPayload = document.getElementById('extractedPayload');
    const payloadType = document.getElementById('payloadType');

    extractedPayload.textContent = result.input;

    if (result.isUrl && !/^(javascript:|data:|file:|vbscript:)/i.test(result.input)) {
      payloadType.innerHTML = '<i class="fa-solid fa-link"></i> Decoded Web URL';
      openUrlBtn.style.display = 'inline-flex';

      const validUrl = result.input.startsWith('http://') || result.input.startsWith('https://') 
        ? result.input 
        : `http://${result.input}`;
      
      currentAnalyzedUrl = validUrl;
      openUrlBtn.href = validUrl;

      if (result.status === 'Dangerous') {
        openUrlBtn.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Open with Caution (High Risk)';
        openUrlBtn.className = 'btn btn-danger btn-lg';
      } else if (result.status === 'Suspicious') {
        openUrlBtn.innerHTML = '<i class="fa-solid fa-arrow-up-right-from-square"></i> Open Link (Suspicious)';
        openUrlBtn.className = 'btn btn-outline btn-lg';
      } else {
        openUrlBtn.innerHTML = '<i class="fa-solid fa-arrow-up-right-from-square"></i> Open Link Safely';
        openUrlBtn.className = 'btn btn-outline btn-lg';
      }
    } else {
      currentAnalyzedUrl = '';
      if (/^(javascript:|data:|file:|vbscript:)/i.test(result.input)) {
        payloadType.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Executable / Script Payload (Blocked)';
      } else {
        payloadType.innerHTML = '<i class="fa-solid fa-font"></i> Decoded Text / Config Data';
      }
      openUrlBtn.style.display = 'none';
      openUrlBtn.href = '#';
    }

    // 3. Score Explanation Summary
    const explanationText = document.getElementById('explanationText');
    if (explanationText) {
      explanationText.textContent = result.explanation;
    }

    // 4. Detected Issues List with Point Badges (XSS-safe)
    const issuesList = document.getElementById('issuesList');
    issuesList.innerHTML = '';

    if (result.issues.length === 0) {
      issuesList.innerHTML = `
        <div class="issue-item low">
          <i class="fa-solid fa-circle-check"></i>
          <div>
            <strong>[Zero Risk Factors]</strong> No suspicious indicators or security anomalies detected.
          </div>
        </div>
      `;
    } else {
      result.issues.forEach(issue => {
        const item = document.createElement('div');
        item.className = `issue-item ${escapeHtml(issue.severity)}`;
        
        let icon = 'fa-solid fa-triangle-exclamation';
        if (issue.severity === 'high') icon = 'fa-solid fa-circle-exclamation';
        if (issue.severity === 'low') icon = 'fa-solid fa-circle-info';

        item.innerHTML = `
          <i class="${icon}"></i>
          <div>
            <div class="issue-header-line">
              <strong>[${escapeHtml(issue.title)}]</strong>
              <span class="pts-badge">+${escapeHtml(issue.points)} pts</span>
            </div>
            <p>${escapeHtml(issue.message)}</p>
          </div>
        `;
        issuesList.appendChild(item);
      });
    }

    // 5. Passed Security Indicators (XSS-safe)
    const highlightsList = document.getElementById('highlightsList');
    highlightsList.innerHTML = '';

    if (result.highlights.length === 0) {
      highlightsList.innerHTML = `
        <div class="highlight-item">
          <i class="fa-solid fa-circle-check"></i>
          <div>
            <strong>[Standard Checked]</strong> Heuristic structural validation complete.
          </div>
        </div>
      `;
    } else {
      result.highlights.forEach(h => {
        const item = document.createElement('div');
        item.className = 'highlight-item';
        item.innerHTML = `
          <i class="fa-solid fa-circle-check"></i>
          <div>
            <strong>[${escapeHtml(h.title)}]</strong> ${escapeHtml(h.message)}
          </div>
        `;
        highlightsList.appendChild(item);
      });
    }

    // 6. Actionable Recommendation
    const adviceBox = document.getElementById('adviceBox');
    const adviceIcon = document.getElementById('adviceIcon');
    const adviceText = document.getElementById('adviceText');

    adviceBox.className = 'advice-box';

    if (result.status === 'Dangerous') {
      adviceBox.classList.add('advice-dangerous');
      adviceIcon.className = 'fa-solid fa-shield-cat';
    } else if (result.status === 'Suspicious') {
      adviceBox.classList.add('advice-suspicious');
      adviceIcon.className = 'fa-solid fa-triangle-exclamation';
    } else {
      adviceBox.classList.add('advice-safe');
      adviceIcon.className = 'fa-solid fa-lightbulb';
    }

    adviceText.textContent = result.advice;

    // Toast Alert
    window.showToast(`Risk Score: ${result.score}/100 (${result.status})`, result.status.toLowerCase());

    // Scroll to results on mobile viewports
    if (window.innerWidth < 960) {
      document.getElementById('resultCard').scrollIntoView({ behavior: 'smooth' });
    }
  }

  // --- Helper Functions ---
  function showLoading() {
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('resultContent').style.display = 'none';
    document.getElementById('loadingState').style.display = 'flex';
  }

  function resetResultsView() {
    document.getElementById('emptyState').style.display = 'flex';
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('resultContent').style.display = 'none';
    
    if (window.QRScanner) {
      window.QRScanner.resetUpload();
      window.QRScanner.stopCamera();
    }

    document.getElementById('inputCard').scrollIntoView({ behavior: 'smooth' });
    window.showToast('Ready for next scan.', 'info');
  }

  function animateCounter(element, start, end, duration) {
    if (!element) return;
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      const val = Math.floor(progress * (end - start) + start);
      element.textContent = val;
      if (progress < 1) {
        window.requestAnimationFrame(step);
      }
    };
    window.requestAnimationFrame(step);
  }

});
