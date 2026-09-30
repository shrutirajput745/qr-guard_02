/**
 * QR Guide 2 - Main Application Controller
 * Handles user interaction, theme toggling, scanner callbacks, and results rendering.
 */

document.addEventListener('DOMContentLoaded', () => {

  // --- Toast Notification Helper ---
  window.showToast = function(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'fa-circle-info';
    if (type === 'success') icon = 'fa-circle-check';
    if (type === 'warning') icon = 'fa-triangle-exclamation';
    if (type === 'error') icon = 'fa-circle-exclamation';

    toast.innerHTML = `
      <i class="fa-solid ${icon}"></i>
      <span>${message}</span>
      <button onclick="this.parentElement.remove()" class="toast-close">&times;</button>
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
  window.QRScanner.init(
    (decodedText) => {
      processQrData(decodedText);
    },
    (errorMessage) => {
      window.showToast(errorMessage, 'warning');
    }
  );

  window.QRSamples.init((sampleUrl) => {
    processQrData(sampleUrl);
  });

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
      });
    });
  }

  // --- Process Decoded Payload ---
  function processQrData(rawPayload) {
    showLoading();

    setTimeout(() => {
      const result = window.QRAnalyzer.analyze(rawPayload);
      renderResults(result);
    }, 450);
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
    animateCounter(scoreValue, 0, result.score, 700);

    // Update Risk Bar Position
    setTimeout(() => {
      meterBarFill.style.width = `${result.score}%`;
      meterPointer.style.left = `${result.score}%`;
    }, 50);

    // 2. Extracted Payload Code Block
    const extractedPayload = document.getElementById('extractedPayload');
    const payloadType = document.getElementById('payloadType');
    const openUrlBtn = document.getElementById('openUrlBtn');

    extractedPayload.textContent = result.input;

    if (result.isUrl) {
      payloadType.innerHTML = '<i class="fa-solid fa-link"></i> Decoded Web URL';
      openUrlBtn.style.display = 'inline-flex';
      openUrlBtn.href = result.input.startsWith('http') ? result.input : `http://${result.input}`;
    } else {
      payloadType.innerHTML = '<i class="fa-solid fa-font"></i> Decoded Text Data';
      openUrlBtn.style.display = 'none';
    }

    // 3. Score Explanation Summary
    const explanationText = document.getElementById('explanationText');
    if (explanationText) {
      explanationText.textContent = result.explanation;
    }

    // 4. Detected Issues List with Point Badges
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
        item.className = `issue-item ${issue.severity}`;
        
        let icon = 'fa-solid fa-triangle-exclamation';
        if (issue.severity === 'high') icon = 'fa-solid fa-circle-exclamation';
        if (issue.severity === 'low') icon = 'fa-solid fa-circle-info';

        item.innerHTML = `
          <i class="${icon}"></i>
          <div>
            <div class="issue-header-line">
              <strong>[${issue.title}]</strong>
              <span class="pts-badge">+${issue.points} pts</span>
            </div>
            <p>${issue.message}</p>
          </div>
        `;
        issuesList.appendChild(item);
      });
    }

    // 5. Passed Security Indicators
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
            <strong>[${h.title}]</strong> ${h.message}
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
    
    window.QRScanner.resetUpload();
    window.QRScanner.stopCamera();

    document.getElementById('inputCard').scrollIntoView({ behavior: 'smooth' });
    window.showToast('Ready for next scan.', 'info');
  }

  function animateCounter(element, start, end, duration) {
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
