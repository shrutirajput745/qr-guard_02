/**
 * QR Guard - Live Demo Lab Controller
 * Implements the interactive demonstration flow:
 * 1. Load / Generate Scenario QR
 * 2. Simulate Degradation (Blur / Low Contrast / Normal)
 * 3. Process & Recover (Image enhancement pipeline)
 * 4. Real QR Decoding (jsQR / Html5Qrcode)
 * 5. Security & Risk Analysis (QRAnalyzer)
 * Full loading, empty, success, and error states with working event handlers.
 */

window.QRLiveDemo = (function() {

  const SCENARIOS = {
    safe: {
      id: 'safe',
      title: 'Safe Official URL',
      payload: 'https://wikipedia.org',
      badge: 'Safe (0 Risk)',
      badgeClass: 'safe',
      type: 'url',
      degradation: 'none',
      icon: 'fa-globe',
      summary: 'Clean official Wikipedia HTTPS link. Tests standard high-speed decoding and zero-risk verification.'
    },
    blurry: {
      id: 'blurry',
      title: 'Blurry Degraded QR',
      payload: 'https://github.com/shrutirajput745/qr-guard_02',
      badge: 'Blur Recovery Demo',
      badgeClass: 'suspicious',
      type: 'url',
      degradation: 'blur',
      icon: 'fa-wand-magic-sparkles',
      summary: 'Defocus blur simulation. Direct scanning fails; adaptive thresholding recovers the payload for security analysis.'
    },
    shortener: {
      id: 'shortener',
      title: 'Suspicious Shortener URL',
      payload: 'http://bit.ly/security-test-381',
      badge: 'Suspicious (35 Risk)',
      badgeClass: 'suspicious',
      type: 'url',
      degradation: 'lowcontrast',
      icon: 'fa-link',
      summary: 'HTTP link shortener mask hiding destination. Flagged for lack of TLS and masking service.'
    },
    phishing: {
      id: 'phishing',
      title: 'High-Risk Quishing Attack',
      payload: 'http://free-reward-claim.top/login',
      badge: 'Dangerous (75 Risk)',
      badgeClass: 'dangerous',
      type: 'url',
      degradation: 'none',
      icon: 'fa-skull-crossbones',
      summary: 'Malicious QR phishing link using an untrusted .TOP TLD, insecure HTTP, and credential theft keywords.'
    }
  };

  let activeScenario = null;
  let currentRawCanvas = null;
  let currentProcessedCanvas = null;
  let currentDecodedPayload = null;

  function init() {
    setupEventListeners();
  }

  function setupEventListeners() {
    // Scenario selector cards
    document.querySelectorAll('.demo-scenario-card').forEach(card => {
      card.addEventListener('click', () => {
        const scenarioKey = card.getAttribute('data-scenario');
        selectScenario(scenarioKey);
      });
    });

    // Run Full Pipeline button
    const runAllBtn = document.getElementById('demoRunAllBtn');
    if (runAllBtn) {
      runAllBtn.addEventListener('click', () => {
        if (!activeScenario) {
          selectScenario('blurry');
        }
        runFullPipeline();
      });
    }

    // Step-by-step buttons
    const stepGenBtn = document.getElementById('demoStepGenBtn');
    if (stepGenBtn) {
      stepGenBtn.addEventListener('click', () => generateScenarioQR(activeScenario || SCENARIOS.safe));
    }

    const stepProcessBtn = document.getElementById('demoStepProcessBtn');
    if (stepProcessBtn) {
      stepProcessBtn.addEventListener('click', () => runProcessingAndDecode());
    }

    const resetBtn = document.getElementById('demoResetBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => resetDemoLab());
    }

    // Direct Test in Universal Scanner button
    const sendToScannerBtn = document.getElementById('demoSendToScannerBtn');
    if (sendToScannerBtn) {
      sendToScannerBtn.addEventListener('click', () => {
        if (!currentDecodedPayload) return;
        const navScanner = document.getElementById('navScanner');
        if (navScanner) navScanner.click();
        const testInput = document.getElementById('genInput');
        if (testInput) testInput.value = currentDecodedPayload;
        const genBtn = document.getElementById('genBtn');
        if (genBtn) genBtn.click();
        if (window.showToast) window.showToast('Transferred decoded payload to Universal Scanner!', 'success');
      });
    }
  }

  function selectScenario(scenarioKey) {
    const scenario = SCENARIOS[scenarioKey];
    if (!scenario) return;
    activeScenario = scenario;

    // Highlight active card
    document.querySelectorAll('.demo-scenario-card').forEach(card => {
      card.classList.toggle('active', card.getAttribute('data-scenario') === scenarioKey);
    });

    // Update scenario description banner
    const titleEl = document.getElementById('demoActiveTitle');
    const descEl = document.getElementById('demoActiveDesc');
    const badgeEl = document.getElementById('demoActiveBadge');
    const targetPayloadEl = document.getElementById('demoActivePayload');

    if (titleEl) titleEl.textContent = scenario.title;
    if (descEl) descEl.textContent = scenario.summary;
    if (badgeEl) {
      badgeEl.className = `sample-badge ${scenario.badgeClass}`;
      badgeEl.textContent = scenario.badge;
    }
    if (targetPayloadEl) targetPayloadEl.textContent = scenario.payload;

    const banner = document.getElementById('demoActiveBanner');
    if (banner) banner.style.display = 'flex';

    // Generate scenario QR on canvas
    generateScenarioQR(scenario);

    if (window.showToast) {
      window.showToast(`Selected "${scenario.title}". Ready to run demonstration.`, 'info');
    }
  }

  function generateScenarioQR(scenario) {
    showEmptyState(false);
    setPipelineStep(1);

    const canvas = document.getElementById('demoOriginalCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const payload = scenario.payload;

    const onQrReady = () => {
      // Apply degradation simulation if specified
      if (scenario.degradation === 'blur') {
        applyCanvasBlur(canvas, 4);
      } else if (scenario.degradation === 'lowcontrast') {
        applyCanvasLowContrast(canvas);
      }
      currentRawCanvas = canvas;
      updateStepStatus(1, 'Generated', 'success');
      enableStepButtons(true);
    };

    if (typeof QRCode !== 'undefined' && QRCode.toCanvas) {
      QRCode.toCanvas(canvas, payload, {
        width: 220,
        margin: 2,
        color: {
          dark: '#0f172a',
          light: '#ffffff'
        }
      }, (err) => {
        if (err) {
          console.warn('QRCode.toCanvas error:', err);
          fallbackDrawLocalImage(scenario, canvas, onQrReady);
        } else {
          onQrReady();
        }
      });
    } else {
      fallbackDrawLocalImage(scenario, canvas, onQrReady);
    }
  }

  function fallbackDrawLocalImage(scenario, canvas, callback) {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      callback();
    };
    img.onerror = () => {
      // Draw placeholder canvas if image fails
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#1e293b';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#38bdf8';
      ctx.font = '12px monospace';
      ctx.fillText('Demo QR Ready', 50, 110);
      callback();
    };
    const demoMap = {
      safe: '/images/demo/demo-normal.png',
      blurry: '/images/demo/demo-blurry.png',
      shortener: '/images/demo/demo-lowcontrast.png',
      phishing: '/images/demo/demo-normal.png'
    };
    img.src = demoMap[scenario.id] || '/images/demo/demo-normal.png';
  }

  /** Apply box blur degradation to canvas */
  function applyCanvasBlur(canvas, radius = 4) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const imgData = ctx.getImageData(0, 0, w, h);
    const d = imgData.data;
    const copy = new Uint8ClampedArray(d);

    // Horizontal pass
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        let r = 0, g = 0, b = 0, count = 0;
        for (let kx = -radius; kx <= radius; kx++) {
          const px = Math.min(w - 1, Math.max(0, x + kx));
          const idx = (y * w + px) * 4;
          r += copy[idx];
          g += copy[idx + 1];
          b += copy[idx + 2];
          count++;
        }
        const outIdx = (y * w + x) * 4;
        d[outIdx] = r / count;
        d[outIdx + 1] = g / count;
        d[outIdx + 2] = b / count;
      }
    }
    ctx.putImageData(imgData, 0, 0);
  }

  /** Apply low contrast degradation to canvas */
  function applyCanvasLowContrast(canvas) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const imgData = ctx.getImageData(0, 0, w, h);
    const d = imgData.data;

    // Compress dynamic range from [0, 255] to [135, 175] (faint gray)
    for (let i = 0; i < d.length; i += 4) {
      const g = Math.round(0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2]);
      const compressed = Math.round(135 + (g / 255) * 45);
      d[i] = compressed;
      d[i + 1] = compressed;
      d[i + 2] = compressed;
    }
    ctx.putImageData(imgData, 0, 0);
  }

  async function runProcessingAndDecode() {
    if (!currentRawCanvas) {
      if (window.showToast) window.showToast('Please load a scenario first.', 'warning');
      return;
    }

    showLoadingState(true);
    setPipelineStep(2);
    updateStepStatus(2, 'Processing Filters…', 'loading');

    const procCanvas = document.getElementById('demoProcessedCanvas');
    const procCtx = procCanvas ? procCanvas.getContext('2d') : null;

    // Use QRRecovery to process and decode
    const rawCtx = currentRawCanvas.getContext('2d');
    const rawData = rawCtx.getImageData(0, 0, currentRawCanvas.width, currentRawCanvas.height);

    setTimeout(async () => {
      let recoveryResult = null;
      if (window.QRRecovery) {
        recoveryResult = await window.QRRecovery.recoverFromPixelData(
          rawData.data,
          rawData.width,
          rawData.height,
          (msg) => {
            const statusLabel = document.getElementById('demoProgressLabel');
            if (statusLabel) statusLabel.textContent = msg;
          },
          (d, w, h) => {
            const c = document.createElement('canvas');
            c.width = w; c.height = h;
            c.getContext('2d').putImageData(new ImageData(d, w, h), 0, 0);
            return c;
          }
        );
      } else if (window.jsQR) {
        const dec = window.jsQR(rawData.data, rawData.width, rawData.height);
        recoveryResult = dec
          ? { success: true, text: dec.data, method: 'Direct jsQR Scan' }
          : { success: false };
      }

      showLoadingState(false);

      if (recoveryResult && recoveryResult.success) {
        currentDecodedPayload = recoveryResult.text;
        setPipelineStep(3);
        updateStepStatus(2, 'Enhanced', 'success');
        updateStepStatus(3, 'Decoded', 'success');

        // Draw processed preview
        if (procCtx) {
          if (recoveryResult.processedCanvas) {
            procCanvas.width = recoveryResult.processedCanvas.width;
            procCanvas.height = recoveryResult.processedCanvas.height;
            procCtx.drawImage(recoveryResult.processedCanvas, 0, 0);
          } else {
            procCtx.drawImage(currentRawCanvas, 0, 0);
          }
        }

        // Show effective method
        const methodEl = document.getElementById('demoEffectiveMethod');
        if (methodEl) {
          methodEl.textContent = recoveryResult.method || 'Adaptive Recovery Pipeline';
          methodEl.parentElement.style.display = 'block';
        }

        // Step 4: Run Heuristic Security Analysis
        runSecurityAnalysis(currentDecodedPayload);

      } else {
        // Honest recovery failure
        updateStepStatus(2, 'Inconclusive', 'warning');
        updateStepStatus(3, 'Decode Failed', 'danger');
        showErrorState('QR code could not be decoded. The degradation was too severe for recovery.');
      }
    }, 400);
  }

  function runSecurityAnalysis(payload) {
    setPipelineStep(4);
    updateStepStatus(4, 'Analyzing Risk…', 'loading');

    setTimeout(() => {
      if (!window.QRAnalyzer) {
        showErrorState('Security Analyzer module not available.');
        return;
      }

      const analysis = window.QRAnalyzer.analyze(payload);
      updateStepStatus(4, 'Complete', 'success');
      renderAnalysisResult(analysis);
    }, 300);
  }

  function renderAnalysisResult(analysis) {
    const resultCard = document.getElementById('demoResultCard');
    if (!resultCard) return;
    resultCard.style.display = 'block';

    // 1. Verdict Banner
    const verdictBanner = document.getElementById('demoVerdictBanner');
    const verdictTitle = document.getElementById('demoVerdictTitle');
    const verdictIcon = document.getElementById('demoVerdictIcon');
    const scoreVal = document.getElementById('demoScoreVal');

    if (verdictBanner) verdictBanner.className = `status-banner status-${analysis.status.toLowerCase()}`;
    if (verdictTitle) verdictTitle.textContent = `${analysis.status.toUpperCase()} / ${analysis.status === 'Dangerous' ? 'HIGH RISK' : analysis.status === 'Suspicious' ? 'MODERATE RISK' : 'LOW RISK'}`;
    if (verdictIcon) {
      verdictIcon.className = analysis.status === 'Dangerous'
        ? 'fa-solid fa-skull-crossbones'
        : analysis.status === 'Suspicious'
        ? 'fa-solid fa-triangle-exclamation'
        : 'fa-solid fa-circle-check';
    }
    if (scoreVal) scoreVal.textContent = analysis.score;

    // 2. Extracted Payload
    const payloadEl = document.getElementById('demoExtractedPayload');
    const typeLabel = document.getElementById('demoTypeLabel');
    if (payloadEl) payloadEl.textContent = analysis.input;
    if (typeLabel) typeLabel.textContent = analysis.qrTypeLabel || 'Decoded QR';

    // 3. Explanation Text
    const expText = document.getElementById('demoExplanationText');
    if (expText) expText.textContent = analysis.explanation;

    // 4. Detected Issues
    const issuesList = document.getElementById('demoIssuesList');
    if (issuesList) {
      issuesList.innerHTML = '';
      if (analysis.issues.length === 0) {
        issuesList.innerHTML = `
          <div class="issue-item low">
            <i class="fa-solid fa-circle-check"></i>
            <div><strong>[Safe Structure]</strong> No security risk indicators triggered.</div>
          </div>`;
      } else {
        analysis.issues.forEach(iss => {
          const item = document.createElement('div');
          item.className = `issue-item ${iss.severity}`;
          const icon = iss.severity === 'high' ? 'fa-circle-exclamation' : 'fa-triangle-exclamation';
          item.innerHTML = `
            <i class="fa-solid ${icon}"></i>
            <div>
              <div class="issue-header-line">
                <strong>[${escapeHtml(iss.title)}]</strong>
                <span class="pts-badge">+${iss.points} pts</span>
              </div>
              <p>${escapeHtml(iss.message)}</p>
            </div>`;
          issuesList.appendChild(item);
        });
      }
    }

    // Scroll smoothly to results
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    if (window.showToast) {
      window.showToast(`Demonstration finished! Verdict: ${analysis.status} (${analysis.score}/100)`, analysis.status.toLowerCase());
    }
  }

  async function runFullPipeline(scenarioKey) {
    if (scenarioKey) selectScenario(scenarioKey);
    else if (!activeScenario) selectScenario('blurry');

    setTimeout(() => {
      runProcessingAndDecode();
    }, 350);
  }

  function resetDemoLab() {
    activeScenario = null;
    currentRawCanvas = null;
    currentProcessedCanvas = null;
    currentDecodedPayload = null;

    document.querySelectorAll('.demo-scenario-card').forEach(c => c.classList.remove('active'));

    const banner = document.getElementById('demoActiveBanner');
    if (banner) banner.style.display = 'none';

    const resultCard = document.getElementById('demoResultCard');
    if (resultCard) resultCard.style.display = 'none';

    const origCanvas = document.getElementById('demoOriginalCanvas');
    if (origCanvas) {
      const ctx = origCanvas.getContext('2d');
      ctx.clearRect(0, 0, origCanvas.width, origCanvas.height);
    }

    const procCanvas = document.getElementById('demoProcessedCanvas');
    if (procCanvas) {
      const ctx = procCanvas.getContext('2d');
      ctx.clearRect(0, 0, procCanvas.width, procCanvas.height);
    }

    const methodEl = document.getElementById('demoEffectiveMethod');
    if (methodEl && methodEl.parentElement) methodEl.parentElement.style.display = 'none';

    setPipelineStep(0);
    showEmptyState(true);
    showLoadingState(false);

    if (window.showToast) window.showToast('Live Demo Lab reset to initial state.', 'info');
  }

  // ── UI State Helpers ──────────────────────────────────────────────────────

  function showEmptyState(show) {
    const el = document.getElementById('demoEmptyState');
    const studio = document.getElementById('demoStudioLayout');
    if (el) el.style.display = show ? 'flex' : 'none';
    if (studio) studio.style.display = show ? 'none' : 'grid';
  }

  function showLoadingState(loading) {
    const loadingEl = document.getElementById('demoLoadingState');
    if (loadingEl) loadingEl.style.display = loading ? 'flex' : 'none';
  }

  function showErrorState(msg) {
    const errorBox = document.getElementById('demoErrorBox');
    if (errorBox) {
      errorBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <div><strong>Pipeline Alert:</strong> <p>${escapeHtml(msg)}</p></div>`;
      errorBox.style.display = 'flex';
    }
    if (window.showToast) window.showToast(msg, 'warning');
  }

  function setPipelineStep(stepNum) {
    for (let i = 1; i <= 4; i++) {
      const stepBadge = document.getElementById(`demoStepBadge${i}`);
      if (stepBadge) {
        stepBadge.classList.toggle('active', i === stepNum);
        stepBadge.classList.toggle('completed', i < stepNum);
      }
    }
  }

  function updateStepStatus(stepNum, label, state) {
    const statusEl = document.getElementById(`demoStepStatus${stepNum}`);
    if (!statusEl) return;
    statusEl.textContent = label;
    statusEl.className = `demo-step-status status-${state}`;
  }

  function enableStepButtons(enabled) {
    const btn = document.getElementById('demoStepProcessBtn');
    if (btn) btn.disabled = !enabled;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  return {
    init,
    selectScenario,
    runFullPipeline,
    runProcessingAndDecode,
    resetDemoLab,
    SCENARIOS
  };

})();
