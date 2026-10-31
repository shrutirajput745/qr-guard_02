/**
 * QR Guard - System Architecture Controller
 * Accurate technical representation of the 5 project stages:
 * User -> Scan QR Code / Upload QR Image -> Extract URL or Text -> Analyze Extracted Content -> Calculate Risk Score -> Display Result
 */

window.QRArchitecture = (function() {

  const FLOW_STEPS = [
    {
      id: 'step1',
      num: '01',
      title: 'Scan QR / Upload Image',
      component: 'User & Input Layer',
      icon: 'fa-camera',
      accentColor: 'var(--accent-blue)',
      shortSummary: 'Acquires raw QR code image through live camera stream or file upload.',
      technicalDetails: 'Uses navigator.mediaDevices.getUserMedia for webcam video frames or FileReader API for PNG/JPG/WEBP drag-and-drop. Frames are drawn onto an in-memory HTML5 Canvas element to access raw Uint8ClampedArray pixel data.',
      workingFlow: 'User ➔ Camera Stream / File Upload ➔ HTML5 Canvas Drawing Buffer',
      example: 'User points their laptop camera at a restaurant QR sticker or drops a screenshot into the browser upload box.',
      keyPoints: [
        'Real-time webcam video stream rendering',
        'Direct drag-and-drop file upload with format validation',
        'Canvas-based pixel extraction for zero network transmission'
      ]
    },
    {
      id: 'step2',
      num: '02',
      title: 'QR Pattern Decoding',
      component: 'Core jsQR Decoder Engine',
      icon: 'fa-qrcode',
      accentColor: 'var(--safe-color)',
      shortSummary: 'Locates 2D barcode finder squares and decodes raw byte payload string.',
      technicalDetails: 'The client-side jsQR engine parses the image pixel matrix, detects the 3 corner finder alignment patterns, reconstructs the perspective grid, and executes Reed-Solomon error correction to extract the encoded string. (A separate planned blur recovery preprocessing workflow is under active development for degraded images).',
      workingFlow: 'Pixel Matrix ➔ Finder Pattern Detection ➔ Reed-Solomon ECC ➔ Raw Payload String',
      example: 'The decoder extracts the raw payload string: "https://wikipedia.org" or "http://192.168.1.15/bank-login.php".',
      keyPoints: [
        'Automatic localization of 3 corner finder alignment patterns',
        'In-browser byte stream parsing and Reed-Solomon error correction',
        'Dedicated planned pipeline for blurry QR preprocessing kept distinct'
      ]
    },
    {
      id: 'step3',
      num: '03',
      title: 'Analyze Extracted Content',
      component: 'Heuristic Security Analyzer',
      icon: 'fa-shield-halved',
      accentColor: 'var(--warning-color)',
      shortSummary: 'Inspects URL protocol, domain reputation, path tokens, and obfuscation tricks.',
      technicalDetails: 'The analyzer.js engine inspects the payload using deterministic rule-based checks: Protocol validation (flagging insecure HTTP vs HTTPS), Host analysis (detecting raw IPv4/IPv6 addresses, high-risk TLDs like .top/.xyz), Path parsing (detecting phishing tokens like "login", "verify", "account"), and deceptive trick detection (@ symbol redirection, double-slash bypass, URL shorteners).',
      workingFlow: 'Extracted String ➔ Protocol Checker ➔ Host & TLD Validator ➔ Path Tokenizer ➔ Symbol Obfuscation Inspector',
      example: 'The analyzer detects plain HTTP (no SSL), a raw IP address (192.168.1.15), and the keyword "login", flagging all 3 suspicious indicators.',
      keyPoints: [
        'Protocol evaluation (Flags plain HTTP and dangerous schemes like javascript:)',
        'Host parsing (Identifies raw IP numbers without registered domains)',
        'Lexical analysis (Tokenizes path for credential-harvesting keywords)'
      ]
    },
    {
      id: 'step4',
      num: '04',
      title: 'Calculate Risk Score',
      component: 'Risk Scoring Engine',
      icon: 'fa-calculator',
      accentColor: 'var(--danger-color)',
      shortSummary: 'Accumulates weighted penalty points from 0 to 100 based on detected threats.',
      technicalDetails: 'Starting from a baseline score of 0, the engine adds pre-calibrated weights for each violation: Plain HTTP (+20), Raw IP Host (+40), Phishing Keywords (+25), Shortener (+15), @ Redirection (+45), Excessive subdomains (+15). The accumulated points are clamped between 0 (clean) and 100 (critical risk).',
      workingFlow: 'Flagged Rule Indicators ➔ Weighted Score Accumulator ➔ Clamped Total Score (0 - 100)',
      example: 'Calculation: HTTP (+20) + Raw IP (+40) + Phishing Keyword (+25) = 85 / 100 Risk Score.',
      keyPoints: [
        'Transparent, deterministic math with zero black-box obscurity',
        'Penalty weights calibrated against standard phishing tactics',
        'Includes explicit disclaimer that a low score cannot guarantee 100% safety'
      ]
    },
    {
      id: 'step5',
      num: '05',
      title: 'Display Result',
      component: 'Result Presentation Layer',
      icon: 'fa-chart-pie',
      accentColor: 'var(--accent-blue)',
      shortSummary: 'Presents color-coded verdict, security breakdown, defanged preview, and action advice.',
      technicalDetails: 'The score is categorized into three explicit tiers: Safe (0–25, Green), Suspicious (26–69, Yellow), and Dangerous (70–100, Red). The interface renders a color badge, dynamic risk meter, full breakdown list explaining each penalty, defanged link preview (to prevent accidental navigation), and logs the record to private browser localStorage.',
      workingFlow: 'Risk Score ➔ Threshold Categorizer ➔ Visual Result Badge + Defanged Link + Local Scan History',
      example: 'The UI displays a Red "DANGEROUS" banner, explains the 3 reasons, and advises the user NOT to proceed.',
      keyPoints: [
        'Instant color-coded categorization (Safe / Suspicious / Dangerous)',
        'Defanged URL preview preventing unintended one-click redirects',
        'Private scan history stored strictly in local browser memory'
      ]
    }
  ];

  let activeStepIndex = 0;

  function init() {
    renderArchitectureDiagram();
    renderStepDetails(activeStepIndex);
    setupControls();
  }

  function renderArchitectureDiagram() {
    const track = document.getElementById('simpleFlowTrack');
    if (!track) return;

    let html = '';
    FLOW_STEPS.forEach((step, idx) => {
      const isActive = idx === activeStepIndex;
      html += `
        <div class="simple-flow-node ${isActive ? 'active' : ''}" data-step-idx="${idx}">
          <div class="simple-node-badge" style="border-color: ${step.accentColor}">
            <span class="node-num" style="color: ${step.accentColor}">${step.num}</span>
            <i class="fa-solid ${step.icon}"></i>
          </div>
          <div class="simple-node-text">
            <strong>${step.title}</strong>
            <small>${step.component}</small>
          </div>
        </div>
      `;

      if (idx < FLOW_STEPS.length - 1) {
        html += `
          <div class="simple-flow-arrow">
            <i class="fa-solid fa-arrow-right"></i>
          </div>
        `;
      }
    });

    track.innerHTML = html;

    // Attach click events to nodes
    track.querySelectorAll('.simple-flow-node').forEach(node => {
      node.addEventListener('click', () => {
        const idx = parseInt(node.getAttribute('data-step-idx'), 10);
        selectStep(idx);
      });
    });
  }

  function renderStepDetails(idx) {
    const container = document.getElementById('simpleStepDetails');
    if (!container) return;

    const step = FLOW_STEPS[idx];
    container.innerHTML = `
      <div class="simple-detail-card" style="border-top: 3px solid ${step.accentColor}">
        <div class="simple-detail-header">
          <div class="simple-detail-title-group">
            <span class="step-badge" style="background: rgba(6, 182, 212, 0.12); color: ${step.accentColor}; border: 1px solid ${step.accentColor}">
              STEP ${step.num} · ${step.component.toUpperCase()}
            </span>
            <h3><i class="fa-solid ${step.icon}" style="color: ${step.accentColor}"></i> ${step.title}</h3>
            <p class="simple-detail-subtitle">${step.shortSummary}</p>
          </div>
          <div class="simple-detail-nav-btns">
            <button class="btn btn-sm btn-outline" id="archPrevStepBtn" ${idx === 0 ? 'disabled' : ''}>
              <i class="fa-solid fa-chevron-left"></i> Previous Step
            </button>
            <button class="btn btn-sm btn-primary" id="archNextStepBtnCard" ${idx === FLOW_STEPS.length - 1 ? 'disabled' : ''}>
              Next Step <i class="fa-solid fa-chevron-right"></i>
            </button>
          </div>
        </div>

        <!-- Technical Data Flow Box -->
        <div class="arch-flow-pipeline-box">
          <div class="pipeline-tag"><i class="fa-solid fa-route"></i> Data Flow:</div>
          <div class="pipeline-code"><code>${step.workingFlow}</code></div>
        </div>

        <div class="simple-detail-grid">
          <div class="simple-detail-col">
            <div class="simple-points-box">
              <h5><i class="fa-solid fa-microchip"></i> How It Works Technically</h5>
              <p class="simple-detail-desc">${step.technicalDetails}</p>
              <ul>
                ${step.keyPoints.map(pt => `<li><i class="fa-solid fa-circle-check"></i> <span>${pt}</span></li>`).join('')}
              </ul>
            </div>
          </div>

          <div class="simple-detail-col">
            <div class="simple-example-box" style="border-left: 3px solid ${step.accentColor}">
              <div class="example-icon"><i class="fa-solid fa-lightbulb"></i></div>
              <div class="example-text">
                <strong>Real Project Example</strong>
                <p>${step.example}</p>
              </div>
            </div>

            <div class="arch-component-specs">
              <h5><i class="fa-solid fa-cube"></i> Project Implementation Truth</h5>
              <div class="spec-row">
                <span class="spec-label">File / Module:</span>
                <span class="spec-val"><code>public/js/${idx === 0 ? 'scanner.js' : idx === 1 ? 'recovery.js + jsQR' : idx === 2 ? 'analyzer.js' : idx === 3 ? 'analyzer.js' : 'app.js & UI'}</code></span>
              </div>
              <div class="spec-row">
                <span class="spec-label">Execution:</span>
                <span class="spec-val">100% Client-Side In-Browser</span>
              </div>
              <div class="spec-row">
                <span class="spec-label">External Database:</span>
                <span class="spec-val" style="color: var(--safe-color)">None (Zero data tracking)</span>
              </div>
            </div>
          </div>
        </div>

        <div class="simple-step-nav-footer">
          <span class="simple-step-counter">Architecture Stage ${idx + 1} of 5</span>
          <span class="simple-step-hint">Click any stage above to inspect its real implementation details</span>
        </div>
      </div>
    `;

    // Reattach card buttons
    const prevBtn = document.getElementById('archPrevStepBtn');
    const nextBtn = document.getElementById('archNextStepBtnCard');
    if (prevBtn) prevBtn.addEventListener('click', prevStep);
    if (nextBtn) nextBtn.addEventListener('click', nextStep);
  }

  function selectStep(idx) {
    if (idx >= 0 && idx < FLOW_STEPS.length) {
      activeStepIndex = idx;
      renderArchitectureDiagram();
      renderStepDetails(idx);
    }
  }

  function nextStep() {
    if (activeStepIndex < FLOW_STEPS.length - 1) {
      selectStep(activeStepIndex + 1);
    }
  }

  function prevStep() {
    if (activeStepIndex > 0) {
      selectStep(activeStepIndex - 1);
    }
  }

  function setupControls() {
    const nextStepBtn = document.getElementById('archNextStepBtn');
    if (nextStepBtn) {
      nextStepBtn.addEventListener('click', () => {
        if (activeStepIndex >= FLOW_STEPS.length - 1) {
          selectStep(0);
        } else {
          nextStep();
        }
      });
    }

    const resetBtn = document.getElementById('archResetBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        selectStep(0);
        if (window.showToast) window.showToast('Architecture flowchart reset to Stage 1.', 'info');
      });
    }
  }

  return {
    init,
    selectStep,
    nextStep,
    prevStep
  };

})();
