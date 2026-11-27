/**
 * QR Guard - QR Integrity Lab UI Controller
 * Drives single-image structural & visual tampering forensics, SHA-256 trust fingerprints,
 * visual anomaly heatmaps, and side-by-side QR replacement comparison.
 * Completely independent from URL threat intelligence (analyzer.js).
 */

window.QRIntegrityLab = (function() {
  const MAX_FILE_BYTES = 8 * 1024 * 1024;

  let currentImageA = null; // { data, width, height, label }
  let currentImageB = null; // { data, width, height, label }
  let currentSingleReport = null;

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function fileToImageData(file) {
    return new Promise((resolve, reject) => {
      if (!file || !file.type.startsWith('image/')) {
        reject(new Error('Please select a valid PNG, JPG, or WEBP image file.'));
        return;
      }
      if (file.size > MAX_FILE_BYTES) {
        reject(new Error('Image exceeds the 8MB maximum file size.'));
        return;
      }
      const reader = new FileReader();
      reader.onload = (ev) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          // Keep reasonable bounds while preserving native resolution
          const maxDim = 900;
          let w = img.naturalWidth || img.width;
          let h = img.naturalHeight || img.height;
          if (w > maxDim || h > maxDim) {
            const scale = maxDim / Math.max(w, h);
            w = Math.round(w * scale);
            h = Math.round(h * scale);
          }
          canvas.width = w;
          canvas.height = h;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, w, h);
          const imgData = ctx.getImageData(0, 0, w, h);
          resolve({
            data: imgData.data,
            width: w,
            height: h,
            dataUrl: ev.target.result,
            label: file.name
          });
        };
        img.onerror = () => reject(new Error('Could not decode image file.'));
        img.src = ev.target.result;
      };
      reader.onerror = () => reject(new Error('Failed to read image file.'));
      reader.readAsDataURL(file);
    });
  }

  function canvasToImageObj(canvas, label) {
    const ctx = canvas.getContext('2d');
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return {
      data: imgData.data,
      width: canvas.width,
      height: canvas.height,
      dataUrl: canvas.toDataURL('image/png'),
      label
    };
  }

  // ── Built-in Synthetic Forensic Samples (Canvas-Generated) ───────────────
  function generateQrCanvas(text, opts = {}) {
    return new Promise((resolve, reject) => {
      if (typeof QRCode === 'undefined' || !QRCode.toCanvas) {
        reject(new Error('QRCode generator library not available.'));
        return;
      }
      const canvas = document.createElement('canvas');
      QRCode.toCanvas(canvas, text, {
        width: opts.width || 280,
        margin: opts.margin !== undefined ? opts.margin : 4,
        errorCorrectionLevel: opts.ec || 'M',
        color: {
          dark: opts.dark || '#0f172a',
          light: opts.light || '#ffffff'
        }
      }, (err) => {
        if (err) reject(err);
        else resolve(canvas);
      });
    });
  }

  async function buildPresetSample(presetKey) {
    if (presetKey === 'clean') {
      const c = await generateQrCanvas('https://wikipedia.org', { ec: 'M' });
      return canvasToImageObj(c, 'preset-clean-qr.png');
    }
    if (presetKey === 'logo') {
      const c = await generateQrCanvas('https://wikipedia.org', { ec: 'H', width: 300 });
      const ctx = c.getContext('2d');
      // Draw a centered legitimate brand badge covering ~12% of center
      const box = 48;
      const x = (c.width - box) / 2;
      const y = (c.height - box) / 2;
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(x - 4, y - 4, box + 8, box + 8);
      ctx.fillStyle = '#2563eb';
      ctx.fillRect(x, y, box, box);
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 20px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('QR', c.width / 2, c.height / 2);
      return canvasToImageObj(c, 'preset-centered-logo.png');
    }
    if (presetKey === 'damaged-finder') {
      const c = await generateQrCanvas('https://wikipedia.org', { ec: 'H', width: 280 });
      const ctx = c.getContext('2d');
      // Scratch / overwrite portion of top-right finder pattern
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(c.width - 78, 22, 42, 42);
      return canvasToImageObj(c, 'preset-damaged-finder.png');
    }
    if (presetKey === 'offcenter-patch') {
      const c = await generateQrCanvas('https://wikipedia.org', { ec: 'H', width: 300 });
      const ctx = c.getContext('2d');
      // Off-center sticker patch in bottom-right data area
      ctx.fillStyle = '#f59e0b';
      ctx.fillRect(c.width - 96, c.height - 96, 46, 46);
      return canvasToImageObj(c, 'preset-offcenter-patch.png');
    }
    if (presetKey === 'rotated') {
      const src = await generateQrCanvas('https://wikipedia.org', { ec: 'M', width: 280 });
      const rot = document.createElement('canvas');
      rot.width = src.width;
      rot.height = src.height;
      const ctx = rot.getContext('2d');
      ctx.translate(rot.width / 2, rot.height / 2);
      ctx.rotate(Math.PI / 2);
      ctx.drawImage(src, -src.width / 2, -src.height / 2);
      return canvasToImageObj(rot, 'preset-rotated-90deg.png');
    }
    if (presetKey === 'different-ec') {
      const c = await generateQrCanvas('https://wikipedia.org', { ec: 'H', width: 280 });
      return canvasToImageObj(c, 'preset-same-payload-ec-H.png');
    }
    if (presetKey === 'replacement') {
      const c = await generateQrCanvas('http://free-reward-claim.top/login', { ec: 'M', width: 280 });
      return canvasToImageObj(c, 'preset-replacement-attack.png');
    }
    throw new Error('Unknown preset: ' + presetKey);
  }

  // ── Render Single-Image Forensic Report ──────────────────────────────────
  function getStatusMeta(status) {
    switch (status) {
      case 'INTACT':
        return { cls: 'safe', icon: 'fa-circle-check' };
      case 'NORMAL_DESIGN_VARIATION':
        return { cls: 'info', icon: 'fa-palette' };
      case 'IMAGE_QUALITY_DEGRADATION':
        return { cls: 'suspicious', icon: 'fa-image' };
      case 'POSSIBLE_VISUAL_MODIFICATION':
        return { cls: 'suspicious', icon: 'fa-triangle-exclamation' };
      case 'CONFIRMED_STRUCTURAL_DAMAGE':
        return { cls: 'dangerous', icon: 'fa-circle-exclamation' };
      default:
        return { cls: 'unknown', icon: 'fa-circle-question' };
    }
  }

  function renderPreview(imgId, placeholderId, dataUrl) {
    const imgEl = document.getElementById(imgId);
    const phEl = document.getElementById(placeholderId);
    if (!imgEl) return;
    if (dataUrl) {
      imgEl.src = dataUrl;
      imgEl.style.display = 'block';
      if (phEl) phEl.style.display = 'none';
    } else {
      imgEl.style.display = 'none';
      if (phEl) phEl.style.display = 'flex';
    }
  }

  function renderSingleAnalysis(imageObj) {
    if (!window.QRIntegrityEngine) return;
    currentImageA = imageObj;
    renderPreview('ilPreviewA', 'ilPlaceholderA', imageObj.dataUrl);

    const report = window.QRIntegrityEngine.analyzeImage(imageObj);
    currentSingleReport = report;

    const emptyEl = document.getElementById('ilSingleEmpty');
    const resultsEl = document.getElementById('ilSingleResults');
    if (emptyEl) emptyEl.style.display = 'none';
    if (resultsEl) resultsEl.style.display = 'block';

    const meta = getStatusMeta(report.overallStatus);
    const banner = document.getElementById('ilStatusBanner');
    if (banner) {
      banner.className = `il-status-banner il-status-${meta.cls}`;
      banner.innerHTML = `
        <div class="il-status-left">
          <div class="il-status-icon"><i class="fa-solid ${meta.icon}"></i></div>
          <div>
            <span class="il-eyebrow">INTEGRITY CLASSIFICATION</span>
            <h3>${escapeHtml(report.overallLabel)}</h3>
            <p>${escapeHtml(report.summary)}</p>
          </div>
        </div>
        <div class="il-status-metrics">
          <div class="il-metric-pill">
            <span>SEVERITY</span>
            <strong>${escapeHtml(report.severity)}</strong>
          </div>
          <div class="il-metric-pill">
            <span>CONFIDENCE</span>
            <strong>${escapeHtml(String(report.confidence))}%</strong>
          </div>
        </div>`;
    }

    // Trust Fingerprints
    const fpBox = document.getElementById('ilFingerprintsBox');
    if (fpBox) {
      const fp = report.fingerprints;
      fpBox.innerHTML = `
        <div class="il-fp-row">
          <div>
            <span class="il-fp-label"><i class="fa-solid fa-key"></i> Payload Fingerprint (SHA-256 of Decoded Payload)</span>
            <code class="il-fp-hash">${escapeHtml(fp.payloadFingerprint || 'UNAVAILABLE (Undecodable QR)')}</code>
          </div>
        </div>
        <div class="il-fp-row">
          <div>
            <span class="il-fp-label"><i class="fa-solid fa-table-cells"></i> Structural Fingerprint (Normalized Matrix SHA-256)</span>
            <code class="il-fp-hash">${escapeHtml(fp.structuralFingerprint || 'UNAVAILABLE')}</code>
          </div>
        </div>
        <div class="il-fp-row">
          <div>
            <span class="il-fp-label"><i class="fa-solid fa-mask"></i> Unmasked Structure Fingerprint (Mask-Normalized SHA-256)</span>
            <code class="il-fp-hash">${escapeHtml(fp.unmaskedStructureFingerprint || 'UNAVAILABLE')}</code>
          </div>
        </div>
        <div class="il-fp-meta">
          <span><strong>Descriptor:</strong> <code>${escapeHtml(fp.descriptor)}</code></span>
          <span><strong>Decoded Payload:</strong> <code>${escapeHtml(report.payload ? report.payload.slice(0, 120) : 'N/A')}</code></span>
        </div>
        <div class="il-trust-caveat">
          <i class="fa-solid fa-circle-info"></i>
          <span>${escapeHtml(fp.trustNotice)}</span>
        </div>`;
    }

    // Structural Properties Grid (explicitly tagged with provenance)
    const structBox = document.getElementById('ilStructureGrid');
    if (structBox) {
      if (!report.structure) {
        structBox.innerHTML = `<div class="il-empty-inline"><i class="fa-solid fa-triangle-exclamation"></i> Structural grid properties are unavailable because QR decoding failed. Visual quality metrics: ${report.visualQuality ? `${report.visualQuality.width}x${report.visualQuality.height}px, Sharpness ${report.visualQuality.sharpnessScore}/100, Contrast ${report.visualQuality.contrastScore}/100` : 'N/A'}.</div>`;
      } else {
        const s = report.structure;
        const vq = report.visualQuality;
        const alignTxt = s.alignmentPatterns.applicable
          ? `${s.alignmentPatterns.overallIntegrityPct}% (${s.alignmentPatterns.count} pattern${s.alignmentPatterns.count !== 1 ? 's' : ''})`
          : 'N/A (Version 1)';
        const verInfoTxt = s.versionInfo.applicable
          ? `${s.versionInfo.matched ? 'Valid' : 'Errors'} (${s.versionInfo.topRightHex})`
          : 'N/A (Versions 1–6)';
        const formatTxt = s.formatInfo.available
          ? `${s.formatInfo.primaryFormatHex} (Agree: ${s.formatInfo.copiesAgree ? 'Yes' : 'No'}, Err: ${s.formatInfo.primaryBitErrors}/${s.formatInfo.secondaryBitErrors})`
          : 'Unavailable';
        const qzTxt = `${s.quietZone.minModules} mod min (T:${s.quietZone.top.modules} B:${s.quietZone.bottom.modules} L:${s.quietZone.left.modules} R:${s.quietZone.right.modules})${s.quietZone.anyClippedByBorder ? ' [Border Clipped]' : ''}`;
        const overlayTxt = s.logoAndOverlay.isUniformColorStyledQR
          ? 'Uniform Color Style (No Logo Overlay)'
          : `${s.logoAndOverlay.estimatedCoveragePct}% data area (Center ${s.logoAndOverlay.centerRegionCoveragePct}%, Outer ${s.logoAndOverlay.outerRegionCoveragePct}%)`;

        const cells = [
          { label: 'QR Version', val: `Version ${s.version}`, src: 'Decoder' },
          { label: 'Module Dimensions', val: `${s.dimensions} (${s.totalModules} modules, ~${s.pixelsPerModule} px/mod)`, src: 'Matrix' },
          { label: 'Error Correction Level', val: s.errorCorrectionName, src: 'Matrix' },
          { label: 'Mask Pattern', val: s.maskPattern !== null ? `Mask ${s.maskPattern}` : 'Unavailable', src: 'Matrix' },
          { label: 'Format Information', val: formatTxt, src: 'Matrix' },
          { label: 'Version Information', val: verInfoTxt, src: 'Matrix' },
          { label: 'Finder Patterns (TL/TR/BL)', val: `${s.finderPatterns.overallIntegrityPct}% (${s.finderPatterns.topLeft.integrityPct}% / ${s.finderPatterns.topRight.integrityPct}% / ${s.finderPatterns.bottomLeft.integrityPct}%)`, src: 'Matrix' },
          { label: 'Alignment Patterns', val: alignTxt, src: 'Matrix' },
          { label: 'Timing Patterns', val: `${s.timingPatterns.integrityPct}% (${s.timingPatterns.matched}/${s.timingPatterns.totalModules})`, src: 'Matrix' },
          { label: 'Quiet Zone Dimensions', val: qzTxt, src: 'Estimated' },
          { label: 'Module Distribution', val: `Dark ${s.moduleDistribution.darkPct}% (${s.moduleDistribution.darkModules}) · Light ${s.moduleDistribution.lightPct}%`, src: 'Matrix' },
          { label: 'Logo / Overlay Interference', val: overlayTxt, src: 'Estimated' },
          { label: 'Visual Quality Metrics', val: `Sharpness ${vq.sharpnessScore}/100 · Contrast ${vq.contrastScore}/100 · Blockiness ${vq.blockinessRatio}`, src: 'Estimated' }
        ];

        structBox.innerHTML = cells.map(c => `
          <div class="il-struct-cell">
            <div class="il-struct-top">
              <span>${escapeHtml(c.label)}</span>
              <em class="il-src-tag src-${escapeHtml(c.src.toLowerCase())}">${escapeHtml(c.src)}</em>
            </div>
            <code>${escapeHtml(c.val)}</code>
          </div>`).join('');
      }
    }

    // Tampering & Anomaly Findings
    const findingsBox = document.getElementById('ilFindingsList');
    if (findingsBox) {
      if (!report.findings || report.findings.length === 0) {
        findingsBox.innerHTML = `
          <div class="highlight-item">
            <i class="fa-solid fa-circle-check"></i>
            <div><strong>[No Visual Anomalies]</strong> Structural markers and visual uniformity passed without anomalies.</div>
          </div>`;
      } else {
        findingsBox.innerHTML = report.findings.map(f => {
          const sevCls = f.severity === 'HIGH' ? 'high' : (f.severity === 'MEDIUM' ? 'medium' : 'low');
          return `
            <div class="issue-item ${sevCls}">
              <i class="fa-solid ${f.severity === 'HIGH' ? 'fa-circle-exclamation' : (f.severity === 'MEDIUM' ? 'fa-triangle-exclamation' : 'fa-circle-info')}"></i>
              <div style="width:100%;">
                <div class="issue-header-line">
                  <strong>${escapeHtml(f.classification.replace(/_/g, ' '))}</strong>
                  <div class="il-badge-pair">
                    <span class="il-mini-badge sev-${sevCls}">Severity: ${escapeHtml(f.severity)}</span>
                    <span class="il-mini-badge conf">Confidence: ${escapeHtml(String(f.confidence))}%</span>
                  </div>
                </div>
                <p><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</p>
                <p>${escapeHtml(f.explanation)}</p>
              </div>
            </div>`;
        }).join('');
      }
    }

    // Visual Anomaly Heatmap Canvas
    drawSingleAnomalyHeatmap(report);

    if (window.showToast) {
      window.showToast(`QR Integrity: ${report.overallLabel} (Confidence ${report.confidence}%)`, meta.cls === 'info' ? 'info' : (meta.cls === 'unknown' ? 'warning' : meta.cls));
    }
  }

  function drawSingleAnomalyHeatmap(report) {
    const matrixCanvas = document.getElementById('ilModuleMatrixCanvas');
    const canvas = document.getElementById('ilSingleHeatmapCanvas');
    const noteEl = document.getElementById('ilHeatmapNote');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    if (matrixCanvas) {
      const mCtx = matrixCanvas.getContext('2d');
      mCtx.clearRect(0, 0, matrixCanvas.width, matrixCanvas.height);
      if (!report.matrix || !report.heatmap) {
        mCtx.fillStyle = '#0f172a';
        mCtx.fillRect(0, 0, matrixCanvas.width, matrixCanvas.height);
        mCtx.fillStyle = '#94a3b8';
        mCtx.font = '11px sans-serif';
        mCtx.textAlign = 'center';
        mCtx.fillText('Matrix unavailable', matrixCanvas.width / 2, matrixCanvas.height / 2);
      } else {
        const dim = report.heatmap.dimension;
        const mCell = matrixCanvas.width / dim;
        for (let r = 0; r < dim; r++) {
          for (let c = 0; c < dim; c++) {
            mCtx.fillStyle = report.matrix[r * dim + c] ? '#0f172a' : '#f8fafc';
            mCtx.fillRect(c * mCell, r * mCell, Math.ceil(mCell), Math.ceil(mCell));
          }
        }
      }
    }

    if (!report.heatmap || !report.matrix) {
      ctx.fillStyle = '#0f172a';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#94a3b8';
      ctx.font = '13px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Heatmap unavailable (QR undecodable)', canvas.width / 2, canvas.height / 2);
      if (noteEl) noteEl.textContent = 'Module-level heatmap requires successful matrix extraction.';
      return;
    }

    const dim = report.heatmap.dimension;
    const scores = report.heatmap.scores;
    const matrix = report.matrix;
    const cell = canvas.width / dim;

    for (let r = 0; r < dim; r++) {
      for (let c = 0; c < dim; c++) {
        const idx = r * dim + c;
        const bit = matrix[idx];
        const s = scores[idx];
        // Base QR tone
        ctx.fillStyle = bit ? '#1e293b' : '#e2e8f0';
        ctx.fillRect(c * cell, r * cell, Math.ceil(cell), Math.ceil(cell));

        // Overlay heat intensity
        if (s >= 0.85) {
          ctx.fillStyle = 'rgba(239, 68, 68, 0.82)'; // Structural mismatch / damage
          ctx.fillRect(c * cell, r * cell, Math.ceil(cell), Math.ceil(cell));
        } else if (s >= 0.55) {
          ctx.fillStyle = 'rgba(245, 158, 11, 0.72)'; // Overlay / patch / colored anomaly
          ctx.fillRect(c * cell, r * cell, Math.ceil(cell), Math.ceil(cell));
        } else if (s >= 0.2) {
          ctx.fillStyle = 'rgba(56, 189, 248, 0.45)'; // Mild contrast uncertainty / blur
          ctx.fillRect(c * cell, r * cell, Math.ceil(cell), Math.ceil(cell));
        }
      }
    }
    if (noteEl) {
      noteEl.textContent = `Normalized ${dim}×${dim} module anomaly map (rotation & scale normalized).`;
    }
  }

  // ── Side-by-Side QR Replacement Comparison ───────────────────────────────
  function runComparison() {
    if (!currentImageA || !currentImageB) {
      if (window.showToast) window.showToast('Please upload or select both QR Image A and QR Image B.', 'warning');
      return;
    }
    const comp = window.QRIntegrityEngine.compareQRs(currentImageA, currentImageB);
    renderComparisonReport(comp);
  }

  function renderComparisonReport(comp) {
    const outEl = document.getElementById('ilCompareResults');
    if (!outEl) return;
    outEl.style.display = 'block';

    const verdictCls =
      comp.verdict === 'PAYLOAD_REPLACEMENT_DETECTED' ? 'dangerous' :
      (comp.verdict === 'IDENTICAL_STRUCTURE_AND_PAYLOAD' ? 'safe' :
      (comp.verdict === 'INSUFFICIENT_EVIDENCE' ? 'unknown' : 'suspicious'));

    const payloadBadge = comp.payloadComparison.identical === true
      ? '<span class="sample-badge safe">IDENTICAL PAYLOAD</span>'
      : (comp.payloadComparison.identical === false
        ? '<span class="sample-badge dangerous">DIFFERENT PAYLOAD</span>'
        : '<span class="sample-badge suspicious">UNAVAILABLE</span>');

    const md = comp.matrixDiff;
    const mc = comp.metadataComparison;

    outEl.innerHTML = `
      <div class="il-status-banner il-status-${verdictCls}" style="margin-bottom:16px;">
        <div class="il-status-left">
          <div class="il-status-icon"><i class="fa-solid ${verdictCls === 'dangerous' ? 'fa-skull-crossbones' : (verdictCls === 'safe' ? 'fa-circle-check' : 'fa-code-compare')}"></i></div>
          <div>
            <span class="il-eyebrow">QR REPLACEMENT INVESTIGATION SUMMARY</span>
            <h3>${escapeHtml(comp.verdict.replace(/_/g, ' '))}</h3>
            <p>${escapeHtml(comp.summary)}</p>
          </div>
        </div>
        <div>${payloadBadge}</div>
      </div>

      <div class="il-compare-metrics-grid">
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>Payload Comparison</span></div>
          <code>${escapeHtml(comp.payloadComparison.status)}</code>
        </div>
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>QR Version (A vs B)</span></div>
          <code>${mc ? `V${mc.versionA} vs V${mc.versionB} (${mc.versionMatch ? 'Match' : 'Different'})` : 'N/A'}</code>
        </div>
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>Error Correction (A vs B)</span></div>
          <code>${mc ? `EC-${mc.ecA} vs EC-${mc.ecB} (${mc.ecMatch ? 'Match' : 'Different'})` : 'N/A'}</code>
        </div>
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>Mask Pattern (A vs B)</span></div>
          <code>${mc ? `Mask ${mc.maskA} vs Mask ${mc.maskB} (${mc.maskMatch ? 'Match' : 'Different'})` : 'N/A'}</code>
        </div>
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>Changed Module Count</span></div>
          <code>${md && md.aligned ? `${md.changedModuleCount} / ${md.totalModules} modules` : 'N/A (Version Mismatch)'}</code>
        </div>
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>Module Difference %</span></div>
          <code>${md && md.aligned ? `${md.differencePercentage}% (Fn: ${md.structuralChanges}, Data/ECC: ${md.dataEccChanges})` : 'N/A'}</code>
        </div>
      </div>

      <div class="il-compare-fp-grid">
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>Image A Payload SHA-256</span></div>
          <code class="il-fp-hash">${escapeHtml(comp.payloadComparison.fingerprintA || 'UNAVAILABLE')}</code>
        </div>
        <div class="il-struct-cell">
          <div class="il-struct-top"><span>Image B Payload SHA-256</span></div>
          <code class="il-fp-hash">${escapeHtml(comp.payloadComparison.fingerprintB || 'UNAVAILABLE')}</code>
        </div>
      </div>

      <div class="il-diff-heatmap-wrap">
        <div>
          <h4><i class="fa-solid fa-fire"></i> Normalized Module Difference Heatmap</h4>
          <p class="il-muted">Compares aligned canonical matrices (rotation &amp; scale normalized — never raw pixel diffs).</p>
          <div class="il-heatmap-legend">
            <span><i class="legend-dot same"></i> Identical Module</span>
            <span><i class="legend-dot data-diff"></i> Data / ECC Changed</span>
            <span><i class="legend-dot fn-diff"></i> Structural Pattern Changed</span>
          </div>
        </div>
        <canvas id="ilCompareHeatmapCanvas" width="220" height="220" class="il-heatmap-canvas"></canvas>
      </div>
    `;

    drawComparisonHeatmap(comp);
  }

  function drawComparisonHeatmap(comp) {
    const canvas = document.getElementById('ilCompareHeatmapCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const md = comp.matrixDiff;
    if (!md || !md.aligned) {
      ctx.fillStyle = '#0f172a';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#94a3b8';
      ctx.font = '12px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('1:1 Matrix Diff Unavailable', canvas.width / 2, canvas.height / 2 - 8);
      ctx.fillText('(Different QR Dimensions)', canvas.width / 2, canvas.height / 2 + 10);
      return;
    }

    const dim = md.dimension;
    const cell = canvas.width / dim;
    const matA = comp.reportA.matrix;

    for (let r = 0; r < dim; r++) {
      for (let c = 0; c < dim; c++) {
        const idx = r * dim + c;
        const diff = md.diffGrid[idx];
        if (diff === 2) {
          ctx.fillStyle = '#ef4444';
        } else if (diff === 1) {
          ctx.fillStyle = '#f59e0b';
        } else {
          ctx.fillStyle = matA[idx] ? '#1e293b' : '#cbd5e1';
        }
        ctx.fillRect(c * cell, r * cell, Math.ceil(cell), Math.ceil(cell));
      }
    }
  }

  // ── Event Wiring ─────────────────────────────────────────────────────────
  function wireDropZone(dropId, inputId, onImageReady) {
    const dropZone = document.getElementById(dropId);
    const fileInput = document.getElementById(inputId);
    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev => {
      dropZone.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); });
    });
    ['dragenter', 'dragover'].forEach(ev => {
      dropZone.addEventListener(ev, () => dropZone.classList.add('dragover'));
    });
    ['dragleave', 'drop'].forEach(ev => {
      dropZone.addEventListener(ev, () => dropZone.classList.remove('dragover'));
    });
    dropZone.addEventListener('drop', async (e) => {
      const file = e.dataTransfer?.files?.[0];
      if (!file) return;
      try {
        const imgObj = await fileToImageData(file);
        onImageReady(imgObj);
      } catch (err) {
        if (window.showToast) window.showToast(err.message, 'warning');
      }
    });
    fileInput.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const imgObj = await fileToImageData(file);
        onImageReady(imgObj);
      } catch (err) {
        if (window.showToast) window.showToast(err.message, 'warning');
      }
    });
  }

  function init() {
    wireDropZone('ilDropZoneA', 'ilFileInputA', (imgObj) => {
      renderSingleAnalysis(imgObj);
    });

    wireDropZone('ilDropZoneB', 'ilFileInputB', (imgObj) => {
      currentImageB = imgObj;
      renderPreview('ilPreviewB', 'ilPlaceholderB', imgObj.dataUrl);
      runComparison();
    });

    const compareBtn = document.getElementById('ilRunCompareBtn');
    if (compareBtn) {
      compareBtn.addEventListener('click', runComparison);
    }

    // Single-image presets
    document.querySelectorAll('.il-preset-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const key = btn.getAttribute('data-preset');
        try {
          const imgObj = await buildPresetSample(key);
          renderSingleAnalysis(imgObj);
        } catch (err) {
          if (window.showToast) window.showToast(err.message, 'error');
        }
      });
    });

    // Comparison presets
    document.querySelectorAll('.il-compare-preset-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const mode = btn.getAttribute('data-compare-preset');
        try {
          const imgA = await buildPresetSample('clean');
          let imgB;
          if (mode === 'rotated') imgB = await buildPresetSample('rotated');
          else if (mode === 'different-ec') imgB = await buildPresetSample('different-ec');
          else if (mode === 'logo') imgB = await buildPresetSample('logo');
          else imgB = await buildPresetSample('replacement');

          renderSingleAnalysis(imgA);
          currentImageB = imgB;
          renderPreview('ilPreviewB', 'ilPlaceholderB', imgB.dataUrl);
          runComparison();
        } catch (err) {
          if (window.showToast) window.showToast(err.message, 'error');
        }
      });
    });
  }

  return {
    init,
    renderSingleAnalysis,
    runComparison
  };
})();
