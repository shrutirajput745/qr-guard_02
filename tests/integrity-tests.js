const crypto = require('crypto');
const QRCode = require('qrcode');
const { PNG } = require('pngjs');
const QRIntegrityEngine = require('../public/js/integrity-engine');

console.log('=== QR GUARD: TRUST FINGERPRINT & VISUAL INTEGRITY TEST SUITE ===\n');

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    console.log(`  ✔ [PASS] ${msg}`);
    passed++;
  } else {
    console.error(`  ✖ [FAIL] ${msg}`);
    failed++;
  }
}

// ── Synthetic Image Helpers (Deterministic, Zero External Assets) ─────────
function createQrRgba(text, opts = {}) {
  const qr = QRCode.create(text, {
    errorCorrectionLevel: opts.ec || 'M',
    version: opts.version || undefined,
    maskPattern: opts.maskPattern !== undefined ? opts.maskPattern : undefined
  });
  const modCount = qr.modules.size;
  const margin = opts.margin !== undefined ? opts.margin : 4;
  const scale = opts.scale || 10;
  const dim = (modCount + margin * 2) * scale;
  const data = new Uint8ClampedArray(dim * dim * 4);

  const fg = opts.fg || [15, 23, 42];
  const bg = opts.bg || [255, 255, 255];

  for (let y = 0; y < dim; y++) {
    const my = Math.floor(y / scale) - margin;
    for (let x = 0; x < dim; x++) {
      const mx = Math.floor(x / scale) - margin;
      const isDark = (mx >= 0 && mx < modCount && my >= 0 && my < modCount)
        ? Boolean(qr.modules.get(my, mx))
        : false;
      const c = isDark ? fg : bg;
      const idx = (y * dim + x) * 4;
      data[idx] = c[0];
      data[idx + 1] = c[1];
      data[idx + 2] = c[2];
      data[idx + 3] = 255;
    }
  }

  return { data, width: dim, height: dim, qr, modCount, margin, scale };
}

function cloneImg(img) {
  return {
    ...img,
    data: new Uint8ClampedArray(img.data)
  };
}

function drawRectModules(img, startModX, startModY, wMods, hMods, rgb) {
  const out = cloneImg(img);
  const { width, height, margin, scale } = img;
  const x0 = Math.max(0, Math.round((margin + startModX) * scale));
  const y0 = Math.max(0, Math.round((margin + startModY) * scale));
  const x1 = Math.min(width, Math.round((margin + startModX + wMods) * scale));
  const y1 = Math.min(height, Math.round((margin + startModY + hMods) * scale));

  for (let y = y0; y < y1; y++) {
    for (let x = x0; x < x1; x++) {
      const idx = (y * width + x) * 4;
      out.data[idx] = rgb[0];
      out.data[idx + 1] = rgb[1];
      out.data[idx + 2] = rgb[2];
    }
  }
  return out;
}

function rotateRgba(img, degrees) {
  const { data, width, height } = img;
  const out = new Uint8ClampedArray(data.length);
  const outW = (degrees === 90 || degrees === 270) ? height : width;
  const outH = (degrees === 90 || degrees === 270) ? width : height;

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let nx = x, ny = y;
      if (degrees === 90) { nx = height - 1 - y; ny = x; }
      else if (degrees === 180) { nx = width - 1 - x; ny = height - 1 - y; }
      else if (degrees === 270) { nx = y; ny = width - 1 - x; }
      const srcIdx = (y * width + x) * 4;
      const dstIdx = (ny * outW + nx) * 4;
      out[dstIdx] = data[srcIdx];
      out[dstIdx + 1] = data[srcIdx + 1];
      out[dstIdx + 2] = data[srcIdx + 2];
      out[dstIdx + 3] = data[srcIdx + 3];
    }
  }
  return { data: out, width: outW, height: outH };
}

function applyBoxBlur(img, radius = 2) {
  const out = cloneImg(img);
  const { data, width, height } = img;
  const tmp = new Uint8ClampedArray(data.length);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let r = 0, g = 0, b = 0, cnt = 0;
      for (let kx = -radius; kx <= radius; kx++) {
        const px = Math.min(width - 1, Math.max(0, x + kx));
        const idx = (y * width + px) * 4;
        r += data[idx]; g += data[idx + 1]; b += data[idx + 2];
        cnt++;
      }
      const oIdx = (y * width + x) * 4;
      tmp[oIdx] = Math.round(r / cnt);
      tmp[oIdx + 1] = Math.round(g / cnt);
      tmp[oIdx + 2] = Math.round(b / cnt);
      tmp[oIdx + 3] = 255;
    }
  }
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let r = 0, g = 0, b = 0, cnt = 0;
      for (let ky = -radius; ky <= radius; ky++) {
        const py = Math.min(height - 1, Math.max(0, y + ky));
        const idx = (py * width + x) * 4;
        r += tmp[idx]; g += tmp[idx + 1]; b += tmp[idx + 2];
        cnt++;
      }
      const oIdx = (y * width + x) * 4;
      out.data[oIdx] = Math.round(r / cnt);
      out.data[oIdx + 1] = Math.round(g / cnt);
      out.data[oIdx + 2] = Math.round(b / cnt);
    }
  }
  return out;
}

// Simulates lossy 8x8 block compression (averaging + quantization + boundary step)
function applyJpegLikeBlockCompression(img) {
  const out = cloneImg(img);
  const { width, height } = img;
  for (let by = 0; by < height; by += 8) {
    for (let bx = 0; bx < width; bx += 8) {
      for (let c = 0; c < 3; c++) {
        let sum = 0, cnt = 0;
        for (let dy = 0; dy < 8 && by + dy < height; dy++) {
          for (let dx = 0; dx < 8 && bx + dx < width; dx++) {
            sum += img.data[((by + dy) * width + (bx + dx)) * 4 + c];
            cnt++;
          }
        }
        const blockMean = sum / cnt;
        for (let dy = 0; dy < 8 && by + dy < height; dy++) {
          for (let dx = 0; dx < 8 && bx + dx < width; dx++) {
            const idx = ((by + dy) * width + (bx + dx)) * 4 + c;
            // Blend toward block mean & quantize to multiples of 16
            const blended = 0.65 * img.data[idx] + 0.35 * blockMean;
            out.data[idx] = Math.min(255, Math.max(0, Math.round(blended / 16) * 16));
          }
        }
      }
    }
  }
  return out;
}

function applyLowContrast(img) {
  const out = cloneImg(img);
  for (let i = 0; i < out.data.length; i += 4) {
    for (let c = 0; c < 3; c++) {
      // Compress 0..255 into faint 130..175 gray band
      out.data[i + c] = Math.round(130 + (out.data[i + c] / 255) * 45);
    }
  }
  return out;
}

function runIntegrityTests() {
  // ── 1. SHA-256 Accuracy vs Node crypto ─────────────────────────────────
  const testStrs = ['https://wikipedia.org', 'https://p\u0430ypal.com/login?a=1&b=2', ''];
  testStrs.forEach(s => {
    const expected = crypto.createHash('sha256').update(s, 'utf8').digest('hex');
    const actual = QRIntegrityEngine.sha256Hex(s);
    assert(actual === expected, `SHA-256 matches Node crypto for "${s.slice(0, 28)}"`);
  });

  // ── 2. Clean QR Structural Extraction & Identical Comparison ───────────
  const cleanA = createQrRgba('https://wikipedia.org', { ec: 'M', maskPattern: 2, scale: 10 });
  const cleanB = createQrRgba('https://wikipedia.org', { ec: 'M', maskPattern: 2, scale: 10 });
  const rClean = QRIntegrityEngine.analyzeImage(cleanA);

  assert(rClean.decodable === true, 'Clean QR decoded successfully');
  assert(rClean.structure.version === cleanA.qr.version, `Extracted QR version (${rClean.structure.version}) matches encoder (${cleanA.qr.version})`);
  assert(rClean.structure.errorCorrectionLevel === 'M', `Extracted EC level is M`);
  assert(rClean.structure.maskPattern === 2, `Extracted mask pattern is 2`);
  assert(rClean.structure.finderPatterns.overallIntegrityPct === 100, 'Clean QR finder integrity is 100%');
  assert(rClean.structure.timingPatterns.integrityPct === 100, 'Clean QR timing integrity is 100%');
  assert(rClean.overallStatus === 'INTACT', `Clean QR status is INTACT (got ${rClean.overallStatus})`);

  const compIdentical = QRIntegrityEngine.compareQRs(cleanA, cleanB);
  assert(compIdentical.verdict === 'IDENTICAL_STRUCTURE_AND_PAYLOAD', 'Identical QRs match structurally and by payload');
  assert(compIdentical.matrixDiff.changedModuleCount === 0, 'Identical QRs have 0 changed modules');

  // ── 3. Same Payload, Different QR Versions ─────────────────────────────
  const ver2 = createQrRgba('https://wikipedia.org', { ec: 'M', version: 2, scale: 10 });
  const ver4 = createQrRgba('https://wikipedia.org', { ec: 'M', version: 4, scale: 10 });
  const compVer = QRIntegrityEngine.compareQRs(ver2, ver4);
  assert(compVer.payloadComparison.identical === true, 'Different versions with same payload share Payload SHA-256');
  assert(compVer.metadataComparison.versionA === 2 && compVer.metadataComparison.versionB === 4, 'Version comparison detects V2 vs V4');
  assert(compVer.verdict === 'SAME_PAYLOAD_DIFFERENT_ENCODING', 'Different versions produce SAME_PAYLOAD_DIFFERENT_ENCODING verdict');
  assert(compVer.matrixDiff.aligned === false, 'Different dimensions cleanly report 1:1 module alignment inapplicable');

  // ── 4. Same Payload, Different Error-Correction Levels ─────────────────
  const ecL = createQrRgba('https://wikipedia.org', { ec: 'L', scale: 10 });
  const ecH = createQrRgba('https://wikipedia.org', { ec: 'H', scale: 10 });
  const compEc = QRIntegrityEngine.compareQRs(ecL, ecH);
  assert(compEc.payloadComparison.identical === true, 'Different EC levels with same payload share Payload SHA-256');
  assert(compEc.metadataComparison.ecA === 'L' && compEc.metadataComparison.ecB === 'H', 'EC comparison detects L vs H');
  assert(compEc.verdict === 'SAME_PAYLOAD_DIFFERENT_ENCODING', 'Different EC levels produce SAME_PAYLOAD_DIFFERENT_ENCODING');

  // ── 5. Same Payload, Different Mask Patterns ───────────────────────────
  const mask1 = createQrRgba('https://wikipedia.org', { ec: 'M', maskPattern: 1, scale: 10 });
  const mask6 = createQrRgba('https://wikipedia.org', { ec: 'M', maskPattern: 6, scale: 10 });
  const compMask = QRIntegrityEngine.compareQRs(mask1, mask6);
  assert(compMask.payloadComparison.identical === true, 'Different masks share Payload SHA-256');
  assert(compMask.metadataComparison.maskA === 1 && compMask.metadataComparison.maskB === 6, 'Mask comparison detects Mask 1 vs Mask 6');
  assert(compMask.metadataComparison.unmaskedFingerprintMatch === true, 'Unmasked structure fingerprint matches across different mask patterns');

  // ── 6. Different Payloads (QR Replacement) ─────────────────────────────
  const phish = createQrRgba('http://free-reward-claim.top/login', { ec: 'M', scale: 10 });
  const compRepl = QRIntegrityEngine.compareQRs(cleanA, phish);
  assert(compRepl.payloadComparison.identical === false, 'Different payloads have distinct Payload SHA-256');
  assert(compRepl.verdict === 'PAYLOAD_REPLACEMENT_DETECTED', 'Different payloads trigger PAYLOAD_REPLACEMENT_DETECTED');

  // ── 7. Rotated & Scaled Images (Invariance Check) ──────────────────────
  const rot90 = rotateRgba(cleanA, 90);
  const rot180 = rotateRgba(cleanA, 180);
  const scaled = createQrRgba('https://wikipedia.org', { ec: 'M', maskPattern: 2, scale: 15 });
  const compRot90 = QRIntegrityEngine.compareQRs(cleanA, rot90);
  const compRot180 = QRIntegrityEngine.compareQRs(cleanA, rot180);
  const compScaled = QRIntegrityEngine.compareQRs(cleanA, scaled);
  assert(compRot90.verdict === 'IDENTICAL_STRUCTURE_AND_PAYLOAD' && compRot90.matrixDiff.changedModuleCount === 0, '90-deg rotation produces identical normalized structural fingerprint');
  assert(compRot180.verdict === 'IDENTICAL_STRUCTURE_AND_PAYLOAD' && compRot180.matrixDiff.changedModuleCount === 0, '180-deg rotation produces identical normalized structural fingerprint');
  assert(compScaled.verdict === 'IDENTICAL_STRUCTURE_AND_PAYLOAD' && compScaled.matrixDiff.changedModuleCount === 0, 'Rescaled image produces identical normalized structural fingerprint');

  // ── 8. Legitimate Brand Logo (False-Positive Prevention) ───────────────
  const logoBase = createQrRgba('https://wikipedia.org', { ec: 'H', version: 3, scale: 10 });
  // Center 5x5 module logo on 29x29 V3 (~10% of data area, well within EC-H 30%)
  const logoImg = drawRectModules(logoBase, 12, 12, 5, 5, [37, 99, 235]);
  const rLogo = QRIntegrityEngine.analyzeImage(logoImg);
  assert(rLogo.decodable === true, 'QR with centered brand logo decodes cleanly');
  assert(rLogo.structure.logoAndOverlay.hasCenteredLogo === true, 'Detects centered logo region');
  assert(rLogo.overallStatus === 'NORMAL_DESIGN_VARIATION', `Legitimate centered logo classified as NORMAL_DESIGN_VARIATION (got ${rLogo.overallStatus})`);

  // ── 9. Damaged Finder Patterns ─────────────────────────────────────────
  const dmgFinderBase = createQrRgba('https://wikipedia.org', { ec: 'H', version: 3, scale: 10 });
  // Damage 4x4 block inside top-right finder (still decodable via jsQR or partially damaged)
  const dmgFinderPartial = drawRectModules(dmgFinderBase, dmgFinderBase.modCount - 6, 1, 4, 4, [255, 255, 255]);
  const rDmgFinder = QRIntegrityEngine.analyzeImage(dmgFinderPartial);
  assert(rDmgFinder.overallStatus === 'CONFIRMED_STRUCTURAL_DAMAGE', `Damaged finder pattern flagged as CONFIRMED_STRUCTURAL_DAMAGE (got ${rDmgFinder.overallStatus})`);

  // ── 10. Low-Resolution, Blur & JPEG Compression (Distinguished from Tampering) ──
  const lowResImg = createQrRgba('https://wikipedia.org', { ec: 'M', scale: 3 });
  const rLowRes = QRIntegrityEngine.analyzeImage(lowResImg);
  assert(rLowRes.decodable === true && rLowRes.overallStatus === 'IMAGE_QUALITY_DEGRADATION', `Low-res QR (${lowResImg.width}px) classified as IMAGE_QUALITY_DEGRADATION (got ${rLowRes.overallStatus})`);

  const jpegImg = applyJpegLikeBlockCompression(cleanA);
  const rJpeg = QRIntegrityEngine.analyzeImage(jpegImg);
  assert(rJpeg.decodable === true && (rJpeg.overallStatus === 'IMAGE_QUALITY_DEGRADATION' || rJpeg.overallStatus === 'INTACT'), `8x8 block-compressed QR not falsely flagged as tampering (got ${rJpeg.overallStatus})`);

  const blurImg = applyBoxBlur(cleanA, 4);
  const rBlur = QRIntegrityEngine.analyzeImage(blurImg);
  assert(rBlur.decodable === true && rBlur.overallStatus === 'IMAGE_QUALITY_DEGRADATION', `Blurred QR classified as IMAGE_QUALITY_DEGRADATION (got ${rBlur.overallStatus})`);

  // ── 11. Uniform Color Styling (False-Positive Prevention) ──────────────
  const blueQr = createQrRgba('https://wikipedia.org', { ec: 'M', fg: [30, 58, 138], scale: 10 });
  const rBlue = QRIntegrityEngine.analyzeImage(blueQr);
  assert(rBlue.overallStatus === 'NORMAL_DESIGN_VARIATION', `Uniform blue styled QR classified as NORMAL_DESIGN_VARIATION (got ${rBlue.overallStatus})`);

  // ── 12. Malformed / Non-QR / Blank Images ──────────────────────────────
  const blankImg = { data: new Uint8ClampedArray(120 * 120 * 4).fill(240), width: 120, height: 120 };
  const rBlank = QRIntegrityEngine.analyzeImage(blankImg);
  assert(rBlank.decodable === false && rBlank.overallStatus === 'UNKNOWN', `Blank image returns UNKNOWN / insufficient evidence (got ${rBlank.overallStatus})`);

  const rInvalid = QRIntegrityEngine.analyzeImage({ data: new Uint8ClampedArray(16), width: 2, height: 2 });
  assert(rInvalid.decodable === false && rInvalid.overallStatus === 'UNKNOWN', 'Malformed undersized buffer handled safely as UNKNOWN');

  const rTruncated = QRIntegrityEngine.analyzeImage({ data: new Uint8ClampedArray(100), width: 100, height: 100 });
  assert(rTruncated.decodable === false && rTruncated.overallStatus === 'UNKNOWN', 'Truncated RGBA pixel buffer rejected cleanly as UNKNOWN');

  const rNaNDims = QRIntegrityEngine.analyzeImage({ data: new Uint8ClampedArray(400), width: NaN, height: 10 });
  assert(rNaNDims.decodable === false && rNaNDims.overallStatus === 'UNKNOWN', 'NaN image dimensions rejected cleanly as UNKNOWN');

  const compUndecodable = QRIntegrityEngine.compareQRs(cleanA, blankImg);
  assert(compUndecodable.comparable === false && compUndecodable.verdict === 'INSUFFICIENT_EVIDENCE', 'Comparing valid QR against blank image returns INSUFFICIENT_EVIDENCE');

  // ── 13. Reproducible Synthetic Benchmark (Precision, Recall, FPR, F1) ──
  console.log('\n▶ Running Reproducible Synthetic Tampering / Damage Benchmark (20 Cases)...');

  const benchmarkCases = [];

  // 10 Negative cases (benign: should NOT be flagged as CONFIRMED_STRUCTURAL_DAMAGE or POSSIBLE_VISUAL_MODIFICATION)
  benchmarkCases.push({ name: 'Neg-01 Clean M', expectedAnomaly: false, img: createQrRgba('https://example.org/1', { ec: 'M', scale: 10 }) });
  benchmarkCases.push({ name: 'Neg-02 Clean H', expectedAnomaly: false, img: createQrRgba('https://example.org/2', { ec: 'H', scale: 10 }) });
  benchmarkCases.push({ name: 'Neg-03 Rotated 90', expectedAnomaly: false, img: rotateRgba(createQrRgba('https://example.org/3', { ec: 'M', scale: 10 }), 90) });
  benchmarkCases.push({ name: 'Neg-04 Rotated 270', expectedAnomaly: false, img: rotateRgba(createQrRgba('https://example.org/4', { ec: 'M', scale: 10 }), 270) });
  benchmarkCases.push({ name: 'Neg-05 Scaled 14x', expectedAnomaly: false, img: createQrRgba('https://example.org/5', { ec: 'M', scale: 14 }) });
  benchmarkCases.push({ name: 'Neg-06 Uniform Blue', expectedAnomaly: false, img: createQrRgba('https://example.org/6', { ec: 'M', fg: [29, 78, 216], scale: 10 }) });
  benchmarkCases.push({ name: 'Neg-07 Inverted Dark', expectedAnomaly: false, img: createQrRgba('https://example.org/7', { ec: 'M', fg: [248, 250, 252], bg: [15, 23, 42], scale: 10 }) });
  {
    const baseLogo = createQrRgba('https://example.org/8', { ec: 'H', version: 3, scale: 10 });
    benchmarkCases.push({ name: 'Neg-08 Centered Logo (EC-H)', expectedAnomaly: false, img: drawRectModules(baseLogo, 12, 12, 5, 5, [37, 99, 235]) });
  }
  benchmarkCases.push({ name: 'Neg-09 Low-Res 3px/mod', expectedAnomaly: false, img: createQrRgba('https://example.org/9', { ec: 'M', scale: 3 }) });
  benchmarkCases.push({ name: 'Neg-10 Low-Contrast Faint', expectedAnomaly: false, img: applyLowContrast(createQrRgba('https://example.org/10', { ec: 'M', scale: 10 })) });

  // 10 Positive cases (structural damage or localized modification)
  {
    const b1 = createQrRgba('https://example.org/p1', { ec: 'H', version: 3, scale: 10 });
    benchmarkCases.push({ name: 'Pos-01 Damaged TR Finder', expectedAnomaly: true, img: drawRectModules(b1, b1.modCount - 6, 1, 4, 4, [255, 255, 255]) });
  }
  {
    const b2 = createQrRgba('https://example.org/p2', { ec: 'H', version: 3, scale: 10 });
    benchmarkCases.push({ name: 'Pos-02 Damaged BL Finder', expectedAnomaly: true, img: drawRectModules(b2, 1, b2.modCount - 6, 4, 4, [255, 255, 255]) });
  }
  {
    const b3 = createQrRgba('https://example.org/p3', { ec: 'H', version: 3, scale: 10 });
    benchmarkCases.push({ name: 'Pos-03 Destroyed TL Finder', expectedAnomaly: true, img: drawRectModules(b3, 0, 0, 7, 7, [255, 255, 255]) });
  }
  {
    const b4 = createQrRgba('https://example.org/p4', { ec: 'H', version: 4, scale: 10 });
    // Corrupt timing row 6 across multiple modules
    benchmarkCases.push({ name: 'Pos-04 Distorted Timing Pattern', expectedAnomaly: true, img: drawRectModules(b4, 9, 6, 10, 1, [15, 23, 42]) });
  }
  {
    const b5 = createQrRgba('https://example.org/p5', { ec: 'H', version: 4, scale: 10 });
    // Off-center colored sticker patch
    benchmarkCases.push({ name: 'Pos-05 Off-Center Orange Patch', expectedAnomaly: true, img: drawRectModules(b5, b5.modCount - 9, b5.modCount - 9, 6, 6, [245, 158, 11]) });
  }
  {
    const b6 = createQrRgba('https://example.org/p6', { ec: 'H', version: 4, scale: 10 });
    benchmarkCases.push({ name: 'Pos-06 Off-Center Whiteout Patch', expectedAnomaly: true, img: drawRectModules(b6, 2, 10, 5, 6, [255, 255, 255]) });
  }
  {
    const b7 = createQrRgba('https://example.org/p7', { ec: 'H', version: 4, scale: 10 });
    benchmarkCases.push({ name: 'Pos-07 Top-Mid Patch Overlay', expectedAnomaly: true, img: drawRectModules(b7, 13, 1, 6, 5, [239, 68, 68]) });
  }
  {
    const b8 = createQrRgba('https://example.org/p8', { ec: 'L', version: 4, scale: 10 });
    // Large centered overlay exceeding EC-L (7%) tolerance
    benchmarkCases.push({ name: 'Pos-08 Oversized Logo on EC-L', expectedAnomaly: true, img: drawRectModules(b8, 11, 11, 11, 11, [220, 38, 38]) });
  }
  {
    const b9 = createQrRgba('https://example.org/p9', { ec: 'H', version: 5, scale: 10 });
    // Corrupt bottom-right alignment pattern
    benchmarkCases.push({ name: 'Pos-09 Damaged Alignment Pattern', expectedAnomaly: true, img: drawRectModules(b9, b9.modCount - 9, b9.modCount - 9, 5, 5, [255, 255, 255]) });
  }
  {
    const b10 = createQrRgba('https://example.org/p10', { ec: 'H', version: 3, scale: 10 });
    // Corrupt vertical timing column 6
    benchmarkCases.push({ name: 'Pos-10 Distorted Vertical Timing', expectedAnomaly: true, img: drawRectModules(b10, 6, 9, 1, 9, [255, 255, 255]) });
  }

  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const item of benchmarkCases) {
    const res = QRIntegrityEngine.analyzeImage(item.img);
    const predictedAnomaly =
      res.overallStatus === 'CONFIRMED_STRUCTURAL_DAMAGE' ||
      res.overallStatus === 'POSSIBLE_VISUAL_MODIFICATION';

    if (item.expectedAnomaly && predictedAnomaly) tp++;
    else if (!item.expectedAnomaly && predictedAnomaly) fp++;
    else if (!item.expectedAnomaly && !predictedAnomaly) tn++;
    else fn++;

    if (predictedAnomaly !== item.expectedAnomaly) {
      console.log(`  ! [BENCHMARK MISS] ${item.name}: expectedAnomaly=${item.expectedAnomaly}, got ${res.overallStatus}`);
    }
  }

  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
  const fpr = (fp + tn) > 0 ? fp / (fp + tn) : 0;
  const fnr = (fn + tp) > 0 ? fn / (fn + tp) : 0;
  const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  console.log(`  Benchmark Matrix: TP=${tp}, FP=${fp}, TN=${tn}, FN=${fn}`);
  console.log(`  Precision=${(precision * 100).toFixed(1)}%, Recall=${(recall * 100).toFixed(1)}%, FPR=${(fpr * 100).toFixed(1)}%, FNR=${(fnr * 100).toFixed(1)}%, F1=${(f1 * 100).toFixed(1)}%`);

  assert(precision >= 0.85, `Benchmark precision >= 85% (measured ${(precision * 100).toFixed(1)}%)`);
  assert(recall >= 0.80, `Benchmark recall >= 80% (measured ${(recall * 100).toFixed(1)}%)`);
  assert(fpr <= 0.15, `Benchmark false-positive rate <= 15% (measured ${(fpr * 100).toFixed(1)}%)`);

  console.log(`\nIntegrity Test Results: ${passed} Passed, ${failed} Failed out of ${passed + failed} Tests\n`);
  if (failed > 0) process.exit(1);
}

runIntegrityTests();
