/**
 * QR Guard - Blur Recovery Lab Module
 * Real image processing pipeline:
 * Original -> Grayscale -> Contrast Stretch -> Denoising -> Sharpening -> Adaptive Thresholding -> Multi-angle Rotations
 * Decodes via jsQR and Html5Qrcode.
 * Honest reporting: If recovery fails, it clearly reports failure. Never fabricates a result.
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.QRRecovery = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {

  const MAX_FILE_SIZE_MB = 8;
  const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;
  let onDecodeSuccess = null;

  // ── 1. Image Quality Estimation (Laplacian Variance & Contrast) ────────────
  function estimateImageQualityFromData(data, width, height) {
    const totalPixels = width * height;
    const gray = new Float32Array(totalPixels);

    for (let i = 0; i < totalPixels; i++) {
      const idx = i * 4;
      gray[i] = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2];
    }

    // Laplacian kernel: [0, 1, 0, 1, -4, 1, 0, 1, 0]
    let sumSq = 0;
    let count = 0;
    for (let y = 1; y < height - 1; y++) {
      const row = y * width;
      for (let x = 1; x < width - 1; x++) {
        const lap =
          gray[row - width + x] + gray[row + width + x] +
          gray[row + x - 1] + gray[row + x + 1] -
          4 * gray[row + x];
        sumSq += lap * lap;
        count++;
      }
    }
    const variance = count > 0 ? sumSq / count : 0;

    // Contrast: standard deviation of grayscale values
    let sum = 0;
    for (let i = 0; i < totalPixels; i++) sum += gray[i];
    const mean = sum / totalPixels;

    let varSum = 0;
    for (let i = 0; i < totalPixels; i++) {
      const diff = gray[i] - mean;
      varSum += diff * diff;
    }
    const stdDev = Math.sqrt(varSum / totalPixels);
    const contrast = Math.round(Math.min(100, Math.max(0, (stdDev / 64) * 100)));

    // Calibrate blur score without artificial early saturation
    // Variance < 40: heavily blurred, 40-150: moderate blur, > 400: sharp
    const rawBlurScore = Math.round(Math.min(100, Math.max(0, (Math.sqrt(variance) / 30) * 100)));

    let qualityLabel = 'Poor Quality';
    let qualityClass = 'quality-poor';
    if (rawBlurScore >= 60 && contrast >= 40) {
      qualityLabel = 'Good Quality';
      qualityClass = 'quality-good';
    } else if (rawBlurScore >= 30 || contrast >= 25) {
      qualityLabel = 'Fair Quality';
      qualityClass = 'quality-fair';
    }

    return {
      blurScore: rawBlurScore,
      contrast: contrast,
      variance: Math.round(variance),
      qualityLabel: qualityLabel,
      qualityClass: qualityClass
    };
  }

  // ── 2. Pure Pixel Transformation Algorithms ──────────────────────────────

  /** Grayscale */
  function processGrayscale(srcData, width, height) {
    const out = new Uint8ClampedArray(srcData.length);
    for (let i = 0; i < srcData.length; i += 4) {
      const g = Math.round(0.299 * srcData[i] + 0.587 * srcData[i + 1] + 0.114 * srcData[i + 2]);
      out[i] = g;
      out[i + 1] = g;
      out[i + 2] = g;
      out[i + 3] = 255;
    }
    return out;
  }

  /** Contrast Stretch (Histogram normalization) */
  function processContrastStretch(srcData, width, height) {
    const out = new Uint8ClampedArray(srcData.length);
    let min = 255;
    let max = 0;

    for (let i = 0; i < srcData.length; i += 4) {
      const g = srcData[i];
      if (g < min) min = g;
      if (g > max) max = g;
    }

    const range = max - min || 1;
    for (let i = 0; i < srcData.length; i += 4) {
      const val = Math.round(((srcData[i] - min) / range) * 255);
      out[i] = val;
      out[i + 1] = val;
      out[i + 2] = val;
      out[i + 3] = 255;
    }
    return out;
  }

  /** 3x3 Denoising (Median filter on grayscale) */
  function processDenoise(srcData, width, height) {
    const out = new Uint8ClampedArray(srcData);
    const window = new Uint8Array(9);

    for (let y = 1; y < height - 1; y++) {
      for (let x = 1; x < width - 1; x++) {
        let wi = 0;
        for (let ky = -1; ky <= 1; ky++) {
          for (let kx = -1; kx <= 1; kx++) {
            window[wi++] = srcData[((y + ky) * width + (x + kx)) * 4];
          }
        }
        // Insertion sort for 9 elements
        for (let i = 1; i < 9; i++) {
          const key = window[i];
          let j = i - 1;
          while (j >= 0 && window[j] > key) {
            window[j + 1] = window[j];
            j--;
          }
          window[j + 1] = key;
        }
        const median = window[4];
        const idx = (y * width + x) * 4;
        out[idx] = median;
        out[idx + 1] = median;
        out[idx + 2] = median;
      }
    }
    return out;
  }

  /** Sharpening Filter (Unsharp mask 3x3 kernel) */
  function processSharpen(srcData, width, height) {
    const out = new Uint8ClampedArray(srcData.length);
    // Center 5, 4 neighbors -1
    const kernel = [0, -1, 0, -1, 5, -1, 0, -1, 0];

    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const outIdx = (y * width + x) * 4;
        if (y === 0 || y === height - 1 || x === 0 || x === width - 1) {
          out[outIdx] = srcData[outIdx];
          out[outIdx + 1] = srcData[outIdx + 1];
          out[outIdx + 2] = srcData[outIdx + 2];
          out[outIdx + 3] = 255;
          continue;
        }
        let sum = 0;
        let ki = 0;
        for (let ky = -1; ky <= 1; ky++) {
          for (let kx = -1; kx <= 1; kx++) {
            const idx = ((y + ky) * width + (x + kx)) * 4;
            sum += srcData[idx] * kernel[ki++];
          }
        }
        const val = Math.max(0, Math.min(255, sum));
        out[outIdx] = val;
        out[outIdx + 1] = val;
        out[outIdx + 2] = val;
        out[outIdx + 3] = 255;
      }
    }
    return out;
  }

  /** Otsu Optimal Global Binarization */
  function processOtsuThreshold(srcData, width, height) {
    const hist = new Array(256).fill(0);
    const total = width * height;

    for (let i = 0; i < srcData.length; i += 4) {
      hist[srcData[i]]++;
    }

    let sum = 0;
    for (let i = 0; i < 256; i++) sum += i * hist[i];

    let sumB = 0;
    let wB = 0;
    let maxVariance = 0;
    let threshold = 128;

    for (let t = 0; t < 256; t++) {
      wB += hist[t];
      if (wB === 0) continue;
      const wF = total - wB;
      if (wF === 0) break;

      sumB += t * hist[t];
      const mB = sumB / wB;
      const mF = (sum - sumB) / wF;
      const between = wB * wF * (mB - mF) * (mB - mF);

      if (between > maxVariance) {
        maxVariance = between;
        threshold = t;
      }
    }

    const out = new Uint8ClampedArray(srcData.length);
    for (let i = 0; i < srcData.length; i += 4) {
      const v = srcData[i] > threshold ? 255 : 0;
      out[i] = v;
      out[i + 1] = v;
      out[i + 2] = v;
      out[i + 3] = 255;
    }
    return out;
  }

  /** Local Adaptive Thresholding (handles uneven illumination/vignetting) */
  function processAdaptiveThreshold(srcData, width, height, blockSize = 25, C = 8) {
    const out = new Uint8ClampedArray(srcData.length);
    const half = Math.floor(blockSize / 2);

    // Compute integral image
    const integral = new Float64Array(width * height);
    for (let y = 0; y < height; y++) {
      let sum = 0;
      for (let x = 0; x < width; x++) {
        sum += srcData[(y * width + x) * 4];
        integral[y * width + x] = sum + (y > 0 ? integral[(y - 1) * width + x] : 0);
      }
    }

    for (let y = 0; y < height; y++) {
      const y1 = Math.max(0, y - half);
      const y2 = Math.min(height - 1, y + half);
      for (let x = 0; x < width; x++) {
        const x1 = Math.max(0, x - half);
        const x2 = Math.min(width - 1, x + half);
        const count = (x2 - x1 + 1) * (y2 - y1 + 1);

        let areaSum = integral[y2 * width + x2];
        if (x1 > 0) areaSum -= integral[y2 * width + (x1 - 1)];
        if (y1 > 0) areaSum -= integral[(y1 - 1) * width + x2];
        if (x1 > 0 && y1 > 0) areaSum += integral[(y1 - 1) * width + (x1 - 1)];

        const mean = areaSum / count;
        const currentVal = srcData[(y * width + x) * 4];
        const outIdx = (y * width + x) * 4;
        const binVal = currentVal > (mean - C) ? 255 : 0;
        out[outIdx] = binVal;
        out[outIdx + 1] = binVal;
        out[outIdx + 2] = binVal;
        out[outIdx + 3] = 255;
      }
    }
    return out;
  }

  /** Rotate Pixel Data 90° Clockwise */
  function processRotate90(srcData, width, height) {
    const out = new Uint8ClampedArray(srcData.length);
    // new width = height, new height = width
    const newW = height;
    const newH = width;

    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const srcIdx = (y * width + x) * 4;
        const newX = height - 1 - y;
        const newY = x;
        const dstIdx = (newY * newW + newX) * 4;
        out[dstIdx] = srcData[srcIdx];
        out[dstIdx + 1] = srcData[srcIdx + 1];
        out[dstIdx + 2] = srcData[srcIdx + 2];
        out[dstIdx + 3] = srcData[srcIdx + 3];
      }
    }
    return { data: out, width: newW, height: newH };
  }

  /** Color Inversion */
  function processInvert(srcData, width, height) {
    const out = new Uint8ClampedArray(srcData.length);
    for (let i = 0; i < srcData.length; i += 4) {
      out[i] = 255 - srcData[i];
      out[i + 1] = 255 - srcData[i + 1];
      out[i + 2] = 255 - srcData[i + 2];
      out[i + 3] = 255;
    }
    return out;
  }

  // ── 3. Canvas Helpers for Browser ──────────────────────────────────────────

  function imageToCanvas(img) {
    const canvas = document.createElement('canvas');
    let w = img.naturalWidth || img.width;
    let h = img.naturalHeight || img.height;

    // Normalize size: If too small (<240), upscale; if too huge (>1200), downscale
    const minDim = Math.min(w, h);
    const maxDim = Math.max(w, h);
    let scale = 1.0;
    if (minDim < 240) {
      scale = 240 / minDim;
    } else if (maxDim > 1200) {
      scale = 1200 / maxDim;
    }

    canvas.width = Math.round(w * scale);
    canvas.height = Math.round(h * scale);
    const ctx = canvas.getContext('2d');
    ctx.imageSmoothingEnabled = scale > 1.0;
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    return canvas;
  }

  function canvasToImageData(canvas) {
    const ctx = canvas.getContext('2d');
    return ctx.getImageData(0, 0, canvas.width, canvas.height);
  }

  function dataToCanvas(data, width, height) {
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    const imgData = new ImageData(data, width, height);
    ctx.putImageData(imgData, 0, 0);
    return canvas;
  }

  // ── 4. Unified QR Decoding Attempt ────────────────────────────────────────

  async function tryDecode(data, width, height, canvasRef) {
    // 1. Try jsQR (fast, synchronous, highly reliable on pixel data)
    const jsQRInstance = (typeof window !== 'undefined' && window.jsQR)
      ? window.jsQR
      : (typeof require !== 'undefined' ? (function() { try { return require('jsqr'); } catch (e) { return null; } })() : null);

    if (jsQRInstance) {
      try {
        const result = jsQRInstance(data, width, height, { inversionAttempts: 'attemptBoth' });
        if (result && result.data && result.data.trim().length > 0) {
          return { success: true, text: result.data };
        }
      } catch (err) {
        console.warn('jsQR attempt error:', err);
      }
    }

    // 2. Fallback to Html5Qrcode in browser if jsQR did not detect
    if (typeof window !== 'undefined' && typeof window.Html5Qrcode !== 'undefined' && canvasRef) {
      try {
        const text = await new Promise((resolve) => {
          canvasRef.toBlob((blob) => {
            if (!blob) return resolve(null);
            const file = new File([blob], 'attempt.png', { type: 'image/png' });
            let readerEl = document.getElementById('__recovery_reader__');
            if (!readerEl) {
              readerEl = document.createElement('div');
              readerEl.id = '__recovery_reader__';
              readerEl.style.display = 'none';
              document.body.appendChild(readerEl);
            }
            try {
              const decoder = new window.Html5Qrcode('__recovery_reader__');
              decoder.scanFile(file, true)
                .then(res => {
                  try { decoder.clear(); } catch (_) {}
                  resolve(res);
                })
                .catch(() => {
                  try { decoder.clear(); } catch (_) {}
                  resolve(null);
                });
            } catch (_) {
              resolve(null);
            }
          }, 'image/png');
        });

        if (text && text.trim().length > 0) {
          return { success: true, text };
        }
      } catch (_) {}
    }

    return { success: false };
  }

  // ── 5. Main Recovery Pipeline ─────────────────────────────────────────────

  async function recoverFromPixelData(data, width, height, onProgress, createProcessedCanvas) {
    const reportProgress = (msg, pct) => {
      if (typeof onProgress === 'function') onProgress(msg, pct);
    };

    reportProgress('Analyzing image quality & variance metrics…', 10);
    const quality = estimateImageQualityFromData(data, width, height);

    // Attempt 1: Direct Decode of Original
    reportProgress('Technique 1/7: Direct decoding of original image…', 20);
    let origCanvas = createProcessedCanvas ? createProcessedCanvas(data, width, height) : null;
    let res = await tryDecode(data, width, height, origCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Original Image (No Enhancement Required)',
        quality,
        processedCanvas: origCanvas
      };
    }

    // Attempt 2: Grayscale Conversion
    reportProgress('Technique 2/7: Grayscale luminance extraction…', 32);
    const grayData = processGrayscale(data, width, height);
    let grayCanvas = createProcessedCanvas ? createProcessedCanvas(grayData, width, height) : null;
    res = await tryDecode(grayData, width, height, grayCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Grayscale Luminance Conversion',
        quality,
        processedCanvas: grayCanvas
      };
    }

    // Attempt 3: Contrast Enhancement (Histogram Stretch)
    reportProgress('Technique 3/7: Histogram dynamic range stretching…', 45);
    const contrastData = processContrastStretch(grayData, width, height);
    let contrastCanvas = createProcessedCanvas ? createProcessedCanvas(contrastData, width, height) : null;
    res = await tryDecode(contrastData, width, height, contrastCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Dynamic Contrast Enhancement',
        quality,
        processedCanvas: contrastCanvas
      };
    }

    // Attempt 4: Denoising Filter + Contrast
    reportProgress('Technique 4/7: 3x3 Median Denoising & noise reduction…', 58);
    const denoiseData = processDenoise(contrastData, width, height);
    let denoiseCanvas = createProcessedCanvas ? createProcessedCanvas(denoiseData, width, height) : null;
    res = await tryDecode(denoiseData, width, height, denoiseCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Median Denoising Filter',
        quality,
        processedCanvas: denoiseCanvas
      };
    }

    // Attempt 5: Sharpening Filter (Unsharp Mask)
    reportProgress('Technique 5/7: Edge enhancement & convolution sharpening…', 70);
    const sharpData = processSharpen(contrastData, width, height);
    let sharpCanvas = createProcessedCanvas ? createProcessedCanvas(sharpData, width, height) : null;
    res = await tryDecode(sharpData, width, height, sharpCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Sharpening Convolution Filter',
        quality,
        processedCanvas: sharpCanvas
      };
    }

    // Attempt 6: Adaptive Thresholding (Otsu & Local Neighborhood)
    reportProgress('Technique 6/7: Adaptive binarization (Otsu & Local Window)…', 82);
    const otsuData = processOtsuThreshold(sharpData, width, height);
    let otsuCanvas = createProcessedCanvas ? createProcessedCanvas(otsuData, width, height) : null;
    res = await tryDecode(otsuData, width, height, otsuCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Adaptive Otsu Binarization',
        quality,
        processedCanvas: otsuCanvas
      };
    }

    // Try Local Adaptive
    const localData = processAdaptiveThreshold(contrastData, width, height);
    let localCanvas = createProcessedCanvas ? createProcessedCanvas(localData, width, height) : null;
    res = await tryDecode(localData, width, height, localCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Local Adaptive Neighborhood Thresholding',
        quality,
        processedCanvas: localCanvas
      };
    }

    // Attempt 7: Multi-angle Rotations (90°, 180°, 270°) and Inversion
    reportProgress('Technique 7/7: Multi-angle rotation and polarity correction…', 92);
    let currentRot = { data: otsuData, width, height };
    for (const deg of [90, 180, 270]) {
      currentRot = processRotate90(currentRot.data, currentRot.width, currentRot.height);
      const rotCanvas = createProcessedCanvas ? createProcessedCanvas(currentRot.data, currentRot.width, currentRot.height) : null;
      res = await tryDecode(currentRot.data, currentRot.width, currentRot.height, rotCanvas);
      if (res.success) {
        return {
          success: true,
          text: res.text,
          method: `Rotation ${deg}° Correction + Binarization`,
          quality,
          processedCanvas: rotCanvas
        };
      }
    }

    // Try Color Inverted
    const invertedData = processInvert(otsuData, width, height);
    const invertCanvas = createProcessedCanvas ? createProcessedCanvas(invertedData, width, height) : null;
    res = await tryDecode(invertedData, width, height, invertCanvas);
    if (res.success) {
      return {
        success: true,
        text: res.text,
        method: 'Polarity Inversion (White-on-Black Recovery)',
        quality,
        processedCanvas: invertCanvas
      };
    }

    // All techniques exhausted honestly
    reportProgress('All 7 enhancement techniques completed.', 100);
    return {
      success: false,
      quality,
      processedCanvas: otsuCanvas || contrastCanvas || grayCanvas
    };
  }

  // ── 6. Browser UI Driver ──────────────────────────────────────────────────

  async function recoverQR(file, imgElement, onProgress) {
    const canvas = imageToCanvas(imgElement);
    const imgData = canvasToImageData(canvas);
    return await recoverFromPixelData(
      imgData.data,
      imgData.width,
      imgData.height,
      onProgress,
      (d, w, h) => dataToCanvas(d, w, h)
    );
  }

  function init(onSuccess) {
    onDecodeSuccess = onSuccess;
    setupRecoveryDropZone();
    setupDemoButtons();
  }

  function setupRecoveryDropZone() {
    if (typeof document === 'undefined') return;
    const dropZone = document.getElementById('recoveryDropZone');
    const fileInput = document.getElementById('recoveryFileInput');
    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev =>
      dropZone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); })
    );
    ['dragenter', 'dragover'].forEach(ev =>
      dropZone.addEventListener(ev, () => dropZone.classList.add('dragover'))
    );
    ['dragleave', 'drop'].forEach(ev =>
      dropZone.addEventListener(ev, () => dropZone.classList.remove('dragover'))
    );

    dropZone.addEventListener('drop', e => {
      const files = e.dataTransfer?.files;
      if (files?.length > 0) handleRecoveryFile(files[0]);
    });

    fileInput.addEventListener('change', e => {
      if (e.target.files?.length > 0) handleRecoveryFile(e.target.files[0]);
    });
  }

  // ── Built-in Demo Suite Wiring (FIX 2) ────────────────────────────────────
  const DEMO_PRESETS = {
    normal: {
      name: 'Normal Clean QR',
      url: '/images/demo/demo-normal.png',
      expected: 'https://wikipedia.org',
      type: 'Safe Web URL',
      description: 'Pristine QR code with standard contrast. Decodes directly without heavy processing.'
    },
    lowcontrast: {
      name: 'Low-Contrast QR',
      url: '/images/demo/demo-lowcontrast.png',
      expected: 'WIFI:S:SecureOffice;T:WPA;P:OfficePass2026;;',
      type: 'Wi-Fi Network',
      description: 'Faint gray-on-gray QR with low dynamic range. Direct scan fails; recovered by Contrast Enhancement.'
    },
    blurry: {
      name: 'Blurry / Degraded QR',
      url: '/images/demo/demo-blurry.png',
      expected: 'https://github.com/shrutirajput745/qr-guard_02',
      type: 'Safe Web URL',
      description: 'Defocus blur causing soft edges and bled modules. Direct scan fails; recovered by Sharpening & Adaptive Thresholding.'
    },
    corrupted: {
      name: 'Severely Corrupted QR',
      url: '/images/demo/demo-corrupted.png',
      expected: '[Unrecoverable]',
      type: 'Damaged QR',
      description: 'Over 65% of finder patterns and data destroyed. Tests that recovery honestly reports failure without fabricating results.'
    }
  };

  let loadedDemoKey = null;

  function setupDemoButtons() {
    if (typeof document === 'undefined') return;

    document.querySelectorAll('.btn-load-demo').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-demo');
        loadDemo(key);
      });
    });

    document.querySelectorAll('.btn-run-demo-recovery').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-demo');
        runDemoRecovery(key);
      });
    });
  }

  function loadDemo(key) {
    const preset = DEMO_PRESETS[key];
    if (!preset) return;
    loadedDemoKey = key;

    showRecoveryPanel();
    updateRecoveryProgress('Loading local demo QR image…', 5);

    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      const origPreview = document.getElementById('recoveryOrigPreview');
      if (origPreview) origPreview.src = img.src;

      const canvas = imageToCanvas(img);
      const imgData = canvasToImageData(canvas);
      const quality = estimateImageQualityFromData(imgData.data, imgData.width, imgData.height);
      showQualityIndicator(quality);

      const expEl = document.getElementById('recoveryExpectedPayload');
      if (expEl) {
        expEl.textContent = preset.expected;
        const box = document.getElementById('recoveryExpectedBox');
        if (box) box.style.display = 'block';
      }

      updateRecoveryProgress(`Ready to test ${preset.name}. Click "Run Recovery".`, 0);
      if (window.showToast) window.showToast(`Loaded ${preset.name}. Click "Run Recovery" to test.`, 'info');
    };
    img.onerror = () => {
      showRecoveryError(`Could not load local demo image: ${preset.url}. Ensure assets are generated.`);
    };
    img.src = preset.url;
  }

  async function runDemoRecovery(key) {
    const preset = DEMO_PRESETS[key || loadedDemoKey];
    if (!preset) {
      if (window.showToast) window.showToast('Please load a demo first.', 'warning');
      return;
    }

    showRecoveryPanel();
    updateRecoveryProgress('Preparing image for analysis…', 5);

    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = async () => {
      const origPreview = document.getElementById('recoveryOrigPreview');
      if (origPreview) origPreview.src = img.src;

      const canvas = imageToCanvas(img);
      const imgData = canvasToImageData(canvas);
      const quality = estimateImageQualityFromData(imgData.data, imgData.width, imgData.height);
      showQualityIndicator(quality);

      const expEl = document.getElementById('recoveryExpectedPayload');
      if (expEl) {
        expEl.textContent = preset.expected;
        const box = document.getElementById('recoveryExpectedBox');
        if (box) box.style.display = 'block';
      }

      const result = await recoverFromPixelData(
        imgData.data,
        imgData.width,
        imgData.height,
        updateRecoveryProgress,
        (d, w, h) => dataToCanvas(d, w, h)
      );

      showRecoveryResult(result, preset.expected);
    };
    img.src = preset.url;
  }

  function handleRecoveryFile(file) {
    if (!file.type.startsWith('image/')) {
      showRecoveryError('Invalid file type. Please upload a PNG, JPG, or WEBP image.');
      return;
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      showRecoveryError(`File too large (max ${MAX_FILE_SIZE_MB}MB). Please upload a smaller image.`);
      return;
    }

    loadedDemoKey = null;
    const expBox = document.getElementById('recoveryExpectedBox');
    if (expBox) expBox.style.display = 'none';

    showRecoveryPanel();
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = async () => {
        const origPreview = document.getElementById('recoveryOrigPreview');
        if (origPreview) origPreview.src = e.target.result;

        const canvas = imageToCanvas(img);
        const imgData = canvasToImageData(canvas);
        const quality = estimateImageQualityFromData(imgData.data, imgData.width, imgData.height);
        showQualityIndicator(quality);

        const result = await recoverQR(file, img, updateRecoveryProgress);
        showRecoveryResult(result, null);
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  function showRecoveryPanel() {
    const panel = document.getElementById('recoveryPanel');
    const resultPanel = document.getElementById('recoveryResultPanel');
    const errorBox = document.getElementById('recoveryErrorBox');
    const procPlaceholder = document.getElementById('recoveryProcessedPlaceholder');
    const procPreview = document.getElementById('recoveryProcessedPreview');

    if (panel) panel.style.display = 'block';
    if (resultPanel) resultPanel.style.display = 'none';
    if (errorBox) errorBox.style.display = 'none';
    if (procPlaceholder) procPlaceholder.style.display = 'flex';
    if (procPreview) procPreview.style.display = 'none';

    updateRecoveryProgress('Starting analysis…', 0);
  }

  function updateRecoveryProgress(message, pct) {
    const bar = document.getElementById('recoveryProgressBar');
    const label = document.getElementById('recoveryProgressLabel');
    const pctEl = document.getElementById('recoveryProgressPct');
    if (bar) bar.style.width = `${pct}%`;
    if (label) label.textContent = message;
    if (pctEl) pctEl.textContent = `${Math.round(pct)}%`;
  }

  function showQualityIndicator(quality) {
    const el = document.getElementById('imageQualityBadge');
    if (!el) return;
    el.className = `quality-badge ${quality.qualityClass}`;
    el.innerHTML = `
      <i class="fa-solid fa-chart-simple"></i>
      <span>Image Quality: <strong>${quality.qualityLabel}</strong></span>
      <span class="quality-detail">
        Sharpness Index: <strong>${quality.blurScore}/100</strong> · Contrast: <strong>${quality.contrast}/100</strong> (Variance: ${quality.variance})
      </span>
    `;
    el.style.display = 'flex';
  }

  function showRecoveryResult(result, expectedPayload) {
    const resultPanel = document.getElementById('recoveryResultPanel');
    const statusEl = document.getElementById('recoveryStatus');
    const methodEl = document.getElementById('recoveryMethod');
    const processedPreviewEl = document.getElementById('recoveryProcessedPreview');
    const processedPlaceholder = document.getElementById('recoveryProcessedPlaceholder');
    const decodedContentEl = document.getElementById('recoveryDecodedContent');
    const decodedWrapper = document.getElementById('recoveryDecodedWrapper');

    if (!resultPanel) return;
    resultPanel.style.display = 'block';

    if (result.processedCanvas && processedPreviewEl) {
      processedPreviewEl.src = result.processedCanvas.toDataURL('image/png');
      processedPreviewEl.style.display = 'block';
      if (processedPlaceholder) processedPlaceholder.style.display = 'none';
    }

    if (result.success) {
      const matchMsg = expectedPayload
        ? (result.text === expectedPayload
            ? ' <span class="badge-matched"><i class="fa-solid fa-circle-check"></i> Matched Expected Payload</span>'
            : ' <span class="badge-diff"><i class="fa-solid fa-triangle-exclamation"></i> Decoded content differs</span>')
        : '';

      if (statusEl) {
        statusEl.className = 'recovery-status recovery-success';
        statusEl.innerHTML = `
          <div class="status-title-row">
            <i class="fa-solid fa-circle-check"></i>
            <span>QR Code Recovered Successfully!</span>
            ${matchMsg}
          </div>
        `;
      }
      if (methodEl) {
        methodEl.innerHTML = `<strong>Effective Technique:</strong> ${escapeHtml(result.method)}`;
      }
      if (decodedWrapper) decodedWrapper.style.display = 'block';
      if (decodedContentEl) decodedContentEl.textContent = result.text;

      if (window.showToast) {
        window.showToast('QR code successfully recovered and decoded!', 'success');
      }

      // Add a prominent button to analyze security
      let analyzeBtn = document.getElementById('recoveryAnalyzeBtn');
      if (!analyzeBtn) {
        analyzeBtn = document.createElement('button');
        analyzeBtn.id = 'recoveryAnalyzeBtn';
        analyzeBtn.className = 'btn btn-primary';
        analyzeBtn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Run Full Security Analysis';
        const actions = resultPanel.querySelector('.recovery-actions');
        if (actions) actions.prepend(analyzeBtn);
      }
      analyzeBtn.style.display = 'inline-flex';
      analyzeBtn.onclick = () => {
        if (onDecodeSuccess) onDecodeSuccess(result.text);
      };
    } else {
      if (statusEl) {
        statusEl.className = 'recovery-status recovery-failed';
        statusEl.innerHTML = `
          <div class="status-title-row">
            <i class="fa-solid fa-circle-xmark"></i>
            <span>Recovery Unsuccessful — QR Code Unreadable</span>
          </div>
          <p class="recovery-fail-msg">
            All 7 enhancement techniques (Grayscale, Contrast Stretch, Denoising, Sharpening, Otsu & Local Adaptive Thresholding, and Multi-angle Rotations) were attempted.
            No valid QR finder patterns or alignment marks could be decoded.
            ${expectedPayload === '[Unrecoverable]' ? '<strong>Evaluation Verified:</strong> The system correctly and honestly identified that this severely corrupted QR code cannot be recovered, without generating false results.' : 'The QR code may be too severely degraded, occluded, or blurred beyond error correction limits.'}
          </p>
        `;
      }
      if (methodEl) methodEl.innerHTML = '<strong>Techniques Attempted:</strong> 7 / 7 enhancement filters evaluated';
      if (decodedWrapper) decodedWrapper.style.display = 'none';
      if (decodedContentEl) decodedContentEl.textContent = '';

      const analyzeBtn = document.getElementById('recoveryAnalyzeBtn');
      if (analyzeBtn) analyzeBtn.style.display = 'none';

      if (window.showToast) {
        window.showToast(expectedPayload === '[Unrecoverable]' ? 'Honest failure verified: unrecoverable QR correctly identified.' : 'QR could not be decoded after all enhancement attempts.', 'warning');
      }
    }
  }

  function showRecoveryError(message) {
    const errorBox = document.getElementById('recoveryErrorBox');
    if (errorBox) {
      errorBox.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(message)}`;
      errorBox.style.display = 'flex';
    }
    if (window.showToast) window.showToast(message, 'error');
  }

  function startRecovery(file) {
    handleRecoveryFile(file);
  }

  function resetRecovery() {
    const panel = document.getElementById('recoveryPanel');
    const resultPanel = document.getElementById('recoveryResultPanel');
    const errorBox = document.getElementById('recoveryErrorBox');
    const fileInput = document.getElementById('recoveryFileInput');
    const qualityBadge = document.getElementById('imageQualityBadge');
    const expBox = document.getElementById('recoveryExpectedBox');

    if (panel) panel.style.display = 'none';
    if (resultPanel) resultPanel.style.display = 'none';
    if (errorBox) errorBox.style.display = 'none';
    if (fileInput) fileInput.value = '';
    if (qualityBadge) qualityBadge.style.display = 'none';
    if (expBox) expBox.style.display = 'none';
    loadedDemoKey = null;
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
    resetRecovery,
    startRecovery,
    handleRecoveryFile,
    loadDemo,
    runDemoRecovery,
    DEMO_PRESETS,
    estimateImageQualityFromData,
    processGrayscale,
    processContrastStretch,
    processDenoise,
    processSharpen,
    processOtsuThreshold,
    processAdaptiveThreshold,
    processRotate90,
    processInvert,
    recoverFromPixelData,
    recoverQR
  };
});
