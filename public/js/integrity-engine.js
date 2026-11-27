/**
 * QR Guard - QR Trust Fingerprint & Visual Integrity Analyzer Engine
 * Independent structural & visual forensics engine for QR codes.
 * Analyzes QR matrix geometry, ISO/IEC 18004 format/version metadata, finder/alignment/timing
 * integrity, quiet zone, logo/overlay interference, visual quality artifacts, SHA-256 payload
 * & structural fingerprints, and rotation/scale-normalized QR replacement comparison.
 *
 * Compatible with both Browser (window.QRIntegrityEngine) and Node.js (module.exports).
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('jsqr'));
  } else {
    root.QRIntegrityEngine = factory(root.jsQR);
  }
})(typeof self !== 'undefined' ? self : this, function(jsQRImpl) {

  // ── 1. Pure-JS Synchronous SHA-256 (FIPS 180-4) ──────────────────────────
  function utf8ToBytes(str) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(str));
    }
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 0x80) {
        bytes.push(c);
      } else if (c < 0x800) {
        bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        const c2 = str.charCodeAt(++i);
        const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
        bytes.push(
          0xf0 | (cp >> 18),
          0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f),
          0x80 | (cp & 0x3f)
        );
      } else {
        bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      }
    }
    return bytes;
  }

  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function sha256Hex(str) {
    const msg = utf8ToBytes(str);
    const bitLen = msg.length * 8;
    msg.push(0x80);
    while ((msg.length % 64) !== 56) msg.push(0);

    const hi = Math.floor(bitLen / 0x100000000);
    const lo = bitLen >>> 0;
    msg.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff);
    msg.push((lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    const W = new Uint32Array(64);
    const rotr = (v, n) => (v >>> n) | (v << (32 - n));

    for (let offset = 0; offset < msg.length; offset += 64) {
      for (let i = 0; i < 16; i++) {
        const j = offset + i * 4;
        W[i] = ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i++) {
        const s0 = (rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3)) >>> 0;
        const s1 = (rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10)) >>> 0;
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }

      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
        const ch = ((e & f) ^ (~e & g)) >>> 0;
        const temp1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
        const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
        const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        const temp2 = (S0 + maj) >>> 0;

        h = g; g = f; f = e;
        e = (d + temp1) >>> 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    return Array.from(H).map(x => x.toString(16).padStart(8, '0')).join('');
  }

  // ── 2. ISO/IEC 18004 Constants (Format, Version, Alignment, Masks) ───────
  // Note: Format table uses jsQR/ZXing EC index ordering (0=L, 1=M, 2=Q, 3=H)
  const EC_LEVEL_MAP = {
    0: { code: 'L', name: 'Low (~7% recovery)', capacityPct: 7 },
    1: { code: 'M', name: 'Medium (~15% recovery)', capacityPct: 15 },
    2: { code: 'Q', name: 'Quartile (~25% recovery)', capacityPct: 25 },
    3: { code: 'H', name: 'High (~30% recovery)', capacityPct: 30 }
  };

  const FORMAT_INFO_TABLE = [
    { bits: 0x5412, ec: 1, mask: 0 }, { bits: 0x5125, ec: 1, mask: 1 },
    { bits: 0x5E7C, ec: 1, mask: 2 }, { bits: 0x5B4B, ec: 1, mask: 3 },
    { bits: 0x45F9, ec: 1, mask: 4 }, { bits: 0x40CE, ec: 1, mask: 5 },
    { bits: 0x4F97, ec: 1, mask: 6 }, { bits: 0x4AA0, ec: 1, mask: 7 },
    { bits: 0x77C4, ec: 0, mask: 0 }, { bits: 0x72F3, ec: 0, mask: 1 },
    { bits: 0x7DAA, ec: 0, mask: 2 }, { bits: 0x789D, ec: 0, mask: 3 },
    { bits: 0x662F, ec: 0, mask: 4 }, { bits: 0x6318, ec: 0, mask: 5 },
    { bits: 0x6C41, ec: 0, mask: 6 }, { bits: 0x6976, ec: 0, mask: 7 },
    { bits: 0x1689, ec: 3, mask: 0 }, { bits: 0x13BE, ec: 3, mask: 1 },
    { bits: 0x1CE7, ec: 3, mask: 2 }, { bits: 0x19D0, ec: 3, mask: 3 },
    { bits: 0x0762, ec: 3, mask: 4 }, { bits: 0x0255, ec: 3, mask: 5 },
    { bits: 0x0D0C, ec: 3, mask: 6 }, { bits: 0x083B, ec: 3, mask: 7 },
    { bits: 0x355F, ec: 2, mask: 0 }, { bits: 0x3068, ec: 2, mask: 1 },
    { bits: 0x3F31, ec: 2, mask: 2 }, { bits: 0x3A06, ec: 2, mask: 3 },
    { bits: 0x24B4, ec: 2, mask: 4 }, { bits: 0x2183, ec: 2, mask: 5 },
    { bits: 0x2EDA, ec: 2, mask: 6 }, { bits: 0x2BED, ec: 2, mask: 7 }
  ];

  // ISO/IEC 18004 Alignment Pattern Center Coordinates (Versions 1..40)
  const ALIGNMENT_CENTERS = [
    [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54],
    [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74],
    [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90],
    [6, 28, 50, 72, 94], [6, 26, 50, 74, 98], [6, 30, 54, 78, 102], [6, 28, 54, 80, 106],
    [6, 32, 58, 84, 110], [6, 30, 58, 86, 114], [6, 34, 62, 90, 118],
    [6, 26, 50, 74, 98, 122], [6, 30, 54, 78, 102, 126], [6, 26, 52, 78, 104, 130],
    [6, 30, 56, 82, 108, 134], [6, 34, 60, 86, 112, 138], [6, 30, 58, 86, 114, 142],
    [6, 34, 62, 90, 118, 146], [6, 30, 54, 78, 102, 126, 150], [6, 24, 50, 76, 102, 128, 154],
    [6, 28, 54, 80, 106, 132, 158], [6, 32, 58, 84, 110, 136, 162],
    [6, 26, 54, 82, 110, 138, 166], [6, 30, 58, 86, 114, 142, 170]
  ];

  // ISO/IEC 18004 Version Info Golay(18,6) codewords for Versions 7..40
  const VERSION_INFO_BITS = {
    7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3, 11: 0x0BBF6, 12: 0x0C762, 13: 0x0D847,
    14: 0x0E60D, 15: 0x0F928, 16: 0x10B78, 17: 0x1145D, 18: 0x12A17, 19: 0x13532, 20: 0x149A6,
    21: 0x15683, 22: 0x168C9, 23: 0x177EC, 24: 0x18EC4, 25: 0x191E1, 26: 0x1AFAB, 27: 0x1B08E,
    28: 0x1CC1A, 29: 0x1D33F, 30: 0x1ED75, 31: 0x1F250, 32: 0x209D5, 33: 0x216F0, 34: 0x228BA,
    35: 0x2379F, 36: 0x24B0B, 37: 0x2542E, 38: 0x26A64, 39: 0x27541, 40: 0x28C69
  };

  const DATA_MASKS = [
    (x, y) => ((y + x) % 2) === 0,
    (x, y) => (y % 2) === 0,
    (x, y) => (x % 3) === 0,
    (x, y) => ((y + x) % 3) === 0,
    (x, y) => ((Math.floor(y / 2) + Math.floor(x / 3)) % 2) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) === 0,
    (x, y) => ((((y * x) % 2) + ((y * x) % 3)) % 2) === 0,
    (x, y) => ((((y + x) % 2) + ((y * x) % 3)) % 2) === 0
  ];

  function hammingDistance(a, b) {
    let x = (a ^ b) >>> 0;
    let count = 0;
    while (x) {
      count++;
      x &= x - 1;
    }
    return count;
  }

  // ── 3. Perspective Homography (Unit Square -> Quad Corners) ──────────────
  function computeQuadTransform(p0, p1, p2, p3, dim) {
    // Maps normalized module coordinates (u, v) in [0, dim]x[0, dim] to pixel (x, y)
    const dx3 = p0.x - p1.x + p2.x - p3.x;
    const dy3 = p0.y - p1.y + p2.y - p3.y;

    let a13 = 0, a23 = 0;
    if (Math.abs(dx3) > 1e-6 || Math.abs(dy3) > 1e-6) {
      const dx1 = p1.x - p2.x;
      const dx2 = p3.x - p2.x;
      const dy1 = p1.y - p2.y;
      const dy2 = p3.y - p2.y;
      const denom = dx1 * dy2 - dx2 * dy1;
      if (Math.abs(denom) > 1e-9) {
        a13 = (dx3 * dy2 - dx2 * dy3) / denom;
        a23 = (dx1 * dy3 - dx3 * dy1) / denom;
      }
    }

    const a11 = p1.x - p0.x + a13 * p1.x;
    const a21 = p3.x - p0.x + a23 * p3.x;
    const a31 = p0.x;
    const a12 = p1.y - p0.y + a13 * p1.y;
    const a22 = p3.y - p0.y + a23 * p3.y;
    const a32 = p0.y;
    const a33 = 1;

    return function mapModuleToPixel(u, v) {
      const s = u / dim;
      const t = v / dim;
      const denom = a13 * s + a23 * t + a33;
      if (Math.abs(denom) < 1e-9) return { x: p0.x, y: p0.y };
      return {
        x: (a11 * s + a21 * t + a31) / denom,
        y: (a12 * s + a22 * t + a32) / denom
      };
    };
  }

  // ── 4. Visual Image Quality & Artifact Metrics (Pure Pixel Analysis) ──────
  function measureVisualMetrics(data, width, height) {
    const total = width * height;
    const gray = new Float32Array(total);
    let coloredPixels = 0;
    let sum = 0;

    for (let i = 0; i < total; i++) {
      const idx = i * 4;
      const r = data[idx], g = data[idx + 1], b = data[idx + 2];
      const lum = 0.299 * r + 0.587 * g + 0.114 * b;
      gray[i] = lum;
      sum += lum;
      const spread = Math.max(r, g, b) - Math.min(r, g, b);
      if (spread > 36) coloredPixels++;
    }

    const mean = sum / total;
    let varSum = 0;
    let lapSumSq = 0;
    let lapCount = 0;

    for (let y = 0; y < height; y++) {
      const row = y * width;
      for (let x = 0; x < width; x++) {
        const diff = gray[row + x] - mean;
        varSum += diff * diff;
        if (y > 0 && y < height - 1 && x > 0 && x < width - 1) {
          const lap = gray[row - width + x] + gray[row + width + x] + gray[row + x - 1] + gray[row + x + 1] - 4 * gray[row + x];
          lapSumSq += lap * lap;
          lapCount++;
        }
      }
    }

    const stdDev = Math.sqrt(varSum / total);
    const lapVariance = lapCount > 0 ? lapSumSq / lapCount : 0;
    const sharpnessScore = Math.round(Math.min(100, Math.max(0, (Math.sqrt(lapVariance) / 30) * 100)));
    const contrastScore = Math.round(Math.min(100, Math.max(0, (stdDev / 64) * 100)));

    // JPEG 8x8 blockiness estimator: compare gradients at 8-px block boundaries vs 4-px mid-block offsets
    let blockEdgeSum = 0, blockEdgeCnt = 0;
    let interiorSum = 0, interiorCnt = 0;
    const blockLines = new Set();
    for (let y = 1; y < height - 1; y++) {
      const row = y * width;
      for (let x = 1; x < width - 1; x++) {
        const gx = Math.abs(gray[row + x] - gray[row + x - 1]);
        const gy = Math.abs(gray[row + x] - gray[row - width + x]);
        if (gx > 0 && gx < 140) {
          if (x % 8 === 0) { blockEdgeSum += gx; blockEdgeCnt++; blockLines.add('x' + x); }
          else if (x % 8 === 4) { interiorSum += gx; interiorCnt++; }
        }
        if (gy > 0 && gy < 140) {
          if (y % 8 === 0) { blockEdgeSum += gy; blockEdgeCnt++; blockLines.add('y' + y); }
          else if (y % 8 === 4) { interiorSum += gy; interiorCnt++; }
        }
      }
    }
    const avgBlockGrad = blockEdgeCnt > 0 ? blockEdgeSum / blockEdgeCnt : 0;
    const avgInteriorGrad = interiorCnt > 0 ? interiorSum / interiorCnt : 0;
    const blockinessRatio = blockLines.size >= 6
      ? (avgInteriorGrad > 0.2 ? avgBlockGrad / avgInteriorGrad : (blockEdgeCnt > 12 && avgBlockGrad > 4 ? 1.5 : 1.0))
      : 1.0;

    return {
      width,
      height,
      gray,
      meanLuminance: Math.round(mean),
      contrastScore,
      sharpnessScore,
      laplacianVariance: Math.round(lapVariance),
      colorRatio: Number((coloredPixels / total).toFixed(4)),
      isColored: (coloredPixels / total) > 0.02,
      blockinessRatio: Number(blockinessRatio.toFixed(3))
    };
  }

  // Fallback finder pattern scan (1:1:3:1:1 ratio) when decoder fails
  function detectCandidateFinders(gray, width, height) {
    const centers = [];
    // Compute adaptive global midpoint
    let minL = 255, maxL = 0;
    for (let i = 0; i < gray.length; i += 4) {
      if (gray[i] < minL) minL = gray[i];
      if (gray[i] > maxL) maxL = gray[i];
    }
    const thresh = (minL + maxL) / 2;
    if (maxL - minL < 20) return 0;

    const stepY = Math.max(2, Math.floor(height / 80));
    for (let y = 0; y < height; y += stepY) {
      const runs = [];
      let curState = gray[y * width] < thresh ? 1 : 0;
      let curLen = 0;
      for (let x = 0; x < width; x++) {
        const s = gray[y * width + x] < thresh ? 1 : 0;
        if (s === curState) {
          curLen++;
        } else {
          runs.push({ s: curState, len: curLen, endX: x });
          curState = s;
          curLen = 1;
        }
      }
      runs.push({ s: curState, len: curLen, endX: width });

      for (let i = 0; i <= runs.length - 5; i++) {
        if (runs[i].s !== 1 || runs[i + 1].s !== 0 || runs[i + 2].s !== 1 || runs[i + 3].s !== 0 || runs[i + 4].s !== 1) {
          continue;
        }
        const totalW = runs[i].len + runs[i + 1].len + runs[i + 2].len + runs[i + 3].len + runs[i + 4].len;
        if (totalW < 7) continue;
        const unit = totalW / 7;
        const tol = unit * 0.65;
        if (
          Math.abs(runs[i].len - unit) < tol &&
          Math.abs(runs[i + 1].len - unit) < tol &&
          Math.abs(runs[i + 2].len - 3 * unit) < tol * 2 &&
          Math.abs(runs[i + 3].len - unit) < tol &&
          Math.abs(runs[i + 4].len - unit) < tol
        ) {
          const cx = runs[i + 2].endX - runs[i + 2].len / 2;
          const dup = centers.some(c => Math.hypot(c.x - cx, c.y - y) < totalW * 0.7);
          if (!dup) centers.push({ x: cx, y });
        }
      }
    }
    return Math.min(3, centers.length);
  }

  // Contrast-stretched clone used strictly as a decoding fallback for faint images
  function buildContrastStretchedRgba(data, width, height) {
    const out = new Uint8ClampedArray(data.length);
    let min = 255, max = 0;
    for (let i = 0; i < data.length; i += 4) {
      const g = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
      if (g < min) min = g;
      if (g > max) max = g;
    }
    const range = max - min || 1;
    for (let i = 0; i < data.length; i += 4) {
      const g = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
      const v = Math.round(((g - min) / range) * 255);
      out[i] = v; out[i + 1] = v; out[i + 2] = v; out[i + 3] = 255;
    }
    return out;
  }

  // ── 5. Matrix Sampling & Structural Extraction ───────────────────────────
  function samplePixel(data, gray, width, height, px, py) {
    const x = Math.round(px);
    const y = Math.round(py);
    if (x < 0 || x >= width || y < 0 || y >= height) {
      return { inBounds: false, lum: 255, chroma: 0 };
    }
    const idx = y * width + x;
    const rgbaIdx = idx * 4;
    const r = data[rgbaIdx], g = data[rgbaIdx + 1], b = data[rgbaIdx + 2];
    const chroma = Math.max(r, g, b) - Math.min(r, g, b);
    return { inBounds: true, lum: gray[idx], chroma };
  }

  function buildFunctionPatternMask(version, dim) {
    const mask = new Uint8Array(dim * dim); // 1 = function/structural, 0 = data/ECC
    const markRect = (left, top, w, h) => {
      for (let y = Math.max(0, top); y < Math.min(dim, top + h); y++) {
        for (let x = Math.max(0, left); x < Math.min(dim, left + w); x++) {
          mask[y * dim + x] = 1;
        }
      }
    };
    markRect(0, 0, 9, 9);           // Top-left finder + separator + format
    markRect(dim - 8, 0, 8, 9);     // Top-right finder + separator + format
    markRect(0, dim - 8, 9, 8);     // Bottom-left finder + separator + format
    markRect(6, 9, 1, dim - 17);    // Vertical timing
    markRect(9, 6, dim - 17, 1);    // Horizontal timing

    const centers = ALIGNMENT_CENTERS[version - 1] || [];
    for (const cx of centers) {
      for (const cy of centers) {
        if ((cx === 6 && cy === 6) || (cx === 6 && cy === dim - 7) || (cx === dim - 7 && cy === 6)) {
          continue;
        }
        markRect(cx - 2, cy - 2, 5, 5);
      }
    }
    if (version >= 7) {
      markRect(dim - 11, 0, 3, 6);
      markRect(0, dim - 11, 6, 3);
    }
    return mask;
  }

  function expectedFinderBit(lx, ly) {
    // Canonical 7x7 finder pattern (0..6)
    if (lx === 0 || lx === 6 || ly === 0 || ly === 6) return 1;
    if (lx === 1 || lx === 5 || ly === 1 || ly === 5) return 0;
    return 1;
  }

  function evaluateFinderRegion(matrix, dim, originX, originY) {
    let matched = 0;
    const total = 49;
    const mismatches = [];
    for (let ly = 0; ly < 7; ly++) {
      for (let lx = 0; lx < 7; lx++) {
        const x = originX + lx;
        const y = originY + ly;
        const expected = expectedFinderBit(lx, ly);
        const actual = matrix[y * dim + x];
        if (actual === expected) {
          matched++;
        } else {
          mismatches.push({ x, y, expected, actual });
        }
      }
    }
    return {
      origin: { x: originX, y: originY },
      matched,
      total,
      integrityPct: Math.round((matched / total) * 100),
      mismatches
    };
  }

  function evaluateAlignmentPatterns(matrix, version, dim) {
    const centers = ALIGNMENT_CENTERS[version - 1] || [];
    const patterns = [];
    for (const cx of centers) {
      for (const cy of centers) {
        if ((cx === 6 && cy === 6) || (cx === 6 && cy === dim - 7) || (cx === dim - 7 && cy === 6)) {
          continue;
        }
        let matched = 0;
        const total = 25;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            const expected = (Math.abs(dx) === 2 || Math.abs(dy) === 2 || (dx === 0 && dy === 0)) ? 1 : 0;
            const actual = matrix[(cy + dy) * dim + (cx + dx)];
            if (actual === expected) matched++;
          }
        }
        patterns.push({
          center: { x: cx, y: cy },
          matched,
          total,
          integrityPct: Math.round((matched / total) * 100)
        });
      }
    }
    const totalMods = patterns.reduce((s, p) => s + p.total, 0);
    const matchedMods = patterns.reduce((s, p) => s + p.matched, 0);
    return {
      count: patterns.length,
      applicable: patterns.length > 0,
      overallIntegrityPct: totalMods > 0 ? Math.round((matchedMods / totalMods) * 100) : null,
      patterns
    };
  }

  function evaluateTimingPatterns(matrix, dim) {
    let total = 0, matched = 0;
    const mismatches = [];
    let curHRun = 0, maxHRun = 0;
    let curVRun = 0, maxVRun = 0;
    for (let i = 8; i <= dim - 9; i++) {
      const expected = (i % 2 === 0) ? 1 : 0;
      // Horizontal y = 6
      total++;
      if (matrix[6 * dim + i] === expected) {
        matched++;
        curHRun = 0;
      } else {
        mismatches.push({ axis: 'horizontal', x: i, y: 6, expected, actual: matrix[6 * dim + i] });
        curHRun++;
        if (curHRun > maxHRun) maxHRun = curHRun;
      }
      // Vertical x = 6
      total++;
      if (matrix[i * dim + 6] === expected) {
        matched++;
        curVRun = 0;
      } else {
        mismatches.push({ axis: 'vertical', x: 6, y: i, expected, actual: matrix[i * dim + 6] });
        curVRun++;
        if (curVRun > maxVRun) maxVRun = curVRun;
      }
    }
    return {
      lengthPerAxis: Math.max(0, dim - 16),
      totalModules: total,
      matched,
      maxConsecutiveMismatch: Math.max(maxHRun, maxVRun),
      integrityPct: total > 0 ? Math.round((matched / total) * 100) : 100,
      mismatches
    };
  }

  function decodeFormatInfoFromMatrix(matrix, dim) {
    let bitsA = 0;
    for (let x = 0; x <= 8; x++) {
      if (x !== 6) bitsA = (bitsA << 1) | matrix[8 * dim + x];
    }
    for (let y = 7; y >= 0; y--) {
      if (y !== 6) bitsA = (bitsA << 1) | matrix[y * dim + 8];
    }

    let bitsB = 0;
    for (let y = dim - 1; y >= dim - 7; y--) {
      bitsB = (bitsB << 1) | matrix[y * dim + 8];
    }
    for (let x = dim - 8; x < dim; x++) {
      bitsB = (bitsB << 1) | matrix[8 * dim + x];
    }

    const matchBest = (rawBits) => {
      let best = null;
      let bestDist = Infinity;
      for (const entry of FORMAT_INFO_TABLE) {
        const d = hammingDistance(rawBits, entry.bits);
        if (d < bestDist) {
          bestDist = d;
          best = entry;
        }
      }
      return { best, dist: bestDist };
    };

    const resA = matchBest(bitsA);
    const resB = matchBest(bitsB);
    const chosen = resA.dist <= resB.dist ? resA : resB;

    const ecInfo = chosen.best ? EC_LEVEL_MAP[chosen.best.ec] : null;
    const maskPattern = chosen.best ? chosen.best.mask : null;

    return {
      available: Boolean(chosen.best && chosen.dist <= 3),
      errorCorrectionLevel: ecInfo ? ecInfo.code : 'UNKNOWN',
      errorCorrectionName: ecInfo ? ecInfo.name : 'Unknown',
      errorCorrectionCapacityPct: ecInfo ? ecInfo.capacityPct : 0,
      maskPattern: maskPattern !== null ? maskPattern : null,
      primaryFormatHex: '0x' + bitsA.toString(16).toUpperCase().padStart(4, '0'),
      secondaryFormatHex: '0x' + bitsB.toString(16).toUpperCase().padStart(4, '0'),
      primaryBitErrors: resA.dist,
      secondaryBitErrors: resB.dist,
      copiesAgree: resA.best && resB.best && (resA.best.ec === resB.best.ec && resA.best.mask === resB.best.mask)
    };
  }

  function decodeVersionInfoFromMatrix(matrix, version, dim) {
    if (version < 7) {
      return {
        applicable: false,
        reason: 'Encoded version blocks exist only in QR Versions 7–40 (ISO/IEC 18004).',
        decoderVersion: version,
        matched: true
      };
    }

    let topRightBits = 0;
    for (let y = 5; y >= 0; y--) {
      for (let x = dim - 9; x >= dim - 11; x--) {
        topRightBits = (topRightBits << 1) | matrix[y * dim + x];
      }
    }

    let bottomLeftBits = 0;
    for (let x = 5; x >= 0; x--) {
      for (let y = dim - 9; y >= dim - 11; y--) {
        bottomLeftBits = (bottomLeftBits << 1) | matrix[y * dim + x];
      }
    }

    const expectedBits = VERSION_INFO_BITS[version];
    const distTR = expectedBits !== undefined ? hammingDistance(topRightBits, expectedBits) : null;
    const distBL = expectedBits !== undefined ? hammingDistance(bottomLeftBits, expectedBits) : null;

    return {
      applicable: true,
      decoderVersion: version,
      topRightHex: '0x' + topRightBits.toString(16).toUpperCase().padStart(5, '0'),
      bottomLeftHex: '0x' + bottomLeftBits.toString(16).toUpperCase().padStart(5, '0'),
      topRightBitErrors: distTR,
      bottomLeftBitErrors: distBL,
      matched: (distTR !== null && distTR <= 3) || (distBL !== null && distBL <= 3)
    };
  }

  function measureQuietZone(mapFn, data, gray, width, height, dim, midpoint) {
    const checkSide = (side) => {
      let cleanHalfSteps = 0;
      let clipped = false;
      const maxSteps = 10; // up to 5.0 modules
      for (let step = 1; step <= maxSteps; step++) {
        const offset = step * 0.5;
        let samples = 0, lightCount = 0;
        for (let t = 0.5; t < dim; t += 2) {
          let u = t, v = t;
          if (side === 'top') v = -offset;
          else if (side === 'bottom') v = dim + offset;
          else if (side === 'left') u = -offset;
          else if (side === 'right') u = dim + offset;

          const p = mapFn(u, v);
          const s = samplePixel(data, gray, width, height, p.x, p.y);
          if (!s.inBounds) {
            clipped = true;
            break;
          }
          samples++;
          if (s.lum >= midpoint * 0.88) lightCount++;
        }
        if (clipped || samples === 0) break;
        if (lightCount / samples >= 0.85) {
          cleanHalfSteps = step;
        } else {
          break;
        }
      }
      return {
        modules: Number((cleanHalfSteps * 0.5).toFixed(1)),
        clippedByImageBorder: clipped
      };
    };

    const top = checkSide('top');
    const bottom = checkSide('bottom');
    const left = checkSide('left');
    const right = checkSide('right');
    const minModules = Math.min(top.modules, bottom.modules, left.modules, right.modules);
    const anyClipped = top.clippedByImageBorder || bottom.clippedByImageBorder || left.clippedByImageBorder || right.clippedByImageBorder;

    return {
      top, bottom, left, right,
      minModules,
      meetsIsoStandard: minModules >= 4.0,
      anyClippedByBorder: anyClipped
    };
  }

  // ── 6. Core Single-Image Structural & Visual Integrity Analysis ──────────
  function analyzeImage(imageInput) {
    if (
      !imageInput ||
      !imageInput.data ||
      !Number.isFinite(imageInput.width) ||
      !Number.isFinite(imageInput.height) ||
      imageInput.width < 10 ||
      imageInput.height < 10 ||
      imageInput.data.length < imageInput.width * imageInput.height * 4
    ) {
      return buildInsufficientEvidenceReport(null, 'Invalid or missing RGBA image buffer.');
    }

    const { data, width, height } = imageInput;
    const visual = measureVisualMetrics(data, width, height);

    if (typeof jsQRImpl !== 'function') {
      return buildInsufficientEvidenceReport(visual, 'QR decoder library (jsQR) is not loaded.');
    }

    // Attempt direct decode first
    let decoded = jsQRImpl(data, width, height, { inversionAttempts: 'attemptBoth' });
    let decodedViaContrastStretch = false;

    if (!decoded) {
      // Try contrast-normalized copy strictly for recovery of faint images
      const stretched = buildContrastStretchedRgba(data, width, height);
      decoded = jsQRImpl(stretched, width, height, { inversionAttempts: 'attemptBoth' });
      if (decoded) decodedViaContrastStretch = true;
    }

    // Handle undecodable / malformed / severely damaged QR images honestly
    if (!decoded) {
      const candidateFinders = detectCandidateFinders(visual.gray, width, height);
      return buildInsufficientEvidenceReport(
        visual,
        candidateFinders >= 1
          ? `Detected ${candidateFinders} partial finder-like pattern(s), but QR decoding failed.`
          : 'No valid QR code structure could be decoded from this image.',
        candidateFinders
      );
    }

    const version = decoded.version;
    const loc = decoded.location;
    if (!version || version < 1 || version > 40 || !loc || !loc.topLeftCorner || !loc.topRightCorner || !loc.bottomRightCorner || !loc.bottomLeftCorner) {
      return buildInsufficientEvidenceReport(visual, 'Decoded QR structure metadata or corner locator points are incomplete.');
    }
    const dim = 17 + 4 * version;

    // Estimate pixels per module from top/left corner distances
    const topWidthPx = Math.hypot(loc.topRightCorner.x - loc.topLeftCorner.x, loc.topRightCorner.y - loc.topLeftCorner.y);
    const leftHeightPx = Math.hypot(loc.bottomLeftCorner.x - loc.topLeftCorner.x, loc.bottomLeftCorner.y - loc.topLeftCorner.y);
    const pixelsPerModule = Number((((topWidthPx + leftHeightPx) / 2) / dim).toFixed(2));

    const mapModuleToPixel = computeQuadTransform(
      loc.topLeftCorner,
      loc.topRightCorner,
      loc.bottomRightCorner,
      loc.bottomLeftCorner,
      dim
    );

    // Calibrate dark/light luminance from top-left finder center (3.5, 3.5) & separator (7.5, 3.5)
    const tlCenter = mapModuleToPixel(3.5, 3.5);
    const tlSep = mapModuleToPixel(7.5, 3.5);
    const darkRefSample = samplePixel(data, visual.gray, width, height, tlCenter.x, tlCenter.y);
    const lightRefSample = samplePixel(data, visual.gray, width, height, tlSep.x, tlSep.y);

    // Determine whether QR is inverted (light modules on dark background)
    const isInverted = darkRefSample.lum > lightRefSample.lum;
    let darkLum = isInverted ? lightRefSample.lum : darkRefSample.lum;
    let lightLum = isInverted ? darkRefSample.lum : lightRefSample.lum;
    if (Math.abs(lightLum - darkLum) < 25) {
      darkLum = 40;
      lightLum = 215;
    }
    const midpoint = (darkLum + lightLum) / 2;
    const halfSpan = Math.max(20, (lightLum - darkLum) / 2);

    // Sample all N x N module centers
    const totalModules = dim * dim;
    const matrix = new Uint8Array(totalModules);
    const moduleLums = new Float32Array(totalModules);
    const moduleChroma = new Float32Array(totalModules);
    const moduleCertainty = new Float32Array(totalModules);

    let darkCount = 0;
    let coloredModuleCount = 0;
    let lowContrastModuleCount = 0;

    for (let r = 0; r < dim; r++) {
      for (let c = 0; c < dim; c++) {
        // 5-point sub-module sample (center + tiny +-0.18 offset) to reduce single-pixel jitter
        const offsets = [[0, 0], [-0.18, 0], [0.18, 0], [0, -0.18], [0, 0.18]];
        let lumSum = 0, chromaMax = 0, cnt = 0;
        for (const [ox, oy] of offsets) {
          const p = mapModuleToPixel(c + 0.5 + ox, r + 0.5 + oy);
          const s = samplePixel(data, visual.gray, width, height, p.x, p.y);
          if (s.inBounds) {
            lumSum += s.lum;
            if (s.chroma > chromaMax) chromaMax = s.chroma;
            cnt++;
          }
        }
        const lum = cnt > 0 ? lumSum / cnt : lightLum;
        const idx = r * dim + c;
        moduleLums[idx] = lum;
        moduleChroma[idx] = chromaMax;

        const isDark = isInverted ? (lum > midpoint) : (lum < midpoint);
        matrix[idx] = isDark ? 1 : 0;
        if (isDark) darkCount++;

        const cert = Math.min(1, Math.abs(lum - midpoint) / halfSpan);
        moduleCertainty[idx] = cert;
        if (cert < 0.35) lowContrastModuleCount++;
        if (chromaMax > 30) coloredModuleCount++;
      }
    }

    // Structural inspections
    const fnMask = buildFunctionPatternMask(version, dim);
    const finderTL = evaluateFinderRegion(matrix, dim, 0, 0);
    const finderTR = evaluateFinderRegion(matrix, dim, dim - 7, 0);
    const finderBL = evaluateFinderRegion(matrix, dim, 0, dim - 7);
    const finderOverallPct = Math.round((finderTL.integrityPct + finderTR.integrityPct + finderBL.integrityPct) / 3);

    const alignmentInfo = evaluateAlignmentPatterns(matrix, version, dim);
    const timingInfo = evaluateTimingPatterns(matrix, dim);
    const formatInfo = decodeFormatInfoFromMatrix(matrix, dim);
    const versionInfo = decodeVersionInfoFromMatrix(matrix, version, dim);
    const quietZone = measureQuietZone(mapModuleToPixel, data, visual.gray, width, height, dim, midpoint);

    // ── Logo, Overlay & Localized Patch Interference Analysis ────────────
    const centerMin = dim * 0.28;
    const centerMax = dim * 0.72;
    let dataModulesTotal = 0;
    let centerDataModules = 0;
    let centerAnomalousModules = 0;
    let outerAnomalousModules = 0;
    let centerColoredModules = 0;
    let outerColoredModules = 0;
    let centerSolidPatchModules = 0;
    let outerSolidPatchModules = 0;

    // Detect uniform solid blocks (>= 3x3 same-value white/dark patch in data area)
    const anomalousMask = new Uint8Array(totalModules);
    const heatmapScores = new Float32Array(totalModules);

    for (let r = 0; r < dim; r++) {
      for (let c = 0; c < dim; c++) {
        const idx = r * dim + c;
        if (fnMask[idx] === 1) continue;
        dataModulesTotal++;
        const inCenter = r >= centerMin && r <= centerMax && c >= centerMin && c <= centerMax;
        if (inCenter) centerDataModules++;

        const isColoredMod = moduleChroma[idx] > 35;
        const isAmbiguousGray = moduleCertainty[idx] < 0.30;

        // Check if module sits inside a 3x3 uniform light block (classic whiteout/logo sticker mask)
        let sameLight3x3 = true;
        if (r >= 1 && r < dim - 1 && c >= 1 && c < dim - 1) {
          for (let dr = -1; dr <= 1 && sameLight3x3; dr++) {
            for (let dc = -1; dc <= 1; dc++) {
              const nIdx = (r + dr) * dim + (c + dc);
              if (matrix[nIdx] !== 0 || fnMask[nIdx] === 1) {
                sameLight3x3 = false;
                break;
              }
            }
          }
        } else {
          sameLight3x3 = false;
        }

        if (sameLight3x3) {
          if (inCenter) centerSolidPatchModules++;
          else outerSolidPatchModules++;
        }

        const isOverlayAnomaly = isColoredMod || isAmbiguousGray || sameLight3x3;
        if (isOverlayAnomaly) {
          anomalousMask[idx] = 1;
          heatmapScores[idx] = Math.max(heatmapScores[idx], isColoredMod ? 0.65 : (sameLight3x3 ? 0.75 : 0.45));
          if (inCenter) {
            centerAnomalousModules++;
            if (isColoredMod) centerColoredModules++;
          } else {
            outerAnomalousModules++;
            if (isColoredMod) outerColoredModules++;
          }
        } else if (moduleCertainty[idx] < 0.55) {
          heatmapScores[idx] = 0.25;
        }
      }
    }

    // Mark structural mismatches in the anomaly heatmap
    [finderTL, finderTR, finderBL].forEach(f => {
      f.mismatches.forEach(m => {
        heatmapScores[m.y * dim + m.x] = 1.0;
      });
    });
    timingInfo.mismatches.forEach(m => {
      heatmapScores[m.y * dim + m.x] = 0.95;
    });

    const totalOverlayPct = dataModulesTotal > 0
      ? Number((((centerAnomalousModules + outerAnomalousModules) / dataModulesTotal) * 100).toFixed(1))
      : 0;
    const centerOverlayPct = centerDataModules > 0
      ? Number(((centerAnomalousModules / centerDataModules) * 100).toFixed(1))
      : 0;
    const outerOverlayPct = (dataModulesTotal - centerDataModules) > 0
      ? Number(((outerAnomalousModules / (dataModulesTotal - centerDataModules)) * 100).toFixed(1))
      : 0;

    // Heuristic to distinguish uniform colored QR styling from a localized logo/overlay:
    const outerDataCount = Math.max(1, dataModulesTotal - centerDataModules);
    const outerColorRatio = outerColoredModules / outerDataCount;
    const isUniformColorStyledQR = visual.isColored && (outerColorRatio > 0.25 || (coloredModuleCount / Math.max(1, darkCount)) > 0.65);
    const effectiveOverlayPct = isUniformColorStyledQR
      ? Number((((centerAnomalousModules - centerColoredModules + outerAnomalousModules - outerColoredModules)) / Math.max(1, dataModulesTotal) * 100).toFixed(1))
      : totalOverlayPct;

    // Centered logo requires distinct centered colored/solid patch modules (not uniform JPEG/blur edge noise)
    const centerIntentionalOverlayMods = isUniformColorStyledQR
      ? centerSolidPatchModules
      : Math.max(centerColoredModules, centerSolidPatchModules);
    const outerIntentionalOverlayMods = isUniformColorStyledQR
      ? outerSolidPatchModules
      : Math.max(outerColoredModules, outerSolidPatchModules);

    const hasCenteredLogo = !isUniformColorStyledQR &&
      centerIntentionalOverlayMods >= 6 &&
      centerOverlayPct >= 8.0 &&
      outerIntentionalOverlayMods < 6;

    // Off-center patch: >= 4 clustered solid whiteout patch modules (i.e., >= 4x4 uniform block) OR >= 10 off-center colored modules
    const hasOffCenterOverlay = !isUniformColorStyledQR &&
      (outerSolidPatchModules >= 5 || outerColoredModules >= 10 || (outerOverlayPct >= 8.0 && outerAnomalousModules > centerAnomalousModules * 1.2));

    // ── 7. Trust Fingerprints ────────────────────────────────────────────
    const payloadStr = decoded.data;
    const payloadFingerprint = sha256Hex(payloadStr);

    const matrixBitStr = Array.from(matrix).join('');
    const ecCode = formatInfo.errorCorrectionLevel;
    const maskId = formatInfo.maskPattern;

    const canonicalPayloadDescriptor = `v${version}|ec:${ecCode}|mask:${maskId !== null ? maskId : 'u'}|dim:${dim}`;
    const structuralFingerprint = sha256Hex(`${canonicalPayloadDescriptor}|${matrixBitStr}`);

    // Unmasked data+ECC bitstring (accounts for mask pattern variation on identical payload+EC+version)
    let unmaskedBits = '';
    if (maskId !== null && DATA_MASKS[maskId]) {
      const maskFn = DATA_MASKS[maskId];
      for (let r = 0; r < dim; r++) {
        for (let c = 0; c < dim; c++) {
          const idx = r * dim + c;
          if (fnMask[idx] === 0) {
            const bit = matrix[idx] ^ (maskFn(c, r) ? 1 : 0);
            unmaskedBits += String(bit);
          }
        }
      }
    }
    const unmaskedStructureFingerprint = unmaskedBits
      ? sha256Hex(`v${version}|ec:${ecCode}|dim:${dim}|unmasked:${unmaskedBits}`)
      : null;

    // ── 8. Visual Tampering & Quality Classification (Low False-Positive) ─
    const findings = [];
    const ecCapacity = formatInfo.errorCorrectionCapacityPct || 15;
    const isLowRes = pixelsPerModule < 3.5 || Math.min(width, height) < 100;
    const isBlurry = visual.sharpnessScore < 42;
    const isLowContrast = visual.contrastScore < 32 || decodedViaContrastStretch;
    const isJpegCompressed = visual.blockinessRatio >= 1.22 && !isBlurry;

    // A. Confirmed Structural Damage checks
    if (finderOverallPct < 88 || finderTL.integrityPct < 85 || finderTR.integrityPct < 85 || finderBL.integrityPct < 85) {
      findings.push({
        code: 'DAMAGED_FINDER_PATTERN',
        classification: 'CONFIRMED_STRUCTURAL_DAMAGE',
        severity: 'HIGH',
        confidence: 92,
        evidence: `Finder integrity: TL ${finderTL.integrityPct}%, TR ${finderTR.integrityPct}%, BL ${finderBL.integrityPct}%.`,
        explanation: 'One or more 7x7 corner finder patterns have altered or missing modules compared to the ISO/IEC 18004 finder template.'
      });
    }

    if (timingInfo.integrityPct < 90 || timingInfo.maxConsecutiveMismatch >= 3) {
      findings.push({
        code: 'DISTORTED_TIMING_PATTERN',
        classification: 'CONFIRMED_STRUCTURAL_DAMAGE',
        severity: 'MEDIUM',
        confidence: 85,
        evidence: `Timing pattern integrity: ${timingInfo.integrityPct}% (${timingInfo.matched}/${timingInfo.totalModules} modules, max consecutive mismatch: ${timingInfo.maxConsecutiveMismatch}).`,
        explanation: 'Alternating timing modules along row 6 / column 6 deviate from expected alternating periodicity.'
      });
    }

    if (alignmentInfo.applicable && alignmentInfo.overallIntegrityPct < 80) {
      findings.push({
        code: 'DAMAGED_ALIGNMENT_PATTERN',
        classification: 'CONFIRMED_STRUCTURAL_DAMAGE',
        severity: 'MEDIUM',
        confidence: 82,
        evidence: `Alignment pattern integrity: ${alignmentInfo.overallIntegrityPct}% across ${alignmentInfo.count} alignment marker(s).`,
        explanation: 'Internal 5x5 alignment marker(s) show structural distortion.'
      });
    }

    // B. Format & Version Metadata anomalies
    if (formatInfo.available && !formatInfo.copiesAgree) {
      findings.push({
        code: 'FORMAT_COPIES_MISMATCH',
        classification: 'POSSIBLE_VISUAL_MODIFICATION',
        severity: 'MEDIUM',
        confidence: 78,
        evidence: `Primary format (${formatInfo.primaryFormatHex}, err=${formatInfo.primaryBitErrors}) vs secondary (${formatInfo.secondaryFormatHex}, err=${formatInfo.secondaryBitErrors}).`,
        explanation: 'The two redundant ISO 18004 format information regions disagree, suggesting localized damage or post-generation alteration.'
      });
    } else if (formatInfo.available && Math.min(formatInfo.primaryBitErrors, formatInfo.secondaryBitErrors) > 0) {
      findings.push({
        code: 'FORMAT_BIT_ERRORS',
        classification: 'IMAGE_QUALITY_DEGRADATION',
        severity: 'LOW',
        confidence: 70,
        evidence: `Format BCH bit errors corrected: primary=${formatInfo.primaryBitErrors}, secondary=${formatInfo.secondaryBitErrors}.`,
        explanation: 'Minor bit errors in format metadata were recovered via BCH error correction; may stem from compression or noise.'
      });
    }

    if (versionInfo.applicable && !versionInfo.matched) {
      findings.push({
        code: 'VERSION_INFO_MISMATCH',
        classification: 'CONFIRMED_STRUCTURAL_DAMAGE',
        severity: 'MEDIUM',
        confidence: 80,
        evidence: `Top-right err=${versionInfo.topRightBitErrors}, bottom-left err=${versionInfo.bottomLeftBitErrors}.`,
        explanation: 'Version 7+ Golay metadata blocks contain unexpected bit errors.'
      });
    }

    // C. Logo & Overlay Interference
    if (hasOffCenterOverlay) {
      findings.push({
        code: 'OFFCENTER_OVERLAY_ANOMALY',
        classification: 'POSSIBLE_VISUAL_MODIFICATION',
        severity: 'MEDIUM',
        confidence: 72,
        evidence: `Off-center data anomaly coverage: ${outerOverlayPct}% (${outerAnomalousModules} modules) vs center ${centerOverlayPct}%.`,
        explanation: 'Detected a localized non-binary or uniform patch outside the typical centered logo zone. Inspect visually for sticker or module replacement.'
      });
    } else if (hasCenteredLogo) {
      if (effectiveOverlayPct > ecCapacity + 8) {
        findings.push({
          code: 'EXCESSIVE_LOGO_COVERAGE',
          classification: 'POSSIBLE_VISUAL_MODIFICATION',
          severity: 'MEDIUM',
          confidence: 74,
          evidence: `Estimated overlay covers ~${effectiveOverlayPct}% of data modules, approaching or exceeding EC-${ecCode} (${ecCapacity}%) tolerance.`,
          explanation: 'Central logo/overlay is large relative to the QR error-correction capacity, reducing resilience and obscuring data modules.'
        });
      } else {
        findings.push({
          code: 'CENTERED_BRAND_LOGO',
          classification: 'NORMAL_DESIGN_VARIATION',
          severity: 'NONE',
          confidence: 80,
          evidence: `Centered overlay covers ~${effectiveOverlayPct}% of data modules (center region ${centerOverlayPct}%), within EC-${ecCode} (${ecCapacity}%) budget; finders ${finderOverallPct}% intact.`,
          explanation: 'Consistent with standard branded QR code design using Reed-Solomon error correction.'
        });
      }
    }

    // D. Normal Styling Variations (Color / Inverted)
    if (isUniformColorStyledQR) {
      findings.push({
        code: 'STYLED_COLOR_MODULES',
        classification: 'NORMAL_DESIGN_VARIATION',
        severity: 'NONE',
        confidence: 85,
        evidence: `Uniformly colored QR modules detected (${Math.round(visual.colorRatio * 100)}% colored pixels); structural patterns intact.`,
        explanation: 'Custom foreground/background colors are a normal QR branding variation and do not indicate tampering.'
      });
    }

    if (isInverted) {
      findings.push({
        code: 'INVERTED_POLARITY',
        classification: 'NORMAL_DESIGN_VARIATION',
        severity: 'NONE',
        confidence: 88,
        evidence: 'Light foreground modules on dark background detected.',
        explanation: 'Inverted QR polarity is a common visual design choice.'
      });
    }

    // E. Image Quality Degradation (Distinguished from Tampering!)
    if (isLowRes) {
      findings.push({
        code: 'LOW_RESOLUTION_IMAGE',
        classification: 'IMAGE_QUALITY_DEGRADATION',
        severity: 'LOW',
        confidence: 86,
        evidence: `Image size ${width}x${height}px (~${pixelsPerModule} px/module).`,
        explanation: 'Low module pixel density increases sampling uncertainty and should not be mistaken for intentional modification.'
      });
    }
    if (isBlurry) {
      findings.push({
        code: 'OPTICAL_BLUR',
        classification: 'IMAGE_QUALITY_DEGRADATION',
        severity: 'LOW',
        confidence: 84,
        evidence: `Sharpness index ${visual.sharpnessScore}/100 (Laplacian variance ${visual.laplacianVariance}).`,
        explanation: 'Uniform blur softens module edges without localized tampering evidence.'
      });
    }
    if (isLowContrast) {
      findings.push({
        code: 'LOW_CONTRAST',
        classification: 'IMAGE_QUALITY_DEGRADATION',
        severity: 'LOW',
        confidence: 85,
        evidence: `Global contrast index ${visual.contrastScore}/100${decodedViaContrastStretch ? ' (required contrast stretch to decode)' : ''}.`,
        explanation: 'Reduced dynamic range lowers module separation.'
      });
    }
    if (isJpegCompressed) {
      findings.push({
        code: 'COMPRESSION_ARTIFACTS',
        classification: 'IMAGE_QUALITY_DEGRADATION',
        severity: 'LOW',
        confidence: 74,
        evidence: `8x8 block-boundary gradient ratio ${visual.blockinessRatio} (typical of lossy JPEG compression).`,
        explanation: 'Compression ringing/blocking is an encoding artifact rather than malicious QR tampering.'
      });
    }

    // F. Quiet Zone Warning (only if contaminated, not simply tightly cropped border)
    if (!quietZone.meetsIsoStandard && !quietZone.anyClippedByBorder) {
      findings.push({
        code: 'CONTAMINATED_QUIET_ZONE',
        classification: 'IMAGE_QUALITY_DEGRADATION',
        severity: 'LOW',
        confidence: 72,
        evidence: `Minimum clean quiet zone: ${quietZone.minModules} modules (ISO 18004 recommends 4.0).`,
        explanation: 'Adjacent graphics or noise encroach on the QR quiet zone border.'
      });
    }

    // ── Overall Integrity Verdict & Separate Confidence / Severity ───────
    const hasConfirmedDamage = findings.some(f => f.classification === 'CONFIRMED_STRUCTURAL_DAMAGE');
    const hasPossibleMod = findings.some(f => f.classification === 'POSSIBLE_VISUAL_MODIFICATION');
    const hasQualityDegrad = findings.some(f => f.classification === 'IMAGE_QUALITY_DEGRADATION');
    const hasDesignVar = findings.some(f => f.classification === 'NORMAL_DESIGN_VARIATION');

    let overallStatus = 'INTACT';
    let overallLabel = 'Structurally Intact';
    let overallSeverity = 'NONE';
    let overallConfidence = 92;
    let summary = 'All structural markers (finder, timing, alignment, format) match ISO/IEC 18004 expectations with no evidence of visual tampering.';

    if (hasConfirmedDamage) {
      overallStatus = 'CONFIRMED_STRUCTURAL_DAMAGE';
      overallLabel = 'Confirmed Structural Damage';
      overallSeverity = 'HIGH';
      overallConfidence = 88;
      summary = 'Structural QR patterns (finder, timing, alignment, or version metadata) exhibit confirmed physical or digital module damage. Visual appearance alone cannot prove malicious intent vs accidental corruption.';
    } else if (hasPossibleMod) {
      overallStatus = 'POSSIBLE_VISUAL_MODIFICATION';
      overallLabel = 'Possible Visual Modification';
      overallSeverity = 'MEDIUM';
      overallConfidence = 74;
      summary = 'Detected localized visual or metadata anomalies (such as an off-center overlay, excessive logo coverage, or format-copy discrepancy). Inspect physically for sticker overlays or tampering.';
    } else if (hasQualityDegrad) {
      overallStatus = 'IMAGE_QUALITY_DEGRADATION';
      overallLabel = 'Image Quality Degradation';
      overallSeverity = 'LOW';
      overallConfidence = 82;
      summary = 'Observed uniform image quality degradation (blur, low contrast, low resolution, or lossy compression artifacts) with structural QR patterns intact. No tampering indicators found.';
    } else if (hasDesignVar) {
      overallStatus = 'NORMAL_DESIGN_VARIATION';
      overallLabel = 'Normal Design Variation';
      overallSeverity = 'NONE';
      overallConfidence = 85;
      summary = 'Detected benign QR styling variation (such as a centered brand logo within error-correction capacity, custom colors, or inverted polarity) with structural integrity preserved.';
    }

    return {
      decodable: true,
      payload: payloadStr,
      byteLength: decoded.binaryData ? decoded.binaryData.length : utf8ToBytes(payloadStr).length,
      overallStatus,
      overallLabel,
      severity: overallSeverity,
      confidence: overallConfidence,
      summary,
      provenance: {
        decoderProvided: [
          'version',
          'payload',
          'byteLength',
          'finderPatternCenters',
          'alignmentCornerPoint'
        ],
        extractedFromMatrix: [
          'dimensions',
          'errorCorrectionLevel',
          'maskPattern',
          'formatInformation',
          'versionInformation',
          'finderIntegrity',
          'alignmentIntegrity',
          'timingIntegrity',
          'moduleDistribution',
          'structuralFingerprint'
        ],
        estimatedVisual: [
          'quietZoneModules',
          'logoOverlayCoverage',
          'sharpnessScore',
          'contrastScore',
          'jpegBlockinessRatio'
        ]
      },
      structure: {
        version,
        dimensions: `${dim}x${dim}`,
        moduleCountPerSide: dim,
        totalModules,
        pixelsPerModule,
        isInverted,
        errorCorrectionLevel: formatInfo.errorCorrectionLevel,
        errorCorrectionName: formatInfo.errorCorrectionName,
        maskPattern: formatInfo.maskPattern,
        formatInfo,
        versionInfo,
        finderPatterns: {
          overallIntegrityPct: finderOverallPct,
          topLeft: finderTL,
          topRight: finderTR,
          bottomLeft: finderBL,
          decoderCenters: {
            topLeft: loc.topLeftFinderPattern,
            topRight: loc.topRightFinderPattern,
            bottomLeft: loc.bottomLeftFinderPattern
          }
        },
        alignmentPatterns: alignmentInfo,
        timingPatterns: timingInfo,
        quietZone,
        moduleDistribution: {
          darkModules: darkCount,
          lightModules: totalModules - darkCount,
          darkPct: Number(((darkCount / totalModules) * 100).toFixed(1)),
          lightPct: Number((((totalModules - darkCount) / totalModules) * 100).toFixed(1)),
          lowContrastModules: lowContrastModuleCount
        },
        logoAndOverlay: {
          isUniformColorStyledQR,
          hasCenteredLogo,
          hasOffCenterOverlay,
          estimatedCoveragePct: effectiveOverlayPct,
          centerRegionCoveragePct: centerOverlayPct,
          outerRegionCoveragePct: outerOverlayPct
        }
      },
      visualQuality: {
        width: visual.width,
        height: visual.height,
        sharpnessScore: visual.sharpnessScore,
        contrastScore: visual.contrastScore,
        laplacianVariance: visual.laplacianVariance,
        blockinessRatio: visual.blockinessRatio,
        isColored: visual.isColored,
        decodedViaContrastStretch
      },
      fingerprints: {
        payloadFingerprint,
        structuralFingerprint,
        unmaskedStructureFingerprint,
        descriptor: canonicalPayloadDescriptor,
        trustNotice: 'Fingerprints verify payload and structural equivalence only. A matching fingerprint does NOT prove that the encoded URL or sender is trustworthy.'
      },
      findings,
      matrix: Array.from(matrix),
      heatmap: {
        dimension: dim,
        scores: Array.from(heatmapScores)
      }
    };
  }

  function buildInsufficientEvidenceReport(visual, reason, candidateFinders = 0) {
    const findings = [];
    let overallStatus = 'UNKNOWN';
    let overallLabel = 'Insufficient Evidence (Unknown)';
    let severity = 'UNKNOWN';
    let confidence = 30;

    if (candidateFinders >= 1) {
      overallStatus = 'CONFIRMED_STRUCTURAL_DAMAGE';
      overallLabel = 'Severely Damaged / Unreadable QR';
      severity = 'HIGH';
      confidence = 75;
      findings.push({
        code: 'UNDECODABLE_DAMAGED_QR',
        classification: 'CONFIRMED_STRUCTURAL_DAMAGE',
        severity: 'HIGH',
        confidence: 75,
        evidence: reason,
        explanation: 'Partial finder geometry was observed, but damage or distortion prevented full ISO/IEC 18004 decoding and matrix extraction.'
      });
    } else {
      findings.push({
        code: 'INSUFFICIENT_EVIDENCE',
        classification: 'INSUFFICIENT_EVIDENCE',
        severity: 'UNKNOWN',
        confidence: 25,
        evidence: reason,
        explanation: 'Unable to locate and decode a valid QR matrix. Structural properties cannot be reliably extracted.'
      });
    }

    return {
      decodable: false,
      payload: null,
      byteLength: 0,
      overallStatus,
      overallLabel,
      severity,
      confidence,
      summary: `${reason} Structural properties are unavailable without a valid decoded QR grid.`,
      provenance: {
        decoderProvided: [],
        extractedFromMatrix: [],
        estimatedVisual: visual ? ['sharpnessScore', 'contrastScore', 'jpegBlockinessRatio'] : []
      },
      structure: null,
      visualQuality: visual ? {
        width: visual.width,
        height: visual.height,
        sharpnessScore: visual.sharpnessScore,
        contrastScore: visual.contrastScore,
        laplacianVariance: visual.laplacianVariance,
        blockinessRatio: visual.blockinessRatio,
        isColored: visual.isColored,
        decodedViaContrastStretch: false
      } : null,
      fingerprints: {
        payloadFingerprint: null,
        structuralFingerprint: null,
        unmaskedStructureFingerprint: null,
        descriptor: 'UNAVAILABLE',
        trustNotice: 'Fingerprints cannot be computed when the QR code cannot be decoded.'
      },
      findings,
      matrix: null,
      heatmap: null
    };
  }

  // ── 7. QR Replacement & Side-by-Side Comparison ──────────────────────────
  function compareQRs(imageA, imageB) {
    const reportA = analyzeImage(imageA);
    const reportB = analyzeImage(imageB);

    if (!reportA.decodable || !reportB.decodable) {
      return {
        comparable: false,
        reportA,
        reportB,
        payloadComparison: {
          status: 'UNAVAILABLE',
          identical: null,
          fingerprintA: reportA.fingerprints.payloadFingerprint,
          fingerprintB: reportB.fingerprints.payloadFingerprint
        },
        metadataComparison: null,
        matrixDiff: null,
        verdict: 'INSUFFICIENT_EVIDENCE',
        summary: !reportA.decodable && !reportB.decodable
          ? 'Neither QR image could be decoded. Insufficient evidence to perform structural comparison.'
          : 'One of the two QR images could not be decoded (severely damaged or malformed), preventing complete matrix comparison.'
      };
    }

    const samePayload = reportA.payload === reportB.payload;
    const sameVersion = reportA.structure.version === reportB.structure.version;
    const sameEC = reportA.structure.errorCorrectionLevel === reportB.structure.errorCorrectionLevel;
    const sameMask = reportA.structure.maskPattern === reportB.structure.maskPattern;
    const sameDim = reportA.structure.moduleCountPerSide === reportB.structure.moduleCountPerSide;

    let matrixDiff = null;
    if (sameDim && reportA.matrix && reportB.matrix) {
      const dim = reportA.structure.moduleCountPerSide;
      const fnMask = buildFunctionPatternMask(reportA.structure.version, dim);
      const totalModules = dim * dim;
      const diffGrid = new Uint8Array(totalModules); // 0=same, 1=data/ECC diff, 2=structural/function diff
      let changedCount = 0;
      let structuralChanges = 0;
      let dataEccChanges = 0;

      for (let i = 0; i < totalModules; i++) {
        if (reportA.matrix[i] !== reportB.matrix[i]) {
          changedCount++;
          if (fnMask[i] === 1) {
            structuralChanges++;
            diffGrid[i] = 2;
          } else {
            dataEccChanges++;
            diffGrid[i] = 1;
          }
        }
      }

      matrixDiff = {
        aligned: true,
        dimension: dim,
        totalModules,
        changedModuleCount: changedCount,
        differencePercentage: Number(((changedCount / totalModules) * 100).toFixed(2)),
        structuralChanges,
        dataEccChanges,
        diffGrid: Array.from(diffGrid)
      };
    } else {
      matrixDiff = {
        aligned: false,
        reason: `Dimension mismatch (${reportA.structure.dimensions} vs ${reportB.structure.dimensions}). Direct 1:1 module alignment requires identical QR versions.`
      };
    }

    // Determine forensic comparison verdict
    let verdict = 'IDENTICAL_STRUCTURE_AND_PAYLOAD';
    let summary = '';

    if (!samePayload) {
      verdict = 'PAYLOAD_REPLACEMENT_DETECTED';
      summary = `ALERT — Different Payloads: Image A and Image B decode to DIFFERENT payloads (Payload SHA-256 mismatch). ${matrixDiff.aligned ? `${matrixDiff.changedModuleCount} of ${matrixDiff.totalModules} modules (${matrixDiff.differencePercentage}%) differ.` : matrixDiff.reason} This indicates a QR replacement or different QR target.`;
    } else if (reportA.fingerprints.structuralFingerprint === reportB.fingerprints.structuralFingerprint) {
      verdict = 'IDENTICAL_STRUCTURE_AND_PAYLOAD';
      summary = `Identical Payload & Canonical Structure: Both QR codes encode the exact same payload and share an identical normalized ${reportA.structure.dimensions} matrix (any visual differences are due to scaling, rotation, color, or image compression).`;
    } else if (!sameVersion || !sameEC || !sameMask) {
      const diffs = [];
      if (!sameVersion) diffs.push(`Version (V${reportA.structure.version} vs V${reportB.structure.version})`);
      if (!sameEC) diffs.push(`Error Correction (${reportA.structure.errorCorrectionLevel} vs ${reportB.structure.errorCorrectionLevel})`);
      if (!sameMask) diffs.push(`Mask Pattern (${reportA.structure.maskPattern} vs ${reportB.structure.maskPattern})`);
      verdict = 'SAME_PAYLOAD_DIFFERENT_ENCODING';
      summary = `Same Payload, Different QR Encoding: Both images encode the identical payload (SHA-256 match), but their visual matrices differ due to ${diffs.join(', ')}.`;
    } else {
      verdict = 'SAME_PAYLOAD_MINOR_MATRIX_VARIANCE';
      summary = `Same Payload with Localized Module Differences: Both images encode the identical payload with V${reportA.structure.version} / EC-${reportA.structure.errorCorrectionLevel} / Mask-${reportA.structure.maskPattern}, yet ${matrixDiff.changedModuleCount} module(s) (${matrixDiff.differencePercentage}%) differ (e.g., due to logo overlay, styling, or ECC noise tolerated by Reed-Solomon).`;
    }

    return {
      comparable: true,
      reportA,
      reportB,
      payloadComparison: {
        status: samePayload ? 'IDENTICAL' : 'DIFFERENT',
        identical: samePayload,
        fingerprintA: reportA.fingerprints.payloadFingerprint,
        fingerprintB: reportB.fingerprints.payloadFingerprint
      },
      metadataComparison: {
        versionMatch: sameVersion,
        versionA: reportA.structure.version,
        versionB: reportB.structure.version,
        ecMatch: sameEC,
        ecA: reportA.structure.errorCorrectionLevel,
        ecB: reportB.structure.errorCorrectionLevel,
        maskMatch: sameMask,
        maskA: reportA.structure.maskPattern,
        maskB: reportB.structure.maskPattern,
        structuralFingerprintMatch: reportA.fingerprints.structuralFingerprint === reportB.fingerprints.structuralFingerprint,
        unmaskedFingerprintMatch: Boolean(
          reportA.fingerprints.unmaskedStructureFingerprint &&
          reportA.fingerprints.unmaskedStructureFingerprint === reportB.fingerprints.unmaskedStructureFingerprint
        )
      },
      matrixDiff,
      verdict,
      summary
    };
  }

  return {
    analyzeImage,
    compareQRs,
    sha256Hex,
    decodeFormatInfoFromMatrix,
    computeQuadTransform
  };
});
