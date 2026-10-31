const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');
const { PNG } = require('pngjs');
const jsQR = require('jsqr');

const demoDir = path.join(__dirname, '..', 'public', 'images', 'demo');
if (!fs.existsSync(demoDir)) {
  fs.mkdirSync(demoDir, { recursive: true });
}

async function generateDemos() {
  console.log('Generating demo QR images in public/images/demo/ ...');

  // 1. Normal Clean QR
  const normalPath = path.join(demoDir, 'demo-normal.png');
  const normalPayload = 'https://wikipedia.org';
  await QRCode.toFile(normalPath, normalPayload, { width: 320, margin: 2 });
  console.log('✔ Created demo-normal.png (Payload:', normalPayload, ')');

  // 2. Low-Contrast Faint QR (Direct decode fails, contrast stretch succeeds)
  const lowContrastPath = path.join(demoDir, 'demo-lowcontrast.png');
  const lowContrastPayload = 'WIFI:S:SecureOffice;T:WPA;P:OfficePass2026;;';
  await QRCode.toFile(lowContrastPath, lowContrastPayload, {
    width: 320,
    margin: 2,
    color: { dark: '#929292', light: '#b6b6b6' }
  });
  console.log('✔ Created demo-lowcontrast.png (Payload:', lowContrastPayload, ')');

  // 3. Blurry QR (Direct decode fails, threshold recovery succeeds)
  const tempBlurryPath = path.join(demoDir, 'temp-blurry.png');
  const blurryPath = path.join(demoDir, 'demo-blurry.png');
  const blurryPayload = 'https://github.com/shrutirajput745/qr-guard_02';
  await QRCode.toFile(tempBlurryPath, blurryPayload, { width: 320, margin: 2 });

  const data = fs.readFileSync(tempBlurryPath);
  const png = PNG.sync.read(data);
  const w = png.width;
  const h = png.height;
  const blurredPng = new PNG({ width: w, height: h });

  const src = Buffer.from(png.data);
  const tmp = Buffer.from(png.data);
  const radius = 5; // Validated threshold

  // Horizontal blur pass
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      let r = 0, count = 0;
      for (let kx = -radius; kx <= radius; kx++) {
        const px = Math.min(w - 1, Math.max(0, x + kx));
        r += src[(y * w + px) * 4];
        count++;
      }
      tmp[(y * w + x) * 4] = Math.round(r / count);
    }
  }

  // Vertical blur pass
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      let r = 0, count = 0;
      for (let ky = -radius; ky <= radius; ky++) {
        const py = Math.min(h - 1, Math.max(0, y + ky));
        r += tmp[(py * w + x) * 4];
        count++;
      }
      const val = Math.round(r / count);
      const outIdx = (y * w + x) * 4;
      blurredPng.data[outIdx] = val;
      blurredPng.data[outIdx + 1] = val;
      blurredPng.data[outIdx + 2] = val;
      blurredPng.data[outIdx + 3] = 255;
    }
  }

  fs.writeFileSync(blurryPath, PNG.sync.write(blurredPng));
  if (fs.existsSync(tempBlurryPath)) fs.unlinkSync(tempBlurryPath);
  console.log('✔ Created demo-blurry.png (Payload:', blurryPayload, ')');

  // 4. Severely Corrupted QR (Unrecoverable — validates honest reporting)
  const corruptedPath = path.join(demoDir, 'demo-corrupted.png');
  const tempCorrPath = path.join(demoDir, 'temp-corr.png');
  await QRCode.toFile(tempCorrPath, 'https://example.com/unreadable', { width: 320, margin: 2 });
  const corrPng = PNG.sync.read(fs.readFileSync(tempCorrPath));
  for (let y = 0; y < corrPng.height; y++) {
    for (let x = 0; x < corrPng.width; x++) {
      const idx = (y * corrPng.width + x) * 4;
      if ((x > 20 && x < 180 && y > 20 && y < 180) || (x > 140 && y > 140) || Math.random() < 0.4) {
        const val = Math.random() < 0.5 ? 245 : 10;
        corrPng.data[idx] = val;
        corrPng.data[idx + 1] = val;
        corrPng.data[idx + 2] = val;
      }
    }
  }
  fs.writeFileSync(corruptedPath, PNG.sync.write(corrPng));
  if (fs.existsSync(tempCorrPath)) fs.unlinkSync(tempCorrPath);
  console.log('✔ Created demo-corrupted.png (Heavily destroyed, tests honest failure)');

  // Validate demos with jsQR
  const normalImg = PNG.sync.read(fs.readFileSync(normalPath));
  const normalDec = jsQR(new Uint8ClampedArray(normalImg.data), normalImg.width, normalImg.height);
  console.log('1. Normal direct decode:', normalDec ? normalDec.data : 'FAILED');

  const lowImg = PNG.sync.read(fs.readFileSync(lowContrastPath));
  const lowDec = jsQR(new Uint8ClampedArray(lowImg.data), lowImg.width, lowImg.height);
  console.log('2. Low-contrast direct decode (should be null):', lowDec ? lowDec.data : 'FAILED_AS_EXPECTED');

  const blurImg = PNG.sync.read(fs.readFileSync(blurryPath));
  const blurDec = jsQR(new Uint8ClampedArray(blurImg.data), blurImg.width, blurImg.height);
  console.log('3. Blurry direct decode (should be null):', blurDec ? blurDec.data : 'FAILED_AS_EXPECTED');
}

generateDemos().catch(err => {
  console.error('Error generating demos:', err);
  process.exit(1);
});
