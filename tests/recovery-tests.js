const fs = require('fs');
const path = require('path');
const { PNG } = require('pngjs');
const jsQR = require('jsqr');
const QRRecovery = require('../public/js/recovery');

console.log('=== QR GUARD 2.0: BLUR RECOVERY & DEMO TEST SUITE ===');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✔ [PASS] ${message}`);
    passed++;
  } else {
    console.error(`  ✖ [FAIL] ${message}`);
    failed++;
  }
}

async function runRecoveryTests() {
  const demoDir = path.join(__dirname, '..', 'public', 'images', 'demo');

  // 1. Check Demo Assets Existence
  const files = ['demo-normal.png', 'demo-lowcontrast.png', 'demo-blurry.png', 'demo-corrupted.png'];
  for (const f of files) {
    const fullPath = path.join(demoDir, f);
    assert(fs.existsSync(fullPath), `Demo image asset exists: ${f}`);
  }

  // Helper to load PNG pixel data
  function loadPng(filename) {
    const filePath = path.join(demoDir, filename);
    const buf = fs.readFileSync(filePath);
    const png = PNG.sync.read(buf);
    return { data: png.data, width: png.width, height: png.height };
  }

  // 2. Test Quality Estimation
  const normalImg = loadPng('demo-normal.png');
  const normalQuality = QRRecovery.estimateImageQualityFromData(normalImg.data, normalImg.width, normalImg.height);
  assert(normalQuality.blurScore > 0, `Normal QR blur score is positive: ${normalQuality.blurScore}/100`);
  assert(normalQuality.contrast > 0, `Normal QR contrast is positive: ${normalQuality.contrast}/100`);
  assert(normalQuality.qualityLabel === 'Good Quality', `Normal QR classified as Good Quality`);

  const blurImg = loadPng('demo-blurry.png');
  const blurQuality = QRRecovery.estimateImageQualityFromData(blurImg.data, blurImg.width, blurImg.height);
  assert(blurQuality.blurScore < normalQuality.blurScore, `Blurry QR has lower sharpness index (${blurQuality.blurScore}) than normal (${normalQuality.blurScore})`);

  // 3. Test Transformation Functions
  const grayData = QRRecovery.processGrayscale(normalImg.data, normalImg.width, normalImg.height);
  assert(grayData.length === normalImg.data.length, 'Grayscale produces matching data length');

  const stretchedData = QRRecovery.processContrastStretch(grayData, normalImg.width, normalImg.height);
  assert(stretchedData.length === grayData.length, 'Contrast stretch produces matching data length');

  const sharpData = QRRecovery.processSharpen(stretchedData, normalImg.width, normalImg.height);
  assert(sharpData.length === grayData.length, 'Sharpen produces matching data length');

  const otsuData = QRRecovery.processOtsuThreshold(sharpData, normalImg.width, normalImg.height);
  assert(otsuData.length === grayData.length, 'Otsu threshold produces matching data length');

  // 4. Test Demo 1: Normal QR Pipeline
  console.log('\n▶ Testing Demo 1: Normal QR (Direct Scan Expected)');
  const res1 = await QRRecovery.recoverFromPixelData(normalImg.data, normalImg.width, normalImg.height);
  assert(res1.success === true, 'Normal QR recovery succeeded');
  assert(res1.text === 'https://wikipedia.org', `Normal QR payload matches: ${res1.text}`);
  assert(res1.method.includes('Original Image'), `Normal QR decoded directly without unnecessary degradation`);

  // 5. Test Demo 2: Low-Contrast QR Pipeline
  console.log('\n▶ Testing Demo 2: Low-Contrast QR (Recovery Required)');
  const lowImg = loadPng('demo-lowcontrast.png');
  const directLow = jsQR(new Uint8ClampedArray(lowImg.data), lowImg.width, lowImg.height);
  assert(!directLow, 'Low-contrast QR fails unenhanced direct decode as expected');

  const res2 = await QRRecovery.recoverFromPixelData(lowImg.data, lowImg.width, lowImg.height);
  assert(res2.success === true, 'Low-contrast QR successfully recovered by pipeline');
  assert(res2.text === 'WIFI:S:SecureOffice;T:WPA;P:OfficePass2026;;', `Low-contrast QR payload matches: ${res2.text}`);
  assert(res2.method.includes('Contrast'), `Effective technique is Contrast Enhancement: ${res2.method}`);

  // 6. Test Demo 3: Blurry QR Pipeline
  console.log('\n▶ Testing Demo 3: Blurry QR (Sharpening / Threshold Recovery Required)');
  const directBlur = jsQR(new Uint8ClampedArray(blurImg.data), blurImg.width, blurImg.height);
  assert(!directBlur, 'Blurry QR fails unenhanced direct decode as expected');

  const res3 = await QRRecovery.recoverFromPixelData(blurImg.data, blurImg.width, blurImg.height);
  assert(res3.success === true, 'Blurry QR successfully recovered by pipeline');
  assert(res3.text === 'https://github.com/shrutirajput745/qr-guard_02', `Blurry QR payload matches: ${res3.text}`);

  // 7. Test Demo 4: Severely Corrupted QR Pipeline (Honest Reporting)
  console.log('\n▶ Testing Demo 4: Severely Corrupted QR (Honest Failure Expected)');
  const corrImg = loadPng('demo-corrupted.png');
  const res4 = await QRRecovery.recoverFromPixelData(corrImg.data, corrImg.width, corrImg.height);
  assert(res4.success === false, 'Severely corrupted QR honestly reported as recovery failure');
  assert(!res4.text, 'No fabricated payload returned on corrupted QR');

  console.log('\n=====================================================');
  console.log(`Recovery Test Results: ${passed} Passed, ${failed} Failed out of ${passed + failed} Tests`);
  console.log('=====================================================');

  if (failed > 0) process.exit(1);
}

runRecoveryTests().catch(e => {
  console.error('Test execution error:', e);
  process.exit(1);
});
