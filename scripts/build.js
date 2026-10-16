const fs = require('fs');
const path = require('path');
const vm = require('vm');

console.log('=====================================================');
console.log('   QR GUIDE 2 - PRODUCTION BUILD & VALIDATION       ');
console.log('=====================================================\n');

let errors = 0;

function checkFileExists(relPath) {
  const fullPath = path.join(__dirname, '..', relPath);
  if (!fs.existsSync(fullPath)) {
    console.error(`  ✖ Missing critical file: ${relPath}`);
    errors++;
    return null;
  }
  const stats = fs.statSync(fullPath);
  console.log(`  ✔ Verified: ${relPath} (${stats.size} bytes)`);
  return fullPath;
}

function checkJsSyntax(relPath) {
  const fullPath = path.join(__dirname, '..', relPath);
  try {
    const code = fs.readFileSync(fullPath, 'utf8');
    new vm.Script(code);
    console.log(`  ✔ JS Syntax Valid: ${relPath}`);
  } catch (err) {
    console.error(`  ✖ JS Syntax Error in ${relPath}:`, err.message);
    errors++;
  }
}

console.log('▶ [1/4] Checking Required Distribution Files...');
checkFileExists('public/index.html');
checkFileExists('public/css/style.css');
checkFileExists('public/js/analyzer.js');
checkFileExists('public/js/app.js');
checkFileExists('public/js/scanner.js');
checkFileExists('public/js/samples.js');
checkFileExists('api/analyze.js');
checkFileExists('api/health.js');
checkFileExists('server.js');
checkFileExists('vercel.json');

console.log('\n▶ [2/4] Validating JavaScript Code Integrity...');
checkJsSyntax('public/js/analyzer.js');
checkJsSyntax('public/js/app.js');
checkJsSyntax('public/js/scanner.js');
checkJsSyntax('public/js/samples.js');
checkJsSyntax('api/analyze.js');
checkJsSyntax('api/health.js');
checkJsSyntax('server.js');

console.log('\n▶ [3/4] Validating HTML Structure & Security Meta...');
try {
  const htmlPath = path.join(__dirname, '..', 'public/index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');

  if (!html.includes('<title>')) {
    console.error('  ✖ Missing <title> tag in index.html');
    errors++;
  } else {
    console.log('  ✔ Found descriptive <title>');
  }

  if (!html.includes('viewport')) {
    console.error('  ✖ Missing responsive viewport meta tag in index.html');
    errors++;
  } else {
    console.log('  ✔ Found responsive viewport meta tag');
  }

  if (!html.includes('toastContainer')) {
    console.error('  ✖ Missing toastContainer in index.html');
    errors++;
  } else {
    console.log('  ✔ Found notification toast container');
  }
} catch (e) {
  console.error('  ✖ Error checking index.html:', e.message);
  errors++;
}

console.log('\n▶ [4/4] Validating Vercel Serverless Handlers...');
try {
  const analyzeHandler = require('../api/analyze');
  const healthHandler = require('../api/health');

  if (typeof analyzeHandler !== 'function') {
    console.error('  ✖ api/analyze.js does not export a function handler');
    errors++;
  } else {
    console.log('  ✔ api/analyze.js exports valid serverless handler');
  }

  if (typeof healthHandler !== 'function') {
    console.error('  ✖ api/health.js does not export a function handler');
    errors++;
  } else {
    console.log('  ✔ api/health.js exports valid serverless handler');
  }
} catch (err) {
  console.error('  ✖ Failed to load serverless handlers:', err.message);
  errors++;
}

console.log('\n=====================================================');
if (errors > 0) {
  console.error(`❌ Build failed with ${errors} error(s).`);
  process.exit(1);
} else {
  console.log('🎉 Production build verification succeeded! Ready for Vercel.');
  console.log('=====================================================\n');
  process.exit(0);
}
