const fs = require('fs');
const path = require('path');

console.log('=== QR GUARD: DOM INTEGRITY & UI STRUCTURE TEST SUITE ===\n');

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

const publicDir = path.join(__dirname, '..', 'public');
const html = fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8');

// 1. Check for duplicate IDs in index.html
const idMatches = [...html.matchAll(/\bid=["']([^"']+)["']/g)].map(m => m[1]);
const idCounts = {};
idMatches.forEach(id => { idCounts[id] = (idCounts[id] || 0) + 1; });
const duplicates = Object.entries(idCounts).filter(([, cnt]) => cnt > 1).map(([id]) => id);
assert(duplicates.length === 0, `No duplicate HTML IDs in index.html (${duplicates.length} found${duplicates.length ? ': ' + duplicates.join(', ') : ''})`);

// 2. Check all 9 navigation buttons have matching page-content sections
const navPages = [...html.matchAll(/class="page-nav-btn[^"]*"[^>]*data-page="([^"]+)"/g)].map(m => m[1]);
assert(navPages.length === 9, `All 9 navigation sections present in sidebar (${navPages.join(', ')})`);
navPages.forEach(page => {
  assert(idCounts[`page-${page}`] === 1, `Page container #page-${page} exists`);
});

// 3. Verify all local <link href="css/..."> and <script src="js/..."> files exist
const localLinks = [...html.matchAll(/(?:href|src)=["']((?:css|js)\/[^"']+)["']/g)].map(m => m[1]);
localLinks.forEach(rel => {
  const full = path.join(publicDir, rel);
  assert(fs.existsSync(full), `Referenced local asset exists: public/${rel}`);
});

// 4. Verify all static getElementById references in app/module JS files exist in index.html
const jsFiles = [
  'app.js', 'scanner.js', 'samples.js', 'history.js',
  'threat-intel.js', 'integrity-lab.js', 'sandbox-ui.js',
  'recovery.js', 'demo.js', 'architecture.js', 'presentation.js'
];
const dynamicallyCreatedIds = new Set(['recoveryAnalyzeBtn', 'archPrevStepBtn', 'archNextStepBtnCard', 'ilCompareHeatmapCanvas']);
const missingIds = [];

jsFiles.forEach(file => {
  const code = fs.readFileSync(path.join(publicDir, 'js', file), 'utf8');
  const refs = [...code.matchAll(/document\.getElementById\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)/g)].map(m => m[1]);
  refs.forEach(id => {
    if (!idCounts[id] && !dynamicallyCreatedIds.has(id)) {
      missingIds.push(`${file}:#${id}`);
    }
  });
});
assert(missingIds.length === 0, `All static getElementById targets exist in index.html (${missingIds.length} missing${missingIds.length ? ': ' + missingIds.join(', ') : ''})`);

// 5. Verify SOC shell, status strip, settings modal, and reduced-motion styles exist
assert(idCounts['socShell'] === 1 && idCounts['socSidebar'] === 1 && idCounts['socSettingsModal'] === 1, 'SOC shell, sidebar, and settings modal IDs present');
const socCss = fs.readFileSync(path.join(publicDir, 'css', 'soc-theme.css'), 'utf8');
assert(socCss.includes('prefers-reduced-motion'), 'soc-theme.css includes prefers-reduced-motion accessibility support');

// 6. Verify security hardening across frontend files
const targetBlankLinks = [...html.matchAll(/<a\b[^>]*target=["']_blank["'][^>]*>/gi)].map(m => m[0]);
const unsafeTargets = targetBlankLinks.filter(tag => !/rel=["'][^"']*noopener/i.test(tag));
assert(unsafeTargets.length === 0, 'All target="_blank" links include rel="noopener"');

const historyCode = fs.readFileSync(path.join(publicDir, 'js', 'history.js'), 'utf8');
assert(historyCode.includes('[?&]am=') && historyCode.includes('sanitizeCsvCell'), 'history.js masks ?am=/&am= and neutralizes CSV formulas');

const presCode = fs.readFileSync(path.join(publicDir, 'js', 'presentation.js'), 'utf8');
assert(!presCode.includes("e.key === 'Space'"), 'presentation.js handles standard space key (" ") rather than "Space"');

console.log(`\nUI Structure Test Results: ${passed} Passed, ${failed} Failed out of ${passed + failed} Tests\n`);
if (failed > 0) process.exit(1);
