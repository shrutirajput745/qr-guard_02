const { execSync } = require('child_process');
const path = require('path');

console.log('=====================================================');
console.log('   QR GUIDE 2 - COMPLETE AUTOMATION TEST SUITE       ');
console.log('=====================================================\n');

try {
  console.log('▶ [1/3] Running Heuristic Analyzer Unit Tests...');
  const unitTestPath = path.join(__dirname, 'unit-tests.js');
  execSync(`node "${unitTestPath}"`, { stdio: 'inherit' });

  console.log('\n▶ [2/3] Running QR Blur Recovery & Demo Tests...');
  const recoveryTestPath = path.join(__dirname, 'recovery-tests.js');
  execSync(`node "${recoveryTestPath}"`, { stdio: 'inherit' });

  console.log('\n▶ [3/5] Running QR Trust Fingerprint & Visual Integrity Tests...');
  const integrityTestPath = path.join(__dirname, 'integrity-tests.js');
  execSync(`node "${integrityTestPath}"`, { stdio: 'inherit' });

  console.log('\n▶ [4/5] Running QR Behavior Sandbox Tests...');
  const sandboxTestPath = path.join(__dirname, 'sandbox-tests.js');
  execSync(`node "${sandboxTestPath}"`, { stdio: 'inherit' });

  console.log('\n▶ [5/6] Running DOM Integrity & UI Structure Tests...');
  const uiTestPath = path.join(__dirname, 'ui-tests.js');
  execSync(`node "${uiTestPath}"`, { stdio: 'inherit' });

  console.log('\n▶ [6/6] Running Backend API & Server Integration Tests...');
  const apiTestPath = path.join(__dirname, 'api-tests.js');
  execSync(`node "${apiTestPath}"`, { stdio: 'inherit' });

  console.log('=====================================================');
  console.log('  🎉 ALL AUTOMATION TESTS PASSED SUCCESSFULLY!        ');
  console.log('=====================================================');
  process.exit(0);
} catch (error) {
  console.error('\n❌ Test suite failed with error:', error.message);
  process.exit(1);
}
