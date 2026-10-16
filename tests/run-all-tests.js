const { execSync } = require('child_process');
const path = require('path');

console.log('=====================================================');
console.log('   QR GUIDE 2 - COMPLETE AUTOMATION TEST SUITE       ');
console.log('=====================================================\n');

try {
  console.log('▶ [1/2] Running Heuristic Analyzer Unit Tests...');
  const unitTestPath = path.join(__dirname, 'unit-tests.js');
  execSync(`node "${unitTestPath}"`, { stdio: 'inherit' });

  console.log('▶ [2/2] Running Backend API & Server Integration Tests...');
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
