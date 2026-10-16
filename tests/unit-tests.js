const QRAnalyzer = require('../public/js/analyzer');

const testCases = [
  // 1. Boundary & Null checks
  { name: 'Empty string', input: '', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Whitespace string', input: '   ', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Null input', input: null, expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Undefined input', input: undefined, expectStatus: 'Dangerous', expectScore: 100 },

  // 2. Safe Web URLs
  { name: 'Official Wikipedia (Safe HTTPS)', input: 'https://wikipedia.org', expectStatus: 'Safe', expectScore: 0, isUrl: true },
  { name: 'GitHub Root (Safe HTTPS)', input: 'https://github.com', expectStatus: 'Safe', expectScore: 0, isUrl: true },
  { name: 'Google Search (Safe HTTPS)', input: 'https://google.com/search?q=qr+code', expectStatus: 'Safe', expectScore: 0, isUrl: true },

  // 3. Legitimate Accounts / Login URLs (Testing False Positive Fixes)
  { name: 'Google Accounts Sign-in', input: 'https://accounts.google.com/signin', expectStatus: 'Safe', maxScore: 29 },
  { name: 'Microsoft Login', input: 'https://login.microsoft.com', expectStatus: 'Safe', maxScore: 29 },
  { name: 'Target Homepage (t.co substring test)', input: 'https://target.com', expectStatus: 'Safe', expectScore: 0 },
  { name: 'Reddit Homepage (t.co substring test)', input: 'https://reddit.com', expectStatus: 'Safe', expectScore: 0 },
  { name: 'Pinterest (t.co substring test)', input: 'https://pinterest.com', expectStatus: 'Safe', expectScore: 0 },

  // 4. Insecure & Suspicious URLs
  { name: 'Plain HTTP Wikipedia', input: 'http://wikipedia.org', expectStatus: 'Safe', expectScore: 20 },
  { name: 'Bitly shortener over HTTP', input: 'http://bit.ly/security-test-381', expectStatus: 'Suspicious', minScore: 30, maxScore: 69 },
  { name: 'High-risk .TOP domain over HTTP', input: 'http://docs-portal.top', expectStatus: 'Suspicious', minScore: 30 },
  { name: 'Double slash open-redirect', input: 'http://example.com//open-redirect', minScore: 30 },
  { name: 'Heavy percent encoding', input: 'http://example.com/%25%25%25%25test', minScore: 30 },

  // 5. Dangerous / Phishing URLs
  { name: 'Phishing: Free reward claim on .TOP with login', input: 'http://free-reward-claim.top/login', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Phishing: Raw IP address login', input: 'http://192.168.1.150/login.php', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Phishing: Paypal brand impersonation on fake domain', input: 'http://paypal.com.account-verify.top/login', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Phishing: @ symbol redirection trick', input: 'http://192.168.1.50/paypal.com/verify-account@login.php', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Subdomain trick with excessive subdomains', input: 'http://security.update.verify.bank.fake-portal.com', minScore: 25 },
  { name: 'Hyphen-heavy domain', input: 'http://secure-login-verify-account-portal.com', minScore: 30 },

  // 6. Dangerous Schemes & Injection
  { name: 'Javascript pseudo-protocol', input: 'javascript:alert(1)', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Data URI script', input: 'data:text/html,<script>alert(1)</script>', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'File URI local traversal', input: 'file:///etc/passwd', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Script tag in payload', input: '<script>window.location="http://evil.com"</script>', expectStatus: 'Dangerous', minScore: 90 },
  { name: 'Shell command execution', input: 'cmd.exe /c start calc.exe', expectStatus: 'Dangerous', minScore: 90 },

  // 7. Non-URL Payloads (Safe)
  { name: 'Wi-Fi QR configuration', input: 'WIFI:S:CampusWiFi;T:WPA;P:Secured123;;', expectStatus: 'Safe', isUrl: false },
  { name: 'Telephone action link', input: 'tel:+18005550199', expectStatus: 'Safe', isUrl: false },
  { name: 'Mailto action link', input: 'mailto:support@example.com', expectStatus: 'Safe', isUrl: false },
  { name: 'Plain text greeting', input: 'Welcome to the 2026 Cybersecurity Symposium!', expectStatus: 'Safe', isUrl: false, expectScore: 0 }
];

console.log('=== QR GUIDE 2: AUTOMATED UNIT TEST SUITE ===');
let passed = 0;
let failed = 0;
const failures = [];

testCases.forEach((tc) => {
  try {
    const res = QRAnalyzer.analyze(tc.input);
    let ok = true;
    const errors = [];

    if (tc.expectStatus && res.status !== tc.expectStatus) {
      ok = false;
      errors.push(`Status mismatch: expected '${tc.expectStatus}', got '${res.status}'`);
    }
    if (tc.expectScore !== undefined && res.score !== tc.expectScore) {
      ok = false;
      errors.push(`Score mismatch: expected ${tc.expectScore}, got ${res.score}`);
    }
    if (tc.minScore !== undefined && res.score < tc.minScore) {
      ok = false;
      errors.push(`Score too low: expected >= ${tc.minScore}, got ${res.score}`);
    }
    if (tc.maxScore !== undefined && res.score > tc.maxScore) {
      ok = false;
      errors.push(`Score too high: expected <= ${tc.maxScore}, got ${res.score}`);
    }
    if (tc.isUrl !== undefined && res.isUrl !== tc.isUrl) {
      ok = false;
      errors.push(`isUrl mismatch: expected ${tc.isUrl}, got ${res.isUrl}`);
    }

    if (ok) {
      passed++;
      console.log(`  ✔ [PASS] ${tc.name} => Score: ${res.score}/100, Status: ${res.status}`);
    } else {
      failed++;
      console.log(`  ✖ [FAIL] ${tc.name} => Score: ${res.score}/100, Status: ${res.status}`);
      errors.forEach(e => console.log(`     └─ ${e}`));
      failures.push({ name: tc.name, input: tc.input, result: res, errors });
    }
  } catch (err) {
    failed++;
    console.log(`  ✖ [ERROR] ${tc.name} threw exception: ${err.message}`);
    failures.push({ name: tc.name, input: tc.input, error: err.message });
  }
});

console.log(`\nUnit Test Results: ${passed} Passed, ${failed} Failed out of ${testCases.length} Tests\n`);

if (failed > 0) {
  process.exit(1);
}
