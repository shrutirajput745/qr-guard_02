const QRAnalyzer = require('../public/js/analyzer');

const testCases = [
  // ── 1. Boundary & Null checks ─────────────────────────────────────────
  { name: 'Empty string', input: '', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Whitespace string', input: '   ', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Null input', input: null, expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Undefined input', input: undefined, expectStatus: 'Dangerous', expectScore: 100 },

  // ── 2. Safe Web URLs ──────────────────────────────────────────────────
  { name: 'Official Wikipedia (Safe HTTPS)', input: 'https://wikipedia.org', expectStatus: 'Safe', expectScore: 0, isUrl: true },
  { name: 'GitHub Root (Safe HTTPS)', input: 'https://github.com', expectStatus: 'Safe', expectScore: 0, isUrl: true },
  { name: 'Google Search (Safe HTTPS)', input: 'https://google.com/search?q=qr+code', expectStatus: 'Safe', expectScore: 0, isUrl: true },

  // ── 3. Legitimate Accounts / Login URLs ───────────────────────────────
  { name: 'Google Accounts Sign-in', input: 'https://accounts.google.com/signin', expectStatus: 'Safe', maxScore: 29 },
  { name: 'Microsoft Login', input: 'https://login.microsoft.com', expectStatus: 'Safe', maxScore: 29 },
  { name: 'Target Homepage (t.co substring test)', input: 'https://target.com', expectStatus: 'Safe', expectScore: 0 },
  { name: 'Reddit Homepage (t.co substring test)', input: 'https://reddit.com', expectStatus: 'Safe', expectScore: 0 },
  { name: 'Pinterest (t.co substring test)', input: 'https://pinterest.com', expectStatus: 'Safe', expectScore: 0 },

  // ── 4. Insecure & Suspicious URLs ─────────────────────────────────────
  { name: 'Plain HTTP Wikipedia', input: 'http://wikipedia.org', expectStatus: 'Safe', expectScore: 20 },
  { name: 'Bitly shortener over HTTP', input: 'http://bit.ly/security-test-381', expectStatus: 'Suspicious', minScore: 30, maxScore: 69 },
  { name: 'High-risk .TOP domain over HTTP', input: 'http://docs-portal.top', expectStatus: 'Suspicious', minScore: 30 },
  { name: 'Double slash open-redirect', input: 'http://example.com//open-redirect', minScore: 30 },
  { name: 'Heavy percent encoding', input: 'http://example.com/%25%25%25%25test', minScore: 30 },

  // ── 5. Dangerous / Phishing URLs ──────────────────────────────────────
  { name: 'Phishing: Free reward claim on .TOP with login', input: 'http://free-reward-claim.top/login', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Phishing: Raw IP address login', input: 'http://192.168.1.150/login.php', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Phishing: Paypal brand impersonation on fake domain', input: 'http://paypal.com.account-verify.top/login', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Phishing: @ symbol redirection trick', input: 'http://192.168.1.50/paypal.com/verify-account@login.php', expectStatus: 'Dangerous', minScore: 70 },
  { name: 'Subdomain trick with excessive subdomains', input: 'http://security.update.verify.bank.fake-portal.com', minScore: 25 },
  { name: 'Hyphen-heavy domain', input: 'http://secure-login-verify-account-portal.com', minScore: 30 },

  // ── 6. Dangerous Schemes & Injection ──────────────────────────────────
  { name: 'Javascript pseudo-protocol', input: 'javascript:alert(1)', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Data URI script', input: 'data:text/html,<script>alert(1)</script>', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'File URI local traversal', input: 'file:///etc/passwd', expectStatus: 'Dangerous', expectScore: 100 },
  { name: 'Script tag in payload', input: '<script>window.location="http://evil.com"</script>', expectStatus: 'Dangerous', minScore: 90 },
  { name: 'Shell command execution', input: 'cmd.exe /c start calc.exe', expectStatus: 'Dangerous', minScore: 90 },

  // ── 7. Universal QR Types: Non-URL Payloads ───────────────────────────
  { name: 'Wi-Fi QR configuration', input: 'WIFI:S:CampusWiFi;T:WPA;P:Secured123;;', expectStatus: 'Safe', isUrl: false },
  { name: 'Telephone action link', input: 'tel:+18005550199', expectStatus: 'Safe', isUrl: false },
  { name: 'Mailto action link', input: 'mailto:support@example.com', expectStatus: 'Safe', isUrl: false },
  { name: 'SMS link', input: 'sms:+14155550199:Hello%20there', expectStatus: 'Safe', isUrl: false },
  { name: 'Geo location QR', input: 'geo:40.7128,-74.0060', expectStatus: 'Safe', isUrl: false },
  { name: 'Plain text greeting', input: 'Welcome to the 2026 Cybersecurity Symposium!', expectStatus: 'Safe', isUrl: false, expectScore: 0 },

  // ── 8. Universal QR Type Classification ──────────────────────────────
  { name: 'UPI Payment QR type classification',
    input: 'upi://pay?pa=merchant@upi&pn=Example+Shop&am=50&tn=Order123&cu=INR',
    expectQrType: 'upi' },
  { name: 'vCard QR type classification',
    input: 'BEGIN:VCARD\nFN:Jane Doe\nTEL:+91-9876543210\nEMAIL:jane@example.com\nORG:TechCorp\nEND:VCARD',
    expectQrType: 'vcard' },
  { name: 'Wi-Fi QR type classification', input: 'WIFI:S:TestNet;T:WPA;P:pass123;;', expectQrType: 'wifi' },
  { name: 'Email QR type classification', input: 'mailto:hello@example.com', expectQrType: 'email' },
  { name: 'Phone QR type classification', input: 'tel:+917890123456', expectQrType: 'phone' },
  { name: 'SMS QR type classification', input: 'sms:+16505551234:Test message', expectQrType: 'sms' },
  { name: 'Geo QR type classification', input: 'geo:37.7749,-122.4194', expectQrType: 'geo' },
  { name: 'Plain text QR type classification', input: 'Hello World', expectQrType: 'text' },
  { name: 'Website URL QR type classification', input: 'https://example.com', expectQrType: 'url' },
  { name: 'Google Play app link QR type classification',
    input: 'https://play.google.com/store/apps/details?id=com.example.app',
    expectQrType: 'applink' },
  { name: 'Instagram social media QR type classification',
    input: 'https://instagram.com/testuser',
    expectQrType: 'social' },
  { name: 'Dangerous scheme QR type classification',
    input: 'javascript:alert(1)', expectQrType: 'dangerous' },

  // ── 9. Edge Cases ─────────────────────────────────────────────────────
  { name: 'Very long URL (length indicator)', input: 'https://example.com/' + 'a'.repeat(100), minScore: 10 },
  { name: 'Non-standard port', input: 'http://example.com:8080/login', minScore: 30 },
  { name: 'HTTPS App Store link is safe', input: 'https://apps.apple.com/us/app/myapp/id123456', expectStatus: 'Safe', maxScore: 10 },

  // ── 10. Advanced Threat Intelligence & URL Forensics ──────────────────
  { name: 'Homograph: Cyrillic "а" in paypal.com',
    input: 'https://p\u0430ypal.com/login',
    expectStatus: 'Dangerous', minScore: 70,
    expectCategory: 'Homograph / IDN Spoofing' },
  { name: 'Homograph: Mixed-script Apple with Cyrillic',
    input: 'https://\u0430\u0440\u0440le.com',
    expectStatus: 'Dangerous', minScore: 70,
    expectCategory: 'Homograph / IDN Spoofing' },
  { name: 'Homograph: Zero-width invisible Unicode character in hostname',
    input: 'https://pay\u200Bpal.com',
    expectStatus: 'Dangerous', minScore: 70,
    expectCategory: 'Homograph / IDN Spoofing' },
  { name: 'Punycode: xn--80ak6aa92e.com (Cyrillic apple spoof)',
    input: 'https://xn--80ak6aa92e.com/signin',
    expectStatus: 'Dangerous', minScore: 70,
    expectCategory: 'Homograph / IDN Spoofing',
    expectDecodedHostContains: '\u0430' },
  { name: 'Punycode: All-Cyrillic IDN domain (xn--e1afmkfd.xn--p1ai)',
    input: 'https://xn--e1afmkfd.xn--p1ai',
    expectStatus: 'Suspicious', minScore: 30,
    expectCategory: 'Homograph / IDN Spoofing' },
  { name: 'Typosquatting: Visual substitution paypa1.com',
    input: 'https://paypa1.com',
    expectStatus: 'Suspicious', minScore: 30,
    expectCategory: 'Typosquatting' },
  { name: 'Typosquatting: Transposition payapl.com',
    input: 'https://payapl.com',
    expectStatus: 'Suspicious', minScore: 30,
    expectCategory: 'Typosquatting' },
  { name: 'Typosquatting: Insertion goggle.com + credential path',
    input: 'https://goggle.com/login',
    expectStatus: 'Suspicious', minScore: 45,
    expectCategory: 'Typosquatting' },
  { name: 'Deceptive Subdomain: Brand in subdomain + risky TLD',
    input: 'https://paypal.com.account-verify.xyz/login',
    expectStatus: 'Dangerous', minScore: 70,
    expectCategory: 'Brand Impersonation' },
  { name: 'Credential Harvesting: Unverified HTTPS login/password/reset',
    input: 'https://untrusted-portal-check.org/auth/reset-password',
    minScore: 15, maxScore: 29,
    expectCategory: 'Credential Harvesting' },
  { name: 'Suspicious Parameters: Encoded redirect destination + login path',
    input: 'https://portal-check.org/login?redirect=https%3A%2F%2Fevil.top%2Fsteal',
    expectStatus: 'Suspicious', minScore: 30,
    expectCategory: 'Suspicious URL Parameters' },
  { name: 'Suspicious Parameters: Executable javascript redirect parameter',
    input: 'https://portal-check.org/go?next=javascript%3Aalert(1)',
    expectStatus: 'Suspicious', minScore: 30,
    expectCategory: 'Suspicious URL Parameters' },
  { name: 'Suspicious Parameters: Credential parameter exposed in query string',
    input: 'https://portal-check.org/auth?password=secret123',
    expectStatus: 'Suspicious', minScore: 30,
    expectCategory: 'Suspicious URL Parameters' },
  { name: 'Suspicious Parameters: Double-encoded redirect parameter',
    input: 'https://portal-check.org/go?url=https%253A%252F%252Fevil.com',
    expectStatus: 'Suspicious', minScore: 30 },
  { name: 'False-positive prevention: /author/profile should not trigger auth',
    input: 'https://example.com/author/profile',
    expectStatus: 'Safe', expectScore: 0 },
  { name: 'False-positive prevention: Wikipedia article with Reset in path',
    input: 'https://en.wikipedia.org/wiki/Reset',
    expectStatus: 'Safe', expectScore: 0 },
  { name: 'False-positive prevention: QR Guard GitHub repo URL',
    input: 'https://github.com/shrutirajput745/qr-guard_02',
    expectStatus: 'Safe', expectScore: 0 },
  { name: 'Malformed URL: Whitespace in URL',
    input: 'https://exa mple.com/login',
    expectStatus: 'Suspicious', minScore: 30 },
  { name: 'Malformed URL: Invalid percent encoding sequence',
    input: 'https://example.com/%ZZbad',
    minScore: 25 },
  { name: 'Oversized URL payload safely clamped at score 100',
    input: 'http://free-reward-claim.top/login?' + 'a='.repeat(2500),
    expectStatus: 'Dangerous', expectScore: 100 },

  // ── 11. Audit Regression Fixes ────────────────────────────────────────
  { name: 'Regression: Control char bypass in javascript: scheme blocked',
    input: 'java\tscript:alert(1)',
    expectStatus: 'Dangerous', expectScore: 100, expectQrType: 'dangerous' },
  { name: 'Regression: Case-insensitive wifi: scheme handled consistently',
    input: 'wifi:S:HomeNet;T:WPA;P:Secret123;;',
    expectStatus: 'Safe', expectScore: 10, expectQrType: 'wifi', isUrl: false },
  { name: 'Regression: UPI payload gets dedicated payment analysis (not Plain Text)',
    input: 'upi://pay?am=500&pa=merchant@upi&pn=Store',
    expectStatus: 'Safe', expectScore: 10, expectQrType: 'upi', isUrl: false },
  { name: 'Regression: Bare domain @ redirection caught (not dropped as plain text)',
    input: 'paypal.com@evil.com/login',
    expectStatus: 'Dangerous', minScore: 70, isUrl: true },
  { name: 'Regression: Bare email address stays Plain Text (no false @ redirection)',
    input: 'support@example.com',
    expectStatus: 'Safe', expectScore: 0, expectQrType: 'text', isUrl: false },
  { name: 'Regression: Substring "xn--" inside non-ACE label does not trigger Punycode',
    input: 'https://prefixn--bar.com/docs',
    expectStatus: 'Safe', expectScore: 0 },
  { name: 'Regression: Non-string numeric input safely rejected',
    input: 12345,
    expectStatus: 'Dangerous', expectScore: 100 },

  { name: 'URL Structure Forensics decomposition accuracy',
    input: 'https://sub1.sub2.example.co.uk:8443/users/verify?redirect=https%3A%2F%2Fdest.org#top',
    minScore: 30,
    checkForensics: (f) => (
      f &&
      f.protocol === 'HTTPS' &&
      f.hostname === 'sub1.sub2.example.co.uk' &&
      f.rootDomain === 'example.co.uk' &&
      Array.isArray(f.subdomains) && f.subdomains.join('.') === 'sub1.sub2' &&
      f.port === '8443' &&
      f.path === '/users/verify' &&
      f.fragment === '#top' &&
      Array.isArray(f.queryParams) && f.queryParams.length === 1 &&
      f.queryParams[0].key === 'redirect' &&
      f.queryParams[0].decodedValue === 'https://dest.org'
    ) }
];

console.log('=== QR GUARD 2.0: AUTOMATED UNIT TEST SUITE ===');
let passed = 0, failed = 0;
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
    if (tc.expectQrType !== undefined && res.qrType !== tc.expectQrType) {
      ok = false;
      errors.push(`QR Type mismatch: expected '${tc.expectQrType}', got '${res.qrType}'`);
    }
    if (tc.expectCategory && (!Array.isArray(res.threatCategories) || !res.threatCategories.includes(tc.expectCategory))) {
      ok = false;
      errors.push(`Missing threat category '${tc.expectCategory}' in [${(res.threatCategories || []).join(', ')}]`);
    }
    if (tc.expectDecodedHostContains && (!res.forensics || !res.forensics.decodedHostname.includes(tc.expectDecodedHostContains))) {
      ok = false;
      errors.push(`Decoded hostname did not contain '${tc.expectDecodedHostContains}'`);
    }
    if (tc.checkForensics && !tc.checkForensics(res.forensics)) {
      ok = false;
      errors.push(`Forensics structure check failed: ${JSON.stringify(res.forensics)}`);
    }
    if (res.score < 0 || res.score > 100) {
      ok = false;
      errors.push(`Score out of bounds [0,100]: ${res.score}`);
    }

    if (ok) {
      passed++;
      const typeInfo = res.qrType ? ` | Type: ${res.qrType}` : '';
      console.log(`  ✔ [PASS] ${tc.name} => Score: ${res.score}/100, Status: ${res.status}${typeInfo}`);
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

// ── 12. Legitimate vs Adversarial URL Detection Benchmark ────────────────
console.log('▶ Running Legitimate vs Adversarial Quishing Benchmark (24 Cases)...');
const detectionBenchmark = [
  // 12 Legitimate URLs (expectedFlagged = false -> status Safe)
  { name: 'Legit-01 Wikipedia', url: 'https://en.wikipedia.org/wiki/QR_code', expectedFlagged: false },
  { name: 'Legit-02 GitHub Repo', url: 'https://github.com/shrutirajput745/qr-guard_02', expectedFlagged: false },
  { name: 'Legit-03 Google Account Signin', url: 'https://accounts.google.com/signin', expectedFlagged: false },
  { name: 'Legit-04 Microsoft Login', url: 'https://login.microsoft.com', expectedFlagged: false },
  { name: 'Legit-05 PayPal Official', url: 'https://www.paypal.com/myaccount/summary', expectedFlagged: false },
  { name: 'Legit-06 Apple Support', url: 'https://apps.apple.com/us/app/test/id12345', expectedFlagged: false },
  { name: 'Legit-07 Author Bio Path', url: 'https://example.com/author/profile', expectedFlagged: false },
  { name: 'Legit-08 Wikipedia Reset Page', url: 'https://en.wikipedia.org/wiki/Reset', expectedFlagged: false },
  { name: 'Legit-09 Reddit Homepage', url: 'https://reddit.com/r/netsec', expectedFlagged: false },
  { name: 'Legit-10 Pinterest', url: 'https://pinterest.com', expectedFlagged: false },
  { name: 'Legit-11 Plain HTTP News Site', url: 'http://example.com/articles/today', expectedFlagged: false },
  { name: 'Legit-12 Safe Subdomain Docs', url: 'https://docs.github.com/en/get-started', expectedFlagged: false },

  // 12 Adversarial / Quishing URLs (expectedFlagged = true -> Suspicious or Dangerous)
  { name: 'Adv-01 Cyrillic PayPal Homograph', url: 'https://p\u0430ypal.com/login', expectedFlagged: true },
  { name: 'Adv-02 Zero-Width Spoof', url: 'https://pay\u200Bpal.com/signin', expectedFlagged: true },
  { name: 'Adv-03 Punycode Apple Spoof', url: 'https://xn--80ak6aa92e.com/signin', expectedFlagged: true },
  { name: 'Adv-04 Lookalike paypa1.com', url: 'https://paypa1.com/verify', expectedFlagged: true },
  { name: 'Adv-05 Transposition payapl.com', url: 'https://payapl.com', expectedFlagged: true },
  { name: 'Adv-06 Raw IP Credential Harvest', url: 'http://192.168.1.55/login.php', expectedFlagged: true },
  { name: 'Adv-07 Scam Bait on .TOP', url: 'http://free-reward-claim.top/login', expectedFlagged: true },
  { name: 'Adv-08 Brand Subdomain Phishing', url: 'https://paypal.com.account-verify.xyz/login', expectedFlagged: true },
  { name: 'Adv-09 At-Symbol Redirection', url: 'https://google.com@evil-login.top/auth', expectedFlagged: true },
  { name: 'Adv-10 Bare At-Redirection', url: 'paypal.com@evil.com/login', expectedFlagged: true },
  { name: 'Adv-11 Executable JS Scheme', url: 'javascript:alert(1)', expectedFlagged: true },
  { name: 'Adv-12 Executable Redirect Param', url: 'https://portal-check.org/go?next=javascript%3Aalert(1)', expectedFlagged: true }
];

let tp = 0, fp = 0, tn = 0, fn = 0;
detectionBenchmark.forEach(item => {
  const r = QRAnalyzer.analyze(item.url);
  const flagged = r.status === 'Suspicious' || r.status === 'Dangerous';
  if (item.expectedFlagged && flagged) tp++;
  else if (!item.expectedFlagged && flagged) fp++;
  else if (!item.expectedFlagged && !flagged) tn++;
  else fn++;
  if (flagged !== item.expectedFlagged) {
    console.log(`  ! [BENCHMARK MISS] ${item.name}: expectedFlagged=${item.expectedFlagged}, got ${r.status} (${r.score})`);
  }
});

const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
const fpr = (fp + tn) > 0 ? fp / (fp + tn) : 0;
const fnr = (fn + tp) > 0 ? fn / (fn + tp) : 0;
const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
console.log(`  URL Detection Matrix: TP=${tp}, FP=${fp}, TN=${tn}, FN=${fn}`);
console.log(`  Precision=${(precision * 100).toFixed(1)}%, Recall=${(recall * 100).toFixed(1)}%, FPR=${(fpr * 100).toFixed(1)}%, FNR=${(fnr * 100).toFixed(1)}%, F1=${(f1 * 100).toFixed(1)}%`);

if (precision < 0.90 || recall < 0.90 || fpr > 0.10 || fnr > 0.10) {
  console.error('  ✖ [FAIL] URL detection benchmark fell below threshold!');
  failed++;
} else {
  console.log('  ✔ [PASS] URL detection benchmark meets Precision/Recall >= 90% and FPR/FNR <= 10%');
}

if (failed > 0) {
  console.log('Failed test cases:');
  failures.forEach(f => console.log(`  - ${f.name}`));
  process.exit(1);
}
