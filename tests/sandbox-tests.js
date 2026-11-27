const QRBehaviorSandbox = require('../public/js/behavior-sandbox');

console.log('=== QR GUARD: BEHAVIOR SANDBOX TEST SUITE ===\n');

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

// 1. Empty / invalid input
const sEmpty = QRBehaviorSandbox.simulate('');
assert(sEmpty.verdict === 'BLOCKED_EXECUTION' && sEmpty.executedCode === false, 'Empty input is blocked without execution');

// 2. Executable javascript: scheme
const sJs = QRBehaviorSandbox.simulate('javascript:alert(document.cookie)');
assert(sJs.verdict === 'BLOCKED_EXECUTION' && sJs.riskLevel === 'CRITICAL', 'javascript: URI blocked with CRITICAL risk');
assert(sJs.networkSimulated === false && sJs.executedCode === false, 'No code executed or network simulated');

// 3. file: and data: schemes
const sFile = QRBehaviorSandbox.simulate('file:///etc/passwd');
assert(sFile.verdict === 'BLOCKED_EXECUTION', 'file: URI blocked in sandbox');
const sData = QRBehaviorSandbox.simulate('data:text/html,<script>alert(1)</script>');
assert(sData.verdict === 'BLOCKED_EXECUTION', 'data: URI blocked in sandbox');

// 4. Embedded script / shell command
const sCmd = QRBehaviorSandbox.simulate('powershell -enc ABC123');
assert(sCmd.verdict === 'BLOCKED_EXECUTION', 'Shell command payload blocked');

// 5. Android Intent URI
const sIntent = QRBehaviorSandbox.simulate('intent://pay/confirm#Intent;scheme=https;package=com.unknown.wallet;S.browser_fallback_url=https%3A%2F%2Fevil.top;end');
assert(sIntent.verdict === 'HIGH_RISK_BEHAVIOR', 'Android intent URI flagged as HIGH_RISK_BEHAVIOR');
assert(sIntent.sideEffects.some(e => e.includes('https://evil.top')), 'Extracts fallback browser URL from Android Intent');

// 6. Static redirect hop + executable download (.apk)
const sApk = QRBehaviorSandbox.simulate('https://portal-check.org/go?redirect=https%3A%2F%2Fevil.top%2Fapp.apk');
assert(sApk.staticRedirectHops.length === 1 && sApk.staticRedirectHops[0].target === 'https://evil.top/app.apk', 'Static redirect hop decoded offline');
const sDirectApk = QRBehaviorSandbox.simulate('https://evil.top/installer/update.apk');
assert(sDirectApk.downloadRisk && sDirectApk.downloadRisk.level === 'HIGH' && sDirectApk.verdict === 'HIGH_RISK_BEHAVIOR', 'Direct .apk download flagged as HIGH risk');

// 7. Executable redirect target inside query parameter
const sExecRedir = QRBehaviorSandbox.simulate('https://portal-check.org/go?next=javascript%3Aalert(1)');
assert(sExecRedir.verdict === 'HIGH_RISK_BEHAVIOR' && sExecRedir.staticRedirectHops[0].isExecutableTarget === true, 'Executable redirect target flagged');

// 8. UPI & Wi-Fi & SMS & Email & Plain Text
const sUpi = QRBehaviorSandbox.simulate('upi://pay?pa=merchant@upi&pn=DemoShop&am=499&cu=INR');
assert(sUpi.verdict === 'CAUTION_INTERACTIVE_ACTION' && sUpi.handlerType.includes('UPI') && sUpi.previewData && sUpi.previewData.payeeAddress === 'merchant@upi', 'UPI payment intent modeled cleanly with previewData');

const sOpenWifi = QRBehaviorSandbox.simulate('WIFI:S:FreeAirportWiFi;T:nopass;P:;;');
assert(sOpenWifi.verdict === 'HIGH_RISK_BEHAVIOR' && sOpenWifi.previewData && sOpenWifi.previewData.ssid === 'FreeAirportWiFi', 'Open/nopass Wi-Fi flagged as HIGH_RISK_BEHAVIOR with previewData');

const sSms = QRBehaviorSandbox.simulate('sms:+14155550199:Confirm%20OTP');
assert(sSms.verdict === 'CAUTION_INTERACTIVE_ACTION' && sSms.previewData && sSms.previewData.kind === 'sms' && sSms.previewData.message === 'Confirm OTP', 'SMS intent modeled with decoded previewData');

const sMail = QRBehaviorSandbox.simulate('mailto:security@example.com?subject=Verify&body=Hello');
assert(sMail.verdict === 'CAUTION_INTERACTIVE_ACTION' && sMail.previewData && sMail.previewData.kind === 'email' && sMail.previewData.to === 'security@example.com', 'Email intent modeled with previewData');

const sWpaWifi = QRBehaviorSandbox.simulate('WIFI:S:CampusWiFi;T:WPA;P:Secured123;;');
assert(sWpaWifi.verdict === 'CAUTION_INTERACTIVE_ACTION', 'WPA Wi-Fi modeled as CAUTION_INTERACTIVE_ACTION');

const sClean = QRBehaviorSandbox.simulate('https://wikipedia.org');
assert(sClean.verdict === 'SAFE_CONTAINED' && sClean.riskLevel === 'LOW', 'Clean HTTPS URL modeled as SAFE_CONTAINED');

const sText = QRBehaviorSandbox.simulate('Welcome to QR Guard');
assert(sText.verdict === 'SAFE_CONTAINED' && sText.handlerType === 'Plain Text Display', 'Plain text modeled safely');

// 9. Audit Regression Fixes (control-char scheme bypass, IDN/port/query bare URLs, vCard, geo, null/non-string)
const sJsTab = QRBehaviorSandbox.simulate('java\tscript:alert(1)');
assert(sJsTab.verdict === 'BLOCKED_EXECUTION' && sJsTab.executedCode === false, 'Control-char javascript: scheme blocked in sandbox');

const sBarePort = QRBehaviorSandbox.simulate('example.com:8080/login');
assert(sBarePort.handlerType === 'Web Browser Navigation' && sBarePort.verdict === 'CAUTION_INTERACTIVE_ACTION', 'Bare domain with port modeled as Web Browser Navigation');

const sBareEmail = QRBehaviorSandbox.simulate('support@example.com');
assert(sBareEmail.handlerType === 'Plain Text Display' && sBareEmail.verdict === 'SAFE_CONTAINED', 'Bare email address stays Plain Text Display');

const sVCard = QRBehaviorSandbox.simulate('BEGIN:VCARD\nFN:Alice Smith\nTEL:+15551234\nEMAIL:alice@example.org\nEND:VCARD');
assert(sVCard.handlerType === 'vCard Contact Handler' && sVCard.previewData && sVCard.previewData.kind === 'vcard' && sVCard.previewData.name === 'Alice Smith', 'vCard uses accurate handlerType and previewData');

const sVCardSingleLine = QRBehaviorSandbox.simulate('BEGIN:VCARD FN:Alice TEL:+123 END:VCARD');
assert(sVCardSingleLine.previewData && sVCardSingleLine.previewData.name === 'Alice' && sVCardSingleLine.previewData.phone === '+123', 'Single-line collapsed vCard parses fields cleanly without trailing tokens');

const sGeo = QRBehaviorSandbox.simulate('geo:37.7749,-122.4194');
assert(sGeo.handlerType === 'GEO Device Handler' && sGeo.previewData && sGeo.previewData.kind === 'geo', 'Geo intent populates geo previewData');

const sNull = QRBehaviorSandbox.simulate(null);
assert(sNull.verdict === 'BLOCKED_EXECUTION' && sNull.executedCode === false, 'Null input safely blocked without throwing');

console.log(`\nBehavior Sandbox Test Results: ${passed} Passed, ${failed} Failed out of ${passed + failed} Tests\n`);
if (failed > 0) process.exit(1);
