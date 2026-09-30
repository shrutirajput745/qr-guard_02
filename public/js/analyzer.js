/**
 * QR Guide 2 - Transparent Heuristic URL & QR Security Analyzer Engine
 * Evaluates 9 simple, meaningful security indicators and provides an itemized score breakdown.
 */

window.QRAnalyzer = {

  analyze: function(rawPayload) {
    const result = {
      input: rawPayload,
      isUrl: false,
      score: 0,
      status: 'Safe', // Safe (0-29), Suspicious (30-69), Dangerous (70-100)
      issues: [],
      scoreBreakdown: [],
      highlights: [],
      explanation: '',
      advice: '',
      disclaimer: 'Disclaimer: This prototype uses basic heuristic risk scoring for educational evaluation. It does not guarantee absolute URL safety or detect all zero-day threats.',
      metrics: {
        protocol: 'N/A',
        hostType: 'Text Payload',
        tld: 'N/A',
        pointsAssigned: 0
      },
      details: {}
    };

    if (!rawPayload || typeof rawPayload !== 'string' || rawPayload.trim() === '') {
      result.issues.push({
        severity: 'high',
        category: 'Data Format',
        title: 'Empty Payload',
        points: 100,
        message: 'The QR code contains empty or unreadable data.'
      });
      result.score = 100;
      result.status = 'Dangerous';
      result.explanation = 'Empty or corrupted QR data cannot be safely processed.';
      result.advice = 'Do not open or execute this QR payload.';
      return result;
    }

    const payload = rawPayload.trim();

    // Check if URL format
    let parsedUrl = null;
    try {
      let urlToTest = payload;
      if (!/^https?:\/\//i.test(urlToTest) && !/^[a-z0-9]+:/i.test(urlToTest)) {
        if (/^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(urlToTest)) {
          urlToTest = 'http://' + urlToTest;
        }
      }
      parsedUrl = new URL(urlToTest);
      if (parsedUrl.protocol && parsedUrl.hostname) {
        result.isUrl = true;
      }
    } catch (e) {
      result.isUrl = false;
    }

    // --- NON-URL PAYLOAD EVALUATION ---
    if (!result.isUrl) {
      result.metrics.hostType = 'Plain Text / Config';
      
      if (/<script|javascript:|data:|file:|cmd\.exe|powershell|bash/i.test(payload)) {
        result.score = 90;
        result.status = 'Dangerous';
        result.issues.push({
          severity: 'high',
          category: 'Script Injection',
          title: 'Executable Code Detected',
          points: 90,
          message: 'Payload contains executable code, script tags, or terminal commands.'
        });
        result.scoreBreakdown.push({ factor: 'Executable Script / Code Pattern', points: 90 });
        result.explanation = 'The QR code contains script or command syntax that could execute malicious code if processed.';
        result.advice = 'Avoid copying or executing this payload in browsers or command terminals.';
      } else if (payload.startsWith('WIFI:')) {
        result.score = 10;
        result.status = 'Safe';
        result.scoreBreakdown.push({ factor: 'Wi-Fi Network Credentials', points: 10 });
        result.highlights.push({
          category: 'Wi-Fi Configuration',
          title: 'Standard Wi-Fi Data',
          message: 'Contains network SSID and encryption passphrase.'
        });
        result.explanation = 'This payload configures a Wi-Fi connection rather than linking to an external website.';
        result.advice = 'Verify that you recognize the Wi-Fi network name before connecting.';
      } else {
        result.score = 0;
        result.status = 'Safe';
        result.scoreBreakdown.push({ factor: 'Standard Plain Text', points: 0 });
        result.highlights.push({
          category: 'Plain Text Payload',
          title: 'No Web Link',
          message: 'Decoded payload is plain text data.'
        });
        result.explanation = 'Plain text content poses no direct web link risks.';
        result.advice = 'Plain text is safe to view. Exercise normal caution if manual links are written inside the text.';
      }
      return result;
    }

    // --- 9 SIMPLE, MEANINGFUL SECURITY INDICATORS ---
    let points = 0;
    const protocol = parsedUrl.protocol.toLowerCase();
    const hostname = parsedUrl.hostname.toLowerCase();
    const fullUrl = parsedUrl.href;

    result.metrics.protocol = protocol.replace(':', '').toUpperCase();
    result.metrics.hostType = 'Domain Host';

    // Indicator 1: HTTPS vs HTTP / Dangerous Scheme
    if (['javascript:', 'data:', 'file:', 'vbscript:', 'intent:'].includes(protocol)) {
      points += 100;
      result.scoreBreakdown.push({ factor: `Dangerous Protocol (${protocol})`, points: 100 });
      result.issues.push({
        severity: 'high',
        category: 'Protocol Security',
        title: 'Executable Protocol Scheme',
        points: 100,
        message: `Uses high-risk scheme (${protocol}) which can execute arbitrary code or access local files.`
      });
    } else if (protocol === 'http:') {
      points += 20;
      result.scoreBreakdown.push({ factor: 'Unencrypted HTTP Connection', points: 20 });
      result.issues.push({
        severity: 'medium',
        category: 'Protocol Security',
        title: 'Unencrypted HTTP Protocol',
        points: 20,
        message: 'HTTP transmits data in plain text without SSL/TLS encryption, exposing traffic to interception.'
      });
    } else if (protocol === 'https:') {
      result.highlights.push({
        category: 'Protocol Security',
        title: 'Encrypted HTTPS Protocol',
        message: 'Uses secure HTTPS encryption.'
      });
    }

    // Indicator 2: IP Address Hostname Detection
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[[a-f0-9:]+\]$/i;
    if (ipRegex.test(hostname)) {
      points += 35;
      result.metrics.hostType = 'Raw IP Host';
      result.scoreBreakdown.push({ factor: 'Direct IP Address Host', points: 35 });
      result.issues.push({
        severity: 'high',
        category: 'Host Identity',
        title: 'Raw IP Hostname',
        points: 35,
        message: 'Uses a direct IP address instead of a domain name. Attackers often use IP addresses to bypass domain blacklists.'
      });
    } else {
      result.highlights.push({
        category: 'Host Identity',
        title: 'Standard Domain Name',
        message: `Resolves via standard domain name (${hostname}).`
      });
    }

    // Indicator 3: Suspicious TLD & Domain Patterns
    const suspiciousTlds = [
      'top', 'xyz', 'club', 'work', 'click', 'link', 'zip', 'mov', 'kim',
      'gq', 'cf', 'ml', 'ga', 'tk', 'su', 'buzz', 'best', 'monster', 'rest',
      'icu', 'cam', 'online'
    ];
    const domainParts = hostname.split('.');
    const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';
    result.metrics.tld = tld ? `.${tld}` : 'N/A';

    if (suspiciousTlds.includes(tld)) {
      points += 25;
      result.scoreBreakdown.push({ factor: `High-Risk TLD (.${tld})`, points: 25 });
      result.issues.push({
        severity: 'medium',
        category: 'Domain Pattern',
        title: `High-Risk TLD (.${tld})`,
        points: 25,
        message: `Top-level domain (.${tld}) is statistically associated with higher rates of phishing registrations.`
      });
    }

    // Hyphen-heavy domain name check (e.g., secure-login-update-paypal.com)
    const hyphenCount = (hostname.split('.')[0] || '').split('-').length - 1;
    if (hyphenCount >= 3) {
      points += 15;
      result.scoreBreakdown.push({ factor: `Hyphenated Domain Pattern (${hyphenCount} hyphens)`, points: 15 });
      result.issues.push({
        severity: 'medium',
        category: 'Domain Pattern',
        title: 'Hyphen-Heavy Hostname',
        points: 15,
        message: 'Contains multiple hyphens in the domain name, a common trick used to mimic legitimate organization names.'
      });
    }

    // Indicator 4: Subdomain Count
    if (domainParts.length > 3) {
      points += 25;
      result.scoreBreakdown.push({ factor: `Excessive Subdomains (${domainParts.length - 2} subdomains)`, points: 25 });
      result.issues.push({
        severity: 'high',
        category: 'Subdomain Count',
        title: 'Deeply Nested Subdomains',
        points: 25,
        message: `Contains ${domainParts.length - 2} subdomains. Attackers nest authentic brand names in subdomains to trick users.`
      });
    }

    // Indicator 5: Phishing Keywords
    const sensitiveKeywords = [
      'paypal', 'bank', 'login', 'verify', 'account', 'secure', 'update',
      'signin', 'wallet', 'crypto', 'appleid', 'microsoft', 'google-login',
      'free-gift', 'prize', 'claim', 'billing', 'passcode'
    ];

    const matchedKeywords = sensitiveKeywords.filter(kw => fullUrl.toLowerCase().includes(kw));
    if (matchedKeywords.length > 0) {
      const isLegitDomain = matchedKeywords.some(kw => hostname === `${kw}.com` || hostname.endsWith(`.${kw}.com`));
      if (!isLegitDomain) {
        points += 30;
        result.scoreBreakdown.push({ factor: `Phishing Keywords [${matchedKeywords.join(', ')}]`, points: 30 });
        result.issues.push({
          severity: 'high',
          category: 'Phishing Keywords',
          title: 'Brand Impersonation Keywords',
          points: 30,
          message: `Contains sensitive keywords [${matchedKeywords.join(', ')}] on an unverified host (${hostname}).`
        });
      }
    }

    // Indicator 6: Presence of `@` Symbol
    if (fullUrl.includes('@')) {
      points += 40;
      result.scoreBreakdown.push({ factor: 'Redirection Symbol (@)', points: 40 });
      result.issues.push({
        severity: 'high',
        category: 'URL Redirection',
        title: 'Presence of "@" Symbol',
        points: 40,
        message: 'Contains "@" symbol. Browsers interpret text before "@" as login credentials, routing the user to the host after "@".'
      });
    }

    // Indicator 7: Suspicious Encoding & Characters (%xx or double slashes in path)
    const hexCount = (fullUrl.match(/%/g) || []).length;
    if (hexCount > 3) {
      points += 15;
      result.scoreBreakdown.push({ factor: `URL Percent Encoding (${hexCount} %xx characters)`, points: 15 });
      result.issues.push({
        severity: 'medium',
        category: 'URL Encoding',
        title: 'Heavy Percent Encoding',
        points: 15,
        message: `Contains ${hexCount} percent-encoded characters (%xx), which obscures path readability.`
      });
    }

    if (parsedUrl.pathname.includes('//')) {
      points += 15;
      result.scoreBreakdown.push({ factor: 'Double Slash Path Traversal (//)', points: 15 });
      result.issues.push({
        severity: 'medium',
        category: 'URL Encoding',
        title: 'Double Slash Path Pattern',
        points: 15,
        message: 'Contains consecutive slashes "//" in the path, often used for open-redirect vulnerabilities.'
      });
    }

    // Indicator 8: URL Shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'goo.gl', 'cutt.ly', 'rb.gy'];
    if (shorteners.some(s => hostname.includes(s))) {
      points += 15;
      result.scoreBreakdown.push({ factor: 'URL Shortening Service', points: 15 });
      result.issues.push({
        severity: 'medium',
        category: 'Link Shorteners',
        title: 'Shortened Destination Masking',
        points: 15,
        message: 'Uses a URL shortener service which conceals the final target web destination.'
      });
    }

    // Indicator 9: URL Length
    if (fullUrl.length > 110) {
      points += 10;
      result.scoreBreakdown.push({ factor: `Excessive URL Length (${fullUrl.length} chars)`, points: 10 });
      result.issues.push({
        severity: 'low',
        category: 'URL Length',
        title: 'Unusually Long URL',
        points: 10,
        message: `URL length is ${fullUrl.length} characters. Extended strings are often used to hide parameters.`
      });
    }

    // Final Score Clamping (0 - 100)
    result.score = Math.min(100, Math.max(0, points));
    result.metrics.pointsAssigned = points;

    // Status Determination
    if (result.score >= 70) {
      result.status = 'Dangerous';
    } else if (result.score >= 30) {
      result.status = 'Suspicious';
    } else {
      result.status = 'Safe';
    }

    // Formulate Explanation Summary
    if (result.scoreBreakdown.length === 0) {
      result.explanation = 'Risk score is 0 because no security anomalies or suspicious indicators were detected.';
    } else {
      const breakdownText = result.scoreBreakdown.map(b => `${b.factor} (+${b.points} pts)`).join(', ');
      result.explanation = `Score of ${result.score}/100 calculated from detected indicators: ${breakdownText}.`;
    }

    // Formulate Safety Advice
    if (result.status === 'Dangerous') {
      result.advice = 'DANGER: High risk score detected. DO NOT visit this URL or enter credentials. Verify the link with the sender through an independent channel.';
    } else if (result.status === 'Suspicious') {
      result.advice = 'WARNING: Moderate risk score. Exercise caution. Check the domain carefully and do not enter sensitive passwords or payment info.';
    } else {
      result.advice = 'SAFE: Low risk score. URL structure matches standard web conventions. Always verify that the domain name matches your intended destination.';
    }

    // Clean highlight if no issues
    if (result.issues.length === 0) {
      result.highlights.push({
        category: 'Clean Structure',
        title: 'Zero Anomalies',
        message: 'Passed all security indicators without triggering risk points.'
      });
    }

    result.details = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      pathname: parsedUrl.pathname,
      search: parsedUrl.search
    };

    return result;
  }

};
