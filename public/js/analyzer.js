/**
 * QR Guide 2 - Transparent Heuristic URL & QR Security Analyzer Engine
 * Evaluates security indicators and provides an itemized score breakdown.
 * Compatible with both Browser (window.QRAnalyzer) and Node.js (module.exports).
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.QRAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {

  // Helper to safely extract domain parts
  function parseHost(hostname) {
    if (!hostname) return { domainParts: [], tld: '', sld: '', registeredDomain: '' };
    const parts = hostname.toLowerCase().split('.').filter(Boolean);
    const tld = parts.length > 1 ? parts[parts.length - 1] : '';
    
    // Check for common multi-part suffixes like .co.uk, .com.au, .gov.uk, .org.uk
    const multiPartSuffixes = ['co.uk', 'com.au', 'co.jp', 'gov.uk', 'org.uk', 'ac.uk', 'com.br', 'co.nz'];
    let registeredDomain = hostname;
    let sld = '';
    
    if (parts.length >= 2) {
      const lastTwo = parts.slice(-2).join('.');
      if (multiPartSuffixes.includes(lastTwo) && parts.length >= 3) {
        registeredDomain = parts.slice(-3).join('.');
        sld = parts[parts.length - 3];
      } else {
        registeredDomain = parts.slice(-2).join('.');
        sld = parts[parts.length - 2];
      }
    } else {
      registeredDomain = hostname;
      sld = hostname;
    }

    return { domainParts: parts, tld, sld, registeredDomain };
  }

  // Known URL Shortener Services
  const KNOWN_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
    'goo.gl', 'cutt.ly', 'rb.gy', 'bl.ink', 'shorturl.at', 'rebrand.ly'
  ];

  // High-Risk TLDs frequently abused in quishing & phishing
  const HIGH_RISK_TLDS = [
    'top', 'xyz', 'club', 'work', 'click', 'link', 'zip', 'mov', 'kim',
    'gq', 'cf', 'ml', 'ga', 'tk', 'su', 'buzz', 'best', 'monster', 'rest',
    'icu', 'cam', 'online', 'fit', 'surf', 'support'
  ];

  // Targeted Brands often impersonated in QR phishing
  const BRAND_TARGETS = [
    { name: 'PayPal', keyword: 'paypal', legitDomains: ['paypal.com', 'paypal.me'] },
    { name: 'Apple', keyword: 'apple', legitDomains: ['apple.com', 'icloud.com'] },
    { name: 'Microsoft', keyword: 'microsoft', legitDomains: ['microsoft.com', 'live.com', 'office.com', 'office365.com'] },
    { name: 'Google', keyword: 'google', legitDomains: ['google.com', 'gmail.com'] },
    { name: 'Chase Bank', keyword: 'chase', legitDomains: ['chase.com'] },
    { name: 'Wells Fargo', keyword: 'wellsfargo', legitDomains: ['wellsfargo.com'] },
    { name: 'Bank of America', keyword: 'bankofamerica', legitDomains: ['bankofamerica.com'] },
    { name: 'Amazon', keyword: 'amazon', legitDomains: ['amazon.com'] },
    { name: 'Netflix', keyword: 'netflix', legitDomains: ['netflix.com'] },
    { name: 'Binance', keyword: 'binance', legitDomains: ['binance.com'] },
    { name: 'Coinbase', keyword: 'coinbase', legitDomains: ['coinbase.com'] }
  ];

  // Action & Credential Harvesting Trigger Keywords
  const CREDENTIAL_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'wallet', 'claim', 'prize',
    'free-gift', 'free-reward', 'billing', 'passcode', 'recover', 'security-update'
  ];

  const QRAnalyzer = {

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
        disclaimer: 'Disclaimer: This prototype uses transparent heuristic risk scoring for educational evaluation. It does not guarantee absolute URL safety or detect all zero-day threats.',
        metrics: {
          protocol: 'N/A',
          hostType: 'Text Payload',
          tld: 'N/A',
          pointsAssigned: 0
        },
        details: {}
      };

      // 1. Validation for empty / null payload
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
        result.scoreBreakdown.push({ factor: 'Empty / Corrupted QR Data', points: 100 });
        result.explanation = 'Empty or corrupted QR data cannot be safely processed.';
        result.advice = 'Do not open or execute this QR payload.';
        return result;
      }

      const payload = rawPayload.trim();

      // Check for high-risk executable script or shell command strings
      const scriptOrCmdRegex = /^(?:javascript:|data:|file:|vbscript:)|<script|cmd\.exe|powershell|bash\s+-c/i;
      const lowerPayload = payload.toLowerCase();

      // Check if it starts with an executable/dangerous protocol
      if (/^(javascript:|data:|file:|vbscript:|intent:)/i.test(payload)) {
        const scheme = payload.split(':')[0].toLowerCase() + ':';
        result.isUrl = true;
        result.score = 100;
        result.status = 'Dangerous';
        result.metrics.protocol = scheme.toUpperCase();
        result.metrics.hostType = 'Executable Scheme';
        result.scoreBreakdown.push({ factor: `Dangerous Protocol Scheme (${scheme})`, points: 100 });
        result.issues.push({
          severity: 'high',
          category: 'Protocol Security',
          title: 'Executable Protocol Scheme',
          points: 100,
          message: `Uses high-risk scheme (${scheme}) which can execute arbitrary script commands or access local system files.`
        });
        result.explanation = `Dangerous executable scheme (${scheme}) detected. This payload can execute arbitrary code on device.`;
        result.advice = 'CRITICAL: Do not open or run this QR payload. It uses an executable scheme designed to exploit browser or system handlers.';
        return result;
      }

      // Check if it's a URL or can be parsed as a URL
      let parsedUrl = null;
      let urlCandidate = payload;

      if (!/^https?:\/\//i.test(urlCandidate) && !/^[a-z0-9]+:\/\//i.test(urlCandidate)) {
        // If it looks like a domain name with path, prepend http:// to evaluate
        if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::[0-9]+)?(?:\/.*)?$/i.test(urlCandidate)) {
          urlCandidate = 'http://' + urlCandidate;
        }
      }

      try {
        parsedUrl = new URL(urlCandidate);
        if (parsedUrl.protocol && (parsedUrl.hostname || parsedUrl.pathname)) {
          // Verify it has standard web protocol or recognizable structure
          if (['http:', 'https:', 'ftp:'].includes(parsedUrl.protocol)) {
            result.isUrl = true;
          }
        }
      } catch (e) {
        result.isUrl = false;
      }

      // --- NON-URL PAYLOAD EVALUATION ---
      if (!result.isUrl) {
        result.metrics.hostType = 'Plain Text / Config';

        // Check for embedded script tags or command lines
        if (/<script|cmd\.exe|powershell|bash\s+-c/i.test(payload)) {
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
          result.explanation = 'The QR code contains script or command syntax that could execute malicious instructions if processed.';
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
          result.explanation = 'This payload configures a local Wi-Fi connection rather than linking to an external website.';
          result.advice = 'Verify that you recognize the Wi-Fi network SSID before connecting.';
        } else if (/^(tel:|sms:|smsto:|mailto:|geo:)/i.test(payload)) {
          result.score = 10;
          result.status = 'Safe';
          const actionType = payload.split(':')[0].toUpperCase();
          result.scoreBreakdown.push({ factor: `${actionType} Action Handler`, points: 10 });
          result.highlights.push({
            category: 'Device Action',
            title: `${actionType} Scheme`,
            message: `Initiates a device action (${actionType}) without navigating to an untrusted web page.`
          });
          result.explanation = `This payload triggers a ${actionType} action on your device.`;
          result.advice = 'Confirm the recipient number or address before placing a call or sending a message.';
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

      // --- 9 SECURITY INDICATORS FOR URLS ---
      let points = 0;
      const protocol = parsedUrl.protocol.toLowerCase();
      const hostname = parsedUrl.hostname.toLowerCase();
      const fullUrl = parsedUrl.href;
      const { domainParts, tld, sld, registeredDomain } = parseHost(hostname);

      result.metrics.protocol = protocol.replace(':', '').toUpperCase();
      result.metrics.hostType = 'Domain Host';
      result.metrics.tld = tld ? `.${tld}` : 'N/A';

      // Indicator 1: HTTPS vs HTTP / Dangerous Scheme
      if (protocol === 'http:') {
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
      } else if (protocol === 'ftp:') {
        points += 15;
        result.scoreBreakdown.push({ factor: 'FTP Protocol', points: 15 });
        result.issues.push({
          severity: 'low',
          category: 'Protocol Security',
          title: 'Unencrypted File Transfer Protocol',
          points: 15,
          message: 'Uses standard FTP which transmits data without modern transport layer encryption.'
        });
      }

      // Indicator 2: IP Address Hostname Detection
      const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[[a-f0-9:]+\]$/i;
      const isIpHost = ipRegex.test(hostname);
      if (isIpHost) {
        points += 35;
        result.metrics.hostType = 'Raw IP Host';
        result.scoreBreakdown.push({ factor: 'Direct IP Address Host', points: 35 });
        result.issues.push({
          severity: 'high',
          category: 'Host Identity',
          title: 'Raw IP Hostname',
          points: 35,
          message: 'Uses a direct IP address instead of a domain name. Attackers use direct IPs to evade domain reputation filters.'
        });
      } else {
        result.highlights.push({
          category: 'Host Identity',
          title: 'Standard Domain Name',
          message: `Resolves via standard domain name (${hostname}).`
        });
      }

      // Indicator 3: Suspicious TLD & Domain Patterns
      if (tld && HIGH_RISK_TLDS.includes(tld)) {
        points += 25;
        result.scoreBreakdown.push({ factor: `High-Risk TLD (.${tld})`, points: 25 });
        result.issues.push({
          severity: 'medium',
          category: 'Domain Pattern',
          title: `High-Risk TLD (.${tld})`,
          points: 25,
          message: `Top-level domain (.${tld}) is statistically associated with higher rates of phishing and spam registrations.`
        });
      }

      // Hyphen count check across domain labels
      const domainNameWithoutTld = domainParts.slice(0, -1).join('.');
      const hyphenCount = (domainNameWithoutTld.match(/-/g) || []).length;
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
      // A typical domain is subdomain.domain.com (3 parts). More than 3 parts (excluding recognized multipart TLDs) is suspicious.
      const subdomainPartsCount = Math.max(0, domainParts.length - (registeredDomain.split('.').length));
      if (subdomainPartsCount >= 2) {
        points += 25;
        result.scoreBreakdown.push({ factor: `Excessive Subdomains (${subdomainPartsCount} subdomains)`, points: 25 });
        result.issues.push({
          severity: 'high',
          category: 'Subdomain Count',
          title: 'Deeply Nested Subdomains',
          points: 25,
          message: `Contains ${subdomainPartsCount} subdomains. Attackers nest authentic brand names in subdomains to trick users.`
        });
      }

      // Indicator 5: Brand Impersonation & Credential Keywords
      // A: Brand Impersonation Check (Targeted Brands)
      let brandImpersonated = false;
      for (const b of BRAND_TARGETS) {
        if (fullUrl.toLowerCase().includes(b.keyword)) {
          // Check if registered domain is one of legitimate domains
          const isLegitBrandDomain = b.legitDomains.some(legit => 
            hostname === legit || hostname.endsWith('.' + legit)
          );
          if (!isLegitBrandDomain) {
            brandImpersonated = true;
            points += 30;
            result.scoreBreakdown.push({ factor: `Brand Impersonation (${b.name})`, points: 30 });
            result.issues.push({
              severity: 'high',
              category: 'Brand Impersonation',
              title: `Brand Impersonation (${b.name})`,
              points: 30,
              message: `URL contains the brand name '${b.name}' but is hosted on an unverified domain (${hostname}).`
            });
            break; // Count once
          }
        }
      }

      // B: Credential / Action Keywords check (if not on standard legit HTTPS site)
      const matchedActionWords = CREDENTIAL_KEYWORDS.filter(kw => fullUrl.toLowerCase().includes(kw));
      if (matchedActionWords.length > 0 && !brandImpersonated) {
        // High risk if credential words appear on: HTTP, high-risk TLD, raw IP host, or scam words (claim, prize)
        const isSuspiciousContext = protocol === 'http:' || isIpHost || HIGH_RISK_TLDS.includes(tld) ||
          matchedActionWords.some(w => ['claim', 'prize', 'free-gift', 'free-reward'].includes(w));
        
        if (isSuspiciousContext) {
          points += 30;
          result.scoreBreakdown.push({ factor: `Sensitive Action Keywords [${matchedActionWords.slice(0, 3).join(', ')}]`, points: 30 });
          result.issues.push({
            severity: 'high',
            category: 'Phishing Keywords',
            title: 'Sensitive Credential / Reward Keywords',
            points: 30,
            message: `URL contains sensitive action keywords [${matchedActionWords.join(', ')}] on an insecure or unverified host (${hostname}).`
          });
        }
      }

      // Indicator 6: Presence of `@` Symbol
      if (fullUrl.includes('@') || payload.includes('@')) {
        points += 40;
        result.scoreBreakdown.push({ factor: 'Redirection Symbol (@)', points: 40 });
        result.issues.push({
          severity: 'high',
          category: 'URL Redirection',
          title: 'Presence of "@" Symbol',
          points: 40,
          message: 'Contains "@" symbol. Browsers interpret text before "@" as credentials, routing the user to the host after "@".'
        });
      }

      // Indicator 7: Suspicious Encoding & Characters (%xx or double slashes)
      const hexCount = (fullUrl.match(/%/g) || []).length;
      if (hexCount > 3) {
        points += 15;
        result.scoreBreakdown.push({ factor: `URL Percent Encoding (${hexCount} %xx characters)`, points: 15 });
        result.issues.push({
          severity: 'medium',
          category: 'URL Encoding',
          title: 'Heavy Percent Encoding',
          points: 15,
          message: `Contains ${hexCount} percent-encoded characters (%xx), which obscures destination path readability.`
        });
      }

      if (parsedUrl.pathname.includes('//') || /https?:\/\/[^\/]+\/\//i.test(payload)) {
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

      // Indicator 8: URL Shorteners (Strict exact or subdomain matching)
      const isShortener = KNOWN_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s));
      if (isShortener) {
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
          message: `URL length is ${fullUrl.length} characters. Extended strings are often used to hide query parameters.`
        });
      }

      // Indicator 10: Non-Standard Port Check
      if (parsedUrl.port && !['80', '443', ''].includes(parsedUrl.port)) {
        points += 15;
        result.scoreBreakdown.push({ factor: `Non-Standard Port (:${parsedUrl.port})`, points: 15 });
        result.issues.push({
          severity: 'low',
          category: 'Port Security',
          title: 'Non-Standard Port',
          points: 15,
          message: `Uses custom port number (${parsedUrl.port}) instead of standard web ports.`
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
        search: parsedUrl.search,
        port: parsedUrl.port || (protocol === 'https:' ? '443' : '80')
      };

      return result;
    }

  };

  return QRAnalyzer;
});
