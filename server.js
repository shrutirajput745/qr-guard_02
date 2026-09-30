const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Security analysis helper function (also usable server-side)
function analyzeUrlSecurity(inputPayload) {
  const result = {
    input: inputPayload,
    isUrl: false,
    score: 0,
    status: 'Safe', // Safe, Suspicious, Dangerous
    issues: [],
    highlights: [],
    details: {}
  };

  if (!inputPayload || typeof inputPayload !== 'string') {
    result.issues.push({ severity: 'High', message: 'Empty or invalid QR code data.' });
    result.score = 100;
    result.status = 'Dangerous';
    return result;
  }

  const rawText = inputPayload.trim();

  // Check if it's a URL
  let parsedUrl = null;
  try {
    // Check if missing scheme but looks like domain
    let urlToTest = rawText;
    if (!/^https?:\/\//i.test(urlToTest) && !/^[a-z]+:/i.test(urlToTest)) {
      if (/^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(urlToTest)) {
        urlToTest = 'http://' + urlToTest;
      }
    }
    parsedUrl = new URL(urlToTest);
    result.isUrl = true;
  } catch (e) {
    result.isUrl = false;
  }

  if (!result.isUrl) {
    // Check for dangerous scripts or commands in raw text
    if (/<script|javascript:|data:|file:|cmd\.exe|powershell/i.test(rawText)) {
      result.score = 85;
      result.status = 'Dangerous';
      result.issues.push({
        severity: 'High',
        category: 'Executable Code',
        message: 'QR code contains executable script or shell command patterns.'
      });
    } else {
      result.score = 0;
      result.status = 'Safe';
      result.highlights.push({
        category: 'Plain Text Payload',
        message: 'Decoded payload is plain text or contact data, not a web URL.'
      });
    }
    return result;
  }

  // --- URL SECURITY RULES ENGINE ---
  let score = 0;
  const protocol = parsedUrl.protocol.toLowerCase();
  const hostname = parsedUrl.hostname.toLowerCase();
  const fullUrl = parsedUrl.href;

  // 1. Dangerous Protocol Scheme Check
  if (['javascript:', 'data:', 'file:', 'vbscript:', 'intent:'].includes(protocol)) {
    score += 100;
    result.issues.push({
      severity: 'High',
      category: 'Dangerous Scheme',
      message: `Uses high-risk protocol scheme (${protocol}) which can execute arbitrary code.`
    });
  } else if (protocol === 'http:') {
    score += 20;
    result.issues.push({
      severity: 'Medium',
      category: 'Insecure Protocol',
      message: 'Uses unencrypted HTTP connection instead of secure HTTPS.'
    });
  } else if (protocol === 'https:') {
    result.highlights.push({
      category: 'Encryption',
      message: 'Uses secure HTTPS connection.'
    });
  }

  // 2. IP Address in Hostname Check
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[[a-f0-9:]+\]$/i;
  if (ipRegex.test(hostname)) {
    score += 35;
    result.issues.push({
      severity: 'High',
      category: 'Raw IP Address',
      message: 'Hostname uses direct IP address instead of a domain name, commonly used in phishing bypasses.'
    });
  }

  // 3. High-Risk TLD Check
  const suspiciousTlds = [
    'top', 'xyz', 'club', 'work', 'click', 'link', 'zip', 'mov', 'kim',
    'gq', 'cf', 'ml', 'ga', 'tk', 'su', 'buzz', 'best', 'monster', 'rest'
  ];
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';
  if (suspiciousTlds.includes(tld)) {
    score += 25;
    result.issues.push({
      severity: 'Medium',
      category: 'High-Risk TLD',
      message: `Top-level domain (.${tld}) has a high statistical correlation with spam and phishing.`
    });
  }

  // 4. Excessive Subdomains Check
  if (domainParts.length > 3) {
    score += 25;
    result.issues.push({
      severity: 'High',
      category: 'Subdomain Spoofing',
      message: `URL contains ${domainParts.length - 2} subdomains. Phishers often nest fake brand names in subdomains.`
    });
  }

  // 5. Brand Impersonation & Phishing Keywords Check
  const sensitiveKeywords = [
    'paypal', 'bank', 'login', 'secure', 'verify', 'account', 'update',
    'signin', 'wallet', 'crypto', 'appleid', 'microsoft', 'google-login',
    'meta-support', 'free-gift', 'claim-prize', 'recover'
  ];
  
  const matchedKeywords = sensitiveKeywords.filter(kw => fullUrl.toLowerCase().includes(kw));
  if (matchedKeywords.length > 0) {
    // Check if the legitimate main domain matches the keyword
    const isLegitDomain = matchedKeywords.some(kw => hostname === `${kw}.com` || hostname.endsWith(`.${kw}.com`));
    if (!isLegitDomain) {
      score += 30;
      result.issues.push({
        severity: 'High',
        category: 'Brand Impersonation',
        message: `URL contains sensitive keywords (${matchedKeywords.join(', ')}) on an unverified domain (${hostname}).`
      });
    }
  }

  // 6. Suspicious Symbols (@ or heavy URL encoding)
  if (fullUrl.includes('@')) {
    score += 40;
    result.issues.push({
      severity: 'High',
      category: 'URL Redirection Trick (@)',
      message: 'Contains "@" character, which can obscure the real destination server.'
    });
  }

  if ((fullUrl.match(/%/g) || []).length > 3) {
    score += 15;
    result.issues.push({
      severity: 'Medium',
      category: 'URL Obfuscation',
      message: 'URL contains excessive encoded characters (%xx), often used to hide true paths.'
    });
  }

  // 7. Known URL Shorteners
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'goo.gl', 'cutt.ly', 'rb.gy'];
  if (shorteners.some(s => hostname.includes(s))) {
    score += 15;
    result.issues.push({
      severity: 'Medium',
      category: 'Shortened URL',
      message: 'URL uses a shortening service which hides the final destination URL.'
    });
  }

  // 8. Non-Standard Port Check
  if (parsedUrl.port && !['80', '443'].includes(parsedUrl.port)) {
    score += 15;
    result.issues.push({
      severity: 'Low',
      category: 'Custom Port',
      message: `Uses unusual port number (${parsedUrl.port}).`
    });
  }

  // 9. Excessive Length Check
  if (fullUrl.length > 110) {
    score += 10;
    result.issues.push({
      severity: 'Low',
      category: 'Excessive Length',
      message: `URL is unusually long (${fullUrl.length} characters), which may obscure query parameters.`
    });
  }

  // Final score clamping (0 - 100)
  result.score = Math.min(100, Math.max(0, score));

  // Determine Status
  if (result.score >= 70) {
    result.status = 'Dangerous';
  } else if (result.score >= 30) {
    result.status = 'Suspicious';
  } else {
    result.status = 'Safe';
  }

  // Add general highlight if clean
  if (result.issues.length === 0) {
    result.highlights.push({
      category: 'Clean Scan',
      message: 'No obvious security anomalies or phishing patterns detected.'
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

// API Endpoint
app.post('/api/analyze', (req, res) => {
  const { qrData } = req.body;
  if (!qrData) {
    return res.status(400).json({ error: 'Missing qrData parameter.' });
  }
  const analysis = analyzeUrlSecurity(qrData);
  res.json(analysis);
});

// Serve main app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 QR Guide 2 running at http://localhost:${PORT}`);
});
