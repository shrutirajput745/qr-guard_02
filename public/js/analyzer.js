/**
 * QR Guard - Universal QR Type Classifier & Threat Intelligence / URL Forensics Engine
 * Classifies QR payload types, decomposes URL structure, detects advanced quishing threats
 * (homographs, punycode, typosquatting, brand impersonation, credential harvesting,
 * suspicious parameters), and produces explainable deterministic risk scores (0-100).
 * Compatible with both Browser (window.QRAnalyzer) and Node.js (module.exports).
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.QRAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {

  const MAX_PAYLOAD_LENGTH = 4096;

  // ── 1. Homoglyph / Confusable Character Map (Unicode -> ASCII) ───────────
  const CONFUSABLE_CHAR_MAP = {
    // Cyrillic lowercase
    '\u0430': 'a', // а
    '\u0435': 'e', // е
    '\u0451': 'e', // ё
    '\u043e': 'o', // о
    '\u0440': 'p', // р
    '\u0441': 'c', // с
    '\u0443': 'y', // у
    '\u0445': 'x', // х
    '\u0456': 'i', // і
    '\u0458': 'j', // ј
    '\u0455': 's', // ѕ
    '\u04bb': 'h', // һ
    '\u0501': 'd', // ԁ
    '\u04cf': 'l', // ӏ
    '\u043a': 'k', // к
    '\u043c': 'm', // м
    '\u043d': 'h', // н
    '\u0432': 'b', // в
    '\u0433': 'r', // г
    '\u0437': '3', // з
    '\u0442': 't', // т
    '\u0454': 'e', // є
    '\u0457': 'i', // ї
    // Cyrillic uppercase
    '\u0410': 'a', // А
    '\u0412': 'b', // В
    '\u0415': 'e', // Е
    '\u041a': 'k', // К
    '\u041c': 'm', // М
    '\u041d': 'h', // Н
    '\u041e': 'o', // О
    '\u0420': 'p', // Р
    '\u0421': 'c', // С
    '\u0422': 't', // Т
    '\u0425': 'x', // Х
    '\u0406': 'i', // І
    '\u0408': 'j', // Ј
    '\u0405': 's', // Ѕ
    // Greek
    '\u03b1': 'a', // α
    '\u03b2': 'b', // β
    '\u03b5': 'e', // ε
    '\u03b9': 'i', // ι
    '\u03ba': 'k', // κ
    '\u03bd': 'v', // ν
    '\u03bf': 'o', // ο
    '\u03c1': 'p', // ρ
    '\u03c4': 't', // τ
    '\u03c5': 'u', // υ
    '\u03c7': 'x', // χ
    '\u0391': 'a', // Α
    '\u0392': 'b', // Β
    '\u0395': 'e', // Ε
    '\u0396': 'z', // Ζ
    '\u0397': 'h', // Η
    '\u0399': 'i', // Ι
    '\u039a': 'k', // Κ
    '\u039c': 'm', // Μ
    '\u039d': 'n', // Ν
    '\u039f': 'o', // Ο
    '\u03a1': 'p', // Ρ
    '\u03a4': 't', // Τ
    '\u03a7': 'x', // Χ
    // Latin lookalikes & accented / Turkish / IPA
    '\u0131': 'i', // ı dotless i
    '\u0261': 'g', // ɡ
    '\u026a': 'i', // ɪ
    '\u029f': 'l', // ʟ
    '\u1d04': 'c', // ᴄ
    '\u1d0f': 'o', // ᴏ
    '\u1d18': 'p', // ᴘ
    '\u00e0': 'a', '\u00e1': 'a', '\u00e2': 'a', '\u00e3': 'a', '\u00e4': 'a', '\u00e5': 'a',
    '\u00e8': 'e', '\u00e9': 'e', '\u00ea': 'e', '\u00eb': 'e',
    '\u00ec': 'i', '\u00ed': 'i', '\u00ee': 'i', '\u00ef': 'i',
    '\u00f2': 'o', '\u00f3': 'o', '\u00f4': 'o', '\u00f5': 'o', '\u00f6': 'o', '\u00f8': 'o',
    '\u00f9': 'u', '\u00fa': 'u', '\u00fb': 'u', '\u00fc': 'u',
    '\u00f1': 'n', '\u00e7': 'c', '\u0142': 'l', '\u015b': 's',
    // Armenian & Cherokee common confusables
    '\u0570': 'h', // հ
    '\u0578': 'n', // ո
    '\u0585': 'o', // օ
    '\u057d': 'u', // ս
    '\u0561': 'a', // ա
    // Common ASCII/Unicode dashes & dots
    '\u2010': '-', '\u2011': '-', '\u2012': '-', '\u2013': '-', '\u2014': '-',
    '\u3002': '.', '\uff0e': '.', '\ufe52': '.'
  };

  const INVISIBLE_CHARS_REGEX = /[\u200B-\u200F\u202A-\u202E\u2060\uFEFF\u00AD]/;

  // ── 2. Pure-JS RFC 3492 Punycode Decoder (xn-- labels -> Unicode) ─────────
  function decodePunycodeLabel(label) {
    if (!label || typeof label !== 'string') return label;
    const lower = label.toLowerCase();
    if (!lower.startsWith('xn--')) return label;

    const input = lower.slice(4);
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;

    function decodeDigit(cp) {
      if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26-35
      if (cp >= 65 && cp <= 90) return cp - 65; // A-Z -> 0-25
      if (cp >= 97 && cp <= 122) return cp - 97; // a-z -> 0-25
      return base;
    }

    function adapt(delta, numPoints, firstTime) {
      let k = 0;
      delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      while (delta > ((base - tMin) * tMax) >> 1) {
        delta = Math.floor(delta / (base - tMin));
        k += base;
      }
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    }

    try {
      const output = [];
      let basicEnd = input.lastIndexOf('-');
      if (basicEnd < 0) basicEnd = 0;

      for (let j = 0; j < basicEnd; j++) {
        const cp = input.charCodeAt(j);
        if (cp >= 0x80) return label;
        output.push(cp);
      }

      let n = initialN;
      let i = 0;
      let bias = initialBias;
      let index = basicEnd > 0 ? basicEnd + 1 : 0;

      while (index < input.length) {
        const oldi = i;
        let w = 1;
        for (let k = base; ; k += base) {
          if (index >= input.length) return label;
          const digit = decodeDigit(input.charCodeAt(index++));
          if (digit >= base) return label;
          if (digit > Math.floor((0x7fffffff - i) / w)) return label;
          i += digit * w;
          const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
          if (digit < t) break;
          if (w > Math.floor(0x7fffffff / (base - t))) return label;
          w *= (base - t);
        }
        const outLen = output.length + 1;
        bias = adapt(i - oldi, outLen, oldi === 0);
        if (Math.floor(i / outLen) > 0x7fffffff - n) return label;
        n += Math.floor(i / outLen);
        i %= outLen;
        output.splice(i++, 0, n);
      }
      return String.fromCodePoint(...output);
    } catch (e) {
      return label;
    }
  }

  function decodePunycodeHostname(hostname) {
    if (!hostname) return hostname;
    return hostname
      .split('.')
      .map(label => (label.toLowerCase().startsWith('xn--') ? decodePunycodeLabel(label) : label))
      .join('.');
  }

  // ── 3. Script Detection & Skeleton Normalization ─────────────────────────
  function detectCharScript(ch) {
    const cp = ch.codePointAt(0);
    if (cp <= 0x007f) {
      if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)) return 'Latin';
      return 'ASCII-Neutral';
    }
    if ((cp >= 0x0080 && cp <= 0x024f) || (cp >= 0x1d00 && cp <= 0x1dbf) || (cp >= 0x1e00 && cp <= 0x1eff)) {
      return 'Latin-Extended';
    }
    if ((cp >= 0x0400 && cp <= 0x04ff) || (cp >= 0x0500 && cp <= 0x052f)) {
      return 'Cyrillic';
    }
    if (cp >= 0x0370 && cp <= 0x03ff) {
      return 'Greek';
    }
    if (cp >= 0x0530 && cp <= 0x058f) {
      return 'Armenian';
    }
    if (cp >= 0x0590 && cp <= 0x05ff) return 'Hebrew';
    if (cp >= 0x0600 && cp <= 0x06ff) return 'Arabic';
    if (cp >= 0x0900 && cp <= 0x097f) return 'Devanagari';
    if (cp >= 0x4e00 && cp <= 0x9fff) return 'Han';
    if (cp >= 0xff01 && cp <= 0xff5e) return 'Fullwidth';
    return 'Unicode-Other';
  }

  function inspectHomographs(unicodeHost) {
    const suspiciousChars = [];
    const scriptsSet = new Set();
    let skeleton = '';
    let hasInvisible = false;

    for (const ch of unicodeHost) {
      if (INVISIBLE_CHARS_REGEX.test(ch)) {
        hasInvisible = true;
        suspiciousChars.push({
          char: ch,
          codePoint: 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0'),
          script: 'Invisible/Format',
          looksLike: '(hidden)'
        });
        continue;
      }

      const cp = ch.codePointAt(0);
      const script = detectCharScript(ch);
      if (script !== 'ASCII-Neutral') {
        scriptsSet.add(script === 'Latin-Extended' ? 'Latin' : script);
      }

      let mapped = ch;
      if (CONFUSABLE_CHAR_MAP[ch]) {
        mapped = CONFUSABLE_CHAR_MAP[ch];
      } else if (cp >= 0xff01 && cp <= 0xff5e) {
        // Fullwidth ASCII variants
        mapped = String.fromCharCode(cp - 0xfee0);
      }

      if (cp > 0x7f) {
        suspiciousChars.push({
          char: ch,
          codePoint: 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'),
          script: script,
          looksLike: mapped !== ch ? mapped : '?'
        });
      }

      skeleton += mapped.toLowerCase();
    }

    const nonAsciiCount = suspiciousChars.length;
    // Mixed script if multiple distinct alphabetic scripts exist (e.g. Latin + Cyrillic)
    const scripts = Array.from(scriptsSet);
    const hasMixedScripts = scripts.length > 1;
    const hasNonLatinConfusable = suspiciousChars.some(
      s => s.script !== 'Latin' && s.script !== 'Latin-Extended' && s.script !== 'Invisible/Format' && s.looksLike !== '?'
    );

    return {
      suspiciousChars,
      scripts,
      hasMixedScripts,
      hasInvisible,
      hasNonLatinConfusable,
      hasUnicode: nonAsciiCount > 0,
      skeleton
    };
  }

  // ── 4. Lightweight Damerau-Levenshtein & ASCII Lookalike Normalization ─────
  function damerauLevenshtein(a, b) {
    const la = a.length;
    const lb = b.length;
    if (la === 0) return lb;
    if (lb === 0) return la;

    const dp = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));
    for (let i = 0; i <= la; i++) dp[i][0] = i;
    for (let j = 0; j <= lb; j++) dp[0][j] = j;

    for (let i = 1; i <= la; i++) {
      for (let j = 1; j <= lb; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        let val = Math.min(
          dp[i - 1][j] + 1,      // deletion
          dp[i][j - 1] + 1,      // insertion
          dp[i - 1][j - 1] + cost // substitution
        );
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          val = Math.min(val, dp[i - 2][j - 2] + 1); // adjacent transposition
        }
        dp[i][j] = val;
      }
    }
    return dp[la][lb];
  }

  function normalizeAsciiLookalikes(str) {
    return str
      .toLowerCase()
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/7/g, 't')
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w');
  }

  function stripAsciiControls(str) {
    return typeof str === 'string' ? str.replace(/[\u0000-\u001f\u007f]+/g, '') : '';
  }

  function hasPunycodeLabel(host) {
    return Boolean(host) && String(host).split('.').some(l => l.toLowerCase().startsWith('xn--'));
  }

  function looksLikeBareDomainUrl(str) {
    if (!str || typeof str !== 'string' || /\s/.test(str)) return false;
    if (/^[a-z0-9+.-]+:/i.test(str) && !/^[a-z0-9.-]+:\d+(?:\/|$)/i.test(str)) return false;
    const beforeQuery = str.split('?')[0].split('#')[0];
    const hostPart = beforeQuery.split('/')[0];
    // Reject bare email addresses like user@example.com unless a path or port follows
    if (hostPart.includes('@') && !beforeQuery.includes('/') && !/:[0-9]+$/.test(hostPart)) {
      return false;
    }
    const targetHostPort = hostPart.includes('@') ? hostPart.slice(hostPart.lastIndexOf('@') + 1) : hostPart;
    const hostOnly = targetHostPort.replace(/:\d+$/, '');
    if (!hostOnly || /[<>"'=();@]/.test(hostOnly)) return false;
    return /^[^\s\/.<>"'=();:@]+(?:\.[^\s\/.<>"'=();:@]+)+$/.test(hostOnly) && /\.(?:[a-z\u0080-\uffff]{2,}|xn--[a-z0-9]{2,})$/i.test(hostOnly);
  }

  // ── 5. Universal QR Type Classifier ──────────────────────────────────────
  function classifyQRType(payload) {
    if (!payload || typeof payload !== 'string') {
      return { type: 'unknown', label: 'Unknown', icon: 'fa-question-circle', parsedData: {} };
    }
    const p = payload.trim();

    // UPI Payment QR
    if (/^upi:\/\//i.test(p)) {
      const params = {};
      try {
        const url = new URL(p);
        params.pa = url.searchParams.get('pa') || '';
        params.pn = url.searchParams.get('pn') || '';
        params.am = url.searchParams.get('am') || '';
        params.tn = url.searchParams.get('tn') || '';
        params.cu = url.searchParams.get('cu') || 'INR';
      } catch (e) { /* ignore parse error */ }
      return {
        type: 'upi',
        label: 'UPI Payment',
        icon: 'fa-indian-rupee-sign',
        parsedData: {
          payeeAddress: params.pa,
          payeeName: params.pn,
          amount: params.am || 'Not specified',
          note: params.tn || 'None',
          currency: params.cu
        }
      };
    }

    // Wi-Fi QR (WIFI:S:ssid;T:WPA;P:pass;;)
    if (/^WIFI:/i.test(p)) {
      const ssid = (p.match(/S:([^;]+)/i) || [])[1] || '';
      const type = (p.match(/T:([^;]+)/i) || [])[1] || 'WPA';
      const hidden = (p.match(/H:(true|false)/i) || [])[1] || 'false';
      return {
        type: 'wifi',
        label: 'Wi-Fi Network',
        icon: 'fa-wifi',
        parsedData: {
          ssid,
          security: type.toUpperCase(),
          hidden: hidden === 'true',
          password: '●●●●●●●● (masked for privacy)'
        }
      };
    }

    // vCard Contact
    if (/^BEGIN:VCARD/i.test(p)) {
      const name = (p.match(/FN:([\s\S]+?)(?=[\r\n]+|\s+(?:(?:TEL|EMAIL|ORG|ADR|URL|NOTE)[:;]|END:VCARD)|$)/i) || [])[1] || '';
      const tel = (p.match(/TEL[^:]*:([\s\S]+?)(?=[\r\n]+|\s+(?:(?:FN|EMAIL|ORG|ADR|URL|NOTE)[:;]|END:VCARD)|$)/i) || [])[1] || '';
      const email = (p.match(/EMAIL[^:]*:([\s\S]+?)(?=[\r\n]+|\s+(?:(?:FN|TEL|ORG|ADR|URL|NOTE)[:;]|END:VCARD)|$)/i) || [])[1] || '';
      const org = (p.match(/ORG:([\s\S]+?)(?=[\r\n]+|\s+(?:(?:FN|TEL|EMAIL|ADR|URL|NOTE)[:;]|END:VCARD)|$)/i) || [])[1] || '';
      return {
        type: 'vcard',
        label: 'Contact Card (vCard)',
        icon: 'fa-address-card',
        parsedData: { name: name.trim(), phone: tel.trim(), email: email.trim(), organization: org.trim() }
      };
    }

    // Email (mailto:)
    if (/^mailto:/i.test(p)) {
      let to = '', subject = '', body = '';
      try {
        const url = new URL(p);
        to = url.pathname;
        subject = url.searchParams.get('subject') || '';
        body = url.searchParams.get('body') || '';
      } catch (e) {
        to = p.replace(/^mailto:/i, '').split('?')[0];
      }
      return {
        type: 'email',
        label: 'Email Address',
        icon: 'fa-envelope',
        parsedData: { to, subject, body: body ? body.substring(0, 80) + (body.length > 80 ? '…' : '') : '' }
      };
    }

    // Phone number (tel:)
    if (/^tel:/i.test(p)) {
      return {
        type: 'phone',
        label: 'Phone Number',
        icon: 'fa-phone',
        parsedData: { number: p.replace(/^tel:/i, '') }
      };
    }

    // SMS
    if (/^(sms:|smsto:)/i.test(p)) {
      const raw = p.replace(/^(sms:|smsto:)/i, '');
      const [number, ...msgParts] = raw.split(':');
      return {
        type: 'sms',
        label: 'SMS Message',
        icon: 'fa-comment-sms',
        parsedData: { number: number.trim(), message: msgParts.join(':').trim() || '' }
      };
    }

    // Geo location (geo:lat,lng)
    if (/^geo:/i.test(p)) {
      const coords = p.replace(/^geo:/i, '').split(',');
      return {
        type: 'geo',
        label: 'Geographic Location',
        icon: 'fa-location-dot',
        parsedData: {
          latitude: coords[0] || '',
          longitude: coords[1] ? coords[1].split(';')[0] : ''
        }
      };
    }

    // Dangerous / executable schemes (checked before host-based classifications; strip control chars to block bypass)
    const normalizedSchemeInput = stripAsciiControls(p);
    if (/^(javascript:|data:|file:|vbscript:|intent:)/i.test(normalizedSchemeInput)) {
      return {
        type: 'dangerous',
        label: 'Dangerous Executable Scheme',
        icon: 'fa-skull-crossbones',
        parsedData: { scheme: normalizedSchemeInput.split(':')[0] }
      };
    }

    // App Store links (Apple / Google Play) - strict host matching to prevent spoofing
    let candidateHost = '';
    try {
      if (/^https?:\/\//i.test(p) || /^ftp:\/\//i.test(p)) {
        candidateHost = new URL(p).hostname.toLowerCase();
      } else if (looksLikeBareDomainUrl(p)) {
        candidateHost = extractRawUrlParts(p).rawHost.toLowerCase();
      }
    } catch (e) {
      candidateHost = '';
    }

    if (
      (candidateHost === 'apps.apple.com' || candidateHost.endsWith('.apps.apple.com')) ||
      ((candidateHost === 'play.google.com' || candidateHost.endsWith('.play.google.com')) && /\/store/i.test(p))
    ) {
      const store = candidateHost.includes('apple.com') ? 'Apple App Store' : 'Google Play Store';
      return {
        type: 'applink',
        label: `App Download (${store})`,
        icon: 'fa-mobile-screen-button',
        parsedData: { store, url: p }
      };
    }

    // Social Media detection (strict domain matching)
    const socialDomains = {
      'facebook.com': { label: 'Facebook', icon: 'fa-brands fa-facebook' },
      'instagram.com': { label: 'Instagram', icon: 'fa-brands fa-instagram' },
      'twitter.com': { label: 'X / Twitter', icon: 'fa-brands fa-x-twitter' },
      'x.com': { label: 'X / Twitter', icon: 'fa-brands fa-x-twitter' },
      'linkedin.com': { label: 'LinkedIn', icon: 'fa-brands fa-linkedin' },
      'youtube.com': { label: 'YouTube', icon: 'fa-brands fa-youtube' },
      'youtu.be': { label: 'YouTube', icon: 'fa-brands fa-youtube' },
      'tiktok.com': { label: 'TikTok', icon: 'fa-brands fa-tiktok' },
      'wa.me': { label: 'WhatsApp', icon: 'fa-brands fa-whatsapp' },
      'whatsapp.com': { label: 'WhatsApp', icon: 'fa-brands fa-whatsapp' }
    };

    if (candidateHost) {
      for (const [domain, info] of Object.entries(socialDomains)) {
        if (candidateHost === domain || candidateHost.endsWith('.' + domain)) {
          return {
            type: 'social',
            label: `Social Media (${info.label})`,
            icon: info.icon,
            parsedData: { platform: info.label, url: p }
          };
        }
      }
    }

    // Web URL (http / https / ftp)
    if (/^https?:\/\//i.test(p) || /^ftp:\/\//i.test(p)) {
      try {
        const url = new URL(p);
        return {
          type: 'url',
          label: 'Website URL',
          icon: 'fa-globe',
          parsedData: {
            protocol: url.protocol,
            host: url.hostname,
            path: url.pathname !== '/' ? url.pathname : '',
            query: url.search || ''
          }
        };
      } catch (e) {
        // Malformed URL with explicit web scheme still classified as URL for forensic inspection
        return {
          type: 'url',
          label: 'Malformed Website URL',
          icon: 'fa-globe',
          parsedData: { raw: p.slice(0, 120) }
        };
      }
    }

    // Plain URL without protocol that looks like a domain (ASCII or Unicode domain labels)
    if (looksLikeBareDomainUrl(p)) {
      return {
        type: 'url',
        label: 'Website URL',
        icon: 'fa-globe',
        parsedData: { host: p.split('/')[0], path: p.includes('/') ? '/' + p.split('/').slice(1).join('/') : '' }
      };
    }

    // Plain text fallback
    return {
      type: 'text',
      label: 'Plain Text',
      icon: 'fa-font',
      parsedData: { length: p.length, preview: p.substring(0, 100) }
    };
  }

  // ── 6. Domain & Host Helper ──────────────────────────────────────────────
  function parseHost(hostname) {
    if (!hostname) return { domainParts: [], tld: '', sld: '', registeredDomain: '', subdomains: [] };
    const clean = hostname.replace(/\.+$/, '').toLowerCase();
    const parts = clean.split('.').filter(Boolean);
    const tld = parts.length > 1 ? parts[parts.length - 1] : '';

    const multiPartSuffixes = [
      'co.uk', 'com.au', 'co.jp', 'gov.uk', 'org.uk', 'ac.uk', 'com.br', 'co.nz',
      'co.in', 'net.in', 'org.in', 'gov.in', 'com.sg', 'co.za'
    ];
    let registeredDomain = clean;
    let sld = '';
    let regPartsCount = 1;

    if (parts.length >= 2) {
      const lastTwo = parts.slice(-2).join('.');
      if (multiPartSuffixes.includes(lastTwo) && parts.length >= 3) {
        regPartsCount = 3;
        registeredDomain = parts.slice(-3).join('.');
        sld = parts[parts.length - 3];
      } else {
        regPartsCount = 2;
        registeredDomain = parts.slice(-2).join('.');
        sld = parts[parts.length - 2];
      }
    } else {
      sld = clean;
    }

    const subdomains = parts.length > regPartsCount ? parts.slice(0, parts.length - regPartsCount) : [];

    return { domainParts: parts, tld, sld, registeredDomain, subdomains };
  }

  // ── 7. Threat Intelligence Reference Lists ───────────────────────────────
  const KNOWN_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
    'goo.gl', 'cutt.ly', 'rb.gy', 'bl.ink', 'shorturl.at', 'rebrand.ly', 'short.io', 'tiny.cc'
  ];

  const HIGH_RISK_TLDS = [
    'top', 'xyz', 'club', 'work', 'click', 'link', 'zip', 'mov', 'kim',
    'gq', 'cf', 'ml', 'ga', 'tk', 'su', 'buzz', 'best', 'monster', 'rest',
    'icu', 'cam', 'online', 'fit', 'surf', 'support', 'cfd', 'sbs', 'quest'
  ];

  // Popular targeted brands for impersonation & typosquatting analysis
  const BRAND_TARGETS = [
    { name: 'PayPal', keyword: 'paypal', legitDomains: ['paypal.com', 'paypal.me'] },
    { name: 'Apple', keyword: 'apple', legitDomains: ['apple.com', 'icloud.com'] },
    { name: 'Microsoft', keyword: 'microsoft', legitDomains: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'microsoftonline.com'] },
    { name: 'Google', keyword: 'google', legitDomains: ['google.com', 'gmail.com', 'googleapis.com', 'gstatic.com'] },
    { name: 'Chase Bank', keyword: 'chase', legitDomains: ['chase.com'] },
    { name: 'Wells Fargo', keyword: 'wellsfargo', legitDomains: ['wellsfargo.com'] },
    { name: 'Bank of America', keyword: 'bankofamerica', legitDomains: ['bankofamerica.com'] },
    { name: 'Amazon', keyword: 'amazon', legitDomains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'aws.amazon.com'] },
    { name: 'Netflix', keyword: 'netflix', legitDomains: ['netflix.com'] },
    { name: 'Binance', keyword: 'binance', legitDomains: ['binance.com'] },
    { name: 'Coinbase', keyword: 'coinbase', legitDomains: ['coinbase.com'] },
    { name: 'GitHub', keyword: 'github', legitDomains: ['github.com', 'githubusercontent.com'] },
    { name: 'Facebook', keyword: 'facebook', legitDomains: ['facebook.com', 'fb.com'] },
    { name: 'Instagram', keyword: 'instagram', legitDomains: ['instagram.com'] },
    { name: 'LinkedIn', keyword: 'linkedin', legitDomains: ['linkedin.com'] },
    { name: 'Dropbox', keyword: 'dropbox', legitDomains: ['dropbox.com'] },
    { name: 'Stripe', keyword: 'stripe', legitDomains: ['stripe.com'] },
    { name: 'Wikipedia', keyword: 'wikipedia', legitDomains: ['wikipedia.org', 'wikimedia.org'] }
  ];

  // Safe standard domains that should not trigger false-positive typosquatting
  const SAFE_TYPOSQUAT_ALLOWLIST = new Set([
    'example.com', 'example.org', 'example.net', 'localhost',
    'target.com', 'reddit.com', 'pinterest.com', 'youtube.com', 'youtu.be',
    'twitter.com', 'x.com', 'whatsapp.com', 'wa.me', 'tiktok.com', 'docs-portal.top'
  ]);

  // Credential Harvesting & Phishing Action Keywords
  const CREDENTIAL_KEYWORDS = [
    'login', 'signin', 'verify', 'password', 'passwd', 'reset', 'account',
    'banking', 'wallet', 'secure', 'authentication', 'auth', 'claim', 'prize',
    'free-gift', 'free-reward', 'billing', 'passcode', 'recover', 'security-update'
  ];

  const SCAM_BAIT_KEYWORDS = ['claim', 'prize', 'free-gift', 'free-reward'];

  const BOUNDARY_CREDENTIAL_KEYWORDS = new Set([
    'auth', 'reset', 'claim', 'prize', 'account', 'secure', 'recover', 'billing'
  ]);

  function matchCredentialKeywords(text) {
    if (!text) return [];
    const lower = text.toLowerCase();
    return CREDENTIAL_KEYWORDS.filter(kw => {
      if (BOUNDARY_CREDENTIAL_KEYWORDS.has(kw)) {
        const escaped = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return new RegExp(`(?:^|[^a-z])${escaped}(?:$|[^a-z])`, 'i').test(lower);
      }
      return lower.includes(kw);
    });
  }

  const REDIRECT_PARAM_NAMES = new Set([
    'redirect', 'redirect_uri', 'redirect_url', 'next', 'url', 'target', 'dest',
    'destination', 'return', 'return_to', 'returnto', 'continue', 'goto', 'out',
    'view', 'callback', 'forward', 'redir', 'u', 'r'
  ]);

  const SENSITIVE_QUERY_PARAM_NAMES = new Set([
    'password', 'passwd', 'pwd', 'pass', 'pin', 'otp', 'secret', 'passcode',
    'cvv', 'ssn', 'auth_token', 'session', 'sessionid', 'access_token', 'credential'
  ]);

  // ── 8. Defensive Raw URL Decomposition Helper ────────────────────────────
  function extractRawUrlParts(inputStr) {
    // Capture literal raw components before WHATWG URL auto-normalizes Unicode to Punycode
    const trimmed = inputStr.trim();
    const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
    const hasExplicitScheme = Boolean(schemeMatch);
    const rawScheme = schemeMatch ? schemeMatch[1].toLowerCase() + ':' : 'http:';
    const afterScheme = hasExplicitScheme ? trimmed.slice(schemeMatch[0].length) : trimmed;

    // Split fragment, query, path safely
    const hashIdx = afterScheme.indexOf('#');
    const beforeHash = hashIdx >= 0 ? afterScheme.slice(0, hashIdx) : afterScheme;
    const rawFragment = hashIdx >= 0 ? afterScheme.slice(hashIdx) : '';

    const queryIdx = beforeHash.indexOf('?');
    const beforeQuery = queryIdx >= 0 ? beforeHash.slice(0, queryIdx) : beforeHash;
    const rawQuery = queryIdx >= 0 ? beforeHash.slice(queryIdx) : '';

    const slashIdx = beforeQuery.indexOf('/');
    const rawAuthority = slashIdx >= 0 ? beforeQuery.slice(0, slashIdx) : beforeQuery;
    const rawPath = slashIdx >= 0 ? beforeQuery.slice(slashIdx) : '/';

    // Authority can contain userinfo@host:port
    const atIdx = rawAuthority.lastIndexOf('@');
    const rawUserInfo = atIdx >= 0 ? rawAuthority.slice(0, atIdx) : '';
    const hostPort = atIdx >= 0 ? rawAuthority.slice(atIdx + 1) : rawAuthority;

    let rawHost = hostPort;
    let rawPort = '';
    if (hostPort.startsWith('[')) {
      const closeBracket = hostPort.indexOf(']');
      if (closeBracket >= 0) {
        rawHost = hostPort.slice(0, closeBracket + 1);
        const afterBracket = hostPort.slice(closeBracket + 1);
        if (afterBracket.startsWith(':')) rawPort = afterBracket.slice(1);
      }
    } else {
      const colonIdx = hostPort.indexOf(':');
      if (colonIdx >= 0) {
        rawHost = hostPort.slice(0, colonIdx);
        rawPort = hostPort.slice(colonIdx + 1);
      }
    }

    return {
      hasExplicitScheme,
      rawScheme,
      rawAuthority,
      rawUserInfo,
      rawHost,
      rawPort,
      rawPath,
      rawQuery,
      rawFragment
    };
  }

  function safeDecodeURIComponent(str) {
    try {
      return { decoded: decodeURIComponent(str), malformed: false };
    } catch (e) {
      return { decoded: str, malformed: true };
    }
  }

  function parseQueryParameters(rawQuery) {
    if (!rawQuery || rawQuery === '?') return [];
    const qs = rawQuery.startsWith('?') ? rawQuery.slice(1) : rawQuery;
    if (!qs) return [];

    return qs.split('&').filter(Boolean).slice(0, 40).map(pair => {
      const eqIdx = pair.indexOf('=');
      const rawKey = eqIdx >= 0 ? pair.slice(0, eqIdx) : pair;
      const rawVal = eqIdx >= 0 ? pair.slice(eqIdx + 1) : '';
      const keyDec = safeDecodeURIComponent(rawKey.replace(/\+/g, ' '));
      const valDec = safeDecodeURIComponent(rawVal.replace(/\+/g, ' '));
      // Second decode pass to detect double-encoding
      const doubleValDec = safeDecodeURIComponent(valDec.decoded);

      const flags = [];
      const keyLower = keyDec.decoded.toLowerCase();
      const valLower = valDec.decoded.toLowerCase();
      const doubleLower = doubleValDec.decoded.toLowerCase();

      if (REDIRECT_PARAM_NAMES.has(keyLower)) {
        if (/^(https?:|\/\/|ftp:)/i.test(valDec.decoded) || /^(https?:|\/\/)/i.test(doubleValDec.decoded) || /https?%3a%2f%2f/i.test(rawVal)) {
          flags.push('nested-redirect-url');
        }
        if (/^(javascript:|data:|vbscript:)/i.test(valLower) || /^(javascript:|data:|vbscript:)/i.test(doubleLower)) {
          flags.push('executable-redirect');
        }
        if (/%[0-9a-f]{2}/i.test(rawVal) && valDec.decoded !== rawVal) {
          flags.push('encoded-redirect');
        }
      } else if (/https?:\/\/|https?%3a%2f%2f/i.test(rawVal) || /https?:\/\//i.test(valLower)) {
        flags.push('nested-url-value');
      }

      if (/%25[0-9a-f]{2}/i.test(rawVal) || /%25[0-9a-f]{2}/i.test(rawKey)) {
        flags.push('double-encoded');
      }
      if (SENSITIVE_QUERY_PARAM_NAMES.has(keyLower)) {
        flags.push('credential-parameter');
      }
      if (keyDec.malformed || valDec.malformed) {
        flags.push('malformed-encoding');
      }

      return {
        key: keyDec.decoded,
        rawKey,
        value: rawVal,
        decodedValue: doubleValDec.decoded !== valDec.decoded ? doubleValDec.decoded : valDec.decoded,
        flags
      };
    });
  }

  // ── 9. Main Analyzer Object ──────────────────────────────────────────────
  const QRAnalyzer = {

    analyze: function(rawPayload) {
      const qrClassification = classifyQRType(rawPayload);

      const result = {
        input: rawPayload,
        isUrl: false,
        qrType: qrClassification.type,
        qrTypeLabel: qrClassification.label,
        qrTypeIcon: qrClassification.icon,
        parsedData: qrClassification.parsedData,
        score: 0,
        status: 'Safe', // Safe (0-29), Suspicious (30-69), Dangerous (70-100)
        issues: [],
        scoreBreakdown: [],
        highlights: [],
        threatCategories: [],
        detectedIndicators: [],
        highlightedComponents: [],
        forensics: null,
        explanation: '',
        advice: '',
        recommendation: '',
        disclaimer: 'Disclaimer: QR Guard uses transparent offline heuristic risk scoring for educational and security evaluation. It does not guarantee absolute URL safety or provide real-time domain reputation.',
        engineVersion: '2.1.0-forensics',
        metrics: {
          protocol: 'N/A',
          hostType: 'Text Payload',
          tld: 'N/A',
          pointsAssigned: 0
        },
        details: {}
      };

      function recordFinding(finding) {
        result.issues.push({
          severity: finding.severity,
          category: finding.category,
          title: finding.title,
          points: finding.points,
          message: finding.message
        });
        result.scoreBreakdown.push({
          factor: finding.factor || finding.title,
          points: finding.points
        });
        result.detectedIndicators.push({
          id: finding.id || finding.title.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
          title: finding.title,
          category: finding.category,
          points: finding.points,
          severity: finding.severity,
          reason: finding.message,
          component: finding.component || 'URL'
        });
        if (!result.threatCategories.includes(finding.category)) {
          result.threatCategories.push(finding.category);
        }
        if (finding.component && finding.componentValue !== undefined) {
          result.highlightedComponents.push({
            part: finding.component,
            value: String(finding.componentValue).slice(0, 180),
            reason: finding.title,
            severity: finding.severity
          });
        }
      }

      // 1. Validation for empty / null / non-string payload
      if (!rawPayload || typeof rawPayload !== 'string' || rawPayload.trim() === '') {
        recordFinding({
          id: 'empty-payload',
          severity: 'high',
          category: 'Data Format',
          title: 'Empty Payload',
          factor: 'Empty / Corrupted QR Data',
          points: 100,
          message: 'The QR code contains empty or unreadable data.',
          component: 'Payload',
          componentValue: '(empty)'
        });
        result.score = 100;
        result.status = 'Dangerous';
        result.metrics.pointsAssigned = 100;
        result.explanation = 'Empty or corrupted QR data cannot be safely processed.';
        result.advice = 'Do not open or execute this QR payload.';
        result.recommendation = result.advice;
        return result;
      }

      // Guard against oversized payloads (ReDoS / memory protection)
      const isOversized = rawPayload.length > MAX_PAYLOAD_LENGTH;
      const payload = rawPayload.slice(0, MAX_PAYLOAD_LENGTH).trim();

      // 2. Dangerous / executable protocol schemes (strip control chars against java\tscript: obfuscation)
      const normalizedPayloadScheme = stripAsciiControls(payload);
      if (/^(javascript:|data:|file:|vbscript:|intent:)/i.test(normalizedPayloadScheme)) {
        const scheme = normalizedPayloadScheme.split(':')[0].toLowerCase() + ':';
        result.isUrl = true;
        result.score = 100;
        result.status = 'Dangerous';
        result.metrics.protocol = scheme.toUpperCase();
        result.metrics.hostType = 'Executable Scheme';
        result.metrics.pointsAssigned = 100;
        recordFinding({
          id: 'executable-scheme',
          severity: 'high',
          category: 'Protocol Security',
          title: 'Executable Protocol Scheme',
          factor: `Dangerous Protocol Scheme (${scheme})`,
          points: 100,
          message: `Uses high-risk scheme (${scheme}) which can execute arbitrary script commands or access local system files.`,
          component: 'Protocol',
          componentValue: scheme
        });
        result.forensics = {
          protocol: scheme.replace(':', '').toUpperCase(),
          hostname: '',
          rawHostname: '',
          punycodeHostname: '',
          decodedHostname: '',
          rootDomain: '',
          subdomains: [],
          port: '',
          path: payload.slice(scheme.length, 160),
          queryParams: [],
          fragment: '',
          encodedComponents: [],
          suspiciousCharacteristics: [`Executable scheme (${scheme})`],
          malformed: false,
          malformedReasons: []
        };
        result.explanation = `Dangerous executable scheme (${scheme}) detected. This payload can execute arbitrary code on device.`;
        result.advice = 'CRITICAL: Do not open or run this QR payload. It uses an executable scheme designed to exploit browser or system handlers.';
        result.recommendation = result.advice;
        return result;
      }

      // 3. Determine whether payload is a Web URL (including Unicode / malformed URLs)
      const rawParts = extractRawUrlParts(payload);
      let parsedUrl = null;
      let urlMalformed = false;
      const malformedReasons = [];

      const looksLikeWebUrl =
        /^https?:\/\//i.test(payload) ||
        /^ftp:\/\//i.test(payload) ||
        looksLikeBareDomainUrl(payload);

      if (looksLikeWebUrl) {
        const urlCandidate = rawParts.hasExplicitScheme ? payload : 'http://' + payload;
        try {
          parsedUrl = new URL(urlCandidate);
          if (parsedUrl.protocol && ['http:', 'https:', 'ftp:'].includes(parsedUrl.protocol.toLowerCase())) {
            result.isUrl = true;
          }
        } catch (e) {
          // Malformed URL that still claims a web scheme or domain-like shape
          if (/^(https?|ftp):\/\//i.test(payload)) {
            result.isUrl = true;
            urlMalformed = true;
            malformedReasons.push('Failed strict WHATWG URL parsing (invalid host, port, or characters)');
          } else {
            result.isUrl = false;
          }
        }
      }

      // --- NON-URL PAYLOAD EVALUATION ---
      if (!result.isUrl) {
        result.metrics.hostType = 'Plain Text / Config';

        if (/<script|cmd\.exe|powershell|bash\s+-c/i.test(payload)) {
          result.score = 90;
          result.status = 'Dangerous';
          result.metrics.pointsAssigned = 90;
          recordFinding({
            id: 'script-injection',
            severity: 'high',
            category: 'Script Injection',
            title: 'Executable Code Detected',
            factor: 'Executable Script / Code Pattern',
            points: 90,
            message: 'Payload contains executable code, script tags, or terminal commands.',
            component: 'Payload',
            componentValue: payload.slice(0, 100)
          });
          result.explanation = 'The QR code contains script or command syntax that could execute malicious instructions if processed.';
          result.advice = 'Avoid copying or executing this payload in browsers or command terminals.';
        } else if (/^WIFI:/i.test(payload)) {
          result.score = 10;
          result.status = 'Safe';
          result.metrics.pointsAssigned = 10;
          result.scoreBreakdown.push({ factor: 'Wi-Fi Network Credentials', points: 10 });
          result.highlights.push({
            category: 'Wi-Fi Configuration',
            title: 'Standard Wi-Fi Data',
            message: 'Contains network SSID and encryption passphrase.'
          });
          result.explanation = 'This payload configures a local Wi-Fi connection rather than linking to an external website.';
          result.advice = 'Verify that you recognize the Wi-Fi network SSID before connecting.';
        } else if (/^upi:\/\//i.test(payload)) {
          result.score = 10;
          result.status = 'Safe';
          result.metrics.protocol = 'UPI';
          result.metrics.hostType = 'Payment Intent';
          result.metrics.pointsAssigned = 10;
          result.scoreBreakdown.push({ factor: 'UPI Payment Handler', points: 10 });
          result.highlights.push({
            category: 'Payment Intent',
            title: 'Standard UPI Payment Payload',
            message: 'Invokes a local UPI payment app intent rather than opening an external webpage.'
          });
          result.explanation = 'This UPI payload prepares a payment prompt targeting the specified VPA.';
          result.advice = 'Always verify the payee name and transaction amount inside your UPI app before entering your PIN.';
        } else if (/^(tel:|sms:|smsto:|mailto:|geo:)/i.test(payload)) {
          result.score = 10;
          result.status = 'Safe';
          result.metrics.pointsAssigned = 10;
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
          result.metrics.pointsAssigned = 0;
          result.scoreBreakdown.push({ factor: 'Standard Plain Text', points: 0 });
          result.highlights.push({
            category: 'Plain Text Payload',
            title: 'No Web Link',
            message: 'Decoded payload is plain text data.'
          });
          result.explanation = 'Plain text content poses no direct web link risks.';
          result.advice = 'Plain text is safe to view. Exercise normal caution if manual links are written inside the text.';
        }
        result.recommendation = result.advice;
        return result;
      }

      // ── 10. URL STRUCTURE FORENSICS DECOMPOSITION ──────────────────────────
      const protocol = (parsedUrl ? parsedUrl.protocol : rawParts.rawScheme).toLowerCase();
      const hostname = (parsedUrl ? parsedUrl.hostname : rawParts.rawHost).toLowerCase();
      const rawHostname = (rawParts.rawHost || hostname).toLowerCase();
      const fullUrl = parsedUrl ? parsedUrl.href : payload;
      const pathname = parsedUrl ? parsedUrl.pathname : rawParts.rawPath;
      const searchStr = parsedUrl ? parsedUrl.search : rawParts.rawQuery;
      const fragment = parsedUrl ? parsedUrl.hash : rawParts.rawFragment;
      const port = parsedUrl ? parsedUrl.port : rawParts.rawPort;

      // Punycode decoding: check both parsedUrl.hostname (may be xn--) and rawHostname at label boundaries
      const punycodeHostname = hasPunycodeLabel(hostname) ? hostname : '';
      const decodedUnicodeHost = hasPunycodeLabel(hostname)
        ? decodePunycodeHostname(hostname)
        : rawHostname;

      const { domainParts, tld, sld, registeredDomain, subdomains } = parseHost(hostname);
      const decodedHostParts = parseHost(decodedUnicodeHost);
      const queryParams = parseQueryParameters(searchStr);

      // Collect encoded components across URL
      const encodedComponents = [];
      const pctMatches = fullUrl.match(/%[0-9a-f]{2}/gi) || [];
      if (pctMatches.length > 0) {
        encodedComponents.push(`${pctMatches.length} percent-encoded sequence(s)`);
      }
      if (/%25[0-9a-f]{2}/i.test(fullUrl)) {
        encodedComponents.push('Double-encoded sequence (%25xx)');
      }
      if (hasPunycodeLabel(hostname) || hasPunycodeLabel(rawHostname)) {
        encodedComponents.push(`Punycode IDN (${punycodeHostname || rawHostname})`);
      }

      // Check additional malformed signals
      if (/\s/.test(payload)) {
        urlMalformed = true;
        malformedReasons.push('Contains whitespace characters inside URL');
      }
      if (!hostname) {
        urlMalformed = true;
        malformedReasons.push('Missing hostname');
      }
      if (rawParts.rawPort && !/^\d+$/.test(rawParts.rawPort)) {
        urlMalformed = true;
        malformedReasons.push(`Invalid non-numeric port '${rawParts.rawPort}'`);
      }
      if (/%(?![0-9a-f]{2})/i.test(payload)) {
        urlMalformed = true;
        malformedReasons.push('Malformed percent-encoding sequence');
      }

      const suspiciousCharacteristics = [];

      result.metrics.protocol = protocol.replace(':', '').toUpperCase();
      result.metrics.hostType = 'Domain Host';
      result.metrics.tld = tld ? `.${tld}` : 'N/A';

      let points = 0;

      // ── INDICATOR 1: Protocol Security ─────────────────────────────────────
      if (protocol === 'http:') {
        points += 20;
        suspiciousCharacteristics.push('Unencrypted HTTP protocol');
        recordFinding({
          id: 'http-protocol',
          severity: 'medium',
          category: 'Protocol Security',
          title: 'Unencrypted HTTP Protocol',
          factor: 'Unencrypted HTTP Connection',
          points: 20,
          message: 'HTTP transmits data in plain text without SSL/TLS encryption, exposing traffic to interception.',
          component: 'Protocol',
          componentValue: 'http://'
        });
      } else if (protocol === 'https:') {
        result.highlights.push({
          category: 'Protocol Security',
          title: 'Encrypted HTTPS Protocol',
          message: 'Uses secure HTTPS encryption.'
        });
      } else if (protocol === 'ftp:') {
        points += 15;
        suspiciousCharacteristics.push('Unencrypted FTP protocol');
        recordFinding({
          id: 'ftp-protocol',
          severity: 'low',
          category: 'Protocol Security',
          title: 'Unencrypted File Transfer Protocol',
          factor: 'FTP Protocol',
          points: 15,
          message: 'Uses standard FTP which transmits data without modern transport layer encryption.',
          component: 'Protocol',
          componentValue: 'ftp://'
        });
      }

      // ── INDICATOR 2: Raw IP Hostname Detection ─────────────────────────────
      const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[[a-f0-9:]+\]$/i;
      const isIpHost = ipRegex.test(hostname);
      if (isIpHost) {
        points += 35;
        result.metrics.hostType = 'Raw IP Host';
        suspiciousCharacteristics.push(`Direct IP host (${hostname})`);
        recordFinding({
          id: 'raw-ip-host',
          severity: 'high',
          category: 'Host Identity',
          title: 'Raw IP Hostname',
          factor: 'Direct IP Address Host',
          points: 35,
          message: 'Uses a direct IP address instead of a domain name. Attackers use direct IPs to evade domain reputation filters.',
          component: 'Hostname',
          componentValue: hostname
        });
      } else if (hostname) {
        result.highlights.push({
          category: 'Host Identity',
          title: 'Standard Domain Name',
          message: `Resolves via standard domain name (${hostname}).`
        });
      }

      // ── INDICATOR 3: Malformed / Oversized URL Check ───────────────────────
      if (isOversized) {
        points += 25;
        suspiciousCharacteristics.push(`Oversized payload (${rawPayload.length} chars)`);
        recordFinding({
          id: 'oversized-url',
          severity: 'high',
          category: 'URL Structure',
          title: 'Oversized QR Payload',
          points: 25,
          message: `Payload length (${rawPayload.length} chars) exceeds safe inspection limits (${MAX_PAYLOAD_LENGTH} chars).`,
          component: 'Payload',
          componentValue: `${rawPayload.length} chars`
        });
      }

      if (urlMalformed) {
        points += 25;
        suspiciousCharacteristics.push('Malformed URL syntax');
        recordFinding({
          id: 'malformed-url',
          severity: 'high',
          category: 'URL Structure',
          title: 'Malformed URL Syntax',
          points: 25,
          message: `URL structure is malformed: ${malformedReasons.join('; ')}.`,
          component: 'URL Structure',
          componentValue: payload.slice(0, 120)
        });
      }

      // ── INDICATOR 4: Homograph Attack, Punycode & Mixed-Script Detection ───
      const homographSource = decodedUnicodeHost || rawHostname;
      const homoInfo = inspectHomographs(homographSource);
      const isPunycode = hasPunycodeLabel(hostname) || hasPunycodeLabel(rawHostname);
      const isExplicitPunycode = hasPunycodeLabel(rawHostname);

      if (homoInfo.hasInvisible) {
        points += 40;
        suspiciousCharacteristics.push('Invisible/zero-width Unicode characters in hostname');
        recordFinding({
          id: 'invisible-unicode',
          severity: 'high',
          category: 'Homograph / IDN Spoofing',
          title: 'Invisible Unicode Characters in Domain',
          points: 40,
          message: 'Hostname contains hidden zero-width or formatting characters designed to deceive visual inspection.',
          component: 'Hostname',
          componentValue: homographSource
        });
      }

      if (homoInfo.hasMixedScripts) {
        const charDetails = homoInfo.suspiciousChars
          .slice(0, 5)
          .map(c => `'${c.char}' (${c.codePoint} ${c.script} -> '${c.looksLike}')`)
          .join(', ');
        points += 40;
        suspiciousCharacteristics.push(`Mixed-script IDN (${homoInfo.scripts.join(' + ')})`);
        recordFinding({
          id: 'mixed-script-homograph',
          severity: 'high',
          category: 'Homograph / IDN Spoofing',
          title: 'Mixed-Script Homograph Attack',
          points: 40,
          message: `Domain mixes multiple character scripts (${homoInfo.scripts.join(' + ')}). Suspicious characters: ${charDetails}.`,
          component: 'Hostname',
          componentValue: homographSource
        });
      } else if (homoInfo.hasUnicode && homoInfo.hasNonLatinConfusable) {
        const charDetails = homoInfo.suspiciousChars
          .slice(0, 5)
          .map(c => `'${c.char}' (${c.codePoint} ${c.script} -> '${c.looksLike}')`)
          .join(', ');
        points += 25;
        suspiciousCharacteristics.push(`Unicode homoglyph characters (${homoInfo.scripts.join(', ')})`);
        recordFinding({
          id: 'unicode-homoglyph',
          severity: 'high',
          category: 'Homograph / IDN Spoofing',
          title: 'Unicode Domain Impersonation',
          points: 25,
          message: `Domain uses non-Latin lookalike characters (${charDetails}) that mimic ASCII Latin letters (skeleton: '${homoInfo.skeleton}').`,
          component: 'Hostname',
          componentValue: homographSource
        });
      } else if (homoInfo.hasUnicode && !homoInfo.hasInvisible) {
        points += 15;
        suspiciousCharacteristics.push(`Internationalized domain name (${homoInfo.scripts.join(', ')})`);
        recordFinding({
          id: 'idn-unicode',
          severity: 'medium',
          category: 'Homograph / IDN Spoofing',
          title: 'Internationalized Domain Name (IDN)',
          points: 15,
          message: `Domain contains non-ASCII Unicode characters (${homoInfo.scripts.join(', ')}). Verify the intended domain carefully.`,
          component: 'Hostname',
          componentValue: homographSource
        });
      }

      if (isExplicitPunycode) {
        const punyPts = homoInfo.hasMixedScripts ? 10 : 20;
        points += punyPts;
        suspiciousCharacteristics.push(`Punycode domain (${punycodeHostname || rawHostname} -> ${decodedUnicodeHost})`);
        recordFinding({
          id: 'punycode-domain',
          severity: homoInfo.hasUnicode ? 'high' : 'medium',
          category: 'Homograph / IDN Spoofing',
          title: 'Punycode (xn--) Encoded Domain',
          points: punyPts,
          message: `Uses Punycode encoding (${punycodeHostname || rawHostname}), which decodes to '${decodedUnicodeHost}'. Attackers use Punycode to conceal lookalike characters.`,
          component: 'Hostname',
          componentValue: `${punycodeHostname || rawHostname} (${decodedUnicodeHost})`
        });
      }

      // ── INDICATOR 5: Suspicious TLD & Hyphen-Heavy Domain ──────────────────
      if (tld && HIGH_RISK_TLDS.includes(tld)) {
        points += 25;
        suspiciousCharacteristics.push(`High-risk TLD (.${tld})`);
        recordFinding({
          id: 'high-risk-tld',
          severity: 'medium',
          category: 'Domain Pattern',
          title: `High-Risk TLD (.${tld})`,
          points: 25,
          message: `Top-level domain (.${tld}) is statistically associated with higher rates of phishing and spam registrations.`,
          component: 'Root Domain',
          componentValue: `.${tld}`
        });
      }

      const domainNameWithoutTld = domainParts.slice(0, -1).join('.');
      const hyphenCount = (domainNameWithoutTld.match(/-/g) || []).length;
      if (hyphenCount >= 3) {
        points += 15;
        suspiciousCharacteristics.push(`Hyphen-heavy hostname (${hyphenCount} hyphens)`);
        recordFinding({
          id: 'hyphen-heavy-domain',
          severity: 'medium',
          category: 'Domain Pattern',
          title: 'Hyphen-Heavy Hostname',
          factor: `Hyphenated Domain Pattern (${hyphenCount} hyphens)`,
          points: 15,
          message: 'Contains multiple hyphens in the domain name, a common trick used to mimic legitimate organization names.',
          component: 'Hostname',
          componentValue: hostname
        });
      }

      // ── INDICATOR 6: Excessive Subdomains ──────────────────────────────────
      const subdomainPartsCount = Math.max(0, domainParts.length - (registeredDomain.split('.').length));
      if (subdomainPartsCount >= 2) {
        points += 25;
        suspiciousCharacteristics.push(`${subdomainPartsCount} nested subdomains`);
        recordFinding({
          id: 'excessive-subdomains',
          severity: 'high',
          category: 'Subdomain Count',
          title: 'Deeply Nested Subdomains',
          factor: `Excessive Subdomains (${subdomainPartsCount} subdomains)`,
          points: 25,
          message: `Contains ${subdomainPartsCount} subdomains. Attackers nest authentic brand names in subdomains to trick users.`,
          component: 'Subdomains',
          componentValue: subdomains.join('.')
        });
      }

      // ── INDICATOR 7: Brand Impersonation & Typosquatting ───────────────────
      // First check if hostname belongs to any legitimate brand domain (must be clean ASCII, no invisible/IDN tricks)
      const isCleanAsciiHost = !homoInfo.hasUnicode && !homoInfo.hasInvisible && !isPunycode;
      const matchedLegitBrand = isCleanAsciiHost
        ? BRAND_TARGETS.find(b =>
            b.legitDomains.some(legit => hostname === legit || hostname.endsWith('.' + legit))
          )
        : null;

      let brandImpersonated = false;
      const skeletonUrl = homoInfo.skeleton + pathname.toLowerCase();
      const skeletonHost = homoInfo.skeleton;

      if (!matchedLegitBrand) {
        // 7A: Explicit Brand Impersonation (subdomains, hyphenated brand domains, or path on untrusted host)
        for (const b of BRAND_TARGETS) {
          const inSubdomain = subdomains.some(sub => sub.includes(b.keyword));
          const inHost = skeletonHost.includes(b.keyword) || hostname.includes(b.keyword);
          const inPath = pathname.toLowerCase().includes(b.keyword);

          if (inSubdomain || inHost || inPath) {
            brandImpersonated = true;
            const location = inSubdomain ? 'deceptive subdomain' : (inHost ? 'unverified domain' : 'URL path on unverified host');
            points += 30;
            suspiciousCharacteristics.push(`Brand impersonation (${b.name} in ${location})`);
            recordFinding({
              id: 'brand-impersonation',
              severity: 'high',
              category: 'Brand Impersonation',
              title: `Brand Impersonation (${b.name})`,
              points: 30,
              message: `URL embeds the brand '${b.name}' in a ${location} (${hostname}) rather than an official ${b.legitDomains[0]} domain.`,
              component: inSubdomain ? 'Subdomains' : (inHost ? 'Hostname' : 'Path'),
              componentValue: inSubdomain ? subdomains.join('.') : (inHost ? hostname : pathname)
            });
            break;
          }
        }

        // 7B: Typosquatting Detection (if not already caught as direct brand impersonation, and not IP/allowlisted)
        if (!brandImpersonated && !isIpHost && !SAFE_TYPOSQUAT_ALLOWLIST.has(registeredDomain)) {
          const targetSld = (decodedHostParts.sld || sld || '').toLowerCase();
          const normalizedSld = normalizeAsciiLookalikes(homoInfo.hasUnicode ? decodedHostParts.sld : targetSld);

          for (const b of BRAND_TARGETS) {
            if (b.keyword.length < 5) continue;
            // Check exact ASCII lookalike match (e.g. paypa1 -> paypal, rnicrosoft -> microsoft)
            if (normalizedSld === b.keyword && targetSld !== b.keyword) {
              brandImpersonated = true;
              points += 30;
              suspiciousCharacteristics.push(`Typosquatting lookalike for ${b.name}`);
              recordFinding({
                id: 'typosquatting-lookalike',
                severity: 'high',
                category: 'Typosquatting',
                title: `Typosquatting Lookalike (${b.name})`,
                points: 30,
                message: `Domain label '${targetSld}' uses visual character substitutions to mimic '${b.legitDomains[0]}'.`,
                component: 'Root Domain',
                componentValue: registeredDomain
              });
              break;
            }

            // Edit distance check (Damerau-Levenshtein: substitutions, omissions, insertions, transpositions)
            // Tight thresholds to prevent false positives on unrelated words
            const maxAllowedDist = b.keyword.length >= 7 ? 2 : 1;
            const dist = damerauLevenshtein(targetSld, b.keyword);
            const normDist = damerauLevenshtein(normalizedSld, b.keyword);
            const bestDist = Math.min(dist, normDist);

            if (bestDist > 0 && bestDist <= maxAllowedDist && Math.abs(targetSld.length - b.keyword.length) <= 1) {
              brandImpersonated = true;
              points += 30;
              suspiciousCharacteristics.push(`Typosquatting candidate for ${b.name} (edit distance ${bestDist})`);
              recordFinding({
                id: 'typosquatting-distance',
                severity: 'high',
                category: 'Typosquatting',
                title: `Typosquatting Domain (${b.name})`,
                points: 30,
                message: `Domain '${registeredDomain}' is within edit distance ${bestDist} of '${b.legitDomains[0]}' (possible typo/transposition spoofing).`,
                component: 'Root Domain',
                componentValue: registeredDomain
              });
              break;
            }
          }
        }
      }

      // ── INDICATOR 8: Contextual Credential Harvesting Detection ───────────
      const pathAndQueryStr = pathname + ' ' + searchStr;
      const matchedPathActionWords = matchCredentialKeywords(pathAndQueryStr);
      const matchedHostActionWords = matchCredentialKeywords(hostname);
      const allMatchedActionWords = Array.from(new Set([...matchedPathActionWords, ...matchedHostActionWords]));

      if (allMatchedActionWords.length > 0) {
        if (matchedLegitBrand && protocol === 'https:') {
          // Legitimate HTTPS brand login page (e.g., accounts.google.com/signin) -> safe context
          result.highlights.push({
            category: 'Authentication Context',
            title: `Verified ${matchedLegitBrand.name} Domain`,
            message: `Authentication path appears on an official HTTPS ${matchedLegitBrand.name} domain (${hostname}).`
          });
        } else if (brandImpersonated) {
          // Brand impersonation + credential keywords -> escalate risk
          points += 15;
          suspiciousCharacteristics.push(`Brand spoofing + credential keywords [${allMatchedActionWords.slice(0, 3).join(', ')}]`);
          recordFinding({
            id: 'brand-credential-combo',
            severity: 'high',
            category: 'Credential Harvesting',
            title: 'Brand Spoofing + Credential Harvesting',
            points: 15,
            message: `Combines brand impersonation with credential/action keywords [${allMatchedActionWords.join(', ')}].`,
            component: matchedPathActionWords.length > 0 ? 'Path / Query' : 'Hostname',
            componentValue: matchedPathActionWords.length > 0 ? (pathname + searchStr) : hostname
          });
        } else {
          const isHighRiskContext =
            protocol === 'http:' ||
            isIpHost ||
            HIGH_RISK_TLDS.includes(tld) ||
            isPunycode ||
            homoInfo.hasUnicode ||
            allMatchedActionWords.some(w => SCAM_BAIT_KEYWORDS.includes(w));

          if (isHighRiskContext) {
            points += 30;
            suspiciousCharacteristics.push(`Credential/scam keywords on risky host [${allMatchedActionWords.slice(0, 3).join(', ')}]`);
            recordFinding({
              id: 'credential-harvesting-high',
              severity: 'high',
              category: 'Credential Harvesting',
              title: 'Sensitive Credential / Reward Keywords',
              factor: `Sensitive Action Keywords [${allMatchedActionWords.slice(0, 3).join(', ')}]`,
              points: 30,
              message: `URL contains sensitive action keywords [${allMatchedActionWords.join(', ')}] on an insecure or unverified host (${hostname}).`,
              component: matchedPathActionWords.length > 0 ? 'Path' : 'Hostname',
              componentValue: matchedPathActionWords.length > 0 ? pathname : hostname
            });
          } else if (matchedPathActionWords.length > 0 && !SAFE_TYPOSQUAT_ALLOWLIST.has(registeredDomain)) {
            // Unverified HTTPS domain with login/password/reset/banking path -> moderate contextual signal
            points += 15;
            suspiciousCharacteristics.push(`Suspicious credential path [${matchedPathActionWords.slice(0, 3).join(', ')}]`);
            recordFinding({
              id: 'credential-harvesting-moderate',
              severity: 'medium',
              category: 'Credential Harvesting',
              title: 'Suspicious Login / Credential Path',
              points: 15,
              message: `Unverified domain (${hostname}) requests credential or authentication actions [${matchedPathActionWords.join(', ')}].`,
              component: 'Path',
              componentValue: pathname + (searchStr || '')
            });
          }
        }
      }

      // ── INDICATOR 9: Presence of `@` Symbol Redirection ───────────────────
      if (fullUrl.includes('@') || payload.includes('@')) {
        points += 40;
        suspiciousCharacteristics.push('Userinfo "@" redirection symbol');
        recordFinding({
          id: 'at-redirection',
          severity: 'high',
          category: 'URL Redirection',
          title: 'Presence of "@" Symbol',
          factor: 'Redirection Symbol (@)',
          points: 40,
          message: 'Contains "@" symbol. Browsers interpret text before "@" as credentials, routing the user to the host after "@".',
          component: 'Authority',
          componentValue: rawParts.rawAuthority || fullUrl
        });
      }

      // ── INDICATOR 10: Suspicious Encoding, Double Slash & Query Parameters ──
      const hexCount = pctMatches.length;
      if (hexCount > 3) {
        points += 15;
        suspiciousCharacteristics.push(`Heavy percent encoding (${hexCount} %xx tokens)`);
        recordFinding({
          id: 'heavy-percent-encoding',
          severity: 'medium',
          category: 'URL Encoding',
          title: 'Heavy Percent Encoding',
          factor: `URL Percent Encoding (${hexCount} %xx characters)`,
          points: 15,
          message: `Contains ${hexCount} percent-encoded characters (%xx), which obscures destination path readability.`,
          component: 'Encoded Components',
          componentValue: pctMatches.slice(0, 8).join('')
        });
      }

      if (pathname.includes('//') || /https?:\/\/[^\/]+\/\//i.test(payload)) {
        points += 15;
        suspiciousCharacteristics.push('Double-slash path traversal (//)');
        recordFinding({
          id: 'double-slash-traversal',
          severity: 'medium',
          category: 'URL Encoding',
          title: 'Double Slash Path Pattern',
          factor: 'Double Slash Path Traversal (//)',
          points: 15,
          message: 'Contains consecutive slashes "//" in the path, often used for open-redirect vulnerabilities.',
          component: 'Path',
          componentValue: pathname
        });
      }

      // Query parameter forensics
      const redirectParams = queryParams.filter(p => p.flags.includes('nested-redirect-url') || p.flags.includes('encoded-redirect'));
      const execRedirectParams = queryParams.filter(p => p.flags.includes('executable-redirect'));
      const credentialParams = queryParams.filter(p => p.flags.includes('credential-parameter'));
      const doubleEncodedParams = queryParams.filter(p => p.flags.includes('double-encoded'));

      if (execRedirectParams.length > 0) {
        points += 30;
        const pNames = execRedirectParams.map(p => p.key).join(', ');
        suspiciousCharacteristics.push(`Executable payload inside redirect parameter (${pNames})`);
        recordFinding({
          id: 'executable-redirect-param',
          severity: 'high',
          category: 'Suspicious URL Parameters',
          title: 'Executable Redirect Parameter',
          points: 30,
          message: `Redirect parameter (${pNames}) embeds an executable scheme (javascript:/data:).`,
          component: `Query Parameter (${pNames})`,
          componentValue: execRedirectParams[0].decodedValue
        });
      } else if (redirectParams.length > 0) {
        points += 15;
        const pNames = redirectParams.map(p => p.key).join(', ');
        suspiciousCharacteristics.push(`Encoded / nested redirect parameter (${pNames})`);
        recordFinding({
          id: 'encoded-redirect-param',
          severity: 'medium',
          category: 'Suspicious URL Parameters',
          title: 'Encoded Redirect Parameter',
          points: 15,
          message: `Query parameter (${pNames}) carries an external or encoded redirect destination (${redirectParams[0].decodedValue.slice(0, 80)}).`,
          component: `Query Parameter (${pNames})`,
          componentValue: `${redirectParams[0].key}=${redirectParams[0].value}`
        });
      }

      if (credentialParams.length > 0) {
        points += 20;
        const pNames = credentialParams.map(p => p.key).join(', ');
        suspiciousCharacteristics.push(`Sensitive credential parameter in URL (${pNames})`);
        recordFinding({
          id: 'credential-query-param',
          severity: 'high',
          category: 'Suspicious URL Parameters',
          title: 'Credential-Related Query Parameter',
          points: 20,
          message: `URL exposes sensitive authentication parameters [${pNames}] directly in the query string.`,
          component: `Query Parameter (${pNames})`,
          componentValue: `${credentialParams[0].key}=***`
        });
      }

      if (doubleEncodedParams.length > 0) {
        points += 15;
        suspiciousCharacteristics.push('Double-encoded query parameter (%25xx)');
        recordFinding({
          id: 'double-encoded-param',
          severity: 'medium',
          category: 'URL Encoding',
          title: 'Double-Encoded Query Parameter',
          points: 15,
          message: `Query parameter '${doubleEncodedParams[0].key}' uses nested double percent-encoding (%25xx) to evade inspection filters.`,
          component: `Query Parameter (${doubleEncodedParams[0].key})`,
          componentValue: doubleEncodedParams[0].value
        });
      }

      // ── INDICATOR 11: URL Shorteners ───────────────────────────────────────
      const isShortener = KNOWN_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s));
      if (isShortener) {
        points += 15;
        suspiciousCharacteristics.push(`URL shortener (${hostname})`);
        recordFinding({
          id: 'url-shortener',
          severity: 'medium',
          category: 'Link Shorteners',
          title: 'Shortened Destination Masking',
          factor: 'URL Shortening Service',
          points: 15,
          message: 'Uses a URL shortener service which conceals the final target web destination.',
          component: 'Hostname',
          componentValue: hostname
        });
      }

      // ── INDICATOR 12: Excessive URL Length ─────────────────────────────────
      if (fullUrl.length > 110) {
        points += 10;
        suspiciousCharacteristics.push(`Excessive length (${fullUrl.length} chars)`);
        recordFinding({
          id: 'excessive-url-length',
          severity: 'low',
          category: 'URL Length',
          title: 'Unusually Long URL',
          factor: `Excessive URL Length (${fullUrl.length} chars)`,
          points: 10,
          message: `URL length is ${fullUrl.length} characters. Extended strings are often used to hide query parameters.`,
          component: 'URL Length',
          componentValue: `${fullUrl.length} characters`
        });
      }

      // ── INDICATOR 13: Non-Standard Port Check ──────────────────────────────
      if (port && !['80', '443', ''].includes(port)) {
        points += 15;
        suspiciousCharacteristics.push(`Non-standard port (:${port})`);
        recordFinding({
          id: 'non-standard-port',
          severity: 'low',
          category: 'Port Security',
          title: 'Non-Standard Port',
          factor: `Non-Standard Port (:${port})`,
          points: 15,
          message: `Uses custom port number (${port}) instead of standard web ports.`,
          component: 'Port',
          componentValue: port
        });
      }

      // ── Final Score Clamping & Verdict ─────────────────────────────────────
      result.score = Math.min(100, Math.max(0, points));
      result.metrics.pointsAssigned = points;

      if (result.score >= 70) {
        result.status = 'Dangerous';
      } else if (result.score >= 30) {
        result.status = 'Suspicious';
      } else {
        result.status = 'Safe';
      }

      if (result.scoreBreakdown.length === 0) {
        result.explanation = 'Risk score is 0 because no security anomalies or suspicious indicators were detected.';
      } else {
        const breakdownText = result.scoreBreakdown.map(b => `${b.factor} (+${b.points} pts)`).join(', ');
        result.explanation = `Score of ${result.score}/100 calculated from detected indicators: ${breakdownText}.`;
      }

      if (result.status === 'Dangerous') {
        result.advice = 'DANGER: High risk score detected. DO NOT visit this URL or enter credentials. Verify the link with the sender through an independent channel.';
      } else if (result.status === 'Suspicious') {
        result.advice = 'WARNING: Moderate risk score detected. Do not enter credentials until the destination has been independently verified.';
      } else {
        result.advice = 'SAFE: Low risk score. URL structure matches standard web conventions. Always verify that the domain name matches your intended destination.';
      }
      result.recommendation = result.advice;

      if (result.issues.length === 0) {
        result.highlights.push({
          category: 'Clean Structure',
          title: 'Zero Anomalies',
          message: 'Passed all threat intelligence and forensic checks without triggering risk points.'
        });
      }

      const defaultPort = protocol === 'https:' ? '443' : (protocol === 'ftp:' ? '21' : '80');

      result.forensics = {
        protocol: protocol.replace(':', '').toUpperCase(),
        hostname: hostname,
        rawHostname: rawHostname,
        punycodeHostname: punycodeHostname || (isPunycode ? rawHostname : ''),
        decodedHostname: decodedUnicodeHost,
        rootDomain: isIpHost ? hostname : (registeredDomain || hostname),
        subdomains: isIpHost ? [] : subdomains,
        port: port || defaultPort,
        isExplicitPort: Boolean(port),
        path: pathname || '/',
        queryParams: queryParams,
        fragment: fragment || '',
        encodedComponents: encodedComponents,
        suspiciousCharacteristics: suspiciousCharacteristics,
        malformed: urlMalformed,
        malformedReasons: malformedReasons
      };

      result.details = {
        protocol: protocol,
        hostname: hostname,
        pathname: pathname,
        search: searchStr,
        port: port || defaultPort
      };

      return result;
    },

    classifyQRType: classifyQRType,
    decodePunycodeHostname: decodePunycodeHostname,
    damerauLevenshtein: damerauLevenshtein
  };

  return QRAnalyzer;
});
