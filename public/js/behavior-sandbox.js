/**
 * QR Guard - QR Behavior Sandbox Engine (Offline Pre-Navigation Simulator)
 * Deterministically simulates OS/browser dispatch behavior, static redirect hops,
 * drive-by download risk, Android intent parsing, payment/Wi-Fi/device side effects,
 * and containment verdicts WITHOUT ever executing payloads or making network requests.
 *
 * Compatible with both Browser (window.QRBehaviorSandbox) and Node.js (module.exports).
 */

(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.QRBehaviorSandbox = factory();
  }
})(typeof self !== 'undefined' ? self : this, function() {

  const MAX_INPUT_CHARS = 4096;

  const EXECUTABLE_SCHEMES = ['javascript:', 'data:', 'file:', 'vbscript:'];
  const RISKY_DOWNLOAD_EXTS = [
    '.apk', '.exe', '.msi', '.dmg', '.pkg', '.bat', '.cmd', '.ps1',
    '.sh', '.vbs', '.js', '.jse', '.scr', '.hta', '.iso', '.jar'
  ];
  const ARCHIVE_EXTS = ['.zip', '.rar', '.7z', '.tar', '.gz'];
  const REDIRECT_KEYS = [
    'redirect', 'redirect_uri', 'redirect_url', 'next', 'url', 'target',
    'dest', 'destination', 'return', 'return_to', 'returnto', 'continue', 'goto'
  ];

  function safeDecode(val) {
    try {
      return decodeURIComponent(val);
    } catch (e) {
      return val;
    }
  }

  function traceStaticRedirects(initialUrl, maxHops = 3) {
    const hops = [];
    let current = initialUrl;
    const visited = new Set([current]);

    for (let i = 0; i < maxHops; i++) {
      let parsed;
      try {
        parsed = new URL(current);
      } catch (e) {
        break;
      }

      let nextTarget = null;
      let viaParam = null;
      for (const [k, v] of parsed.searchParams.entries()) {
        if (REDIRECT_KEYS.includes(k.toLowerCase())) {
          const d1 = safeDecode(v);
          const d2 = safeDecode(d1);
          const candidate = /^(https?:\/\/|javascript:|data:|vbscript:|\/\/)/i.test(d2)
            ? d2
            : (/^(https?:\/\/|javascript:|data:|vbscript:|\/\/)/i.test(d1) ? d1 : null);
          if (candidate) {
            nextTarget = candidate.startsWith('//') ? `${parsed.protocol}${candidate}` : candidate;
            viaParam = k;
            break;
          }
        }
      }

      if (!nextTarget || visited.has(nextTarget)) break;
      visited.add(nextTarget);
      hops.push({
        hopNumber: i + 1,
        fromHost: parsed.hostname,
        parameter: viaParam,
        target: nextTarget.slice(0, 220),
        isExecutableTarget: /^(javascript:|data:|vbscript:|file:)/i.test(nextTarget)
      });
      current = nextTarget;
    }
    return hops;
  }

  function parseAndroidIntent(payload) {
    // intent://<host>/<path>#Intent;scheme=https;package=com.example;S.browser_fallback_url=...;end
    const hashIdx = payload.indexOf('#Intent;');
    const basePart = hashIdx >= 0 ? payload.slice('intent://'.length, hashIdx) : payload.slice('intent://'.length);
    const metaPart = hashIdx >= 0 ? payload.slice(hashIdx + '#Intent;'.length) : '';
    const tokens = metaPart.split(';').filter(t => t && t !== 'end');

    const attrs = {};
    tokens.forEach(tok => {
      const eq = tok.indexOf('=');
      if (eq > 0) {
        attrs[tok.slice(0, eq)] = tok.slice(eq + 1);
      }
    });

    return {
      targetPath: basePart,
      scheme: attrs.scheme || 'unspecified',
      packageName: attrs.package || 'unspecified',
      action: attrs.action || 'VIEW',
      fallbackUrl: attrs['S.browser_fallback_url'] ? safeDecode(attrs['S.browser_fallback_url']) : null
    };
  }

  function simulate(rawPayload) {
    if (rawPayload === null || rawPayload === undefined || typeof rawPayload !== 'string' || rawPayload.trim() === '') {
      return {
        input: rawPayload || '',
        verdict: 'BLOCKED_EXECUTION',
        verdictLabel: 'Blocked — Empty / Invalid Payload',
        riskLevel: 'HIGH',
        handlerType: 'None (Invalid Payload)',
        networkSimulated: false,
        executedCode: false,
        timeline: [
          { stage: 1, title: 'Input Validation', action: 'Rejected empty or unreadable QR payload.', status: 'blocked' }
        ],
        permissionsRequested: [],
        staticRedirectHops: [],
        downloadRisk: null,
        sideEffects: ['Payload cannot be safely dispatched by any OS or browser handler.'],
        recommendations: ['Do not attempt to open empty or corrupted QR payloads.'],
        sandboxNotice: 'Offline deterministic simulation only. No URLs were fetched and no code was executed.'
      };
    }

    const payload = rawPayload.slice(0, MAX_INPUT_CHARS).trim();
    const lower = payload.toLowerCase();

    const timeline = [
      { stage: 1, title: 'Payload Decoded', action: `Captured ${payload.length} character payload in isolated sandbox memory.`, status: 'info' }
    ];
    const permissionsRequested = [];
    const sideEffects = [];
    const recommendations = [];
    let staticRedirectHops = [];
    let downloadRisk = null;
    let previewData = null;
    let handlerType = 'Plain Text Viewer';
    let verdict = 'SAFE_CONTAINED';
    let verdictLabel = 'Safe & Contained';
    let riskLevel = 'LOW';

    // 1. Executable / Dangerous Schemes
    if (EXECUTABLE_SCHEMES.some(s => lower.startsWith(s))) {
      const scheme = payload.split(':')[0].toLowerCase() + ':';
      handlerType = scheme === 'file:' ? 'Local Filesystem Handler' : 'Active Script / URI Execution Sink';
      verdict = 'BLOCKED_EXECUTION';
      verdictLabel = `Blocked Execution (${scheme})`;
      riskLevel = 'CRITICAL';

      permissionsRequested.push('Arbitrary Script / DOM Execution', scheme === 'file:' ? 'Local File Read Access' : 'Browser Context Hijacking');
      sideEffects.push(`If opened in an unprotected WebView or browser, '${scheme}' can execute active script or access local resources.`);
      timeline.push({
        stage: 2,
        title: 'URI Scheme Dispatch',
        action: `Identified executable scheme '${scheme}'.`,
        status: 'danger'
      });
      timeline.push({
        stage: 3,
        title: 'Sandbox Containment Enforced',
        action: `Halted execution before DOM/OS evaluation. Payload rendered inert.`,
        status: 'blocked'
      });
      recommendations.push(`CRITICAL: Never open or paste '${scheme}' QR payloads into a browser address bar.`);
    }
    // 2. Embedded script tags or shell commands in text
    else if (/<script|cmd\.exe|powershell|bash\s+-c/i.test(payload)) {
      handlerType = 'Text / Command Injection Pattern';
      verdict = 'BLOCKED_EXECUTION';
      verdictLabel = 'Blocked — Script / Command Pattern';
      riskLevel = 'CRITICAL';
      permissionsRequested.push('Shell / Script Interpreter');
      sideEffects.push('Payload contains embedded HTML script tags or command-line execution syntax.');
      timeline.push({
        stage: 2,
        title: 'Static Pattern Inspection',
        action: 'Detected embedded <script> or shell execution instructions.',
        status: 'danger'
      });
      timeline.push({
        stage: 3,
        title: 'Sandbox Containment Enforced',
        action: 'Blocked execution and neutralized HTML/script rendering.',
        status: 'blocked'
      });
      recommendations.push('Do not copy this string into command terminals or unescaped web inputs.');
    }
    // 3. Android Intent URI
    else if (lower.startsWith('intent://')) {
      const intentInfo = parseAndroidIntent(payload);
      previewData = { kind: 'intent', ...intentInfo };
      handlerType = 'Android Intent Dispatcher';
      verdict = 'HIGH_RISK_BEHAVIOR';
      verdictLabel = 'High-Risk App Intent';
      riskLevel = 'HIGH';
      permissionsRequested.push('Third-Party App Launch', 'Deep-Link Parameter Passing');
      if (intentInfo.fallbackUrl) permissionsRequested.push('Fallback Browser Redirect');

      timeline.push({
        stage: 2,
        title: 'Intent URI Parsing',
        action: `Targets package '${intentInfo.packageName}' using scheme '${intentInfo.scheme}'.`,
        status: 'warning'
      });
      timeline.push({
        stage: 3,
        title: 'Fallback & Deep-Link Simulation',
        action: intentInfo.fallbackUrl
          ? `If app is absent, device redirects browser to: ${intentInfo.fallbackUrl}`
          : 'Triggers external mobile app handler without prior domain verification.',
        status: 'danger'
      });
      sideEffects.push(`Launches mobile package '${intentInfo.packageName}' via Android Intent bridge.`);
      if (intentInfo.fallbackUrl) {
        sideEffects.push(`Fallback browser URL detected: ${intentInfo.fallbackUrl}`);
      }
      recommendations.push('Verify the target Android package and fallback URL before allowing app launch.');
    }
    // 4. Web URL (http / https / ftp or bare domain)
    else if (/^(https?|ftp):\/\//i.test(payload) || (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/.*)?$/i.test(payload) && !/\s/.test(payload))) {
      const candidate = /^(https?|ftp):\/\//i.test(payload) ? payload : 'http://' + payload;
      let parsed = null;
      try {
        parsed = new URL(candidate);
      } catch (e) {
        parsed = null;
      }

      if (!parsed) {
        handlerType = 'Malformed Web URL';
        verdict = 'HIGH_RISK_BEHAVIOR';
        verdictLabel = 'Blocked — Malformed URL';
        riskLevel = 'HIGH';
        timeline.push({
          stage: 2,
          title: 'URL Parser Simulation',
          action: 'URL failed strict WHATWG parsing inside sandbox.',
          status: 'danger'
        });
        sideEffects.push('Malformed URL syntax may trigger inconsistent parser behavior across browsers.');
        recommendations.push('Do not open malformed URLs.');
      } else {
        const proto = parsed.protocol.toLowerCase();
        handlerType = proto === 'ftp:' ? 'FTP File Client' : 'Web Browser Navigation';
        permissionsRequested.push('Outbound Network Request', proto === 'http:' ? 'Plaintext Cleartext Transport' : 'TLS Encrypted Transport');

        timeline.push({
          stage: 2,
          title: 'Protocol & Transport Simulation',
          action: proto === 'https:'
            ? `Browser initiates TLS connection to '${parsed.hostname}' (port ${parsed.port || '443'}).`
            : `Browser initiates UNENCRYPTED ${proto.toUpperCase()} connection to '${parsed.hostname}' (traffic exposed on local network).`,
          status: proto === 'https:' ? 'safe' : 'warning'
        });

        // Static Redirect Hop Simulation
        staticRedirectHops = traceStaticRedirects(parsed.href);
        if (staticRedirectHops.length > 0) {
          permissionsRequested.push('Cross-Origin Redirect Chain');
          staticRedirectHops.forEach(hop => {
            timeline.push({
              stage: timeline.length + 1,
              title: `Static Redirect Hop #${hop.hopNumber}`,
              action: `Query parameter '${hop.parameter}' redirects browser toward '${hop.target}'.`,
              status: hop.isExecutableTarget ? 'danger' : 'warning'
            });
            sideEffects.push(`Predicted redirect via '${hop.parameter}' -> ${hop.target}`);
          });
        }

        // Drive-by / Binary Download Detection
        const pathLower = parsed.pathname.toLowerCase();
        const matchedRiskyExt = RISKY_DOWNLOAD_EXTS.find(ext => pathLower.endsWith(ext));
        const matchedArchiveExt = ARCHIVE_EXTS.find(ext => pathLower.endsWith(ext));
        if (matchedRiskyExt) {
          downloadRisk = { level: 'HIGH', extension: matchedRiskyExt, reason: `Direct executable/installer file (${matchedRiskyExt}) in URL path.` };
          permissionsRequested.push('Local File Download / Installer Prompt');
          sideEffects.push(`Navigating here likely triggers download of an executable/installer (${matchedRiskyExt}).`);
          timeline.push({
            stage: timeline.length + 1,
            title: 'Download Payload Simulation',
            action: `Detected executable file target (${matchedRiskyExt}). Risk of drive-by malware installation.`,
            status: 'danger'
          });
        } else if (matchedArchiveExt) {
          downloadRisk = { level: 'MEDIUM', extension: matchedArchiveExt, reason: `Compressed archive (${matchedArchiveExt}) in URL path.` };
          permissionsRequested.push('Archive File Download');
          sideEffects.push(`URL points to a downloadable archive (${matchedArchiveExt}).`);
        }

        // Check userinfo @ redirection or credential/login interaction
        const hasAtTrick = parsed.username !== '' || parsed.password !== '' || payload.includes('@');
        const hasExecRedirect = staticRedirectHops.some(h => h.isExecutableTarget);
        const hasCredentialFormHint = /(login|signin|verify|password|reset|banking|wallet)/i.test(parsed.pathname + parsed.search);

        if (hasAtTrick) {
          sideEffects.push('Browser userinfo "@" redirection routes connection to host after "@", ignoring spoofed prefix.');
        }
        if (hasCredentialFormHint) {
          permissionsRequested.push('Interactive Web Form / Potential Credential Prompt');
          sideEffects.push('Destination path indicates an authentication or account-action interface.');
        }

        if (hasExecRedirect || hasAtTrick || (downloadRisk && downloadRisk.level === 'HIGH')) {
          verdict = 'HIGH_RISK_BEHAVIOR';
          verdictLabel = 'High-Risk Navigation Behavior';
          riskLevel = 'HIGH';
          recommendations.push('Do not navigate to this URL or download files from it without independent verification.');
        } else if (proto !== 'https:' || staticRedirectHops.length > 0 || downloadRisk || hasCredentialFormHint) {
          verdict = 'CAUTION_INTERACTIVE_ACTION';
          verdictLabel = 'Caution — Verify Destination Behavior';
          riskLevel = 'MEDIUM';
          recommendations.push('Confirm the domain identity before entering credentials or accepting downloads.');
        } else {
          verdict = 'SAFE_CONTAINED';
          verdictLabel = 'Standard Web Navigation';
          riskLevel = 'LOW';
          recommendations.push('Standard HTTPS navigation behavior predicted; verify domain matches your expectation.');
        }
      }
    }
    // 5. UPI Payment QR
    else if (lower.startsWith('upi://')) {
      handlerType = 'UPI Payment App Intent';
      verdict = 'CAUTION_INTERACTIVE_ACTION';
      verdictLabel = 'Financial Payment Prompt';
      riskLevel = 'MEDIUM';
      let pa = 'unknown', pn = 'unknown', am = 'user-entered', cu = 'INR';
      try {
        const u = new URL(payload);
        pa = u.searchParams.get('pa') || pa;
        pn = u.searchParams.get('pn') || pn;
        am = u.searchParams.get('am') || am;
        cu = u.searchParams.get('cu') || cu;
      } catch (e) { /* ignore */ }
      permissionsRequested.push('Payment App Invocation', 'Financial Transaction Authorization');
      previewData = { kind: 'upi', payeeAddress: pa, payeeName: pn, amount: am, currency: cu };
      timeline.push({
        stage: 2,
        title: 'Payment App Dispatch',
        action: `Opens UPI app targeting payee '${pn}' (${pa}) for amount ${am} ${cu}.`,
        status: 'warning'
      });
      sideEffects.push(`Prompts user to authorize a ${cu} payment (amount: ${am}) to ${pa}.`);
      recommendations.push('Always verify the payee name and amount inside your UPI app before entering your PIN.');
    }
    // 6. Wi-Fi Auto-Configuration
    else if (/^WIFI:/i.test(payload)) {
      handlerType = 'OS Wi-Fi Network Manager';
      const ssid = (payload.match(/S:([^;]+)/i) || [])[1] || 'Unknown';
      const sec = ((payload.match(/T:([^;]+)/i) || [])[1] || 'OPEN').toUpperCase();
      const weakSec = sec === 'NOPASS' || sec === 'OPEN' || sec === 'WEP';

      verdict = weakSec ? 'HIGH_RISK_BEHAVIOR' : 'CAUTION_INTERACTIVE_ACTION';
      verdictLabel = weakSec ? 'Insecure Wi-Fi Join Prompt' : 'Wi-Fi Configuration Prompt';
      riskLevel = weakSec ? 'HIGH' : 'MEDIUM';

      permissionsRequested.push('Wi-Fi Interface Reconfiguration', 'Local Network Traffic Routing');
      const isHidden = /H:true/i.test(payload);
      previewData = { kind: 'wifi', ssid, security: sec, hidden: isHidden, password: '●●●●●●●● (masked)' };
      timeline.push({
        stage: 2,
        title: 'OS Wi-Fi Provisioning',
        action: `Prompts device to connect to SSID '${ssid}' using ${sec} security.`,
        status: weakSec ? 'danger' : 'warning'
      });
      sideEffects.push(weakSec
        ? `Network '${ssid}' uses ${sec} (unencrypted or broken encryption), exposing traffic to eavesdropping.`
        : `Device switches wireless association to '${ssid}' (${sec}).`);
      recommendations.push('Only join Wi-Fi networks whose SSID you physically confirmed with the venue.');
    }
    // 7. Device Communication Schemes (tel, sms, mailto, geo, vcard)
    else if (/^(tel:|sms:|smsto:|mailto:|geo:|BEGIN:VCARD)/i.test(payload)) {
      const prefix = payload.split(':')[0].toUpperCase();
      handlerType = `${prefix} Device Handler`;
      verdict = 'CAUTION_INTERACTIVE_ACTION';
      verdictLabel = 'Device Action Prompt';
      riskLevel = 'LOW';
      permissionsRequested.push(`OS ${prefix} App Launch`);
      if (/^(sms:|smsto:)/i.test(payload)) {
        const rawSms = payload.replace(/^(sms:|smsto:)/i, '');
        const [num, ...msgParts] = rawSms.split(':');
        previewData = { kind: 'sms', recipient: num.trim(), message: safeDecode(msgParts.join(':').trim() || '(none)') };
      } else if (/^mailto:/i.test(payload)) {
        let to = '', subject = '', body = '';
        try {
          const u = new URL(payload);
          to = u.pathname;
          subject = u.searchParams.get('subject') || '';
          body = u.searchParams.get('body') || '';
        } catch (e) {
          to = payload.replace(/^mailto:/i, '').split('?')[0];
        }
        previewData = { kind: 'email', to, subject: subject || '(none)', body: body || '(none)' };
      } else if (/^tel:/i.test(payload)) {
        previewData = { kind: 'phone', number: payload.replace(/^tel:/i, '') };
      }
      timeline.push({
        stage: 2,
        title: 'Local Device Intent',
        action: `Opens native ${prefix} application with pre-filled parameters; no web page opened.`,
        status: 'safe'
      });
      sideEffects.push(`Prepares a ${prefix} action awaiting user confirmation.`);
      recommendations.push('Confirm recipient details before placing a call, sending a message, or saving a contact.');
    }
    // 8. Plain Text
    else {
      handlerType = 'Plain Text Display';
      verdict = 'SAFE_CONTAINED';
      verdictLabel = 'Safe Plain Text';
      riskLevel = 'LOW';
      timeline.push({
        stage: 2,
        title: 'Text Rendering',
        action: 'Displays static text only. No URI scheme, network call, or device intent triggered.',
        status: 'safe'
      });
      sideEffects.push('No automated OS or browser side effects.');
      recommendations.push('Plain text cannot launch actions automatically.');
    }

    return {
      input: payload,
      verdict,
      verdictLabel,
      riskLevel,
      handlerType,
      networkSimulated: false,
      executedCode: false,
      timeline,
      permissionsRequested,
      staticRedirectHops,
      downloadRisk,
      previewData,
      sideEffects,
      recommendations,
      sandboxNotice: 'Offline deterministic simulation only. No external URLs were fetched and no code was executed.'
    };
  }

  return {
    simulate,
    traceStaticRedirects,
    parseAndroidIntent
  };
});
