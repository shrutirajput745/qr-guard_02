/**
 * QR Guard - Scan History Module
 * Stores scan results in localStorage with privacy protection.
 * Sensitive data (Wi-Fi passwords, payment amounts) are masked before storage.
 */

window.QRHistory = (function() {
  const STORAGE_KEY = localStorage.getItem('qrguard_history') ? 'qrguard_history' : (localStorage.getItem('qrguard2_history') ? 'qrguard2_history' : 'qrguard_history');
  const MAX_HISTORY = 50; // cap to avoid localStorage overflow

  // QR types whose raw content should be partially masked in history
  const SENSITIVE_TYPES = ['wifi', 'upi', 'vcard'];

  function maskSensitivePayload(qrType, input) {
    if (qrType === 'wifi') {
      // Remove password from Wi-Fi string before storing
      return input.replace(/(P:)[^;]*/i, '$1[MASKED]');
    }
    if (qrType === 'upi') {
      // Keep payee name/address but remove amount
      return input.replace(/(&am=)[^&]*/i, '$1[MASKED]');
    }
    // vCard: keep name/org but mask phone and email
    if (qrType === 'vcard') {
      return '[vCard contact — content masked for privacy]';
    }
    return input;
  }

  function load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) {
      return [];
    }
  }

  function save(records) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
    } catch (e) {
      console.warn('QR Guard: Could not save history to localStorage:', e);
    }
  }

  function addEntry(result) {
    const records = load();
    const maskedPayload = SENSITIVE_TYPES.includes(result.qrType)
      ? maskSensitivePayload(result.qrType, result.input)
      : result.input;

    const entry = {
      id: Date.now() + '_' + Math.random().toString(36).slice(2, 8),
      timestamp: new Date().toISOString(),
      qrType: result.qrType || 'text',
      qrTypeLabel: result.qrTypeLabel || 'Plain Text',
      status: result.status,
      score: result.score,
      payload: maskedPayload.length > 120 ? maskedPayload.substring(0, 120) + '…' : maskedPayload
    };

    records.unshift(entry); // newest first
    if (records.length > MAX_HISTORY) records.pop();
    save(records);
    return entry;
  }

  function clearAll() {
    localStorage.removeItem(STORAGE_KEY);
  }

  function exportCSV() {
    const records = load();
    if (records.length === 0) return null;

    const header = ['ID', 'Timestamp', 'QR Type', 'Risk Status', 'Risk Score', 'Payload (truncated)'];
    const rows = records.map(r => [
      r.id,
      r.timestamp,
      r.qrTypeLabel,
      r.status,
      r.score,
      '"' + (r.payload || '').replace(/"/g, '""') + '"'
    ].join(','));

    return [header.join(','), ...rows].join('\n');
  }

  function formatTimestamp(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleString(undefined, {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
      });
    } catch (e) {
      return iso;
    }
  }

  function getStatusClass(status) {
    if (status === 'Dangerous') return 'dangerous';
    if (status === 'Suspicious') return 'suspicious';
    return 'safe';
  }

  function getStatusIcon(status) {
    if (status === 'Dangerous') return 'fa-skull-crossbones';
    if (status === 'Suspicious') return 'fa-triangle-exclamation';
    return 'fa-circle-check';
  }

  // ─── Render History Tab ───────────────────────────────────────────────────
  function renderHistory() {
    const container = document.getElementById('historyList');
    const emptyMsg  = document.getElementById('historyEmpty');
    const countEl   = document.getElementById('historyScanCount');
    if (!container) return;

    const records = load();

    if (countEl) {
      countEl.textContent = records.length === 0
        ? 'No scans yet'
        : `${records.length} scan${records.length !== 1 ? 's' : ''} recorded`;
    }

    if (records.length === 0) {
      container.innerHTML = '';
      if (emptyMsg) emptyMsg.style.display = 'flex';
      return;
    }

    if (emptyMsg) emptyMsg.style.display = 'none';

    container.innerHTML = records.map(r => `
      <div class="history-item history-${getStatusClass(r.status)}">
        <div class="history-item-icon">
          <i class="fa-solid ${getStatusIcon(r.status)}"></i>
        </div>
        <div class="history-item-body">
          <div class="history-item-top">
            <span class="history-type-badge">
              <i class="fa-solid fa-tag"></i> ${escapeHtml(r.qrTypeLabel)}
            </span>
            <span class="history-risk-badge history-risk-${getStatusClass(r.status)}">
              ${escapeHtml(r.status)} · ${r.score}/100
            </span>
          </div>
          <div class="history-payload">${escapeHtml(r.payload)}</div>
          <div class="history-time">
            <i class="fa-regular fa-clock"></i> ${formatTimestamp(r.timestamp)}
          </div>
        </div>
      </div>
    `).join('');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ─── Public API ───────────────────────────────────────────────────────────
  return {
    addEntry,
    clearAll,
    load,
    exportCSV,
    renderHistory
  };
})();
