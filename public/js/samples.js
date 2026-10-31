/**
 * QR Guard - Demo Samples & QR Generator Module
 */

window.QRSamples = {

  init: function(onSelectSample) {
    // Bind click handlers to demo sample buttons
    const sampleBtns = document.querySelectorAll('.test-sample-btn');
    sampleBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        // data-url can include encoded newlines &#10; for vCard — decode them
        const rawUrl = btn.getAttribute('data-url') || '';
        // Decode HTML entities for vCard newlines
        const targetUrl = rawUrl.replace(/&#10;/g, '\n').replace(/&#13;/g, '\r');
        if (targetUrl && onSelectSample) {
          onSelectSample(targetUrl);
        }
      });
    });

    // Custom Generator Event
    const genBtn    = document.getElementById('genBtn');
    const genInput  = document.getElementById('genInput');
    const genOutput = document.getElementById('genOutput');
    const qrCanvas  = document.getElementById('qrCanvas');

    if (genBtn && genInput) {
      genBtn.addEventListener('click', () => {
        const val = genInput.value.trim();
        if (!val) {
          if (window.showToast) window.showToast('Please enter text or a URL to generate a QR code.', 'warning');
          return;
        }

        // Render QR Code on canvas
        if (typeof QRCode !== 'undefined') {
          QRCode.toCanvas(qrCanvas, val, { width: 180, margin: 2 }, (error) => {
            if (error) console.error(error);
            if (genOutput) genOutput.style.display = 'flex';
          });
        }

        // Trigger security analysis
        if (onSelectSample) onSelectSample(val);
      });
    }
  }

};
