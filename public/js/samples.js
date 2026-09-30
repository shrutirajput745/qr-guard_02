/**
 * QR Guide 2 - Expanded Demo Samples & QR Generator Module
 */

window.QRSamples = {
  
  init: function(onSelectSample) {
    // Bind click handlers to demo sample buttons
    const sampleBtns = document.querySelectorAll('.test-sample-btn');
    sampleBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetUrl = btn.getAttribute('data-url');
        if (targetUrl && onSelectSample) {
          onSelectSample(targetUrl);
        }
      });
    });

    // Custom Generator Event
    const genBtn = document.getElementById('genBtn');
    const genInput = document.getElementById('genInput');
    const genOutput = document.getElementById('genOutput');
    const qrCanvas = document.getElementById('qrCanvas');

    if (genBtn && genInput) {
      genBtn.addEventListener('click', () => {
        const val = genInput.value.trim();
        if (!val) {
          if (window.showToast) {
            window.showToast('Please enter text or a URL to generate a QR code.', 'warning');
          } else {
            alert('Please enter text or a URL to generate a QR code.');
          }
          return;
        }

        // Render QR Code using QRCode library on canvas
        if (typeof QRCode !== 'undefined') {
          QRCode.toCanvas(qrCanvas, val, { width: 180, margin: 2 }, (error) => {
            if (error) console.error(error);
            if (genOutput) genOutput.style.display = 'flex';
          });
        }

        // Trigger immediate security analysis
        if (onSelectSample) {
          onSelectSample(val);
        }
      });
    }
  }

};
