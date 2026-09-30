/**
 * QR Guide 2 - Camera & File QR Scanner Module
 * Handles camera scanning, drag-and-drop file decoding, and unreadable QR error handling.
 */

window.QRScanner = {
  html5QrcodeScanner: null,
  isScanning: false,
  onScanSuccessCallback: null,
  onScanErrorCallback: null,

  init: function(onSuccess, onError) {
    this.onScanSuccessCallback = onSuccess;
    this.onScanErrorCallback = onError;
    this.setupDropZone();
  },

  startCamera: function() {
    if (this.isScanning) return;

    const overlay = document.getElementById('scannerOverlay');
    if (overlay) overlay.style.display = 'flex';

    if (!this.html5QrcodeScanner) {
      this.html5QrcodeScanner = new Html5Qrcode("reader");
    }

    const config = {
      fps: 10,
      qrbox: { width: 220, height: 220 },
      aspectRatio: 1.0
    };

    this.html5QrcodeScanner.start(
      { facingMode: "environment" },
      config,
      (decodedText, decodedResult) => {
        // Success
        this.stopCamera();
        if (this.onScanSuccessCallback) {
          this.onScanSuccessCallback(decodedText);
        }
      },
      (errorMessage) => {
        // Normal frame scanning state when searching for QR
      }
    ).then(() => {
      this.isScanning = true;
      const startBtn = document.getElementById('startCamBtn');
      const stopBtn = document.getElementById('stopCamBtn');
      if (startBtn) startBtn.style.display = 'none';
      if (stopBtn) stopBtn.style.display = 'inline-flex';
    }).catch(err => {
      console.warn("Camera access failed or denied:", err);
      this.stopCamera();
      if (this.onScanErrorCallback) {
        this.onScanErrorCallback("Camera access unavailable or denied by browser. You can test using Image Upload or Demo Samples.");
      }
    });
  },

  stopCamera: function() {
    const startBtn = document.getElementById('startCamBtn');
    const stopBtn = document.getElementById('stopCamBtn');
    const overlay = document.getElementById('scannerOverlay');

    if (this.html5QrcodeScanner && this.isScanning) {
      this.html5QrcodeScanner.stop().then(() => {
        this.isScanning = false;
        if (startBtn) startBtn.style.display = 'inline-flex';
        if (stopBtn) stopBtn.style.display = 'none';
        if (overlay) overlay.style.display = 'none';
      }).catch(err => console.error("Failed to stop scanner:", err));
    } else {
      if (startBtn) startBtn.style.display = 'inline-flex';
      if (stopBtn) stopBtn.style.display = 'none';
      if (overlay) overlay.style.display = 'none';
    }
  },

  setupDropZone: function() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    if (!dropZone || !fileInput) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
      }, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length > 0) {
        this.handleFile(files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        this.handleFile(e.target.files[0]);
      }
    });
  },

  handleFile: function(file) {
    if (!file.type.startsWith('image/')) {
      if (this.onScanErrorCallback) {
        this.onScanErrorCallback("Invalid File Format: Please select an image file (PNG, JPG, WEBP).");
      }
      return;
    }

    const previewImg = document.getElementById('previewImg');
    const uploadPreview = document.getElementById('uploadPreview');
    const dropZone = document.getElementById('dropZone');
    const uploadFileName = document.getElementById('uploadFileName');
    const uploadErrorBox = document.getElementById('uploadErrorBox');

    if (uploadErrorBox) uploadErrorBox.style.display = 'none';

    const reader = new FileReader();
    reader.onload = (e) => {
      if (previewImg) previewImg.src = e.target.result;
      if (uploadFileName) uploadFileName.textContent = file.name;
      if (dropZone) dropZone.style.display = 'none';
      if (uploadPreview) uploadPreview.style.display = 'flex';
    };
    reader.readAsDataURL(file);

    // Decode QR from image file
    const html5QrCode = new Html5Qrcode("reader");
    html5QrCode.scanFile(file, true)
      .then(decodedText => {
        if (this.onScanSuccessCallback) {
          this.onScanSuccessCallback(decodedText);
        }
      })
      .catch(err => {
        console.error("QR Decoding failed:", err);
        if (uploadErrorBox) {
          uploadErrorBox.style.display = 'block';
          uploadErrorBox.innerHTML = `
            <div class="upload-error-content">
              <i class="fa-solid fa-triangle-exclamation"></i>
              <div>
                <strong>Unreadable QR Code:</strong>
                <p>No valid QR pattern was detected in this image. Ensure the image is well-lit, unblurred, and contains a complete QR code.</p>
              </div>
            </div>
          `;
        }
        if (this.onScanErrorCallback) {
          this.onScanErrorCallback("Could not extract a valid QR code from the uploaded image.");
        }
      });
  },

  resetUpload: function() {
    const dropZone = document.getElementById('dropZone');
    const uploadPreview = document.getElementById('uploadPreview');
    const fileInput = document.getElementById('fileInput');
    const uploadErrorBox = document.getElementById('uploadErrorBox');

    if (dropZone) dropZone.style.display = 'flex';
    if (uploadPreview) uploadPreview.style.display = 'none';
    if (fileInput) fileInput.value = '';
    if (uploadErrorBox) uploadErrorBox.style.display = 'none';
  }
};
