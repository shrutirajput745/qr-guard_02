/**
 * QR Guard - Camera & File QR Scanner Module
 * Handles camera scanning, drag-and-drop file decoding, and unreadable QR error handling.
 */

window.QRScanner = {
  html5QrcodeScanner: null,
  currentUploadFile: null,
  isScanning: false,
  onScanSuccessCallback: null,
  onScanErrorCallback: null,

  init: function(onSuccess, onError) {
    this.onScanSuccessCallback = onSuccess;
    this.onScanErrorCallback = onError;
    // Initialize UI components
    this.setupDropZone();
    // Enhance & Scan button wiring
    const enhanceBtn = document.getElementById('enhanceScanBtn');
    if (enhanceBtn) {
      enhanceBtn.addEventListener('click', () => {
        if (!this.currentUploadFile) {
          this.onScanErrorCallback && this.onScanErrorCallback('No file selected for enhancement.');
          return;
        }
        const navRecovery = document.getElementById('navRecovery');
        if (navRecovery) navRecovery.click();
        if (window.QRRecovery) {
          window.QRRecovery.startRecovery(this.currentUploadFile);
        }
      });
    }
  },

  startCamera: function() {
    if (this.isScanning || this.isStarting) return;
    this.isStarting = true;
    this.stopRequested = false;

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
      this.isStarting = false;
      if (this.stopRequested) {
        this.isScanning = true;
        this.stopCamera();
        return;
      }
      this.isScanning = true;
      const startBtn = document.getElementById('startCamBtn');
      const stopBtn = document.getElementById('stopCamBtn');
      const camBadge = document.getElementById('camStatusBadge');
      if (startBtn) startBtn.style.display = 'none';
      if (stopBtn) stopBtn.style.display = 'inline-flex';
      if (camBadge) {
        camBadge.className = 'cam-status-badge active';
        camBadge.innerHTML = '<i class="fa-solid fa-circle"></i> SCANNING ACTIVE';
      }
    }).catch(err => {
      this.isStarting = false;
      this.stopRequested = false;
      console.warn("Camera access failed or denied:", err);
      this.stopCamera();
      const camBadge = document.getElementById('camStatusBadge');
      if (camBadge) {
        camBadge.className = 'cam-status-badge error';
        camBadge.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> CAMERA UNAVAILABLE';
      }
      if (this.onScanErrorCallback) {
        this.onScanErrorCallback("Camera access unavailable or denied by browser. You can test using Image Upload or Demo Samples.");
      }
    });
  },

  stopCamera: function() {
    if (this.isStarting) {
      this.stopRequested = true;
    }
    const startBtn = document.getElementById('startCamBtn');
    const stopBtn = document.getElementById('stopCamBtn');
    const overlay = document.getElementById('scannerOverlay');
    const camBadge = document.getElementById('camStatusBadge');

    if (this.html5QrcodeScanner && this.isScanning) {
      this.html5QrcodeScanner.stop().then(() => {
        this.isScanning = false;
        this.stopRequested = false;
        if (startBtn) startBtn.style.display = 'inline-flex';
        if (stopBtn) stopBtn.style.display = 'none';
        if (overlay) overlay.style.display = 'none';
        if (camBadge) {
          camBadge.className = 'cam-status-badge';
          camBadge.innerHTML = '<i class="fa-solid fa-circle"></i> STANDBY';
        }
      }).catch(err => {
        this.isScanning = false;
        this.stopRequested = false;
        console.error("Failed to stop scanner:", err);
      });
    } else {
      if (startBtn) startBtn.style.display = 'inline-flex';
      if (stopBtn) stopBtn.style.display = 'none';
      if (overlay) overlay.style.display = 'none';
      if (camBadge) {
        camBadge.className = 'cam-status-badge';
        camBadge.innerHTML = '<i class="fa-solid fa-circle"></i> STANDBY';
      }
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
      if (files && files.length > 0) {
        this.currentUploadFile = files[0];
        const enhanceBtn = document.getElementById('enhanceScanBtn');
        if (enhanceBtn) enhanceBtn.style.display = 'inline-block';
        this.handleFile(files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        this.currentUploadFile = e.target.files[0];
        const enhanceBtn = document.getElementById('enhanceScanBtn');
        if (enhanceBtn) enhanceBtn.style.display = 'inline-block';
        this.handleFile(e.target.files[0]);
      }
    });
  },

  handleFile: function(file) {
    if (!file || !file.type.startsWith('image/')) {
      if (this.onScanErrorCallback) {
        this.onScanErrorCallback("Invalid File Format: Please select an image file (PNG, JPG, WEBP).");
      }
      return;
    }

    if (file.size > 8 * 1024 * 1024) {
      if (this.onScanErrorCallback) {
        this.onScanErrorCallback("File Too Large: Image exceeds the 8MB maximum upload limit.");
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
    reader.onerror = () => {
      if (this.onScanErrorCallback) {
        this.onScanErrorCallback("Failed to read uploaded image file.");
      }
    };
    reader.readAsDataURL(file);
    // store current file for enhancement
    this.currentUploadFile = file;

    const showDecodeFailure = () => {
      if (uploadErrorBox) {
        uploadErrorBox.style.display = 'block';
        uploadErrorBox.innerHTML = `
          <div class="upload-error-content">
            <i class="fa-solid fa-triangle-exclamation"></i>
            <div>
              <strong>Unreadable QR Code:</strong>
              <p>No valid QR pattern detected directly. Try clicking <strong>"Enhance & Scan"</strong> below to recover blurry, low-contrast, or noisy QR codes.</p>
            </div>
          </div>
        `;
      }
      if (this.onScanErrorCallback) {
        this.onScanErrorCallback("Could not extract a valid QR code directly. Try the Blur Recovery Lab.");
      }
    };

    const tryJsQr = () => {
      const objectUrl = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        try {
          const cvs = document.createElement('canvas');
          const w = img.naturalWidth || img.width;
          const h = img.naturalHeight || img.height;
          if (w > 0 && h > 0) {
            cvs.width = w;
            cvs.height = h;
            const ctx = cvs.getContext('2d');
            ctx.drawImage(img, 0, 0);
            const imgData = ctx.getImageData(0, 0, w, h);
            if (window.jsQR) {
              const qr = window.jsQR(imgData.data, w, h, { inversionAttempts: 'attemptBoth' });
              if (qr && qr.data) {
                URL.revokeObjectURL(objectUrl);
                if (this.onScanSuccessCallback) {
                  this.onScanSuccessCallback(qr.data);
                }
                return;
              }
            }
          }
        } catch (e) {
          console.warn("jsQR fallback scan error:", e);
        }
        URL.revokeObjectURL(objectUrl);
        showDecodeFailure();
      };
      img.onerror = () => {
        URL.revokeObjectURL(objectUrl);
        showDecodeFailure();
      };
      img.src = objectUrl;
    };

    // Decode QR from image file using Html5Qrcode, fallback to jsQR
    try {
      const html5QrCode = (!this.isScanning && this.html5QrcodeScanner)
        ? this.html5QrcodeScanner
        : new Html5Qrcode("reader");
      html5QrCode.scanFile(file, false)
        .then(decodedText => {
          if (this.onScanSuccessCallback) {
            this.onScanSuccessCallback(decodedText);
          }
        })
        .catch(err => {
          console.warn("Html5Qrcode scan failed, trying jsQR fallback:", err);
          tryJsQr();
        });
    } catch (e) {
      tryJsQr();
    }
  },

  resetUpload: function() {
    // Reset current file and hide enhance button
    this.currentUploadFile = null;
    const enhanceBtn = document.getElementById('enhanceScanBtn');
    if (enhanceBtn) enhanceBtn.style.display = 'none';
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
