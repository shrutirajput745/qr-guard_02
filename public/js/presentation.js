/**
 * QR Guard - Modern Cybersecurity Presentation Engine (9 Clean Slides)
 * Designed for computer engineering college presentations.
 * Features:
 * - 9 Essential Slides matching project implementation
 * - Interactive slide progress pills and keyboard navigation
 * - Fullscreen mode support
 * - Direct PPTX download trigger
 */

window.QRPresentation = (function() {

  const TOTAL_SLIDES = 9;
  let currentSlide = 0;
  let isFullscreen = false;

  const SLIDE_TITLES = [
    '01. Cover & Title',
    '02. Problem Statement',
    '03. Project Objectives',
    '04. Proposed Solution',
    '05. System Architecture',
    '06. Smart Technique',
    '07. Project Demonstration',
    '08. Future Roadmap',
    '09. Closing & Thank You'
  ];

  function init() {
    setupSlideTrack();
    setupEventListeners();
    updateSlideView();
  }

  function setupSlideTrack() {
    const track = document.getElementById('presentationTrack');
    if (!track) return;

    let html = '';
    for (let i = 0; i < TOTAL_SLIDES; i++) {
      html += `
        <button class="slide-step-pill ${i === 0 ? 'active' : ''}" 
                data-slide="${i}" 
                title="${SLIDE_TITLES[i]}">
          <span class="step-dot"></span>
          <span class="step-label">${i + 1}</span>
        </button>
      `;
    }
    track.innerHTML = html;

    // Attach click events
    track.querySelectorAll('.slide-step-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        const idx = parseInt(pill.getAttribute('data-slide'), 10);
        goToSlide(idx);
      });
    });
  }

  function setupEventListeners() {
    // Prev / Next buttons
    const prevBtn = document.getElementById('presPrevBtn');
    const nextBtn = document.getElementById('presNextBtn');
    if (prevBtn) prevBtn.addEventListener('click', prevSlide);
    if (nextBtn) nextBtn.addEventListener('click', nextSlide);

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
      const presPage = document.getElementById('page-presentation');
      if (!presPage || !presPage.classList.contains('active')) return;

      if (e.key === 'ArrowRight' || e.key === 'PageDown' || e.key === ' ') {
        if (e.key === 'Space' && e.target.tagName !== 'BUTTON' && e.target.tagName !== 'INPUT' && e.target.tagName !== 'SELECT') {
          e.preventDefault();
        }
        nextSlide();
      } else if (e.key === 'ArrowLeft' || e.key === 'PageUp') {
        prevSlide();
      } else if (e.key === 'Home') {
        goToSlide(0);
      } else if (e.key === 'End') {
        goToSlide(TOTAL_SLIDES - 1);
      }
    });

    // Fullscreen toggle
    const fullscreenBtn = document.getElementById('presFullscreenBtn');
    if (fullscreenBtn) {
      fullscreenBtn.addEventListener('click', toggleFullscreen);
    }

    // Back to QR Guard button
    const backBtn = document.getElementById('presBackBtn');
    if (backBtn) {
      backBtn.addEventListener('click', () => {
        const navScanner = document.getElementById('navScanner');
        if (navScanner) navScanner.click();
      });
    }

    // Show Architecture Shortcut button
    const showArchBtn = document.getElementById('presShowArchBtn');
    if (showArchBtn) {
      showArchBtn.addEventListener('click', () => {
        goToSlide(4); // Slide 5 is index 4 (System Architecture Diagram)
      });
    }

    // Quick jump dropdown
    const jumpSelect = document.getElementById('presJumpSelect');
    if (jumpSelect) {
      jumpSelect.addEventListener('change', (e) => {
        goToSlide(parseInt(e.target.value, 10));
      });
    }

    // Download PPTX button
    const downloadPptxBtn = document.getElementById('presDownloadPptxBtn');
    if (downloadPptxBtn) {
      downloadPptxBtn.addEventListener('click', () => {
        window.open('/QR_Guard_Presentation.pptx', '_blank');
        if (window.showToast) {
          window.showToast('Downloading QR_Guard_Presentation.pptx...', 'success');
        }
      });
    }
  }

  function updateSlideView() {
    const slides = document.querySelectorAll('.presentation-slide');
    const trackPills = document.querySelectorAll('.slide-step-pill');
    const counterEl = document.getElementById('presSlideCounter');
    const titleEl = document.getElementById('presSlideTitle');
    const jumpSelect = document.getElementById('presJumpSelect');

    slides.forEach((slide, idx) => {
      if (idx === currentSlide) {
        slide.classList.add('active');
        slide.style.display = 'block';
      } else {
        slide.classList.remove('active');
        slide.style.display = 'none';
      }
    });

    trackPills.forEach((pill, idx) => {
      pill.classList.toggle('active', idx === currentSlide);
    });

    if (counterEl) {
      const formattedNum = String(currentSlide + 1).padStart(2, '0');
      counterEl.textContent = `Slide ${formattedNum} / 09`;
    }

    if (titleEl) {
      titleEl.textContent = SLIDE_TITLES[currentSlide];
    }

    if (jumpSelect) {
      jumpSelect.value = String(currentSlide);
    }

    // Prev / Next button state
    const prevBtn = document.getElementById('presPrevBtn');
    const nextBtn = document.getElementById('presNextBtn');
    if (prevBtn) prevBtn.disabled = (currentSlide === 0);
    if (nextBtn) nextBtn.disabled = (currentSlide === TOTAL_SLIDES - 1);
  }

  function goToSlide(index) {
    if (index >= 0 && index < TOTAL_SLIDES) {
      currentSlide = index;
      updateSlideView();
      // Scroll deck into view
      const deck = document.getElementById('presentationDeck');
      if (deck && !isFullscreen) {
        deck.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }
  }

  function nextSlide() {
    if (currentSlide < TOTAL_SLIDES - 1) {
      goToSlide(currentSlide + 1);
    }
  }

  function prevSlide() {
    if (currentSlide > 0) {
      goToSlide(currentSlide - 1);
    }
  }

  function toggleFullscreen() {
    const deck = document.getElementById('presentationDeck');
    const btn = document.getElementById('presFullscreenBtn');
    if (!deck) return;

    isFullscreen = !isFullscreen;
    if (isFullscreen) {
      deck.classList.add('fullscreen-mode');
      if (btn) btn.innerHTML = '<i class="fa-solid fa-compress"></i> Exit Fullscreen';
      document.body.style.overflow = 'hidden';
      // Request browser fullscreen if available
      if (deck.requestFullscreen) {
        deck.requestFullscreen().catch(() => {});
      }
    } else {
      deck.classList.remove('fullscreen-mode');
      if (btn) btn.innerHTML = '<i class="fa-solid fa-expand"></i> Fullscreen';
      document.body.style.overflow = '';
      if (document.exitFullscreen && document.fullscreenElement) {
        document.exitFullscreen().catch(() => {});
      }
    }
  }

  // Handle browser fullscreen exit via ESC
  document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement && isFullscreen) {
      isFullscreen = false;
      const deck = document.getElementById('presentationDeck');
      const btn = document.getElementById('presFullscreenBtn');
      if (deck) deck.classList.remove('fullscreen-mode');
      if (btn) btn.innerHTML = '<i class="fa-solid fa-expand"></i> Fullscreen';
      document.body.style.overflow = '';
    }
  });

  return {
    init,
    goToSlide,
    nextSlide,
    prevSlide,
    toggleFullscreen
  };

})();
