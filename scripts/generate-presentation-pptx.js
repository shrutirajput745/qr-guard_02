const PptxGenJS = require('pptxgenjs');
const path = require('path');
const fs = require('fs');

async function createPresentation() {
  const pptx = new PptxGenJS();

  // Configure Presentation Dimensions (16:9 Widescreen)
  pptx.layout = 'LAYOUT_16x9';
  pptx.author = 'QR Guard Engineering Team';
  pptx.company = 'Department of Computer Engineering';
  pptx.title = 'QR Guard — Scan Smart. Think Safe.';

  // Modern Cybersecurity Palette: Deep navy, electric cyan, crisp white, subtle purple & sky blue
  const THEME = {
    bgDark: '080E1A',      // Deep navy background
    cardBg: '0F1829',      // Elevated card surface
    cardBorder: '1E2D48',  // Sleek border line
    textLight: 'F8FAFC',   // Crisp white
    textMuted: '94A3B8',   // Secondary text
    cyan: '00F0FF',        // Electric cyan accent
    blueLight: '38BDF8',   // Soft sky blue
    blueDeep: '1D4ED8',    // Deep accent blue
    purpleAccent: '8B5CF6',// Subtle purple accent
    purpleMuted: 'A78BFA', // Light purple
    emerald: '10B981',     // Active safe green
    amber: 'F59E0B',       // Warning / In-dev orange
    rose: 'EF4444',        // Threat red
    innerCard: '091220'    // Recessed container
  };

  // Standard Header for Slides 2 to 9
  function addHeader(slide, title, category, slideNum) {
    // Solid navy background
    slide.addShape(pptx.ShapeType.rect, {
      x: 0, y: 0, w: '100%', h: '100%',
      fill: { color: THEME.bgDark }
    });

    // Top Category Pill (with subtle purple/cyan border)
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 0.38, w: 2.8, h: 0.34,
      rectRadius: 0.08,
      fill: { color: '0A192F' },
      line: { color: THEME.cyan, width: 0.8 }
    });
    slide.addText(category.toUpperCase(), {
      x: 0.8, y: 0.38, w: 2.8, h: 0.34,
      fontSize: 9.5, bold: true, color: THEME.cyan,
      align: 'center', valign: 'middle'
    });

    // Slide Title
    slide.addText(title, {
      x: 0.8, y: 0.8, w: 10.0, h: 0.6,
      fontSize: 22, bold: true, color: THEME.textLight,
      valign: 'middle'
    });

    // Slide Number Tracker
    slide.addText(`${slideNum} / 09`, {
      x: 11.2, y: 0.38, w: 1.8, h: 0.34,
      fontSize: 11, bold: true, color: THEME.purpleMuted,
      align: 'right', valign: 'middle'
    });

    // Clean divider line
    slide.addShape(pptx.ShapeType.line, {
      x: 0.8, y: 1.45, w: 11.7, h: 0,
      line: { color: THEME.cardBorder, width: 1 }
    });
  }

  // ==========================================================================
  // SLIDE 1: COVER SLIDE
  // Project Name: QR Guard | Tagline: "Scan Smart. Think Safe."
  // Subtitle: Smart QR Code Analysis and Security Awareness
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    slide.addShape(pptx.ShapeType.rect, {
      x: 0, y: 0, w: '100%', h: '100%',
      fill: { color: THEME.bgDark }
    });

    // Main Card Surface
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 0.6, w: 11.73, h: 6.3,
      rectRadius: 0.16,
      fill: { color: THEME.cardBg },
      line: { color: THEME.cardBorder, width: 1.2 }
    });

    // ── LEFT COLUMN: Text Hierarchy & Academic Details ───────────────────────

    // Eyebrow Tag: Project Presentation
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 1.2, y: 0.95, w: 2.7, h: 0.34,
      rectRadius: 0.08,
      fill: { color: '0A2038' },
      line: { color: THEME.cyan, width: 0.9 }
    });
    slide.addText('PROJECT PRESENTATION', {
      x: 1.2, y: 0.95, w: 2.7, h: 0.34,
      fontSize: 9.5, bold: true, color: THEME.cyan,
      align: 'center', valign: 'middle'
    });

    // Main Title: QR Guard
    slide.addText('QR Guard', {
      x: 1.15, y: 1.38, w: 6.0, h: 0.85,
      fontSize: 46, bold: true, color: THEME.textLight,
      valign: 'middle'
    });

    // Tagline: Scan Smart. Think Safe.
    slide.addText('Scan Smart. Think Safe.', {
      x: 1.2, y: 2.25, w: 6.0, h: 0.42,
      fontSize: 18, bold: true, color: THEME.cyan,
      valign: 'middle'
    });

    // Subtitle & Short Project Description
    slide.addText('Smart QR Code Analysis and Security Awareness', {
      x: 1.2, y: 2.72, w: 5.8, h: 0.35,
      fontSize: 13, bold: true, color: THEME.purpleMuted
    });
    slide.addText('A smarter approach to QR code analysis, content understanding, and security awareness.', {
      x: 1.2, y: 3.1, w: 5.8, h: 0.55,
      fontSize: 11.5, color: THEME.textMuted
    });

    // Academic Metadata: Understated, Clean Placeholders for College Evaluation
    const academicBoxes = [
      {
        label: 'PRESENTED BY',
        value: '[Student Name(s)]',
        sub: 'Roll No: [PRN / Roll Numbers]',
        y: 3.8
      },
      {
        label: 'DEPARTMENT / COURSE',
        value: '[Course or Department]',
        sub: 'Department of Computer Engineering',
        y: 4.55
      },
      {
        label: 'GUIDED BY & INSTITUTION',
        value: '[Faculty Guide Name]',
        sub: 'College / Institute: [College Name]',
        y: 5.3
      }
    ];

    academicBoxes.forEach(box => {
      slide.addShape(pptx.ShapeType.roundRect, {
        x: 1.2, y: box.y, w: 5.8, h: 0.65,
        rectRadius: 0.06,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });

      // Accent Bar on Left (Cyan / Purple gradient feel)
      slide.addShape(pptx.ShapeType.roundRect, {
        x: 1.2, y: box.y, w: 0.08, h: 0.65,
        rectRadius: 0.02,
        fill: { color: THEME.cyan }
      });

      slide.addText(box.label, {
        x: 1.38, y: box.y + 0.07, w: 3.0, h: 0.2,
        fontSize: 8.5, bold: true, color: THEME.blueLight
      });
      slide.addText(box.value, {
        x: 1.38, y: box.y + 0.28, w: 3.2, h: 0.3,
        fontSize: 11, bold: true, color: THEME.textLight
      });
      slide.addText(box.sub, {
        x: 4.2, y: box.y + 0.16, w: 2.7, h: 0.35,
        fontSize: 8.5, color: THEME.textMuted, align: 'right'
      });
    });

    // ── RIGHT COLUMN: Hero Cybersecurity Shield & QR Visual ──────────────────
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 7.3, y: 0.95, w: 4.85, h: 5.15,
      rectRadius: 0.12,
      fill: { color: '071120' },
      line: { color: THEME.cardBorder, width: 1 }
    });

    const heroSvgPath = path.join(__dirname, '..', 'public', 'images', 'qr-guard-hero-shield.svg');
    if (fs.existsSync(heroSvgPath)) {
      slide.addImage({
        path: heroSvgPath,
        x: 7.55, y: 1.1, w: 4.35, h: 4.35
      });
    }

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 8.1, y: 5.45, w: 3.25, h: 0.38,
      rectRadius: 0.08,
      fill: { color: '0B1B32' },
      line: { color: THEME.cyan, width: 0.8 }
    });
    slide.addText('ZERO-TRUST PRE-NAVIGATION INSPECTION', {
      x: 8.1, y: 5.45, w: 3.25, h: 0.38,
      fontSize: 8.5, bold: true, color: THEME.cyan,
      align: 'center', valign: 'middle'
    });

    slide.addNotes(
      "Good morning respected evaluators. Today we present 'QR Guard: Scan Smart. Think Safe.' " +
      "QR Guard is an intelligent client-side QR scanner and heuristic URL security analyzer. " +
      "It helps users decode visual codes safely, understand their underlying content, and inspect links before opening them."
    );
  }

  // ==========================================================================
  // SLIDE 2: PROBLEM STATEMENT
  // Problem-to-Impact Layout with Simple Language
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Problem Statement: Hidden Risks Behind Visual Codes', 'Problem Statement', '02');

    const issues = [
      {
        num: '01',
        title: 'Everyday Usage & Blind Trust',
        icon: '📱',
        desc: 'QR codes are commonly used for accessing websites, sharing information, and making digital interactions easier. However, users cannot know what content a QR code contains before scanning it.',
        impact: 'Impact: Blind trust leads users to open unknown destinations without prior verification.',
        color: THEME.blueLight
      },
      {
        num: '02',
        title: 'Unchecked URL Destinations',
        icon: '⚠️',
        desc: 'Unknown links inside QR codes may lead to misleading or potentially unsafe websites. Standard phone cameras frequently auto-navigate users without warning.',
        impact: 'Impact: Exposes users to phishing scams, credential harvesting, and deceptive redirects.',
        color: THEME.amber
      },
      {
        num: '03',
        title: 'Degraded Image Scanning Failures',
        icon: '🔍',
        desc: 'Blurry, low-contrast, or damaged QR codes can be difficult to scan. Environmental glare and motion blur frequently cause scanning to fail silently.',
        impact: 'Impact: Users experience unhelpful scan failures with no recovery options or feedback.',
        color: THEME.rose
      }
    ];

    issues.forEach((it, idx) => {
      const cx = 0.8 + idx * 3.9;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: cx, y: 1.8, w: 3.65, h: 4.4,
        rectRadius: 0.14,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1.2 }
      });

      // Problem Badge
      slide.addShape(pptx.ShapeType.roundRect, {
        x: cx + 0.3, y: 2.1, w: 0.65, h: 0.35,
        rectRadius: 0.06,
        fill: { color: '0D243F' },
        line: { color: it.color, width: 1 }
      });
      slide.addText(it.num, {
        x: cx + 0.3, y: 2.1, w: 0.65, h: 0.35,
        fontSize: 11, bold: true, color: it.color,
        align: 'center', valign: 'middle'
      });

      slide.addText(`${it.icon}  ${it.title}`, {
        x: cx + 0.3, y: 2.65, w: 3.05, h: 0.45,
        fontSize: 14.5, bold: true, color: THEME.textLight
      });

      slide.addText(it.desc, {
        x: cx + 0.3, y: 3.2, w: 3.05, h: 1.45,
        fontSize: 11, color: THEME.textMuted,
        lineSpacingMultiple: 1.15
      });

      // Impact Box
      slide.addShape(pptx.ShapeType.roundRect, {
        x: cx + 0.25, y: 4.8, w: 3.15, h: 1.15,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: it.color, width: 0.8 }
      });
      slide.addText(it.impact, {
        x: cx + 0.35, y: 4.9, w: 2.95, h: 0.95,
        fontSize: 9.8, bold: true, color: it.color
      });
    });

    // Summary Observation Bar
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 6.4, w: 11.45, h: 0.55,
      rectRadius: 0.08,
      fill: { color: '15233A' },
      line: { color: THEME.blueLight, width: 1 }
    });
    slide.addText('Core Problem: Users need a security-conscious intermediate step before opening unknown QR content.', {
      x: 1.0, y: 6.4, w: 11.0, h: 0.55,
      fontSize: 11.5, bold: true, color: THEME.textLight,
      valign: 'middle'
    });

    slide.addNotes(
      "In Slide 2, we explain the core problem: QR codes are ubiquitous, but human eyes cannot interpret them before scanning. " +
      "Default phone camera applications auto-open links immediately, putting users at risk of quishing. " +
      "Additionally, degraded images often fail to scan without helpful feedback."
    );
  }

  // ==========================================================================
  // SLIDE 3: PROJECT OBJECTIVES
  // Clearly Distinguishing Strategic Goals from a Simple Feature List
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Project Objectives: Clear Strategic Goals', 'Objectives', '03');

    const objectives = [
      {
        num: 'OBJ 1',
        title: 'Interpret Supported QR Content',
        goal: 'Make QR code content easier to understand. Parse raw visual patterns and display their underlying data clearly before any action occurs.',
        focus: 'Focus: Content transparency and zero blind auto-navigation.'
      },
      {
        num: 'OBJ 2',
        title: 'Improve Suspicious URL Awareness',
        goal: 'Improve awareness before users open unknown links. Alert users to potentially suspicious URLs, unencrypted protocols, and deceptive hostnames.',
        focus: 'Focus: Proactive threat awareness and informed decision-making.'
      },
      {
        num: 'OBJ 3',
        title: 'Simple & Readable Presentation',
        goal: 'Present decoded information in a simple and readable format. Organize supported payloads (URLs, Wi-Fi, contacts, UPI, text) into clear visual cards.',
        focus: 'Focus: Accessible, user-friendly cybersecurity interface.'
      },
      {
        num: 'OBJ 4',
        title: 'Encourage Mindful QR Usage',
        goal: 'Encourage more informed and security-conscious QR code usage, helping users build a habit to verify before opening.',
        focus: 'Focus: Educational impact: Scan Smart. Think Safe.'
      }
    ];

    objectives.forEach((obj, idx) => {
      const gx = 0.8 + idx * 2.92;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: gx, y: 1.8, w: 2.75, h: 3.8,
        rectRadius: 0.12,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1.2 }
      });

      // Tag
      slide.addShape(pptx.ShapeType.roundRect, {
        x: gx + 0.2, y: 2.05, w: 1.1, h: 0.32,
        rectRadius: 0.06,
        fill: { color: '0E223D' },
        line: { color: THEME.cyan, width: 1 }
      });
      slide.addText(obj.num, {
        x: gx + 0.2, y: 2.05, w: 1.1, h: 0.32,
        fontSize: 10, bold: true, color: THEME.cyan,
        align: 'center', valign: 'middle'
      });

      slide.addText(obj.title, {
        x: gx + 0.2, y: 2.55, w: 2.35, h: 0.65,
        fontSize: 13.5, bold: true, color: THEME.textLight
      });

      slide.addText(obj.goal, {
        x: gx + 0.2, y: 3.25, w: 2.35, h: 1.35,
        fontSize: 10.5, color: THEME.textMuted,
        lineSpacingMultiple: 1.15
      });

      // Bottom Focus Tag
      slide.addShape(pptx.ShapeType.roundRect, {
        x: gx + 0.18, y: 4.75, w: 2.39, h: 0.7,
        rectRadius: 0.06,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });
      slide.addText(obj.focus, {
        x: gx + 0.25, y: 4.8, w: 2.25, h: 0.6,
        fontSize: 9, bold: true, color: THEME.blueLight
      });
    });

    // Dedicated Research Objective: Blur Recovery
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 5.8, w: 11.45, h: 1.15,
      rectRadius: 0.1,
      fill: { color: '1A1528' },
      line: { color: THEME.purpleAccent, width: 1.2, dashType: 'dash' }
    });
    slide.addText('RESEARCH OBJECTIVE · FUTURE ENHANCEMENT', {
      x: 1.1, y: 5.92, w: 5.0, h: 0.25,
      fontSize: 9.5, bold: true, color: THEME.purpleMuted
    });
    slide.addText('Explore recovery techniques for unclear or blurry QR codes as a future enhancement:', {
      x: 1.1, y: 6.22, w: 6.0, h: 0.3,
      fontSize: 11, bold: true, color: THEME.textLight
    });
    slide.addText('Investigate browser-based digital image preprocessing (contrast enhancement, sharpening kernels) to recover low-quality QR codes in a subsequent development phase.', {
      x: 1.1, y: 6.52, w: 10.8, h: 0.35,
      fontSize: 10.5, color: THEME.textMuted
    });

    slide.addNotes(
      "Here we distinguish strategic objectives from mere feature bullet points. " +
      "Our objectives focus on helping users interpret QR payloads, improving pre-click awareness, " +
      "presenting findings simply, and investigating blur recovery as a designated future research goal."
    );
  }

  // ==========================================================================
  // SLIDE 4: PROPOSED SOLUTION — QR GUARD
  // How QR Guard Addresses the Problem & Clear Implemented vs Planned Split
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Proposed Solution: How QR Guard Solves the Problem', 'Proposed Solution', '04');

    // Left Column: The 5-Step Core Solution (Green border)
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 1.8, w: 6.0, h: 5.15,
      rectRadius: 0.14,
      fill: { color: THEME.cardBg },
      line: { color: THEME.emerald, width: 1.5 }
    });

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 1.1, y: 2.05, w: 2.6, h: 0.35,
      rectRadius: 0.06,
      fill: { color: '064E3B' },
      line: { color: THEME.emerald, width: 1 }
    });
    slide.addText('IMPLEMENTED SOLUTION', {
      x: 1.1, y: 2.05, w: 2.6, h: 0.35,
      fontSize: 10, bold: true, color: '#6EE7B7',
      align: 'center', valign: 'middle'
    });

    slide.addText('Core 5-Step QR Guard Approach', {
      x: 1.1, y: 2.55, w: 5.3, h: 0.45,
      fontSize: 16.5, bold: true, color: THEME.textLight
    });

    const solutionSteps = [
      { step: '1', title: 'Accept QR Code Input', desc: 'Accept camera video stream, image uploads, or sample payloads.' },
      { step: '2', title: 'Decode Available Content', desc: 'Extract encoded data on client-side using pure JavaScript (jsQR).' },
      { step: '3', title: 'Identify Content Type', desc: 'Automatically classify into URL, Wi-Fi, vCard, UPI, or text.' },
      { step: '4', title: 'Display in Readable Format', desc: 'Present decoded information cleanly with dedicated visual cards.' },
      { step: '5', title: 'Pre-Navigation URL Review', desc: 'Inspect destination characteristics and warn users before opening.' }
    ];

    solutionSteps.forEach((st, i) => {
      const sy = 3.12 + i * 0.74;
      slide.addShape(pptx.ShapeType.ellipse, {
        x: 1.1, y: sy + 0.05, w: 0.32, h: 0.32,
        fill: { color: '064E3B' },
        line: { color: THEME.emerald, width: 1 }
      });
      slide.addText(st.step, {
        x: 1.1, y: sy + 0.05, w: 0.32, h: 0.32,
        fontSize: 10, bold: true, color: '#6EE7B7',
        align: 'center', valign: 'middle'
      });

      slide.addText(st.title, {
        x: 1.55, y: sy, w: 5.0, h: 0.28,
        fontSize: 11.5, bold: true, color: THEME.textLight
      });
      slide.addText(st.desc, {
        x: 1.55, y: sy + 0.26, w: 5.0, h: 0.42,
        fontSize: 10, color: THEME.textMuted
      });
    });

    // Right Column: Planned Enhancements (Amber border)
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 7.1, y: 1.8, w: 5.15, h: 5.15,
      rectRadius: 0.14,
      fill: { color: THEME.cardBg },
      line: { color: THEME.amber, width: 1.5, dashType: 'dash' }
    });

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 7.4, y: 2.05, w: 3.1, h: 0.35,
      rectRadius: 0.06,
      fill: { color: '451A03' },
      line: { color: THEME.amber, width: 1 }
    });
    slide.addText('PLANNED — UNDER DEVELOPMENT', {
      x: 7.4, y: 2.05, w: 3.1, h: 0.35,
      fontSize: 10, bold: true, color: '#FDE68A',
      align: 'center', valign: 'middle'
    });

    slide.addText('Blur Recovery Lab (Future Scope)', {
      x: 7.4, y: 2.55, w: 4.6, h: 0.45,
      fontSize: 16.5, bold: true, color: THEME.textLight
    });

    const plannedAspects = [
      { title: 'Separate Preprocessing Pipeline', desc: 'Planned module to preprocess blurry images before sending to decoder.' },
      { title: 'Image Enhancement Research', desc: 'Testing unsharp masking and adaptive binarization for unreadable codes.' },
      { title: 'Controlled Test Lab', desc: 'A dedicated test environment to validate blur recovery once implemented.' },
      { title: 'Honest Development Status', desc: 'Currently in experimental research phase; not presented as working.' }
    ];

    plannedAspects.forEach((pa, i) => {
      const py = 3.2 + i * 0.9;
      slide.addText(`⏳  ${pa.title}`, {
        x: 7.4, y: py, w: 4.6, h: 0.3,
        fontSize: 11.5, bold: true, color: THEME.amber
      });
      slide.addText(pa.desc, {
        x: 7.65, y: py + 0.28, w: 4.4, h: 0.55,
        fontSize: 10, color: THEME.textMuted
      });
    });

    slide.addNotes(
      "This slide explains how QR Guard approaches the problem through a clear 5-step flow. " +
      "Importantly, we distinguish our working functionality—camera input, decoding, classification, and URL review—" +
      "from our planned Blur Recovery Lab, which is currently under development."
    );
  }

  // ==========================================================================
  // SLIDE 5: SYSTEM ARCHITECTURE
  // Clean Flowchart with Main Data Flow, URL Branch & Planned Blur Workflow
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'System Architecture: Data Pipeline & Component Flow', 'System Architecture', '05');

    // ── MAIN FLOW CONTAINER (Top Box) ────────────────────────────────────────
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 1.7, w: 11.7, h: 3.45,
      rectRadius: 0.12,
      fill: { color: THEME.cardBg },
      line: { color: THEME.cardBorder, width: 1.2 }
    });

    slide.addText('PRIMARY RUNTIME DATA FLOW (CURRENT IMPLEMENTATION)', {
      x: 1.1, y: 1.85, w: 8.0, h: 0.3,
      fontSize: 10.5, bold: true, color: THEME.cyan
    });

    // 5 Sequential Nodes: User -> Input -> Decoder -> Decoded Content -> Content Type
    const topRowNodes = [
      { title: 'User', sub: 'Camera / File Upload', color: THEME.blueLight, x: 1.0 },
      { title: 'QR Code Input', sub: 'HTML5 Video / Canvas', color: THEME.cyan, x: 3.1 },
      { title: 'QR Decoder', sub: 'jsQR Matrix Extraction', color: THEME.blueLight, x: 5.2 },
      { title: 'Decoded Content', sub: 'Raw Payload String', color: THEME.purpleMuted, x: 7.3 },
      { title: 'Content Type ID', sub: 'URL / Wi-Fi / UPI / Text', color: THEME.emerald, x: 9.4 }
    ];

    topRowNodes.forEach((node, i) => {
      slide.addShape(pptx.ShapeType.roundRect, {
        x: node.x, y: 2.25, w: 1.75, h: 1.1,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: node.color, width: 1.2 }
      });

      slide.addText(node.title, {
        x: node.x + 0.05, y: 2.38, w: 1.65, h: 0.35,
        fontSize: 11.5, bold: true, color: THEME.textLight,
        align: 'center'
      });
      slide.addText(node.sub, {
        x: node.x + 0.05, y: 2.75, w: 1.65, h: 0.5,
        fontSize: 9, color: node.color,
        align: 'center'
      });

      // Horizontal Arrow
      if (i < topRowNodes.length - 1) {
        slide.addShape(pptx.ShapeType.rightArrow, {
          x: node.x + 1.78, y: 2.7, w: 0.3, h: 0.18,
          fill: { color: THEME.cyan },
          line: { color: THEME.cyan }
        });
      }
    });

    // Downward Branch for URL Analysis & Result Display
    slide.addShape(pptx.ShapeType.downArrow, {
      x: 10.15, y: 3.38, w: 0.22, h: 0.25,
      fill: { color: THEME.emerald },
      line: { color: THEME.emerald }
    });

    // Sub-row: URL Analysis Branch + Final Result Display
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 5.2, y: 3.75, w: 3.85, h: 1.15,
      rectRadius: 0.08,
      fill: { color: '121F38' },
      line: { color: THEME.amber, width: 1.2 }
    });
    slide.addText('URL Analysis Branch (When Applicable)', {
      x: 5.3, y: 3.85, w: 3.65, h: 0.3,
      fontSize: 11, bold: true, color: THEME.amber,
      align: 'center'
    });
    slide.addText('Heuristic Evaluation: Protocol, IP Host, Suspicious TLDs, Shorteners', {
      x: 5.3, y: 4.15, w: 3.65, h: 0.65,
      fontSize: 9.5, color: THEME.textMuted,
      align: 'center'
    });

    // Arrow to Result Display
    slide.addShape(pptx.ShapeType.rightArrow, {
      x: 9.1, y: 4.25, w: 0.25, h: 0.18,
      fill: { color: THEME.amber },
      line: { color: THEME.amber }
    });

    // Result Display Node
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 9.4, y: 3.75, w: 1.75, h: 1.15,
      rectRadius: 0.08,
      fill: { color: '063B2C' },
      line: { color: THEME.emerald, width: 1.4 }
    });
    slide.addText('Result Display', {
      x: 9.45, y: 3.88, w: 1.65, h: 0.3,
      fontSize: 12, bold: true, color: '#6EE7B7',
      align: 'center'
    });
    slide.addText('Verdict Badge & Content Card', {
      x: 9.45, y: 4.2, w: 1.65, h: 0.6,
      fontSize: 9, color: THEME.textLight,
      align: 'center'
    });

    // ── PLANNED BLUR RECOVERY CONTAINER (Bottom Box) ─────────────────────────
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 5.3, w: 11.7, h: 1.65,
      rectRadius: 0.12,
      fill: { color: '0C1524' },
      line: { color: THEME.amber, width: 1.2, dashType: 'dash' }
    });

    slide.addText('PLANNED BLUR RECOVERY WORKFLOW (PLANNED — UNDER DEVELOPMENT)', {
      x: 1.1, y: 5.42, w: 8.0, h: 0.26,
      fontSize: 9.5, bold: true, color: THEME.amber
    });

    const plannedFlow = [
      { title: 'Blurry QR Image', sub: 'Low Contrast / Defocus', x: 1.5 },
      { title: 'Planned Image Preprocessing', sub: 'Contrast & Sharpening Filters', x: 5.0 },
      { title: 'QR Decoder', sub: 'Re-attempt Finder Detection', x: 8.5 }
    ];

    plannedFlow.forEach((pf, idx) => {
      slide.addShape(pptx.ShapeType.roundRect, {
        x: pf.x, y: 5.8, w: 2.8, h: 0.95,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: THEME.amber, width: 0.8 }
      });

      slide.addText(pf.title, {
        x: pf.x + 0.1, y: 5.9, w: 2.6, h: 0.32,
        fontSize: 11, bold: true, color: THEME.textLight,
        align: 'center'
      });
      slide.addText(pf.sub, {
        x: pf.x + 0.1, y: 6.25, w: 2.6, h: 0.35,
        fontSize: 9, color: THEME.amber,
        align: 'center'
      });

      if (idx < 2) {
        slide.addShape(pptx.ShapeType.rightArrow, {
          x: pf.x + 2.85, y: 6.2, w: 0.6, h: 0.18,
          fill: { color: THEME.amber },
          line: { color: THEME.amber }
        });
      }
    });

    slide.addNotes(
      "Our system architecture flowchart clearly maps the data pipeline. " +
      "The main pipeline flows from User to QR Input, through the QR Decoder, into Decoded Content, Content Type Identification, and Result Display. " +
      "URLs branch into a dedicated heuristic analysis step. " +
      "At the bottom, our planned Blur Recovery workflow is explicitly marked with a dashed border as Planned — Under Development."
    );
  }

  // ==========================================================================
  // SLIDE 6: SMART TECHNIQUE AND WORKING LOGIC
  // Technical Concepts in Simple Terms (No Fabricated AI/ML)
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Smart Technique & Working Logic: Technical Approach', 'Working Logic', '06');

    const techniques = [
      {
        num: '01',
        title: 'QR Code Decoding Logic',
        desc: 'Converts the visual QR pattern into readable data. Detects the three corner finder markers, rectifies perspective skew, and reads binary data modules.',
        tech: 'Client-side jsQR engine · Zero server transmission'
      },
      {
        num: '02',
        title: 'Content Identification',
        desc: 'Identifies the type of information contained in the QR code (URL, Wi-Fi configuration, vCard contact, UPI payment, or plaintext) to format the output appropriately.',
        tech: 'Deterministic schema parsing · Safe attribute extraction'
      },
      {
        num: '03',
        title: 'URL Inspection & Safety Checks',
        desc: 'Performs rule-based URL checks (plain HTTP, raw IP addresses, suspicious TLDs, shorteners) to help users understand destination risks before opening.',
        tech: 'Transparent heuristic scoring · Explanatory findings'
      },
      {
        num: '04',
        title: 'Clear, Actionable User Interface',
        desc: 'Presents information in an intuitive layout with color-coded safety indicators, defanged previews, and clear action choices.',
        tech: 'Responsive cybersecurity dashboard · Zero-trust workflow'
      }
    ];

    techniques.forEach((tech, i) => {
      const ty = 1.75 + i * 1.08;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: 0.8, y: ty, w: 11.7, h: 0.95,
        rectRadius: 0.08,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1 }
      });

      // Number badge
      slide.addShape(pptx.ShapeType.roundRect, {
        x: 1.05, y: ty + 0.22, w: 0.5, h: 0.45,
        rectRadius: 0.06,
        fill: { color: '0D243F' },
        line: { color: THEME.cyan, width: 1 }
      });
      slide.addText(tech.num, {
        x: 1.05, y: ty + 0.22, w: 0.5, h: 0.45,
        fontSize: 11, bold: true, color: THEME.cyan,
        align: 'center', valign: 'middle'
      });

      // Title & Tech Tag
      slide.addText(tech.title, {
        x: 1.75, y: ty + 0.12, w: 4.2, h: 0.35,
        fontSize: 12.5, bold: true, color: THEME.textLight
      });
      slide.addText(tech.tech, {
        x: 1.75, y: ty + 0.48, w: 4.2, h: 0.35,
        fontSize: 9.5, bold: true, color: THEME.blueLight
      });

      // Description
      slide.addText(tech.desc, {
        x: 6.1, y: ty + 0.1, w: 6.1, h: 0.75,
        fontSize: 10.5, color: THEME.textMuted,
        valign: 'middle', lineSpacingMultiple: 1.15
      });
    });

    // Important Realism / Disclosure Box
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 6.25, w: 11.7, h: 0.8,
      rectRadius: 0.08,
      fill: { color: '181E2E' },
      line: { color: THEME.purpleAccent, width: 1 }
    });
    slide.addText('IMPORTANT REALISTIC DISCLOSURE:', {
      x: 1.0, y: 6.33, w: 3.5, h: 0.22,
      fontSize: 9, bold: true, color: THEME.purpleMuted
    });
    slide.addText('QR Guard does NOT claim guaranteed security or detection of every malicious link. It provides transparent heuristics to raise user awareness. Blur recovery is a proposed enhancement requiring further testing.', {
      x: 1.0, y: 6.55, w: 11.2, h: 0.45,
      fontSize: 10, color: THEME.textLight
    });

    slide.addNotes(
      "In Slide 6, we explain the technical concept in simple, realistic terms. " +
      "We explain how visual QR patterns are decoded, how content is categorized, and how URLs are inspected. " +
      "We emphasize honesty: QR Guard raises awareness through heuristics without falsely claiming guaranteed protection."
    );
  }

  // ==========================================================================
  // SLIDE 7: DEMONSTRATION OF THE CURRENT PROJECT
  // 5-Step Demo Sequence & Verified Working Functional Areas
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Project Demonstration: Step-by-Step Live Walkthrough', 'Demonstration', '07');

    const steps = [
      {
        step: 'STEP 1',
        title: 'Open QR Guard',
        desc: 'Launch application in any modern browser. Interface opens ready for live camera scanning or image drop.',
        tag: 'Universal Access'
      },
      {
        step: 'STEP 2',
        title: 'Provide QR Input',
        desc: 'Scan a physical QR code using camera, upload a local image file, or select pre-loaded test samples.',
        tag: 'Multi-Input'
      },
      {
        step: 'STEP 3',
        title: 'Decode & Display',
        desc: 'QR decoder instantly extracts data. The application identifies whether content is a URL, Wi-Fi, or contact.',
        tag: 'Instant Parsing'
      },
      {
        step: 'STEP 4',
        title: 'Review URL Analysis',
        desc: 'For URLs, review the risk score, protocol status, domain details, and heuristic findings before opening.',
        tag: 'Security Review'
      },
      {
        step: 'STEP 5',
        title: 'Blur Lab Preview',
        desc: 'Briefly view the experimental Blur Recovery Lab interface, noting its status as a future enhancement.',
        tag: 'Future Lab'
      }
    ];

    steps.forEach((st, idx) => {
      const sx = 0.8 + idx * 2.33;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: sx, y: 1.8, w: 2.18, h: 3.7,
        rectRadius: 0.1,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1.2 }
      });

      // Step Tag
      slide.addShape(pptx.ShapeType.roundRect, {
        x: sx + 0.15, y: 2.0, w: 1.1, h: 0.3,
        rectRadius: 0.06,
        fill: { color: '0D243F' },
        line: { color: THEME.cyan, width: 1 }
      });
      slide.addText(st.step, {
        x: sx + 0.15, y: 2.0, w: 1.1, h: 0.3,
        fontSize: 9.5, bold: true, color: THEME.cyan,
        align: 'center', valign: 'middle'
      });

      slide.addText(st.title, {
        x: sx + 0.15, y: 2.45, w: 1.88, h: 0.45,
        fontSize: 12.5, bold: true, color: THEME.textLight
      });

      slide.addText(st.desc, {
        x: sx + 0.15, y: 3.0, w: 1.88, h: 1.8,
        fontSize: 10, color: THEME.textMuted,
        lineSpacingMultiple: 1.15
      });

      // Subtag
      slide.addShape(pptx.ShapeType.roundRect, {
        x: sx + 0.15, y: 4.95, w: 1.88, h: 0.35,
        rectRadius: 0.06,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });
      slide.addText(st.tag, {
        x: sx + 0.15, y: 4.95, w: 1.88, h: 0.35,
        fontSize: 8.5, bold: true, color: THEME.blueLight,
        align: 'center', valign: 'middle'
      });
    });

    // Honest Verified Features vs Experimental Lab Callout
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 5.75, w: 11.45, h: 1.15,
      rectRadius: 0.1,
      fill: { color: '1A1528' },
      line: { color: THEME.amber, width: 1.2 }
    });
    slide.addText('VERIFIED LIVE DEMONSTRATION SCOPE:', {
      x: 1.1, y: 5.88, w: 4.5, h: 0.25,
      fontSize: 9.5, bold: true, color: THEME.emerald
    });
    slide.addText('Camera scanning, image drop, URL risk scoring, Wi-Fi payloads, and UPI previews are verified and operational.', {
      x: 1.1, y: 6.18, w: 10.8, h: 0.3,
      fontSize: 10.5, color: THEME.textLight
    });
    slide.addText('Note: Blur Recovery Lab is Under Development — presented as an experimental prototype for architecture completeness.', {
      x: 1.1, y: 6.5, w: 10.8, h: 0.3,
      fontSize: 10, bold: true, color: THEME.amber
    });

    slide.addNotes(
      "In Slide 7, we present the exact 5-step live demonstration sequence for our presentation: " +
      "Opening the tool, providing QR input, observing instant decoding, reviewing URL analysis, and previewing the experimental Blur Lab. " +
      "We explicitly note that Blur Recovery is under development."
    );
  }

  // ==========================================================================
  // SLIDE 8: FUTURE SCOPE AND MILESTONES
  // Clean Visual Roadmap with 6 Concrete Milestones
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Future Scope & Milestones: Engineering Roadmap', 'Future Scope', '08');

    const roadmap = [
      {
        num: 'M1',
        title: 'Complete Blur Recovery Lab',
        desc: 'Implement and test digital image processing techniques (contrast adjustment, unsharp mask filter) to recover blurry codes.',
        status: 'Priority Research Goal'
      },
      {
        num: 'M2',
        title: 'Sample-Based Demonstrations',
        desc: 'Add reliable, verifiable sample-based demonstrations for degraded QR recovery across different blur levels.',
        status: 'Testing & Validation'
      },
      {
        num: 'M3',
        title: 'Improve Error Handling',
        desc: 'Improve guidance and troubleshooting when QR codes are damaged, unreadable, or corrupted.',
        status: 'User Experience'
      },
      {
        num: 'M4',
        title: 'Expand QR Content Types',
        desc: 'Expand testing across additional QR formats including calendar events, crypto addresses, and multi-contact vCards.',
        status: 'Format Coverage'
      },
      {
        num: 'M5',
        title: 'Improve URL Analysis',
        desc: 'Improve URL analysis and user feedback by safely unshortening redirect links and expanding heuristic checks.',
        status: 'Security Depth'
      },
      {
        num: 'M6',
        title: 'Refine Interface & Usability',
        desc: 'Add camera zoom controls, lighting indicators, exportable audit reports, and accessibility improvements.',
        status: 'Usability Polish'
      }
    ];

    roadmap.forEach((rm, idx) => {
      const col = idx % 3;
      const row = Math.floor(idx / 3);
      const rx = 0.8 + col * 3.9;
      const ry = 1.8 + row * 2.5;

      slide.addShape(pptx.ShapeType.roundRect, {
        x: rx, y: ry, w: 3.65, h: 2.3,
        rectRadius: 0.1,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1 }
      });

      // Milestone Pill
      slide.addShape(pptx.ShapeType.roundRect, {
        x: rx + 0.2, y: ry + 0.2, w: 0.7, h: 0.3,
        rectRadius: 0.06,
        fill: { color: '2E1065' },
        line: { color: THEME.purpleAccent, width: 1 }
      });
      slide.addText(rm.num, {
        x: rx + 0.2, y: ry + 0.2, w: 0.7, h: 0.3,
        fontSize: 10, bold: true, color: '#DDD6FE',
        align: 'center', valign: 'middle'
      });

      slide.addText(rm.title, {
        x: rx + 1.05, y: ry + 0.18, w: 2.4, h: 0.35,
        fontSize: 12, bold: true, color: THEME.textLight
      });

      slide.addText(rm.desc, {
        x: rx + 0.2, y: ry + 0.62, w: 3.25, h: 1.05,
        fontSize: 10, color: THEME.textMuted,
        lineSpacingMultiple: 1.15
      });

      // Bottom Status
      slide.addShape(pptx.ShapeType.roundRect, {
        x: rx + 0.2, y: ry + 1.75, w: 3.25, h: 0.38,
        rectRadius: 0.06,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });
      slide.addText(rm.status, {
        x: rx + 0.2, y: ry + 1.75, w: 3.25, h: 0.38,
        fontSize: 8.5, bold: true, color: THEME.cyan,
        align: 'center', valign: 'middle'
      });
    });

    slide.addNotes(
      "Slide 8 presents our visual roadmap across 6 clearly identified future milestones. " +
      "We highlight completing the Blur Recovery Lab, expanding sample testing, enhancing error handling, " +
      "supporting more QR schemas, deepening URL unshortening, and refining cross-device usability."
    );
  }

  // ==========================================================================
  // SLIDE 9: CONCLUSION AND THANK YOU
  // Project Summary, Core Takeaways & Ending Tagline
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    slide.addShape(pptx.ShapeType.rect, {
      x: 0, y: 0, w: '100%', h: '100%',
      fill: { color: THEME.bgDark }
    });

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 0.7, w: 11.7, h: 6.1,
      rectRadius: 0.16,
      fill: { color: THEME.cardBg },
      line: { color: THEME.cyan, width: 1.4 }
    });

    // Closing Title
    slide.addText('Thank You', {
      x: 1.5, y: 1.1, w: 10.3, h: 0.8,
      fontSize: 44, bold: true, color: THEME.textLight,
      align: 'center', valign: 'middle'
    });

    // Tagline
    slide.addText('QR Guard — Scan Smart. Think Safe.', {
      x: 1.5, y: 1.95, w: 10.3, h: 0.42,
      fontSize: 19, bold: true, color: THEME.cyan,
      align: 'center', valign: 'middle'
    });

    // 3 Summary Cards
    const summaryCards = [
      {
        title: 'Understandable & Aware',
        desc: 'QR Guard aims to make QR code interaction more understandable and security-conscious for everyday users.'
      },
      {
        title: 'Transparent Heuristics',
        desc: 'The project focuses on decoding, presenting information clearly, and encouraging users to review unknown links carefully.'
      },
      {
        title: 'Active Future Scope',
        desc: 'Further development will focus on improving recovery capabilities and reliability through the Blur Recovery Lab.'
      }
    ];

    summaryCards.forEach((sc, idx) => {
      const scx = 1.3 + idx * 3.65;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: scx, y: 2.7, w: 3.4, h: 2.1,
        rectRadius: 0.1,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 1 }
      });

      slide.addText(sc.title, {
        x: scx + 0.2, y: 2.9, w: 3.0, h: 0.35,
        fontSize: 12.5, bold: true, color: THEME.blueLight,
        align: 'center'
      });

      slide.addText(sc.desc, {
        x: scx + 0.2, y: 3.35, w: 3.0, h: 1.25,
        fontSize: 10.5, color: THEME.textLight,
        align: 'center', lineSpacingMultiple: 1.2
      });
    });

    // Ready for Questions & Demo
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 3.5, y: 5.15, w: 6.3, h: 0.5,
      rectRadius: 0.08,
      fill: { color: '0D2847' },
      line: { color: THEME.cyan, width: 1 }
    });
    slide.addText('Ready for Live Demonstration & Faculty Evaluation', {
      x: 3.5, y: 5.15, w: 6.3, h: 0.5,
      fontSize: 12, bold: true, color: THEME.cyan,
      align: 'center', valign: 'middle'
    });

    slide.addText('Department of Computer Engineering · Academic Evaluation', {
      x: 1.5, y: 5.95, w: 10.3, h: 0.35,
      fontSize: 10.5, color: THEME.purpleMuted,
      align: 'center', valign: 'middle'
    });

    slide.addNotes(
      "To conclude: QR Guard empowers users to scan with confidence. " +
      "It decodes visual codes client-side, classifies content transparently, and encourages users to think before opening unknown links. " +
      "Thank you for your valuable time and feedback. We are now ready for your questions and the live demonstration."
    );
  }

  // Save the generated presentation
  const rootOutPath = path.join(__dirname, '..', 'QR_Guard_Presentation.pptx');
  const docsOutPath = path.join(__dirname, '..', 'docs', 'QR_Guard_Presentation.pptx');
  const publicOutPath = path.join(__dirname, '..', 'public', 'QR_Guard_Presentation.pptx');

  await pptx.writeFile({ fileName: rootOutPath });
  console.log(`✔ Presentation saved successfully: ${rootOutPath}`);

  fs.copyFileSync(rootOutPath, docsOutPath);
  console.log(`✔ Docs presentation bundle copied: ${docsOutPath}`);

  fs.copyFileSync(rootOutPath, publicOutPath);
  console.log(`✔ Web presentation bundle copied: ${publicOutPath}`);
}

createPresentation().catch(err => {
  console.error('✖ Error generating presentation:', err);
  process.exit(1);
});
