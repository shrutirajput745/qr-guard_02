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

  // Deep navy, white, cyan, and restrained blue palette
  const THEME = {
    bgDark: '090E1A',      // Deep navy background
    cardBg: '101A2E',      // Card surface
    cardBorder: '1E304D',  // Subtle slate border
    textLight: 'F8FAFC',   // Crisp white
    textMuted: '94A3B8',   // Secondary text
    cyan: '00F0FF',        // Electric cyan accent
    blueLight: '38BDF8',   // Soft sky blue
    blueDeep: '1D4ED8',    // Deep accent blue
    emerald: '10B981',     // Active safe green
    amber: 'F59E0B',       // Warning / In-dev orange
    rose: 'EF4444',        // Threat red
    innerCard: '0B1424'    // Inner recessed container
  };

  function addHeader(slide, title, category, slideNum) {
    // Solid navy background
    slide.addShape(pptx.ShapeType.rect, {
      x: 0, y: 0, w: '100%', h: '100%',
      fill: { color: THEME.bgDark }
    });

    // Top Category Pill
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 0.38, w: 2.8, h: 0.34,
      rectRadius: 0.08,
      fill: { color: '0E223D' },
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
      fontSize: 11, bold: true, color: THEME.textMuted,
      align: 'right', valign: 'middle'
    });

    // Clean divider line
    slide.addShape(pptx.ShapeType.line, {
      x: 0.8, y: 1.45, w: 11.7, h: 0,
      line: { color: THEME.cardBorder, width: 1 }
    });
  }

  // ==========================================================================
  // SLIDE 1 — COVER (Redesigned Premium Hero Slide)
  // Two-column layout: Title, Tagline, Description & Academic Metadata (Left)
  // Hero Cybersecurity Shield & QR Visual (Right)
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
      x: 1.15, y: 1.4, w: 6.0, h: 0.95,
      fontSize: 46, bold: true, color: THEME.textLight,
      valign: 'middle'
    });

    // Tagline: Scan Smart. Think Safe.
    slide.addText('Scan Smart. Think Safe.', {
      x: 1.2, y: 2.38, w: 6.0, h: 0.45,
      fontSize: 18, bold: true, color: THEME.cyan,
      valign: 'middle'
    });

    // Short Project Description
    slide.addText('A smarter approach to QR code analysis, content understanding, and security awareness.', {
      x: 1.2, y: 2.9, w: 5.8, h: 0.7,
      fontSize: 13, color: THEME.textMuted,
      lineSpacingMultiple: 1.2
    });

    // Academic Metadata: Understated, Clean Placeholders
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
        sub: 'B.E. / B.Tech Computer Engineering',
        y: 4.6
      },
      {
        label: 'GUIDED BY',
        value: '[Faculty Name]',
        sub: 'Academic Project Evaluation Guide',
        y: 5.4
      }
    ];

    academicBoxes.forEach(box => {
      // Row Background Pill
      slide.addShape(pptx.ShapeType.roundRect, {
        x: 1.2, y: box.y, w: 5.8, h: 0.7,
        rectRadius: 0.06,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });

      // Cyan Accent Bar on Left
      slide.addShape(pptx.ShapeType.roundRect, {
        x: 1.2, y: box.y, w: 0.08, h: 0.7,
        rectRadius: 0.02,
        fill: { color: THEME.cyan }
      });

      // Label & Value
      slide.addText(box.label, {
        x: 1.38, y: box.y + 0.08, w: 3.0, h: 0.22,
        fontSize: 8.5, bold: true, color: THEME.blueLight
      });
      slide.addText(box.value, {
        x: 1.38, y: box.y + 0.3, w: 3.2, h: 0.32,
        fontSize: 11, bold: true, color: THEME.textLight
      });
      slide.addText(box.sub, {
        x: 4.4, y: box.y + 0.18, w: 2.5, h: 0.35,
        fontSize: 9, color: THEME.textMuted, align: 'right'
      });
    });

    // ── RIGHT COLUMN: Hero Cybersecurity Shield & QR Visual ──────────────────

    // Container Background for Hero Visual
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 7.3, y: 0.95, w: 4.85, h: 5.15,
      rectRadius: 0.12,
      fill: { color: '071120' },
      line: { color: THEME.cardBorder, width: 1 }
    });

    // Vector Hero Shield Graphic
    const heroSvgPath = path.join(__dirname, '..', 'public', 'images', 'qr-guard-hero-shield.svg');
    if (fs.existsSync(heroSvgPath)) {
      slide.addImage({
        path: heroSvgPath,
        x: 7.55, y: 1.1, w: 4.35, h: 4.35
      });
    }

    // Telemetry Status Badge Below Graphic
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
  }

  // ==========================================================================
  // SLIDE 2 — PROBLEM STATEMENT
  // Problem-to-Impact Layout
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Problem Statement: Hidden Risks Behind Visual Codes', 'Problem Analysis', '02');

    const issues = [
      {
        step: '01',
        title: 'Opaque Destinations',
        problem: 'QR codes cannot be read by human eyes. Users cannot discern the destination host, protocol, or payload prior to scanning.',
        impact: 'Impact: Blind trust allows attackers to disguise malicious endpoints inside benign physical media.',
        color: THEME.blueLight
      },
      {
        step: '02',
        title: 'Unchecked URL Threats',
        problem: 'Many QR codes encode deceptive URLs: plain HTTP, raw IP addresses, fake subdomains, or phishing keywords.',
        impact: 'Impact: Standard camera apps immediately auto-navigate, exposing users to credential harvesting and scams.',
        color: THEME.amber
      },
      {
        step: '03',
        title: 'Degraded Image Readability',
        problem: 'Low-quality webcams, glare, motion blur, and low-contrast lighting make QR images difficult or impossible to decode.',
        impact: 'Impact: Scanning failures leave users stranded without recovery options or explanation of why the scan failed.',
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

      // Step Badge
      slide.addShape(pptx.ShapeType.roundRect, {
        x: cx + 0.3, y: 2.1, w: 0.6, h: 0.35,
        rectRadius: 0.06,
        fill: { color: '0D243F' },
        line: { color: it.color, width: 1 }
      });
      slide.addText(it.step, {
        x: cx + 0.3, y: 2.1, w: 0.6, h: 0.35,
        fontSize: 11, bold: true, color: it.color,
        align: 'center', valign: 'middle'
      });

      slide.addText(it.title, {
        x: cx + 0.3, y: 2.65, w: 3.05, h: 0.45,
        fontSize: 15, bold: true, color: THEME.textLight
      });

      slide.addText(it.problem, {
        x: cx + 0.3, y: 3.2, w: 3.05, h: 1.4,
        fontSize: 11.5, color: THEME.textMuted
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
        fontSize: 10, bold: true, color: it.color
      });
    });

    // Summary Banner
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 6.4, w: 11.45, h: 0.55,
      rectRadius: 0.08,
      fill: { color: '15233A' },
      line: { color: THEME.blueLight, width: 1 }
    });
    slide.addText('Core Insight: Security inspection must occur on the client side before the web browser initiates any network navigation.', {
      x: 1.0, y: 6.4, w: 11.0, h: 0.55,
      fontSize: 11.5, bold: true, color: THEME.textLight,
      valign: 'middle'
    });
  }

  // ==========================================================================
  // SLIDE 3 — PROJECT OBJECTIVES
  // Distinguishing Objectives from Features
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Project Objectives: Strategic Goals vs. Concrete Features', 'Objectives', '03');

    const goals = [
      {
        num: 'OBJ 1',
        title: 'Interpret Supported QR Content',
        goal: 'Empower users to understand what is encoded in a QR code across standard formats (URLs, text, Wi-Fi, vCard, payments) without blind execution.',
        metric: 'Objective: Content transparency and zero auto-navigation.'
      },
      {
        num: 'OBJ 2',
        title: 'Improve Suspicious URL Awareness',
        goal: 'Expose red flags in web addresses through transparent, rule-based indicators such as plain HTTP, raw IP hosts, deceptive characters, and shorteners.',
        metric: 'Objective: Actionable security literacy for non-technical users.'
      },
      {
        num: 'OBJ 3',
        title: 'Make Risk Analysis Understandable',
        goal: 'Provide an explainable, deterministic risk score (0–100) and clear tier verdicts (Safe, Suspicious, Dangerous) backed by specific reasons.',
        metric: 'Objective: Transparent evaluation, eliminating black-box confusion.'
      },
      {
        num: 'OBJ 4',
        title: 'Explore Blur Readability Techniques',
        goal: 'Research image processing techniques (contrast adjustment, sharpening) to assess the viability of recovering degraded QR codes in future releases.',
        metric: 'Objective: Future-phase research groundwork (Experimental).'
      }
    ];

    goals.forEach((g, idx) => {
      const gx = 0.8 + idx * 2.92;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: gx, y: 1.8, w: 2.75, h: 5.15,
        rectRadius: 0.12,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1.2 }
      });

      // Objective Tag
      slide.addShape(pptx.ShapeType.roundRect, {
        x: gx + 0.2, y: 2.05, w: 1.1, h: 0.32,
        rectRadius: 0.06,
        fill: { color: '0E223D' },
        line: { color: THEME.cyan, width: 1 }
      });
      slide.addText(g.num, {
        x: gx + 0.2, y: 2.05, w: 1.1, h: 0.32,
        fontSize: 10, bold: true, color: THEME.cyan,
        align: 'center', valign: 'middle'
      });

      slide.addText(g.title, {
        x: gx + 0.2, y: 2.55, w: 2.35, h: 0.75,
        fontSize: 14, bold: true, color: THEME.textLight
      });

      slide.addText(g.goal, {
        x: gx + 0.2, y: 3.45, w: 2.35, h: 2.1,
        fontSize: 11, color: THEME.textMuted
      });

      // Bottom Metric / Focus Card
      slide.addShape(pptx.ShapeType.roundRect, {
        x: gx + 0.18, y: 5.65, w: 2.39, h: 1.05,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });
      slide.addText(g.metric, {
        x: gx + 0.25, y: 5.72, w: 2.25, h: 0.9,
        fontSize: 9.5, bold: true, color: THEME.blueLight
      });
    });
  }

  // ==========================================================================
  // SLIDE 4 — PROPOSED SOLUTION
  // Implemented vs Planned Distinction
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Proposed Solution: The QR Guard Defense Architecture', 'Architecture', '04');

    // Left Box: Implemented Functionality (Green border)
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 1.8, w: 5.6, h: 5.15,
      rectRadius: 0.14,
      fill: { color: THEME.cardBg },
      line: { color: THEME.emerald, width: 1.5 }
    });

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 1.1, y: 2.05, w: 2.4, h: 0.35,
      rectRadius: 0.06,
      fill: { color: '064E3B' },
      line: { color: THEME.emerald, width: 1 }
    });
    slide.addText('IMPLEMENTED & ACTIVE', {
      x: 1.1, y: 2.05, w: 2.4, h: 0.35,
      fontSize: 10, bold: true, color: '#6EE7B7',
      align: 'center', valign: 'middle'
    });

    slide.addText('Core Defense Engine', {
      x: 1.1, y: 2.55, w: 5.0, h: 0.45,
      fontSize: 17, bold: true, color: THEME.textLight
    });

    const implementedItems = [
      { t: 'Multi-Modal Input Capture', d: 'Live camera video stream via getUserMedia and drag-and-drop image file support.' },
      { t: 'Client-Side QR Decoding', d: 'In-browser localization of finder patterns and Reed-Solomon payload extraction using jsQR.' },
      { t: 'Content Classification', d: 'Automatic categorization of decoded data: URLs, Wi-Fi setups, vCards, SMS, payments.' },
      { t: 'Heuristic URL Risk Analyzer', d: '9 deterministic security checks (plain HTTP, raw IP, phishing keywords, deceptive @ signs).' },
      { t: 'Defanged Preview & Scoring', d: '0–100 risk score with Safe/Suspicious/Dangerous verdicts and safe sanitized previews.' }
    ];

    implementedItems.forEach((item, i) => {
      const iy = 3.1 + i * 0.74;
      slide.addText(`✔ ${item.t}`, {
        x: 1.1, y: iy, w: 5.0, h: 0.28,
        fontSize: 11.5, bold: true, color: THEME.emerald
      });
      slide.addText(item.d, {
        x: 1.35, y: iy + 0.24, w: 4.75, h: 0.45,
        fontSize: 10, color: THEME.textMuted
      });
    });

    // Right Box: Planned Functionality (Amber border)
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 6.65, y: 1.8, w: 5.6, h: 5.15,
      rectRadius: 0.14,
      fill: { color: THEME.cardBg },
      line: { color: THEME.amber, width: 1.5 }
    });

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 6.95, y: 2.05, w: 2.8, h: 0.35,
      rectRadius: 0.06,
      fill: { color: '451A03' },
      line: { color: THEME.amber, width: 1 }
    });
    slide.addText('PLANNED — UNDER DEVELOPMENT', {
      x: 6.95, y: 2.05, w: 2.8, h: 0.35,
      fontSize: 10, bold: true, color: '#FDE68A',
      align: 'center', valign: 'middle'
    });

    slide.addText('Future Research Features', {
      x: 6.95, y: 2.55, w: 5.0, h: 0.45,
      fontSize: 17, bold: true, color: THEME.textLight
    });

    const plannedItems = [
      { t: 'Blur Recovery Lab (Experimental)', d: 'Digital image processing filters to enhance low-contrast, out-of-focus, or noisy QR images.' },
      { t: 'Adaptive Image Preprocessing', d: 'Histogram stretching, unsharp mask convolution, and Otsu binarization before decoding.' },
      { t: 'Expanded Content Parsers', d: 'Deeper heuristic inspection of specialized schemas (crypto wallets, complex vCard data).' },
      { t: 'Sandboxed Redirection Tracing', d: 'Future safe backend unshortening of bit.ly or t.co links without executing scripts.' }
    ];

    plannedItems.forEach((item, i) => {
      const iy = 3.2 + i * 0.9;
      slide.addText(`⏳ ${item.t}`, {
        x: 6.95, y: iy, w: 5.0, h: 0.28,
        fontSize: 11.5, bold: true, color: THEME.amber
      });
      slide.addText(item.d, {
        x: 7.2, y: iy + 0.24, w: 4.75, h: 0.55,
        fontSize: 10, color: THEME.textMuted
      });
    });
  }

  // ==========================================================================
  // SLIDE 5 — SYSTEM ARCHITECTURE
  // Professional Flowchart: Main Flow + Separate Planned Flow
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'System Architecture: Data Pipeline & Component Flow', 'Flowchart', '05');

    // Main Active Pipeline Box
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 1.7, w: 11.7, h: 3.3,
      rectRadius: 0.12,
      fill: { color: THEME.cardBg },
      line: { color: THEME.cardBorder, width: 1.2 }
    });

    slide.addText('PRIMARY DATA FLOW (IMPLEMENTED & VERIFIED)', {
      x: 1.1, y: 1.85, w: 6.0, h: 0.3,
      fontSize: 10.5, bold: true, color: THEME.cyan
    });

    // 5 Horizontal Flow Nodes
    const mainNodes = [
      { title: 'User Input', sub: 'Camera / File Upload', color: THEME.blueLight, x: 1.1 },
      { title: 'QR Decoding', sub: 'jsQR Matrix Parser', color: THEME.cyan, x: 3.4 },
      { title: 'Content Routing', sub: 'URL / Text / Wi-Fi', color: 'A78BFA', x: 5.7 },
      { title: 'URL Analysis', sub: '9 Heuristic Checks', color: THEME.amber, x: 8.0 },
      { title: 'Result Display', sub: 'Score & Verdict Badge', color: THEME.emerald, x: 10.3 }
    ];

    mainNodes.forEach((node, i) => {
      slide.addShape(pptx.ShapeType.roundRect, {
        x: node.x, y: 2.25, w: 1.9, h: 2.4,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: node.color, width: 1.2 }
      });

      slide.addShape(pptx.ShapeType.ellipse, {
        x: node.x + 0.75, y: 2.45, w: 0.4, h: 0.4,
        fill: { color: '0F233E' },
        line: { color: node.color, width: 1 }
      });
      slide.addText(`${i + 1}`, {
        x: node.x + 0.75, y: 2.45, w: 0.4, h: 0.4,
        fontSize: 11, bold: true, color: node.color,
        align: 'center', valign: 'middle'
      });

      slide.addText(node.title, {
        x: node.x + 0.1, y: 2.95, w: 1.7, h: 0.4,
        fontSize: 12.5, bold: true, color: THEME.textLight,
        align: 'center'
      });

      slide.addText(node.sub, {
        x: node.x + 0.1, y: 3.4, w: 1.7, h: 0.5,
        fontSize: 10, bold: true, color: node.color,
        align: 'center'
      });

      // Arrow
      if (i < 4) {
        slide.addShape(pptx.ShapeType.rightArrow, {
          x: node.x + 1.93, y: 3.3, w: 0.32, h: 0.22,
          fill: { color: THEME.cyan },
          line: { color: THEME.cyan }
        });
      }
    });

    // Planned Workflow Box (Dashed style)
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 5.2, w: 11.7, h: 1.75,
      rectRadius: 0.12,
      fill: { color: '0D1626' },
      line: { color: THEME.amber, width: 1.2, dashType: 'dash' }
    });

    slide.addText('PLANNED BLUR RECOVERY WORKFLOW (UNDER DEVELOPMENT)', {
      x: 1.1, y: 5.35, w: 6.5, h: 0.28,
      fontSize: 10, bold: true, color: THEME.amber
    });

    const plannedNodes = [
      { title: 'Blurry QR Image', sub: 'Low Contrast / Defocus', x: 1.5 },
      { title: 'Planned Preprocessing', sub: 'Contrast & Sharpening Filters', x: 5.0 },
      { title: 'QR Decoder', sub: 'Re-attempt Finder Detection', x: 8.5 }
    ];

    plannedNodes.forEach((pn, idx) => {
      slide.addShape(pptx.ShapeType.roundRect, {
        x: pn.x, y: 5.75, w: 2.8, h: 0.95,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: THEME.amber, width: 0.8 }
      });

      slide.addText(pn.title, {
        x: pn.x + 0.15, y: 5.85, w: 2.5, h: 0.35,
        fontSize: 11, bold: true, color: THEME.textLight,
        align: 'center'
      });

      slide.addText(pn.sub, {
        x: pn.x + 0.15, y: 6.2, w: 2.5, h: 0.35,
        fontSize: 9.5, color: THEME.amber,
        align: 'center'
      });

      if (idx < 2) {
        slide.addShape(pptx.ShapeType.rightArrow, {
          x: pn.x + 2.85, y: 6.12, w: 0.6, h: 0.18,
          fill: { color: THEME.amber },
          line: { color: THEME.amber }
        });
      }
    });
  }

  // ==========================================================================
  // SLIDE 6 — SMART TECHNIQUE
  // Technical Approach (No Fake AI/ML)
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Technical Approach: Deterministic Engineering Logic', 'Technology', '06');

    const techniques = [
      {
        title: '1. QR Localization & Decoding',
        desc: 'Extracts video frames onto HTML5 Canvas, identifies 3 finder pattern markers, builds the perspective transformation grid, and computes Reed-Solomon error correction.',
        impl: 'Pure JavaScript · jsQR library · Zero native binaries'
      },
      {
        title: '2. Content-Dependent Routing',
        desc: 'Inspects decoded raw string prefixes (http://, https://, WIFI:, upi://, tel:, mailto:). Routes payloads to specific classification views with defanged safety shields.',
        impl: 'Deterministic string analysis · Safe URL object parsing'
      },
      {
        title: '3. Heuristic URL Analysis Engine',
        desc: 'Applies 9 itemized security rules to URLs: Protocol security, raw IP check, sensitive brand keywords, excessive subdomains, URL shorteners, and deceptive @ signs.',
        impl: 'analyzer.js Rule Matrix · 0–100 penalty score clamping'
      },
      {
        title: '4. Planned Image Preprocessing',
        desc: 'Researching browser-based image enhancements: 3x3 unsharp convolution kernel, dynamic histogram stretching, and Otsu thresholding for degraded QR recovery.',
        impl: 'Under Active Development · Non-functional research prototype'
      }
    ];

    techniques.forEach((tech, i) => {
      const ty = 1.8 + i * 1.25;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: 0.8, y: ty, w: 11.7, h: 1.12,
        rectRadius: 0.1,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1 }
      });

      // Title
      slide.addText(tech.title, {
        x: 1.1, y: ty + 0.12, w: 4.8, h: 0.35,
        fontSize: 13, bold: true, color: THEME.textLight
      });

      // Implementation badge
      slide.addText(tech.impl, {
        x: 1.1, y: ty + 0.55, w: 4.8, h: 0.45,
        fontSize: 10, bold: true, color: THEME.cyan
      });

      // Description
      slide.addText(tech.desc, {
        x: 6.0, y: ty + 0.12, w: 6.2, h: 0.88,
        fontSize: 11, color: THEME.textMuted,
        valign: 'middle'
      });
    });
  }

  // ==========================================================================
  // SLIDE 7 — PROJECT DEMONSTRATION
  // Genuine Screenshots & Verified Working Areas
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Project Demonstration: Verified Application Interface', 'Demonstration', '07');

    const demoCards = [
      {
        title: '1. QR Input & Decoding Area',
        sub: 'Live Camera & Image Drop Zone',
        desc: 'User captures QR code through webcam feed or drags a local PNG/JPG file. Canvas immediately extracts raw pixels without server upload.',
        status: 'Active Implemented Feature',
        statusColor: THEME.emerald,
        bullets: ['• HTML5 getUserMedia camera integration', '• Real-time video frame scanning loop', '• Drag-and-drop file dropzone with validation']
      },
      {
        title: '2. Content Interpretation Area',
        sub: 'Payload Classification & Safety Shield',
        desc: 'Decoded text is parsed and categorized. Defanged URL preview prevents accidental browser navigation.',
        status: 'Active Implemented Feature',
        statusColor: THEME.emerald,
        bullets: ['• Categorizes URLs, Wi-Fi, vCard, Payments', '• Defanged display: hxxps://domain[.]com', '• Explicit "Proceed to URL" user confirmation']
      },
      {
        title: '3. URL Security Analysis Area',
        sub: 'Explainable Heuristic Risk Verdict',
        desc: 'Evaluates URL against 9 transparent rules, generates a 0–100 risk score, and assigns a clear Safe, Suspicious, or Dangerous verdict.',
        status: 'Active Implemented Feature',
        statusColor: THEME.emerald,
        bullets: ['• Color-coded Risk Meter (Green/Yellow/Red)', '• Itemized rule breakdown with specific reasons', '• Real-time client evaluation in under 50ms']
      }
    ];

    demoCards.forEach((c, idx) => {
      const cx = 0.8 + idx * 3.9;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: cx, y: 1.8, w: 3.65, h: 5.15,
        rectRadius: 0.14,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1.2 }
      });

      // Status Pill
      slide.addShape(pptx.ShapeType.roundRect, {
        x: cx + 0.25, y: 2.05, w: 2.3, h: 0.32,
        rectRadius: 0.06,
        fill: { color: '064E3B' },
        line: { color: c.statusColor, width: 1 }
      });
      slide.addText(c.status, {
        x: cx + 0.25, y: 2.05, w: 2.3, h: 0.32,
        fontSize: 9.5, bold: true, color: '#6EE7B7',
        align: 'center', valign: 'middle'
      });

      slide.addText(c.title, {
        x: cx + 0.25, y: 2.5, w: 3.15, h: 0.45,
        fontSize: 14, bold: true, color: THEME.textLight
      });

      slide.addText(c.sub, {
        x: cx + 0.25, y: 2.95, w: 3.15, h: 0.3,
        fontSize: 10.5, bold: true, color: THEME.blueLight
      });

      slide.addText(c.desc, {
        x: cx + 0.25, y: 3.35, w: 3.15, h: 1.4,
        fontSize: 11, color: THEME.textMuted
      });

      // Inner Box with bullets
      slide.addShape(pptx.ShapeType.roundRect, {
        x: cx + 0.2, y: 4.85, w: 3.25, h: 1.85,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });
      slide.addText(c.bullets.join('\n\n'), {
        x: cx + 0.3, y: 4.95, w: 3.05, h: 1.65,
        fontSize: 10, color: THEME.textLight
      });
    });
  }

  // ==========================================================================
  // SLIDE 8 — FUTURE ROADMAP
  // 4 Specific Milestones (Future Goals)
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    addHeader(slide, 'Future Roadmap: Planned Engineering Milestones', 'Roadmap', '08');

    const milestones = [
      {
        num: 'MILESTONE 01',
        title: 'Implement & Test Blur Recovery Lab',
        desc: 'Complete implementation and rigorous testing of the image enhancement pipeline (dynamic contrast, unsharp mask filter) to reliably recover blurry and low-contrast QR codes.',
        status: 'Priority Goal: Experimental phase completion'
      },
      {
        num: 'MILESTONE 02',
        title: 'Improve URL Analysis & Testing',
        desc: 'Expand heuristic rule definitions, add safe URL redirection unshortening via secure serverless proxy, and build automated validation suites for evolving phishing patterns.',
        status: 'Enhance static heuristic accuracy'
      },
      {
        num: 'MILESTONE 03',
        title: 'Test Additional QR Content Types',
        desc: 'Introduce specialized parsers and threat verification for cryptocurrency transfer links, payment strings (UPI/SEPA), complex calendar invites, and multi-contact vCards.',
        status: 'Broaden content domain coverage'
      },
      {
        num: 'MILESTONE 04',
        title: 'Improve Usability & Error Handling',
        desc: 'Provide guided user hints when lighting is inadequate, add accessibility screen-reader support, exportable security reports, and browser extension integration.',
        status: 'UI/UX and cross-device polish'
      }
    ];

    milestones.forEach((m, idx) => {
      const mx = 0.8 + idx * 2.92;
      slide.addShape(pptx.ShapeType.roundRect, {
        x: mx, y: 1.8, w: 2.75, h: 5.15,
        rectRadius: 0.12,
        fill: { color: THEME.cardBg },
        line: { color: THEME.cardBorder, width: 1.2 }
      });

      // Milestone Tag
      slide.addShape(pptx.ShapeType.roundRect, {
        x: mx + 0.2, y: 2.05, w: 1.6, h: 0.32,
        rectRadius: 0.06,
        fill: { color: '2E1065' },
        line: { color: 'A78BFA', width: 1 }
      });
      slide.addText(m.num, {
        x: mx + 0.2, y: 2.05, w: 1.6, h: 0.32,
        fontSize: 9.5, bold: true, color: '#DDD6FE',
        align: 'center', valign: 'middle'
      });

      slide.addText(m.title, {
        x: mx + 0.2, y: 2.55, w: 2.35, h: 0.75,
        fontSize: 13.5, bold: true, color: THEME.textLight
      });

      slide.addText(m.desc, {
        x: mx + 0.2, y: 3.45, w: 2.35, h: 2.1,
        fontSize: 11, color: THEME.textMuted
      });

      // Status Note
      slide.addShape(pptx.ShapeType.roundRect, {
        x: mx + 0.18, y: 5.65, w: 2.39, h: 1.05,
        rectRadius: 0.08,
        fill: { color: THEME.innerCard },
        line: { color: THEME.cardBorder, width: 0.8 }
      });
      slide.addText(m.status, {
        x: mx + 0.25, y: 5.72, w: 2.25, h: 0.9,
        fontSize: 9.5, bold: true, color: THEME.cyan
      });
    });
  }

  // ==========================================================================
  // SLIDE 9 — CLOSING
  // Title: Thank You | Tagline: QR Guard — Scan Smart. Think Safe.
  // ==========================================================================
  {
    const slide = pptx.addSlide();
    slide.addShape(pptx.ShapeType.rect, {
      x: 0, y: 0, w: '100%', h: '100%',
      fill: { color: THEME.bgDark }
    });

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.8, y: 0.8, w: 11.7, h: 5.9,
      rectRadius: 0.18,
      fill: { color: THEME.cardBg },
      line: { color: THEME.cyan, width: 1.5 }
    });

    // Thank You Title
    slide.addText('Thank You', {
      x: 1.5, y: 1.4, w: 10.3, h: 0.9,
      fontSize: 46, bold: true, color: THEME.textLight,
      align: 'center', valign: 'middle'
    });

    // Tagline
    slide.addText('QR Guard — Scan Smart. Think Safe.', {
      x: 1.5, y: 2.35, w: 10.3, h: 0.45,
      fontSize: 20, bold: true, color: THEME.cyan,
      align: 'center', valign: 'middle'
    });

    // Summary Card Box
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 2.0, y: 3.0, w: 9.3, h: 1.6,
      rectRadius: 0.1,
      fill: { color: THEME.innerCard },
      line: { color: THEME.cardBorder, width: 1 }
    });

    slide.addText('PROJECT SUMMARY', {
      x: 2.2, y: 3.15, w: 8.9, h: 0.3,
      fontSize: 11, bold: true, color: THEME.blueLight,
      align: 'center'
    });

    slide.addText('QR Guard delivers a functional client-side security barrier against QR phishing. By combining local camera and image decoding with transparent heuristic risk scoring, it enables users to evaluate untrusted destinations safely without sacrificing privacy.', {
      x: 2.3, y: 3.5, w: 8.7, h: 0.95,
      fontSize: 12, color: THEME.textLight,
      align: 'center'
    });

    // Ready for Questions & Demo
    slide.addShape(pptx.ShapeType.roundRect, {
      x: 3.8, y: 4.85, w: 5.7, h: 0.5,
      rectRadius: 0.08,
      fill: { color: '0D2847' },
      line: { color: THEME.cyan, width: 1 }
    });
    slide.addText('Ready for Live Demonstration & Faculty Evaluation', {
      x: 3.8, y: 4.85, w: 5.7, h: 0.5,
      fontSize: 12, bold: true, color: THEME.cyan,
      align: 'center', valign: 'middle'
    });

    slide.addText('Questions & Discussion · Department of Computer Engineering', {
      x: 1.5, y: 5.65, w: 10.3, h: 0.35,
      fontSize: 11, color: THEME.textMuted,
      align: 'center', valign: 'middle'
    });
  }

  // Save the generated presentation
  const rootOutPath = path.join(__dirname, '..', 'QR_Guard_Presentation.pptx');
  const publicOutPath = path.join(__dirname, '..', 'public', 'QR_Guard_Presentation.pptx');

  await pptx.writeFile({ fileName: rootOutPath });
  console.log(`✔ Presentation saved successfully: ${rootOutPath}`);

  // Copy to public directory for direct browser download
  fs.copyFileSync(rootOutPath, publicOutPath);
  console.log(`✔ Web presentation bundle copied: ${publicOutPath}`);
}

createPresentation().catch(err => {
  console.error('✖ Error generating presentation:', err);
  process.exit(1);
});
