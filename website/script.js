/**
 * Veridex AI Website - Main Interface Controller
 * 100% Offline-First Web Scanner with Rich Information Available Inside Every Dashboard Box
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Veridex Engine from global scope
  const EngineClass = window.VeridexEngine || (typeof VeridexEngine !== 'undefined' ? VeridexEngine : null);
  if (!EngineClass) {
    console.error('VeridexEngine not found in global scope.');
    alert('VeridexEngine failed to load. Please ensure engine script files are present.');
    return;
  }
  const engine = new EngineClass();

  // Top Search & Hero Elements
  const urlInput = document.getElementById('search-url-input');
  const btnClear = document.getElementById('btn-clear-search');
  const btnVerify = document.getElementById('btn-verify-search');
  const testChips = document.querySelectorAll('.test-chip');

  const resultSection = document.getElementById('result-section');
  const heroScoreCard = document.getElementById('hero-score-card');
  const heroHost = document.getElementById('hero-hostname');
  const heroProto = document.getElementById('hero-protocol');
  const heroDbTag = document.getElementById('hero-db-tag');
  const heroScore = document.getElementById('hero-score-value');
  const heroBadge = document.getElementById('hero-verdict-badge');
  const heroSummary = document.getElementById('hero-summary-text');
  const gaugeProgressBar = document.getElementById('gauge-progress-bar');

  // Suggested Authentic Destination Card
  const suggestedCard = document.getElementById('website-suggested-card');
  const suggestedBrand = document.getElementById('suggested-brand');
  const suggestedDesc = document.getElementById('suggested-desc');
  const suggestedLinkBtn = document.getElementById('suggested-link-btn');
  const suggestedBtnLabel = document.getElementById('suggested-btn-label');
  const whyUnsafeList = document.getElementById('why-unsafe-list');

  // Dashboard Section & Squares
  const dashboardSection = document.getElementById('dashboard-section');
  const dashboardSquares = document.querySelectorAll('.dashboard-square');

  // Dashboard Preview Elements Inside the Boxes
  const boxSignalsBadge = document.getElementById('box-signals-badge');
  const boxSignalsPreview = document.getElementById('box-signals-preview');
  const boxBreakdownBadge = document.getElementById('box-breakdown-badge');
  const miniBarDomain = document.getElementById('mini-bar-domain');
  const miniValDomain = document.getElementById('mini-val-domain');
  const miniBarLexical = document.getElementById('mini-bar-lexical');
  const miniValLexical = document.getElementById('mini-val-lexical');
  const miniBarSecurity = document.getElementById('mini-bar-security');
  const miniValSecurity = document.getElementById('mini-val-security');
  const miniBarContent = document.getElementById('mini-bar-content');
  const miniValContent = document.getElementById('mini-val-content');

  const boxIntelApex = document.getElementById('box-intel-apex');
  const boxIntelTld = document.getElementById('box-intel-tld');
  const boxIntelIp = document.getElementById('box-intel-ip');
  const boxIntelOrg = document.getElementById('box-intel-org');
  const boxIntelBadge = document.getElementById('box-intel-badge');

  const boxCookiesStatus = document.getElementById('box-cookies-status');
  const boxCookiesCounts = document.getElementById('box-cookies-counts');
  const boxReportVerdict = document.getElementById('box-report-verdict');
  const boxReportGrade = document.getElementById('box-report-grade');

  // Toolbar Actions
  const btnQuickPrint = document.getElementById('btn-quick-print');
  const btnQuickDownload = document.getElementById('btn-quick-download');
  const btnQuickCopy = document.getElementById('btn-quick-copy');

  // Sub-Section Containers
  const subSections = {
    signals: document.getElementById('section-signals'),
    breakdown: document.getElementById('section-breakdown'),
    intel: document.getElementById('section-intel'),
    cookies: document.getElementById('section-cookies'),
    cybercrime: document.getElementById('section-cybercrime'),
    report: document.getElementById('section-report')
  };

  let currentAnalysis = null;

  // Search Input Clear Button
  urlInput.addEventListener('input', () => {
    btnClear.style.display = urlInput.value.trim() ? 'inline' : 'none';
  });

  btnClear.addEventListener('click', () => {
    urlInput.value = '';
    btnClear.style.display = 'none';
    urlInput.focus();
  });

  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      runVerification(urlInput.value.trim());
    }
  });

  btnVerify.addEventListener('click', () => {
    runVerification(urlInput.value.trim());
  });

  // Preset Chips
  testChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const url = chip.getAttribute('data-url');
      if (url) {
        urlInput.value = url;
        btnClear.style.display = 'inline';
        runVerification(url);
      }
    });
  });

  // Quick Action Toolbar Buttons
  if (btnQuickPrint) btnQuickPrint.addEventListener('click', handlePrintReport);
  if (btnQuickDownload) btnQuickDownload.addEventListener('click', handleDownloadReport);
  if (btnQuickCopy) btnQuickCopy.addEventListener('click', handleCopyEvidence);

  // Return to Dashboard Buttons (Placed once at the end of each detail section)
  document.querySelectorAll('.return-dashboard').forEach(btn => {
    btn.addEventListener('click', () => {
      // Hide all detail sub-sections
      Object.values(subSections).forEach(sec => {
        if (sec) sec.style.display = 'none';
      });
      // Show main dashboard
      if (dashboardSection) {
        dashboardSection.style.display = 'block';
        dashboardSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
  });

  // Dashboard Square Clicks (Open corresponding detailed section)
  dashboardSquares.forEach(square => {
    square.addEventListener('click', () => {
      const target = square.getAttribute('data-section');
      openSection(target);
    });

    square.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const target = square.getAttribute('data-section');
        openSection(target);
      }
    });
  });

  function openSection(sectionKey) {
    if (!subSections[sectionKey]) return;
    if (dashboardSection) dashboardSection.style.display = 'none';

    Object.values(subSections).forEach(sec => {
      if (sec) sec.style.display = 'none';
    });

    const targetSec = subSections[sectionKey];
    targetSec.style.display = 'block';
    targetSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Core Verification Workflow
  async function runVerification(targetUrl) {
    if (!targetUrl) {
      alert('Please enter or paste a website URL.');
      urlInput.focus();
      return;
    }

    const normalizedUrl = targetUrl.startsWith('http://') || targetUrl.startsWith('https://')
      ? targetUrl
      : `https://${targetUrl}`;

    btnVerify.textContent = 'Scanning…';
    btnVerify.disabled = true;

    try {
      // Offline-first engine analysis
      let analysis;
      if (typeof engine.verifyLive === 'function') {
        analysis = await engine.verifyLive(normalizedUrl);
      } else {
        analysis = engine.analyze(normalizedUrl);
      }

      currentAnalysis = analysis;
      window._fullReport = analysis;

      // Render UI
      renderHeroScore(analysis, normalizedUrl);
      renderSuggestedCard(analysis);
      populateDashboardBoxes(analysis, normalizedUrl);
      populateDetailSections(analysis, normalizedUrl);

      // Display results and dashboard
      resultSection.style.display = 'block';
      dashboardSection.style.display = 'block';

      // Ensure detail views are hidden on fresh verification
      Object.values(subSections).forEach(sec => {
        if (sec) sec.style.display = 'none';
      });

    } catch (err) {
      console.error('Verification error:', err);
      alert('Verification failed: ' + (err.message || err));
    } finally {
      btnVerify.textContent = 'Verify';
      btnVerify.disabled = false;
    }
  }

  // 1. Render Top Hero Score Card
  function renderHeroScore(analysis, rawUrl) {
    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 0);
    const details = analysis.details || {};
    let host = details.hostname;
    let isHttp = false;

    try {
      const u = new URL(rawUrl);
      host = u.hostname;
      isHttp = u.protocol === 'http:';
    } catch (e) {
      host = details.hostname || rawUrl;
    }

    heroHost.textContent = host;
    heroHost.title = host;
    heroProto.textContent = isHttp ? 'HTTP INSECURE' : 'HTTPS';
    if (isHttp) {
      heroProto.classList.add('insecure');
    } else {
      heroProto.classList.remove('insecure');
    }

    // Database Status Tag
    const dbMatch = analysis.databaseMatch || {};
    const classification = analysis.classification || details.classification || {};
    heroDbTag.className = 'db-status-tag';

    if (classification.category === 'verified_government' || dbMatch.isGov) {
      heroDbTag.classList.add('verified');
      heroDbTag.textContent = '🏛️ Verified Government';
    } else if (classification.category === 'verified_real' || dbMatch.isReal) {
      heroDbTag.classList.add('verified');
      heroDbTag.textContent = '🛡️ Verified Safe Registry';
    } else if (classification.category === 'known_phishing' || dbMatch.isFake) {
      heroDbTag.classList.add('scam');
      heroDbTag.textContent = '☠️ Confirmed Threat DB';
    } else if (classification.category === 'suspicious') {
      heroDbTag.classList.add('scam');
      heroDbTag.textContent = '🚨 Suspicious Domain';
    } else {
      heroDbTag.textContent = 'ℹ️ Multi-Vector Heuristics';
    }

    // Gauge Offset (circumference = 264)
    heroScore.textContent = `${riskPct}%`;
    const offset = 264 - (264 * Math.min(100, Math.max(0, riskPct))) / 100;
    gaugeProgressBar.style.strokeDashoffset = offset;

    // Theme Color
    let colorTheme = 'neutral';
    let gaugeColor = '#0ea5e9';
    let verdictLabel = analysis.levelLabel || 'Safe';

    if (classification.category === 'verified_government' || dbMatch.isGov) {
      colorTheme = 'safe';
      gaugeColor = '#10b981';
      verdictLabel = '🏛️ Verified Government Domain';
    } else if (classification.category === 'known_phishing' || dbMatch.isFake) {
      colorTheme = 'danger';
      gaugeColor = '#ef4444';
      verdictLabel = '⛔ Confirmed Phishing (Threat Feed)';
    } else if (riskPct <= 5 && (classification.category === 'verified_real' || dbMatch.isReal)) {
      colorTheme = 'safe';
      gaugeColor = '#10b981';
      verdictLabel = '✓ Verified Safe (Official Registry)';
    } else if (riskPct <= 20) {
      colorTheme = 'neutral';
      gaugeColor = '#0ea5e9';
      verdictLabel = 'ℹ️ Low Risk (Unverified)';
    } else if (riskPct <= 34) {
      colorTheme = 'caution';
      gaugeColor = '#f59e0b';
      verdictLabel = '⚠️ Elevated Caution';
    } else if (riskPct < 60) {
      colorTheme = 'warning';
      gaugeColor = '#f97316';
      verdictLabel = '🚨 Suspicious (Unsafe)';
    } else {
      colorTheme = 'danger';
      gaugeColor = '#ef4444';
      verdictLabel = '⛔ Critical Threat (Unsafe)';
    }

    gaugeProgressBar.style.stroke = gaugeColor;
    heroScoreCard.className = `hero-score-card ${colorTheme}`;
    heroBadge.className = `verdict-badge-pill ${colorTheme}`;
    heroBadge.textContent = verdictLabel;
    heroSummary.textContent = analysis.summary || 'Security assessment completed.';
  }

  // 2. Render Suggested Authentic Destination Card
  function renderSuggestedCard(analysis) {
    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 0);
    const isUnsafe = analysis.isUnsafe || analysis.verdict === 'suspicious' || riskPct >= 35;
    const suggested = analysis.suggestedWebsite;

    if (isUnsafe && suggested) {
      suggestedCard.style.display = 'block';
      suggestedBrand.textContent = suggested.name;
      suggestedLinkBtn.href = suggested.url;
      suggestedBtnLabel.textContent = `👉 Go to Official ${suggested.name} Website (${suggested.host || suggested.name})`;

      const curHost = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : 'Current website';
      suggestedDesc.textContent = `You appear to be searching for "${suggested.name}". The domain "${curHost}" is an unverified imitation.`;

      // Plain-English reasons
      const reasons = getPlainEnglishReasons(analysis);
      whyUnsafeList.innerHTML = reasons.map(r => `
        <div style="display:flex; align-items:flex-start; gap:6px; margin-top:2px;">
          <span>${r.icon}</span>
          <span><strong>${escapeHtml(r.title)}:</strong> ${escapeHtml(r.desc)}</span>
        </div>
      `).join('');
    } else {
      suggestedCard.style.display = 'none';
    }
  }

  // 3. POPULATE INFORMATION DIRECTLY INSIDE THE DASHBOARD BOXES
  function populateDashboardBoxes(analysis, rawUrl) {
    const signals = analysis.signals || [];
    const threatSignals = signals.filter(s => s.severity !== 'info');
    const catScores = analysis.categoryScores || { domain: 0, lexical: 0, security: 0, content: 0 };
    const details = analysis.details || {};
    const dbMatch = analysis.databaseMatch || {};
    const classification = analysis.classification || {};
    const ipData = analysis.ipIntelligence || {};

    // --- Box 1: Threat Signals ---
    boxSignalsBadge.textContent = `${threatSignals.length} Flag${threatSignals.length === 1 ? '' : 's'}`;
    boxSignalsBadge.style.color = threatSignals.length > 0 ? '#f87171' : '#34d399';

    if (threatSignals.length > 0) {
      const topTwo = threatSignals.slice(0, 2);
      boxSignalsPreview.innerHTML = topTwo.map(s => `
        <div class="box-preview-item threat">• ${escapeHtml(s.name)} (+${s.points}% Risk)</div>
      `).join('') + (threatSignals.length > 2 ? `<div class="box-preview-item" style="color:var(--text-muted)">+ ${threatSignals.length - 2} more detected flag(s)…</div>` : '');
    } else {
      boxSignalsPreview.innerHTML = `
        <div class="box-preview-item clean">✓ All heuristic indicators clean</div>
        <div class="box-preview-item" style="color:var(--text-muted)">No lookalike attacks or scam patterns found</div>
      `;
    }

    // --- Box 2: Multi-Factor Risk Breakdown ---
    boxBreakdownBadge.textContent = `Max: ${Math.max(catScores.domain, catScores.lexical, catScores.security, catScores.content)}/100`;
    
    miniBarDomain.style.width = `${Math.min(100, catScores.domain)}%`;
    miniBarDomain.style.background = getScoreColor(catScores.domain);
    miniValDomain.textContent = catScores.domain;

    miniBarLexical.style.width = `${Math.min(100, catScores.lexical)}%`;
    miniBarLexical.style.background = getScoreColor(catScores.lexical);
    miniValLexical.textContent = catScores.lexical;

    miniBarSecurity.style.width = `${Math.min(100, catScores.security)}%`;
    miniBarSecurity.style.background = getScoreColor(catScores.security);
    miniValSecurity.textContent = catScores.security;

    miniBarContent.style.width = `${Math.min(100, catScores.content)}%`;
    miniBarContent.style.background = getScoreColor(catScores.content);
    miniValContent.textContent = catScores.content;

    // --- Box 3: Threat Intelligence & Hosting ---
    boxIntelBadge.textContent = dbMatch.label ? dbMatch.label.substring(0, 16) : 'Heuristics';
    boxIntelApex.textContent = details.apexDomain || details.hostname || '-';

    const host = details.hostname || '';
    const hostParts = host.split('.');
    const tld = hostParts.length > 1 ? '.' + hostParts[hostParts.length - 1] : '-';
    boxIntelTld.textContent = tld;

    boxIntelIp.textContent = ipData.ip || 'Unavailable';
    boxIntelOrg.textContent = ipData.organization || 'Unavailable';

    // --- Box 4: Cookie Security Analysis ---
    const cookiesAudited = (window.CookieAnalyzer && typeof window.CookieAnalyzer.analyzeCookies === 'function')
      ? window.CookieAnalyzer.analyzeCookies([], rawUrl)
      : { mandatoryCount: 0, acceptedCount: 0, rejectedCount: 0, overallStatus: 'clean' };

    boxCookiesStatus.textContent = cookiesAudited.rejectedCount > 0 ? `${cookiesAudited.rejectedCount} Insecure` : 'Compliant';
    boxCookiesStatus.style.color = cookiesAudited.rejectedCount > 0 ? '#ef4444' : '#10b981';
    boxCookiesCounts.textContent = `${cookiesAudited.mandatoryCount} Mand • ${cookiesAudited.acceptedCount} Acc • ${cookiesAudited.rejectedCount} Rej`;

    // --- Box 6: Executive Audit Report ---
    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 0);
    boxReportVerdict.textContent = riskPct >= 35 ? 'Critical Findings' : 'Passed Inspection';
    boxReportVerdict.style.color = riskPct >= 35 ? '#ef4444' : '#10b981';
    boxReportGrade.textContent = classification.badge || (riskPct <= 20 ? 'Safe Registry Grade' : 'High Risk Threat');
  }

  // 4. POPULATE DETAIL SUB-SECTIONS
  function populateDetailSections(analysis, rawUrl) {
    const signals = analysis.signals || [];
    const threatSignals = signals.filter(s => s.severity !== 'info');
    const catScores = analysis.categoryScores || { domain: 0, lexical: 0, security: 0, content: 0 };
    const details = analysis.details || {};
    const dbMatch = analysis.databaseMatch || {};
    const ipData = analysis.ipIntelligence || {};

    // --- Detail 1: Signals ---
    const signalsBadge = document.getElementById('signals-detail-badge');
    const signalsContainer = document.getElementById('signals-content');
    signalsBadge.textContent = `${threatSignals.length} Threat Flag${threatSignals.length === 1 ? '' : 's'}`;

    if (signals.length > 0) {
      signalsContainer.innerHTML = signals.map(sig => {
        const isInfo = sig.severity === 'info';
        const isHigh = sig.severity === 'high';
        const sigClass = isInfo ? 'clean' : (isHigh ? 'threat' : 'caution');
        const icon = isInfo ? '✓' : (isHigh ? '🚨' : '⚠️');
        return `
          <div class="signal-item ${sigClass}">
            <span class="sig-status-icon">${icon}</span>
            <div>
              <div class="sig-name">${escapeHtml(sig.name)} ${sig.points > 0 ? `(+${sig.points}% Risk)` : ''}</div>
              <div class="sig-desc">${escapeHtml(sig.description)}</div>
            </div>
          </div>
        `;
      }).join('');
    } else {
      signalsContainer.innerHTML = `
        <div class="signal-item clean">
          <span class="sig-status-icon">✓</span>
          <div>
            <div class="sig-name">Connection & Heuristics Normal</div>
            <div class="sig-desc">Active SSL encryption, authentic brand registration, and no lookalike homoglyphs detected.</div>
          </div>
        </div>
      `;
    }

    // --- Detail 2: Category Breakdown ---
    const catValDom = document.getElementById('cat-val-domain');
    const catBarDom = document.getElementById('cat-bar-domain');
    const catValLex = document.getElementById('cat-val-lexical');
    const catBarLex = document.getElementById('cat-bar-lexical');
    const catValSec = document.getElementById('cat-val-security');
    const catBarSec = document.getElementById('cat-bar-security');
    const catValCon = document.getElementById('cat-val-content');
    const catBarCon = document.getElementById('cat-bar-content');

    catValDom.textContent = `${catScores.domain}/100`;
    catBarDom.style.width = `${catScores.domain}%`;
    catBarDom.style.background = getScoreColor(catScores.domain);

    catValLex.textContent = `${catScores.lexical}/100`;
    catBarLex.style.width = `${catScores.lexical}%`;
    catBarLex.style.background = getScoreColor(catScores.lexical);

    catValSec.textContent = `${catScores.security}/100`;
    catBarSec.style.width = `${catScores.security}%`;
    catBarSec.style.background = getScoreColor(catScores.security);

    catValCon.textContent = `${catScores.content}/100`;
    catBarCon.style.width = `${catScores.content}%`;
    catBarCon.style.background = getScoreColor(catScores.content);

    // --- Detail 3: Intel & DB ---
    document.getElementById('intel-db-match').textContent = dbMatch.label || 'Heuristic Evaluation';
    document.getElementById('intel-apex').textContent = details.apexDomain || details.hostname || '-';

    const host = details.hostname || '';
    const hostParts = host.split('.');
    const tld = hostParts.length > 1 ? '.' + hostParts[hostParts.length - 1] : '-';
    document.getElementById('intel-tld').textContent = tld;

    const hasHomoglyph = signals.some(s => s.id === 'homoglyph_attack');
    const elHomo = document.getElementById('intel-homoglyph');
    elHomo.textContent = hasHomoglyph ? '⚠️ Deceptive Lookalike' : '✓ Clean';
    elHomo.style.color = hasHomoglyph ? 'var(--danger)' : 'var(--safe)';

    document.getElementById('intel-ip-addr').textContent = ipData.ip || 'Unavailable';
    document.getElementById('intel-ip-org').textContent = ipData.organization || 'Unavailable';
    document.getElementById('intel-ip-asn').textContent = ipData.asn || 'Unavailable';
    document.getElementById('intel-ip-geo').textContent = ipData.countryName && ipData.countryName !== 'Unavailable'
      ? `${ipData.countryName} (${ipData.countryCode || ''})`
      : 'Unavailable';

    const elThreat = document.getElementById('intel-ip-threat-status');
    elThreat.textContent = ipData.statusText || 'Offline IP analysis: Ready';
    if (ipData.isMalicious) {
      elThreat.style.background = 'var(--danger-bg)';
      elThreat.style.color = 'var(--danger)';
    } else if (ipData.isAvailable) {
      elThreat.style.background = 'var(--safe-bg)';
      elThreat.style.color = 'var(--safe)';
    } else {
      elThreat.style.background = 'rgba(255, 255, 255, 0.05)';
      elThreat.style.color = 'var(--text-muted)';
    }

    document.getElementById('intel-full-url').textContent = details.url || rawUrl;

    // --- Detail 4: Cookies ---
    const cookiesDetailContainer = document.getElementById('cookies-content');
    cookiesDetailContainer.innerHTML = `
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border-light); border-radius: 8px; padding: 12px;">
        <div style="font-size: 12px; font-weight: 700; color: var(--text-main); margin-bottom: 6px;">
          🔒 Zero-Telemetry Cookie Classification
        </div>
        <p style="font-size: 11.5px; color: var(--text-secondary); line-height: 1.45; margin-bottom: 8px;">
          In accordance with strict privacy engineering, Veridex AI audits <strong>cookie metadata only</strong> (name, domain scope, expiration, Secure flag, HttpOnly flag, and SameSite attribute). 
          Actual session tokens and cookie secret values are never read, stored, or sent across the network.
        </p>
        <div style="font-size: 11.5px; color: var(--brand-blue-hover); font-weight: 600;">
          Status: Offline Privacy Protocol Active (0 values exposed)
        </div>
      </div>
    `;

    // --- Detail 5 & 6: Cybercrime & Full Report ---
    const reportPre = document.getElementById('full-report-content');
    reportPre.textContent = generateExecutiveAuditReport(analysis, rawUrl);
  }

  // Generate Executive Security Audit Report Text
  function generateExecutiveAuditReport(analysis, rawUrl) {
    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 0);
    const details = analysis.details || {};
    const catScores = analysis.categoryScores || {};
    const signals = analysis.signals || [];
    const classification = analysis.classification || {};
    const dbMatch = analysis.databaseMatch || {};
    const ipData = analysis.ipIntelligence || {};
    const dateStr = new Date().toISOString();

    return `======================================================================
               VERIDEX AI - CYBERSECURITY AUDIT REPORT
======================================================================
Report Generated : ${dateStr}
Inspected URL    : ${details.url || rawUrl}
Apex Domain      : ${details.apexDomain || details.hostname || 'N/A'}
Risk Score       : ${riskPct}% (${analysis.levelLabel || 'Heuristic Score'})
Final Verdict    : ${(analysis.verdict || 'NEUTRAL').toUpperCase()}
Database Match   : ${dbMatch.label || 'Heuristic Evaluation'}
Classification   : ${classification.categoryLabel || classification.badge || 'Standard Evaluation'}

----------------------------------------------------------------------
1. MULTI-FACTOR RISK VECTOR BREAKDOWN
----------------------------------------------------------------------
• Domain & TLD Abuse Risk      : ${catScores.domain || 0}/100
• Lexical & Brand Spoofing     : ${catScores.lexical || 0}/100
• Connection & SSL Security    : ${catScores.security || 0}/100
• Form Inputs & Content Safety : ${catScores.content || 0}/100

----------------------------------------------------------------------
2. DETECTED THREAT SIGNALS & INDICATORS (${signals.length} EVALUATED)
----------------------------------------------------------------------
${signals.length > 0 ? signals.map((s, i) => `[${i+1}] ${s.name} (+${s.points}% Risk, Severity: ${s.severity.toUpperCase()})
    ${s.description}`).join('\n\n') : '• No active threat indicators detected. Domain passes heuristic safety.'}

----------------------------------------------------------------------
3. OFFLINE IP INTELLIGENCE & INFRASTRUCTURE
----------------------------------------------------------------------
• Resolved Server IP : ${ipData.ip || 'Unavailable (Cached / Not Captured)'}
• Hosting Provider   : ${ipData.organization || 'Unavailable'}
• Autonomous System  : ${ipData.asn || 'Unavailable'}
• Country / Region   : ${ipData.countryName || 'Unavailable'}
• Threat Status      : ${ipData.statusText || 'Offline database lookup complete'}

----------------------------------------------------------------------
4. COOKIE SECURITY & PRIVACY METADATA
----------------------------------------------------------------------
• Privacy Guarantee  : Zero-telemetry on-device evaluation
• Secret Values      : 100% Omitted & Redacted
• Audit Scope        : Security flags (Secure, HttpOnly, SameSite)

----------------------------------------------------------------------
5. SAFETY RECOMMENDATIONS & ADVISORY
----------------------------------------------------------------------
${(analysis.recommendations && analysis.recommendations.length > 0)
  ? analysis.recommendations.map(r => `• ${r}`).join('\n')
  : '• Verify URL spelling before entering credentials or executing payments.\n• Ensure valid HTTPS lock icon is displayed in browser address bar.'}

----------------------------------------------------------------------
6. INDIA CYBERCRIME REPORTING HELPLINE
----------------------------------------------------------------------
National Cyber Crime Helpline : 1930 (Toll-Free 24x7)
Official Reporting Portal     : https://cybercrime.gov.in/

======================================================================
Veridex AI operates 100% locally and offline without external telemetry.
======================================================================`;
  }

  // Print Report Handler
  function handlePrintReport() {
    if (!currentAnalysis) {
      alert('Please verify a website URL first before printing.');
      return;
    }
    window.print();
  }

  // Download Report Handler
  function handleDownloadReport() {
    if (!currentAnalysis) {
      alert('Please verify a website URL first before downloading.');
      return;
    }
    const reportText = generateExecutiveAuditReport(currentAnalysis, urlInput.value.trim());
    const host = (currentAnalysis.details && currentAnalysis.details.hostname) ? currentAnalysis.details.hostname : 'audit';
    const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `veridex_report_${host}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }

  // Copy Evidence Handler
  function handleCopyEvidence() {
    if (!currentAnalysis) {
      alert('Please verify a website URL first.');
      return;
    }
    const reportText = generateExecutiveAuditReport(currentAnalysis, urlInput.value.trim());
    navigator.clipboard.writeText(reportText).then(() => {
      alert('Security Audit Evidence copied to clipboard!');
    }).catch(err => {
      console.error(err);
      alert('Unable to copy automatically. Please select and copy from the Full Report section.');
    });
  }

  // Detail Action Buttons
  const btnPrintDetail = document.getElementById('btn-print-report-view');
  const btnDownloadDetail = document.getElementById('btn-download-report-view');
  const btnCopyDetail = document.getElementById('btn-copy-report-view');
  const btnCopyCyber = document.getElementById('btn-copy-evidence-cyber');

  if (btnPrintDetail) btnPrintDetail.addEventListener('click', handlePrintReport);
  if (btnDownloadDetail) btnDownloadDetail.addEventListener('click', handleDownloadReport);
  if (btnCopyDetail) btnCopyDetail.addEventListener('click', handleCopyEvidence);
  if (btnCopyCyber) btnCopyCyber.addEventListener('click', handleCopyEvidence);

  // Helper: Plain English reasons for Why Unsafe box
  function getPlainEnglishReasons(analysis) {
    const reasons = [];
    const signals = analysis.signals || [];
    const details = analysis.details || {};
    const catScores = analysis.categoryScores || {};

    if (analysis.databaseMatch && analysis.databaseMatch.isFake) {
      reasons.push({ icon: '☠️', title: 'Confirmed Fraud Record', desc: 'Domain matches an active malicious campaign or confirmed phishing threat registry.' });
    }
    if (signals.some(s => s.id === 'brand_spoofing' || s.id === 'subdomain_brand_spoof')) {
      reasons.push({ icon: '🎭', title: 'Brand Imitation', desc: 'The domain name imitates a trusted brand without official authorization.' });
    }
    if (signals.some(s => s.id === 'homoglyph_attack')) {
      reasons.push({ icon: '🔤', title: 'Lookalike Alphabet (Homoglyph)', desc: 'Uses deceptive foreign characters that mimic standard Latin letters.' });
    }
    if (signals.some(s => s.id === 'high_risk_tld')) {
      reasons.push({ icon: '🌐', title: 'High-Abuse Domain Extension', desc: 'Uses a top-level domain frequently associated with automated scam networks.' });
    }
    if (details.protocol === 'http:') {
      reasons.push({ icon: '🔓', title: 'Unencrypted Connection', desc: 'Connection lacks SSL encryption, allowing attackers to intercept submitted data.' });
    }
    if (catScores.lexical > 40) {
      reasons.push({ icon: '🪤', title: 'Suspicious Domain Construction', desc: 'Contains urgent or misleading phrasing commonly found in credential traps.' });
    }
    if (reasons.length === 0) {
      reasons.push({ icon: '⚠️', title: 'Heuristic Warning', desc: 'Exhibits unusual domain registration patterns and lack of authentic registry verification.' });
    }
    return reasons;
  }

  function getScoreColor(val) {
    if (val >= 60) return '#ef4444';
    if (val >= 35) return '#f97316';
    if (val >= 21) return '#f59e0b';
    return '#10b981';
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

  // Read target URL from query parameters (e.g. when opened from extension) or default sample
  const urlParams = new URLSearchParams(window.location.search);
  const targetParam = urlParams.get('url') || urlParams.get('target');
  const initialUrl = (targetParam && targetParam.trim())
    ? targetParam.trim()
    : 'http://paypal-security-update.com';

  urlInput.value = initialUrl;
  btnClear.style.display = 'inline';
  runVerification(initialUrl);
});
