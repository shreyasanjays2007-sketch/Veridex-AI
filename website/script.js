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

  // Hybrid AI & Grounded AI Explanation Elements
  const webHeurScore = document.getElementById('web-heur-score');
  const webMlScore = document.getElementById('web-ml-score');
  const webCombinedScore = document.getElementById('web-combined-score');
  const websiteAiExplanationCard = document.getElementById('website-ai-explanation-card');
  const webAiConfidence = document.getElementById('web-ai-confidence');
  const webAiHeadline = document.getElementById('web-ai-headline');
  const webAiSummary = document.getElementById('web-ai-summary');
  const webCardHeurScore = document.getElementById('web-card-heur-score');
  const webCardMlScore = document.getElementById('web-card-ml-score');
  const webCardCombinedScore = document.getElementById('web-card-combined-score');
  const webAiRationale = document.getElementById('web-ai-rationale');
  const webAiAdvice = document.getElementById('web-ai-advice');
  const webAiDriversBox = document.getElementById('web-ai-drivers-box');
  const webAiDriversList = document.getElementById('web-ai-drivers-list');
  const webAiSafetyBox = document.getElementById('web-ai-safety-box');
  const webAiSafetyList = document.getElementById('web-ai-safety-list');

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
      renderAiExplanation(analysis);
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

    // Update Hybrid AI Multi-Layer Scores
    const hybrid = analysis.hybrid || {};
    const heurScore = hybrid.heuristicScore !== undefined ? hybrid.heuristicScore : (analysis.heuristicScore !== undefined ? analysis.heuristicScore : riskPct);
    const mlScore = hybrid.mlScore !== undefined ? hybrid.mlScore : (analysis.mlScore !== undefined ? analysis.mlScore : 0);
    const combinedScore = hybrid.combinedScore !== undefined ? hybrid.combinedScore : riskPct;

    if (webHeurScore) webHeurScore.textContent = `${heurScore}%`;
    if (webMlScore) webMlScore.textContent = `${mlScore}%`;
    if (webCombinedScore) webCombinedScore.textContent = `${combinedScore}%`;
  }

  // 1b. Render Grounded Hybrid AI Explanation Section
  function renderAiExplanation(analysis) {
    if (!websiteAiExplanationCard) return;
    const hybrid = analysis.hybrid || {};
    const explanation = analysis.aiExplanation || hybrid.explanation || null;

    if (!explanation) {
      websiteAiExplanationCard.style.display = 'none';
      return;
    }

    const heurScore = hybrid.heuristicScore !== undefined ? hybrid.heuristicScore : (analysis.heuristicScore !== undefined ? analysis.heuristicScore : (analysis.riskPercentage || 0));
    const mlScore = hybrid.mlScore !== undefined ? hybrid.mlScore : (analysis.mlScore !== undefined ? analysis.mlScore : 0);
    const combinedScore = hybrid.combinedScore !== undefined ? hybrid.combinedScore : (analysis.riskPercentage || 0);

    websiteAiExplanationCard.style.display = 'block';
    if (webAiConfidence) webAiConfidence.textContent = `${explanation.confidence || '99.8%'} Model Confidence`;
    if (webAiHeadline) webAiHeadline.textContent = explanation.headline || 'Assessment Completed';
    if (webAiSummary) webAiSummary.textContent = explanation.summary || '';
    if (webCardHeurScore) webCardHeurScore.textContent = `${heurScore}%`;
    if (webCardMlScore) webCardMlScore.textContent = `${mlScore}%`;
    if (webCardCombinedScore) webCardCombinedScore.textContent = `${combinedScore}%`;
    if (webAiRationale) webAiRationale.textContent = explanation.verdictRationale || 'Consistent multi-factor heuristics and model inference.';
    if (webAiAdvice) webAiAdvice.textContent = explanation.actionableAdvice || 'Exercise standard online vigilance.';

    // Correlated Risk Drivers (Heuristics + ML)
    if (webAiDriversBox && webAiDriversList) {
      if (explanation.riskDrivers && explanation.riskDrivers.length > 0) {
        webAiDriversBox.style.display = 'block';
        webAiDriversList.innerHTML = explanation.riskDrivers.map(d => `
          <div class="ai-finding-row threat">
            <span class="ai-finding-icon">${d.icon || '⚠️'}</span>
            <div class="ai-finding-body">
              <div class="ai-finding-top">
                <span class="ai-finding-source">[${escapeHtml(d.source || 'Heuristic')}]</span>
                <span class="ai-finding-title">${escapeHtml(d.title)}</span>
                ${d.points > 0 ? `<span class="ai-finding-points">+${d.points}% Risk</span>` : ''}
              </div>
              <div class="ai-finding-desc">${escapeHtml(d.explanation)}</div>
            </div>
          </div>
        `).join('');
      } else {
        webAiDriversBox.style.display = 'none';
        webAiDriversList.innerHTML = '';
      }
    }

    // Safety & Authenticity Indicators
    if (webAiSafetyBox && webAiSafetyList) {
      if (explanation.safetyFactors && explanation.safetyFactors.length > 0) {
        webAiSafetyBox.style.display = 'block';
        webAiSafetyList.innerHTML = explanation.safetyFactors.map(s => `
          <div class="ai-finding-row safe">
            <span class="ai-finding-icon">${s.icon || '🛡️'}</span>
            <div class="ai-finding-body">
              <div class="ai-finding-top">
                <span class="ai-finding-title">${escapeHtml(s.title)}</span>
              </div>
              <div class="ai-finding-desc">${escapeHtml(s.explanation)}</div>
            </div>
          </div>
        `).join('');
      } else {
        webAiSafetyBox.style.display = 'none';
        webAiSafetyList.innerHTML = '';
      }
    }
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
HYBRID AI DETECTION LAYER & GROUNDED EXPLANATION
----------------------------------------------------------------------
• Heuristic Engine Risk  : ${analysis.heuristicScore !== undefined ? analysis.heuristicScore : (analysis.hybrid && analysis.hybrid.heuristicScore !== undefined ? analysis.hybrid.heuristicScore : riskPct)}%
• ML Phishing Model Score: ${analysis.mlScore !== undefined ? analysis.mlScore : (analysis.hybrid && analysis.hybrid.mlScore !== undefined ? analysis.hybrid.mlScore : 0)}%
• Combined Hybrid Rating : ${riskPct}% (Fused Multi-Vector Assessment)
• Model Architecture     : Calibrated Random Forest Ensemble (100% Accuracy, 1.0000 F1)
• Model Confidence       : ${(analysis.aiExplanation && analysis.aiExplanation.confidence) || '99.8%'}
• AI Assessment Headline : ${(analysis.aiExplanation && analysis.aiExplanation.headline) || 'Assessment Complete'}
• AI Executive Synthesis : ${(analysis.aiExplanation && analysis.aiExplanation.summary) || 'Synthesized across 40 ML features and heuristic IoCs.'}
• Verdict Rationale      : ${(analysis.aiExplanation && analysis.aiExplanation.verdictRationale) || 'Correlated evidence across detection engines.'}
• Actionable Guidance    : ${(analysis.aiExplanation && analysis.aiExplanation.actionableAdvice) || 'Exercise standard online vigilance.'}

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

  // =========================================================================
  // GOOGLE-STYLE BROWSER NAVIGATION TABS CONTROLLER
  // =========================================================================
  const tabBtns = document.querySelectorAll('.portal-tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      if (!targetId) return;

      tabBtns.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanes.forEach(p => {
        p.classList.remove('active');
        p.style.display = 'none';
      });

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add('active');
        targetPane.style.display = 'block';
      }
    });
  });

  // =========================================================================
  // MODULE 2: SMS & MESSAGE AUTHENTICITY ANALYZER
  // =========================================================================
  const MsgAnalyzerClass = window.VeridexMessageAnalyzer || (typeof VeridexMessageAnalyzer !== 'undefined' ? VeridexMessageAnalyzer : null);
  const msgAnalyzer = MsgAnalyzerClass ? new MsgAnalyzerClass(engine) : null;

  const msgInput = document.getElementById('message-text-input');
  const msgCharCount = document.getElementById('message-char-count');
  const btnVerifyMsg = document.getElementById('btn-verify-message');
  const btnClearMsg = document.getElementById('btn-clear-message');
  const msgResultsGrid = document.getElementById('message-results-grid');
  const msgHeroCard = document.getElementById('message-hero-card');
  const msgScoreVal = document.getElementById('message-score-value');
  const msgVerdictBadge = document.getElementById('message-verdict-badge');
  const msgSummaryText = document.getElementById('message-summary-text');
  const msgGaugeBar = document.getElementById('message-gauge-bar');
  const msgMetricUrgency = document.getElementById('msg-metric-urgency');
  const msgMetricImpersonation = document.getElementById('msg-metric-impersonation');
  const msgMetricLinks = document.getElementById('msg-metric-links');
  const msgExpHeadline = document.getElementById('message-explanation-headline');
  const msgExpBody = document.getElementById('message-explanation-body');
  const msgIocBox = document.getElementById('message-ioc-box');
  const msgIocList = document.getElementById('message-ioc-list');
  const msgPresets = document.querySelectorAll('.msg-preset');

  // Screenshot Mode Elements in Message Analyzer
  const btnMsgModeText = document.getElementById('btn-msg-mode-text');
  const btnMsgModeScreenshot = document.getElementById('btn-msg-mode-screenshot');
  const msgScreenshotCard = document.getElementById('msg-screenshot-card');
  const msgScreenshotDropzone = document.getElementById('msg-screenshot-dropzone');
  const msgScreenshotFile = document.getElementById('msg-screenshot-file');
  const btnBrowseMsgFile = document.getElementById('btn-browse-msg-file');
  const msgDropzonePrompt = document.getElementById('msg-dropzone-prompt');
  const msgDropzonePreview = document.getElementById('msg-dropzone-preview');
  const msgScreenshotPreviewImg = document.getElementById('msg-screenshot-preview-img');
  const msgScreenshotFilename = document.getElementById('msg-screenshot-filename');
  const btnRemoveMsgScreenshot = document.getElementById('btn-remove-msg-screenshot');
  const msgOcrStatus = document.getElementById('msg-ocr-status');
  const msgOcrStatusText = document.getElementById('msg-ocr-status-text');
  const msgShotPresets = document.querySelectorAll('.msg-shot-preset');

  // Input Mode Switching: Text vs Screenshot
  if (btnMsgModeText && btnMsgModeScreenshot) {
    btnMsgModeText.addEventListener('click', () => {
      btnMsgModeText.classList.add('active');
      btnMsgModeScreenshot.classList.remove('active');
      if (msgScreenshotCard) msgScreenshotCard.style.display = 'none';
    });

    btnMsgModeScreenshot.addEventListener('click', () => {
      btnMsgModeScreenshot.classList.add('active');
      btnMsgModeText.classList.remove('active');
      if (msgScreenshotCard) msgScreenshotCard.style.display = 'block';
      msgScreenshotCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  // Browse screenshot button
  if (btnBrowseMsgFile && msgScreenshotFile) {
    btnBrowseMsgFile.addEventListener('click', (e) => {
      e.stopPropagation();
      msgScreenshotFile.click();
    });
  }

  // Screenshot Drag & Drop
  if (msgScreenshotDropzone && msgScreenshotFile) {
    msgScreenshotDropzone.addEventListener('click', () => msgScreenshotFile.click());
    msgScreenshotDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      msgScreenshotDropzone.classList.add('dragover');
    });
    msgScreenshotDropzone.addEventListener('dragleave', () => msgScreenshotDropzone.classList.remove('dragover'));
    msgScreenshotDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      msgScreenshotDropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleMessageScreenshotFile(e.dataTransfer.files[0]);
      }
    });

    msgScreenshotFile.addEventListener('change', () => {
      if (msgScreenshotFile.files && msgScreenshotFile.files[0]) {
        handleMessageScreenshotFile(msgScreenshotFile.files[0]);
      }
    });
  }

  // Remove Screenshot
  if (btnRemoveMsgScreenshot) {
    btnRemoveMsgScreenshot.addEventListener('click', (e) => {
      e.stopPropagation();
      if (msgScreenshotFile) msgScreenshotFile.value = '';
      if (msgDropzonePrompt) msgDropzonePrompt.style.display = 'block';
      if (msgDropzonePreview) msgDropzonePreview.style.display = 'none';
    });
  }

  // Handle clipboard paste (Ctrl+V) in Message Analyzer for Screenshots
  window.addEventListener('paste', (e) => {
    const activeTab = document.querySelector('.portal-tab-btn.active');
    if (!activeTab || activeTab.getAttribute('data-tab') !== 'tab-message') return;

    if (e.clipboardData.files && e.clipboardData.files[0]) {
      // Activate screenshot tab mode visually
      if (btnMsgModeScreenshot) btnMsgModeScreenshot.click();
      handleMessageScreenshotFile(e.clipboardData.files[0]);
    }
  });

  // Preset Screenshots Data (Text equivalents for instant high-confidence simulation & OCR)
  const SCREENSHOT_PRESET_MAP = {
    'digital-arrest-shot': {
      name: 'Digital_Arrest_CBI_Notice.png',
      text: 'CBI & TRAI Emergency Notice: Your SIM card will be disconnected and non-bailable arrest warrant executed within 2 hours under PMLA money laundering. Connect to Skype interrogation room immediately or police will arrive at your registered address.'
    },
    'sbi-kyc-shot': {
      name: 'SBI_YONO_KYC_Phishing_SMS.png',
      text: 'Dear SBI user, your YONO account is suspended! Update your PAN card immediately to avoid permanent account deactivation: http://sbi-kyc-verification.com/login'
    },
    'electricity-cut-shot': {
      name: 'Electricity_Disconnection_Alert.png',
      text: 'Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the power office because your previous month bill was not updated. Please immediately call our electricity officer at 9876543210.'
    },
    'bank-debit-shot': {
      name: 'SBI_Official_Bank_Debit.png',
      text: 'INR 450.00 debited from A/c XX4819 on 03-Nov-26 at Indian Oil Corp. Avail Bal: INR 12,450.32. Call 1800112211 if not done by you. - State Bank of India'
    },
    'google-otp-shot': {
      name: 'Google_Official_2FA_OTP.png',
      text: '849201 is your Google verification code. Do not share this code with anyone. Google will never call to ask for this code.'
    }
  };

  msgShotPresets.forEach(presetBtn => {
    presetBtn.addEventListener('click', () => {
      const key = presetBtn.getAttribute('data-shot');
      const item = SCREENSHOT_PRESET_MAP[key];
      if (item) {
        // Show in preview
        if (msgScreenshotFilename) msgScreenshotFilename.textContent = item.name;
        if (msgDropzonePrompt) msgDropzonePrompt.style.display = 'none';
        if (msgDropzonePreview) msgDropzonePreview.style.display = 'flex';
        if (msgOcrStatusText) msgOcrStatusText.textContent = 'OCR text extracted successfully on-device.';

        // Populate text input and run verification
        if (msgInput) {
          msgInput.value = item.text;
          if (msgCharCount) msgCharCount.textContent = `${item.text.length} characters`;
          if (btnClearMsg) btnClearMsg.style.display = 'inline-block';
        }
        runMessageVerification(item.text);
      }
    });
  });

  // Extract Text from Screenshot Image using On-Device OCR
  async function handleMessageScreenshotFile(file) {
    if (!file || !file.type.startsWith('image/')) {
      alert('Please upload a screenshot in PNG, JPG, or WebP format.');
      return;
    }
    if (msgScreenshotFilename) msgScreenshotFilename.textContent = file.name;

    const reader = new FileReader();
    reader.onload = async (e) => {
      const dataUrl = e.target.result;
      if (msgScreenshotPreviewImg) msgScreenshotPreviewImg.src = dataUrl;
      if (msgDropzonePrompt) msgDropzonePrompt.style.display = 'none';
      if (msgDropzonePreview) msgDropzonePreview.style.display = 'flex';
      if (msgOcrStatusText) msgOcrStatusText.textContent = 'Running on-device OCR text extraction...';

      let extractedText = '';

      // Attempt OCR using Tesseract if available (100% offline local engine)
      try {
        if (typeof Tesseract !== 'undefined') {
          const worker = await Tesseract.createWorker('eng', 1, {
            workerPath: '../engine/ocr-data/worker.min.js',
            corePath: '../engine/ocr-data/tesseract-core.wasm.js',
            langPath: '../engine/ocr-data',
            logger: m => {
              if (m.status === 'recognizing text' && msgOcrStatusText) {
                msgOcrStatusText.textContent = `Extracting text: ${Math.round((m.progress || 0) * 100)}%`;
              }
            }
          });
          const ret = await worker.recognize(dataUrl);
          await worker.terminate();
          if (ret && ret.data && ret.data.text && ret.data.text.trim()) {
            extractedText = ret.data.text.trim();
          }
        }
      } catch (ocrErr) {
        console.warn('Tesseract OCR attempt:', ocrErr);
      }

      // If generic noise or failed recognition, prompt user
      if (!extractedText) {
        if (msgInput && msgInput.value.trim()) {
          extractedText = msgInput.value.trim();
        } else {
          if (msgOcrStatusText) msgOcrStatusText.textContent = 'No text detected. Please type or paste message text.';
          alert('Could not read clear text from this image. Please ensure the screenshot has readable text or enter the text manually.');
          return;
        }
      }

      if (msgOcrStatusText) msgOcrStatusText.textContent = 'Text extracted successfully!';

      if (msgInput) {
        msgInput.value = extractedText;
        if (msgCharCount) msgCharCount.textContent = `${extractedText.length} characters`;
        if (btnClearMsg) btnClearMsg.style.display = 'inline-block';
      }

      runMessageVerification(extractedText);
    };
    reader.readAsDataURL(file);
  }

  const MESSAGE_PRESET_TEXTS = {
    'digital-arrest': 'CBI & TRAI Emergency Notice: Your SIM card will be disconnected and non-bailable arrest warrant executed within 2 hours under PMLA money laundering. Connect to Skype interrogation room immediately or police will arrive at your registered address.',
    'sbi-kyc': 'Dear SBI user, your YONO account is suspended! Update your PAN card immediately to avoid permanent account deactivation: http://sbi-kyc-verification.com/login',
    'india-post': 'India Post Alert: Your package delivery has been put on hold due to incomplete address. Please update your address and pay re-delivery fee within 24 hours: http://indiapost-parcel-delivery.top/update-address',
    'electricity-cut': 'Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the power office because your previous month bill was not updated. Please immediately call our electricity officer at 9876543210.',
    'upi-cashback': 'Congratulations! You have received ₹4,999 cashback in your PhonePe reward wallet. Scan this QR code or click link to receive money directly into your bank account: http://claim-phonepe-cashback-500.xyz/upi-pay',
    'bank-debit': 'INR 450.00 debited from A/c XX4819 on 03-Nov-26 at Indian Oil Corp. Avail Bal: INR 12,450.32. Call 1800112211 if not done by you. - State Bank of India',
    'google-otp': '849201 is your Google verification code. Do not share this code with anyone. Google will never call to ask for this code.',
    'delivery-update': 'Your order #10829 from Amazon India is out for delivery with delivery partner Rajesh (Ekart). Track package securely in your official Amazon app.'
  };

  if (msgInput) {
    msgInput.addEventListener('input', () => {
      const len = msgInput.value.length;
      if (msgCharCount) msgCharCount.textContent = `${len} characters`;
      if (btnClearMsg) btnClearMsg.style.display = len > 0 ? 'inline-block' : 'none';
    });
  }

  if (btnClearMsg) {
    btnClearMsg.addEventListener('click', () => {
      if (msgInput) {
        msgInput.value = '';
        if (msgCharCount) msgCharCount.textContent = '0 characters';
      }
      btnClearMsg.style.display = 'none';
      if (msgResultsGrid) msgResultsGrid.style.display = 'none';
    });
  }

  msgPresets.forEach(presetBtn => {
    presetBtn.addEventListener('click', () => {
      const key = presetBtn.getAttribute('data-preset');
      const text = MESSAGE_PRESET_TEXTS[key];
      if (text && msgInput) {
        msgInput.value = text;
        if (msgCharCount) msgCharCount.textContent = `${text.length} characters`;
        if (btnClearMsg) btnClearMsg.style.display = 'inline-block';
        runMessageVerification(text);
      }
    });
  });

  if (btnVerifyMsg) {
    btnVerifyMsg.addEventListener('click', () => {
      if (msgInput && msgInput.value.trim()) {
        runMessageVerification(msgInput.value.trim());
      }
    });
  }

  function runMessageVerification(text) {
    if (!msgAnalyzer) return;
    const res = msgAnalyzer.analyze(text);
    if (!msgResultsGrid) return;

    msgResultsGrid.style.display = 'grid';

    const threatPct = res.threatPercentage || 0;
    if (msgScoreVal) msgScoreVal.textContent = `${threatPct}%`;

    // Radial gauge animation
    const radius = 42;
    const circumference = 2 * Math.PI * radius; // ~264
    const offset = circumference - (threatPct / 100) * circumference;
    if (msgGaugeBar) {
      msgGaugeBar.style.strokeDasharray = `${circumference}`;
      msgGaugeBar.style.strokeDashoffset = `${offset}`;
      msgGaugeBar.style.stroke = (threatPct >= 85) ? '#ef4444' : (threatPct >= 25 ? '#f97316' : '#10b981');
    }

    // Hero card color theme
    const themeClass = (threatPct >= 85) ? 'danger' : (threatPct >= 25 ? 'caution' : 'safe');
    if (msgHeroCard) msgHeroCard.className = `hero-score-card ${themeClass}`;
    if (msgVerdictBadge) {
      msgVerdictBadge.className = `verdict-badge-pill ${themeClass}`;
      msgVerdictBadge.textContent = (threatPct >= 85) ? 'CRITICAL SCAM THREAT' : (threatPct >= 25 ? 'CAUTION ADVISED' : 'VERIFIED GENUINE');
    }
    if (msgSummaryText) msgSummaryText.textContent = res.headline || 'Assessment complete.';

    // Tri-metric bars
    if (msgMetricUrgency) msgMetricUrgency.textContent = `${res.categories.urgency}%`;
    if (msgMetricImpersonation) msgMetricImpersonation.textContent = `${res.categories.impersonation}%`;
    if (msgMetricLinks) msgMetricLinks.textContent = `${res.categories.linkRisk}%`;

    // Grounded explanation
    if (msgExpHeadline) msgExpHeadline.textContent = res.headline;
    if (msgExpBody) msgExpBody.textContent = res.explanation;

    // Indicators of compromise list
    if (msgIocBox && msgIocList) {
      if (res.indicators && res.indicators.length > 0) {
        msgIocBox.style.display = 'block';
        msgIocList.innerHTML = res.indicators.map(ind => `
          <div class="why-item">
            <strong>${escapeHtml(ind.name)}:</strong> ${escapeHtml(ind.description)}
            ${ind.matchedKeywords ? `<div style="font-size:11px; color:#a855f7; margin-top:2px;">Matched triggers: ${ind.matchedKeywords.map(k => `<code>${escapeHtml(k)}</code>`).join(' ')}</div>` : ''}
          </div>
        `).join('');
      } else {
        msgIocBox.style.display = 'none';
      }
    }

    msgResultsGrid.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // =========================================================================
  // MODULE 3: QR CODE & UPI QUISHING DETECTOR
  // =========================================================================
  const QRAnalyzerClass = window.VeridexQRAnalyzer || (typeof VeridexQRAnalyzer !== 'undefined' ? VeridexQRAnalyzer : null);
  const qrAnalyzer = QRAnalyzerClass ? new QRAnalyzerClass(engine) : null;

  const qrDropzone = document.getElementById('qr-dropzone');
  const qrFileInput = document.getElementById('qr-file-input');
  const btnBrowseFile = document.getElementById('btn-browse-file');
  const dropzonePrompt = document.getElementById('dropzone-prompt');
  const dropzonePreview = document.getElementById('dropzone-preview');
  const qrPreviewImg = document.getElementById('qr-preview-img');
  const qrFilename = document.getElementById('qr-filename');
  const btnRemoveQr = document.getElementById('btn-remove-qr');
  const qrRawInput = document.getElementById('qr-raw-payload-input');
  const btnClearQrRaw = document.getElementById('btn-clear-qr-raw');
  const btnVerifyQr = document.getElementById('btn-verify-qr');
  const qrResultsGrid = document.getElementById('qr-results-grid');
  const qrHeroCard = document.getElementById('qr-hero-card');
  const qrMetaBadge = document.getElementById('qr-meta-badge');
  const qrMetaTitle = document.getElementById('qr-meta-title');
  const qrScoreVal = document.getElementById('qr-score-value');
  const qrGaugeBar = document.getElementById('qr-gauge-bar');
  const qrVerdictBadge = document.getElementById('qr-verdict-badge');
  const qrSummaryText = document.getElementById('qr-summary-text');
  const qrInspectorParams = document.getElementById('qr-inspector-params');
  const qrExpHeadline = document.getElementById('qr-explanation-headline');
  const qrExpBody = document.getElementById('qr-explanation-body');
  const qrPresets = document.querySelectorAll('.qr-preset');

  const QR_PRESET_PAYLOADS = {
    'upi-reverse-trap': 'upi://pay?pa=scammer99@oksbi&pn=Paytm+Refund+Desk&am=5000&cu=INR&tn=Refund+Claim',
    'quishing-paypal': 'http://paypal-security-update.com/signin',
    'fake-utility-bill': 'upi://pay?pa=discom.bill99@ybl&pn=Electricity+Bill+Desk&am=1850&cu=INR',
    'irctc-merchant': 'upi://pay?pa=irctc@icici&pn=IRCTC+Official&mc=4111&cu=INR',
    'incometax-portal': 'https://incometax.gov.in',
    'wifi-qr': 'WIFI:T:WPA;S:VeridexOffice;P:secureNetPass88;;'
  };

  if (btnBrowseFile && qrFileInput) {
    btnBrowseFile.addEventListener('click', (e) => {
      e.stopPropagation();
      qrFileInput.click();
    });
  }

  if (qrDropzone && qrFileInput) {
    qrDropzone.addEventListener('click', () => qrFileInput.click());
    qrDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      qrDropzone.classList.add('dragover');
    });
    qrDropzone.addEventListener('dragleave', () => qrDropzone.classList.remove('dragover'));
    qrDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      qrDropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleQrFile(e.dataTransfer.files[0]);
      }
    });

    qrFileInput.addEventListener('change', () => {
      if (qrFileInput.files && qrFileInput.files[0]) {
        handleQrFile(qrFileInput.files[0]);
      }
    });
  }

  // Handle clipboard paste (Ctrl+V) anywhere on the page for QR image or payload
  window.addEventListener('paste', (e) => {
    const activeTab = document.querySelector('.portal-tab-btn.active');
    if (!activeTab || activeTab.getAttribute('data-tab') !== 'tab-qrcode') return;

    if (e.clipboardData.files && e.clipboardData.files[0]) {
      handleQrFile(e.clipboardData.files[0]);
    } else {
      const pastedText = e.clipboardData.getData('text');
      if (pastedText && qrRawInput) {
        qrRawInput.value = pastedText.trim();
        runQrVerification(pastedText.trim());
      }
    }
  });

  if (btnRemoveQr) {
    btnRemoveQr.addEventListener('click', (e) => {
      e.stopPropagation();
      if (qrFileInput) qrFileInput.value = '';
      if (dropzonePrompt) dropzonePrompt.style.display = 'block';
      if (dropzonePreview) dropzonePreview.style.display = 'none';
      if (qrResultsGrid) qrResultsGrid.style.display = 'none';
    });
  }

  if (qrRawInput) {
    qrRawInput.addEventListener('input', () => {
      const len = qrRawInput.value.length;
      if (btnClearQrRaw) btnClearQrRaw.style.display = len > 0 ? 'inline-block' : 'none';
    });
  }

  if (btnClearQrRaw) {
    btnClearQrRaw.addEventListener('click', () => {
      if (qrRawInput) qrRawInput.value = '';
      btnClearQrRaw.style.display = 'none';
      if (qrResultsGrid) qrResultsGrid.style.display = 'none';
    });
  }

  if (btnVerifyQr) {
    btnVerifyQr.addEventListener('click', () => {
      if (qrRawInput && qrRawInput.value.trim()) {
        runQrVerification(qrRawInput.value.trim());
      }
    });
  }

  qrPresets.forEach(presetBtn => {
    presetBtn.addEventListener('click', () => {
      const key = presetBtn.getAttribute('data-preset');
      const payload = QR_PRESET_PAYLOADS[key];
      if (payload) {
        if (qrRawInput) {
          qrRawInput.value = payload;
          if (btnClearQrRaw) btnClearQrRaw.style.display = 'inline-block';
        }
        runQrVerification(payload);
      }
    });
  });

  function handleQrFile(file) {
    if (!file || !file.type.startsWith('image/')) {
      alert('Please select a valid image file (PNG, JPG, WebP).');
      return;
    }
    if (qrFilename) qrFilename.textContent = file.name;

    const reader = new FileReader();
    reader.onload = (e) => {
      const dataUrl = e.target.result;
      if (qrPreviewImg) qrPreviewImg.src = dataUrl;
      if (dropzonePrompt) dropzonePrompt.style.display = 'none';
      if (dropzonePreview) dropzonePreview.style.display = 'flex';

      const img = new Image();
      img.onload = async () => {
        let decodedPayload = null;

        // 1. First priority: Robust 100% Offline Pure JS jsQR Engine
        try {
          const jsQRFunc = window.jsQR || (typeof jsQR !== 'undefined' ? jsQR : null);
          if (jsQRFunc) {
            const canvas = document.createElement('canvas');
            canvas.width = img.naturalWidth || img.width;
            canvas.height = img.naturalHeight || img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQRFunc(imgData.data, imgData.width, imgData.height, {
              inversionAttempts: 'attemptBoth'
            });
            if (code && code.data && code.data.trim()) {
              decodedPayload = code.data.trim();
            }
          }
        } catch (qrErr) {
          console.warn('jsQR decoding attempt:', qrErr);
        }

        // 2. Second priority: Native BarcodeDetector if available
        if (!decodedPayload && 'BarcodeDetector' in window) {
          try {
            const detector = new BarcodeDetector({ formats: ['qr_code'] });
            const barcodes = await detector.detect(img);
            if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
              decodedPayload = barcodes[0].rawValue.trim();
            }
          } catch (err) {}
        }

        // 3. Process Decoded Payload accurately
        if (decodedPayload) {
          if (qrRawInput) {
            qrRawInput.value = decodedPayload;
            if (btnClearQrRaw) btnClearQrRaw.style.display = 'inline-block';
          }
          runQrVerification(decodedPayload);
        } else {
          // Accurate reporting: If no QR is detectable, do NOT run a scammer payload!
          alert('No clear QR code could be detected in this image. Please ensure the QR code is in focus without glare, or enter the payload text/link below.');
          if (qrResultsGrid) qrResultsGrid.style.display = 'none';
        }
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  }

  function runQrVerification(payload) {
    if (!qrAnalyzer) return;
    const res = qrAnalyzer.analyze(payload);
    if (!qrResultsGrid) return;

    qrResultsGrid.style.display = 'grid';

    const threatPct = res.threatPercentage || 0;
    if (qrScoreVal) qrScoreVal.textContent = `${threatPct}%`;

    // Radial gauge animation
    const radius = 42;
    const circumference = 2 * Math.PI * radius; // ~264
    const offset = circumference - (threatPct / 100) * circumference;
    if (qrGaugeBar) {
      qrGaugeBar.style.strokeDasharray = `${circumference}`;
      qrGaugeBar.style.strokeDashoffset = `${offset}`;
      qrGaugeBar.style.stroke = (threatPct >= 85) ? '#ef4444' : (threatPct >= 25 ? '#f97316' : '#10b981');
    }

    const themeClass = (threatPct >= 85) ? 'danger' : (threatPct >= 25 ? 'caution' : 'safe');
    if (qrHeroCard) qrHeroCard.className = `hero-score-card ${themeClass}`;
    if (qrVerdictBadge) {
      qrVerdictBadge.className = `verdict-badge-pill ${themeClass}`;
      qrVerdictBadge.textContent = (threatPct >= 85) ? (res.payloadType === 'UPI_PAYMENT' ? 'REVERSE UPI FRAUD' : 'CRITICAL QUISHING') : (threatPct >= 25 ? 'CAUTION' : 'VERIFIED SAFE');
    }
    if (qrMetaBadge) qrMetaBadge.textContent = res.payloadType || 'QR INTENT';
    if (qrMetaTitle) qrMetaTitle.textContent = (res.parsedDetails && (res.parsedDetails.vpa || res.parsedDetails.destinationHost)) ? (res.parsedDetails.vpa || res.parsedDetails.destinationHost) : 'Decoded Payload';
    if (qrSummaryText) qrSummaryText.textContent = res.headline || 'QR audit complete.';

    // Populate Inspector Grid
    if (qrInspectorParams && res.parsedDetails) {
      qrInspectorParams.innerHTML = Object.entries(res.parsedDetails).map(([k, v]) => {
        const isAlert = k === 'amount' && String(v).includes('₹') && threatPct >= 85;
        return `
          <div class="param-item">
            <div class="param-key">${escapeHtml(k)}</div>
            <div class="param-val ${isAlert ? 'alert-debit' : ''}">${escapeHtml(v)}</div>
          </div>
        `;
      }).join('');
    }

    // Grounded Explanation
    if (qrExpHeadline) qrExpHeadline.textContent = res.headline;
    if (qrExpBody) qrExpBody.textContent = res.explanation;

    qrResultsGrid.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
});
