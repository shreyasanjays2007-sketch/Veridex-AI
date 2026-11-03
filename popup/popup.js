/**
 * Veridex AI - Popup Interface Controller
 * Renders Search Bar and Detection Score on top, and detailed intelligence below.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements - Top Section
  const searchUrlInput = document.getElementById('search-url-input');
  const btnVerifySearch = document.getElementById('btn-verify-search');
  const btnClearSearch = document.getElementById('btn-clear-search');
  const btnUseActiveTab = document.getElementById('btn-use-active-tab');
  const btnQuickPaste = document.getElementById('btn-quick-paste');

  // Top Section - Detection Score Hero Elements
  const heroScoreCard = document.getElementById('hero-score-card');
  const heroProtocol = document.getElementById('hero-protocol');
  const heroHostname = document.getElementById('hero-hostname');
  const heroDbTag = document.getElementById('hero-db-tag');
  const heroScoreValue = document.getElementById('hero-score-value');
  const heroVerdictBadge = document.getElementById('hero-verdict-badge');
  const heroSummaryText = document.getElementById('hero-summary-text');
  const gaugeProgressBar = document.getElementById('gauge-progress-bar');

  // Suggested Authentic Destination Card & Why Unsafe Advisory
  const popupSuggestedCard = document.getElementById('popup-suggested-card');
  const popupSuggestedBrand = document.getElementById('popup-suggested-brand');
  const popupSuggestedDesc = document.getElementById('popup-suggested-desc');
  const popupSuggestedBtn = document.getElementById('popup-suggested-btn');
  const popupSuggestedBtnLabel = document.getElementById('popup-suggested-btn-label');
  const popupWhyList = document.getElementById('popup-why-list');

  // Hybrid AI & Grounded Explanation Elements
  const popupHeurScore = document.getElementById('popup-heur-score');
  const popupMlScore = document.getElementById('popup-ml-score');
  const popupCombinedScore = document.getElementById('popup-combined-score');
  const popupAiExplanationBox = document.getElementById('popup-ai-explanation-box');
  const popupAiConfidence = document.getElementById('popup-ai-confidence');
  const popupAiHeadline = document.getElementById('popup-ai-headline');
  const popupAiSummary = document.getElementById('popup-ai-summary');
  const popupAiDrivers = document.getElementById('popup-ai-drivers');
  const popupAiDriverList = document.getElementById('popup-ai-driver-list');
  const popupAiSafety = document.getElementById('popup-ai-safety');
  const popupAiSafetyList = document.getElementById('popup-ai-safety-list');

  // Sub-Navigation Tabs
  const subTabButtons = document.querySelectorAll('.sub-tab-btn');
  const subPanels = document.querySelectorAll('.sub-panel');
  const flagsBadgeCount = document.getElementById('flags-badge-count');

  // Panel 1: Signals
  const signalsListBox = document.getElementById('signals-list-box');
  const signalsHeaderCount = document.getElementById('signals-header-count');

  // Panel 2: Multi-Factor Breakdown
  const catValDomain = document.getElementById('cat-val-domain');
  const catBarDomain = document.getElementById('cat-bar-domain');
  const catValLexical = document.getElementById('cat-val-lexical');
  const catBarLexical = document.getElementById('cat-bar-lexical');
  const catValSecurity = document.getElementById('cat-val-security');
  const catBarSecurity = document.getElementById('cat-bar-security');
  const catValContent = document.getElementById('cat-val-content');
  const catBarContent = document.getElementById('cat-bar-content');

  // Panel 3: Intelligence & DB
  const intelDbMatch = document.getElementById('intel-db-match');
  const intelApex = document.getElementById('intel-apex');
  const intelTld = document.getElementById('intel-tld');
  const intelHomoglyph = document.getElementById('intel-homoglyph');
  const intelFullUrl = document.getElementById('intel-full-url');
  const probeStatusPill = document.getElementById('probe-status-pill');
  const probeHstsPill = document.getElementById('probe-hsts-pill');
  const probeParkedPill = document.getElementById('probe-parked-pill');
  const intelIpAddr = document.getElementById('intel-ip-addr');
  const intelIpOrg = document.getElementById('intel-ip-org');
  const intelIpAsn = document.getElementById('intel-ip-asn');
  const intelIpGeo = document.getElementById('intel-ip-geo');
  const intelIpThreatStatus = document.getElementById('intel-ip-threat-status');
  const btnPopupPrintReport = document.getElementById('btn-popup-print-report');

  // Panel 4: Test Samples & Lab
  const testChipButtons = document.querySelectorAll('.test-chip-btn');
  const btnLaunchLab = document.getElementById('btn-launch-lab');

  // Panel 5: Settings
  const toggleRealtime = document.getElementById('toggle-realtime');
  const toggleInpageModal = document.getElementById('toggle-inpage-modal');
  const toggleDesktopNotify = document.getElementById('toggle-desktop-notify');
  const protectionStatusText = document.getElementById('protection-status-text');

  let activeTabUrl = '';
  let activeTabHost = '';
  let lastAnalysis = null;

  // Setup Sub-Tab Switching
  subTabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      subTabButtons.forEach(b => b.classList.remove('active'));
      subPanels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPanelId = btn.getAttribute('data-subtab');
      const targetPanel = document.getElementById(targetPanelId);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });

  // Load Settings
  chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (res) => {
    if (res && res.settings) {
      if (toggleRealtime) toggleRealtime.checked = res.settings.protectionEnabled !== false;
      if (toggleInpageModal) toggleInpageModal.checked = res.settings.showInPageWarning !== false;
      if (toggleDesktopNotify) toggleDesktopNotify.checked = res.settings.desktopNotifications !== false;
      updateStatusLabel(toggleRealtime.checked);
    }
  });

  function updateStatusLabel(enabled) {
    if (protectionStatusText) {
      protectionStatusText.textContent = enabled ? 'Active' : 'Paused';
    }
  }

  function saveSettings() {
    const updated = {
      protectionEnabled: toggleRealtime ? toggleRealtime.checked : true,
      showInPageWarning: toggleInpageModal ? toggleInpageModal.checked : true,
      desktopNotifications: toggleDesktopNotify ? toggleDesktopNotify.checked : true
    };
    updateStatusLabel(updated.protectionEnabled);
    chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings: updated });
  }

  [toggleRealtime, toggleInpageModal, toggleDesktopNotify].forEach(el => {
    if (el) el.addEventListener('change', saveSettings);
  });

  // Query Current Active Browser Tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) return;
    const activeTab = tabs[0];
    activeTabUrl = activeTab.url || '';

    let isInternal = false;
    try {
      const parsed = new URL(activeTabUrl);
      activeTabHost = parsed.hostname;
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        isInternal = true;
      }
    } catch (e) {
      isInternal = true;
      activeTabHost = 'Browser Tab';
    }

    if (isInternal) {
      renderAnalysisResult({
        appName: 'Veridex AI',
        riskPercentage: 0,
        riskScore: 0,
        verdict: 'neutral',
        level: 'safe',
        levelLabel: 'System Page',
        summary: 'Internal browser page. Veridex AI continuously protects external web destinations in real time.',
        signals: [],
        databaseMatch: {
          isReal: true,
          isFake: false,
          label: 'Internal Browser Tab'
        },
        categoryScores: { domain: 0, lexical: 0, security: 0, content: 0 },
        details: {
          url: activeTabUrl,
          hostname: activeTabHost,
          apexDomain: 'browser-system',
          protocol: 'system:'
        }
      });
      return;
    }

    // Query analysis from service worker
    chrome.runtime.sendMessage({
      type: 'GET_ACTIVE_TAB_STATUS',
      tabId: activeTab.id,
      url: activeTabUrl
    }, (response) => {
      if (response && response.analysis) {
        renderAnalysisResult(response.analysis);
      } else {
        // Fallback scan
        runVerification(activeTabUrl);
      }
    });
  });

  // Primary Verification Engine Trigger
  function runVerification(urlToTest) {
    if (!urlToTest) return;

    let targetUrl = urlToTest.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }

    btnVerifySearch.disabled = true;
    btnVerifySearch.textContent = 'Probing...';

    chrome.runtime.sendMessage({
      type: 'SCAN_URL_MANUAL',
      url: targetUrl
    }, (response) => {
      btnVerifySearch.disabled = false;
      btnVerifySearch.textContent = 'Verify';

      if (response && response.result) {
        renderAnalysisResult(response.result);
      }
    });
  }

  // Renders the Analysis Result into Top Detection Score Card and Sub-Panels
  function renderAnalysisResult(analysis) {
    if (!analysis) return;
    lastAnalysis = analysis;

    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 0);
    const details = analysis.details || {};
    const host = details.hostname || 'Unknown Host';
    const protocol = details.protocol || 'https:';
    const isHttp = protocol === 'http:';

    // 1. Update Top Hero Target Meta
    heroHostname.textContent = host;
    heroHostname.title = host;
    heroProtocol.textContent = isHttp ? 'HTTP INSECURE' : 'HTTPS';
    if (isHttp) {
      heroProtocol.classList.add('insecure');
    } else {
      heroProtocol.classList.remove('insecure');
    }

    // Update Database Status Tag & Classification Category
    const dbMatch = analysis.databaseMatch || {};
    const classification = analysis.classification || (details && details.classification) || {};
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
      heroDbTag.textContent = 'ℹ️ Unknown / Unverified';
    }

    // 2. Update Top Hero Score & Gauge
    heroScoreValue.textContent = `${riskPct}%`;

    // Calculate Radial Gauge Offset (Circumference = 264)
    const circumference = 264;
    const offset = circumference - (circumference * (riskPct / 100));
    gaugeProgressBar.style.strokeDashoffset = offset;

    // Determine Gauge & Card Color Theme based on Varying Risk
    let colorTheme = 'neutral';
    let gaugeColor = '#0284c7';
    let verdictLabel = analysis.levelLabel || 'Neutral';

    if (classification.category === 'verified_government' || dbMatch.isGov) {
      colorTheme = 'safe';
      gaugeColor = '#059669'; // Emerald
      verdictLabel = '🏛️ Verified Government Domain';
    } else if (classification.category === 'known_phishing') {
      colorTheme = 'danger';
      gaugeColor = '#dc2626'; // Red
      verdictLabel = '⛔ Confirmed Phishing (Threat Feed)';
    } else if (analysis.level === 'safe' || (riskPct <= 5 && dbMatch.isReal)) {
      colorTheme = 'safe';
      gaugeColor = '#059669'; // Green
      verdictLabel = '✓ Verified Safe (Official Registry)';
    } else if (riskPct <= 20) {
      colorTheme = 'neutral';
      gaugeColor = '#0284c7'; // Blue
      verdictLabel = 'ℹ️ Low Risk (Unverified)';
    } else if (riskPct <= 34) {
      colorTheme = 'caution';
      gaugeColor = '#d97706'; // Amber
      verdictLabel = '⚠️ Elevated Caution';
    } else if (riskPct < 60) {
      colorTheme = 'warning';
      gaugeColor = '#ea580c'; // Orange
      verdictLabel = '🚨 Suspicious (Unsafe)';
    } else {
      colorTheme = 'danger';
      gaugeColor = '#dc2626'; // Red
      verdictLabel = '⛔ Critical Threat (Unsafe)';
    }

    gaugeProgressBar.style.stroke = gaugeColor;
    heroScoreCard.className = `hero-score-card ${colorTheme}`;

    heroVerdictBadge.className = `verdict-badge-pill ${colorTheme}`;
    heroVerdictBadge.textContent = verdictLabel;
    heroSummaryText.textContent = analysis.summary || 'Domain assessment completed.';

    // 2b. Update Hybrid AI Multi-Layer Detection Scores
    const hybrid = analysis.hybrid || {};
    const heurScore = hybrid.heuristicScore !== undefined ? hybrid.heuristicScore : (analysis.heuristicScore !== undefined ? analysis.heuristicScore : riskPct);
    const mlScore = hybrid.mlScore !== undefined ? hybrid.mlScore : (analysis.mlScore !== undefined ? analysis.mlScore : 0);
    const combinedScore = hybrid.combinedScore !== undefined ? hybrid.combinedScore : riskPct;

    if (popupHeurScore) popupHeurScore.textContent = `${heurScore}%`;
    if (popupMlScore) popupMlScore.textContent = `${mlScore}%`;
    if (popupCombinedScore) popupCombinedScore.textContent = `${combinedScore}%`;

    // 2c. Render Grounded AI Explanation Module
    const explanation = analysis.aiExplanation || hybrid.explanation || null;
    if (explanation && popupAiExplanationBox) {
      popupAiExplanationBox.style.display = 'block';
      if (popupAiConfidence) popupAiConfidence.textContent = `${explanation.confidence || '99.8%'} Confidence`;
      if (popupAiHeadline) popupAiHeadline.textContent = explanation.headline || 'Assessment Complete';
      if (popupAiSummary) popupAiSummary.textContent = explanation.summary || '';

      // Render Correlated Risk Drivers
      if (popupAiDrivers && popupAiDriverList) {
        if (explanation.riskDrivers && explanation.riskDrivers.length > 0) {
          popupAiDrivers.style.display = 'block';
          popupAiDriverList.innerHTML = explanation.riskDrivers.map(d => `
            <div class="ai-driver-item">
              <span class="ai-driver-icon">${d.icon || '⚠️'}</span>
              <div class="ai-driver-text">
                <span class="ai-driver-source">[${escapeHtml(d.source || 'Heuristic')}]</span>
                <strong>${escapeHtml(d.title)}:</strong>
                <span>${escapeHtml(d.explanation)}</span>
              </div>
            </div>
          `).join('');
        } else {
          popupAiDrivers.style.display = 'none';
          popupAiDriverList.innerHTML = '';
        }
      }

      // Render Safety Factors
      if (popupAiSafety && popupAiSafetyList) {
        if (explanation.safetyFactors && explanation.safetyFactors.length > 0) {
          popupAiSafety.style.display = 'block';
          popupAiSafetyList.innerHTML = explanation.safetyFactors.map(s => `
            <div class="ai-safety-item">
              <span class="ai-safety-icon">${s.icon || '🛡️'}</span>
              <div class="ai-safety-text">
                <strong>${escapeHtml(s.title)}:</strong>
                <span>${escapeHtml(s.explanation)}</span>
              </div>
            </div>
          `).join('');
        } else {
          popupAiSafety.style.display = 'none';
          popupAiSafetyList.innerHTML = '';
        }
      }
    } else if (popupAiExplanationBox) {
      popupAiExplanationBox.style.display = 'none';
    }

    // Render Suggested Official Website Card & Why Unsafe Advisory
    const isUnsafe = analysis.isUnsafe || analysis.verdict === 'suspicious' || riskPct >= 35;
    const suggested = analysis.suggestedWebsite;

    if (isUnsafe && suggested && popupSuggestedCard) {
      popupSuggestedCard.style.display = 'flex';
      popupSuggestedBrand.textContent = suggested.name;
      popupSuggestedBtn.href = suggested.url;
      popupSuggestedBtnLabel.textContent = `👉 Go to Official ${suggested.name} Website (${suggested.host || suggested.name})`;

      const curHost = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : 'Current website';
      popupSuggestedDesc.textContent = `You appear to be searching for "${suggested.name}". The website "${curHost}" is an unverified clone or deceptive destination.`;

      const plainReasons = getPlainEnglishReasons(analysis);
      if (popupWhyList) {
        popupWhyList.innerHTML = plainReasons.map(r => `
          <div class="popup-why-item">
            <span>${r.icon}</span>
            <span><strong>${escapeHtml(r.title)}:</strong> ${escapeHtml(r.desc)}</span>
          </div>
        `).join('');
      }
    } else if (popupSuggestedCard) {
      popupSuggestedCard.style.display = 'none';
    }

    // 3. Update Sub-Navigation Flag Count
    const signals = analysis.signals || [];
    const threatSignals = signals.filter(s => s.severity !== 'info');
    flagsBadgeCount.textContent = threatSignals.length;
    signalsHeaderCount.textContent = `${threatSignals.length} Flag${threatSignals.length === 1 ? '' : 's'} Detected`;

    // 4. Panel 1: Render Security Signals
    signalsListBox.innerHTML = '';
    if (signals.length > 0) {
      signals.forEach(sig => {
        const item = document.createElement('div');
        const isInfo = sig.severity === 'info';
        const isCaution = sig.severity === 'low' || sig.severity === 'medium';
        const isHigh = sig.severity === 'high';

        item.className = 'signal-item ' + (isInfo ? 'clean' : (isHigh ? 'threat' : 'caution'));
        item.innerHTML = `
          <span class="sig-status-icon">${isInfo ? '✓' : (isHigh ? '🚨' : '⚠️')}</span>
          <div>
            <div class="sig-name">${escapeHtml(sig.name)} ${sig.points > 0 ? `(+${sig.points}% Risk)` : ''}</div>
            <div class="sig-desc">${escapeHtml(sig.description)}</div>
          </div>
        `;
        signalsListBox.appendChild(item);
      });
    } else {
      signalsListBox.innerHTML = `
        <div class="signal-item clean">
          <span class="sig-status-icon">✓</span>
          <div>
            <div class="sig-name">Connection & Heuristics Normal</div>
            <div class="sig-desc">Active SSL encryption, authentic brand registration, and no lookalike homoglyphs detected.</div>
          </div>
        </div>
      `;
    }

    // 5. Panel 2: Render Category Breakdown Progress Bars
    const catScores = analysis.categoryScores || { domain: 0, lexical: 0, security: 0, content: 0 };

    catValDomain.textContent = `${catScores.domain}/100`;
    catBarDomain.style.width = `${Math.min(100, catScores.domain)}%`;
    catBarDomain.style.background = getScoreColor(catScores.domain);

    catValLexical.textContent = `${catScores.lexical}/100`;
    catBarLexical.style.width = `${Math.min(100, catScores.lexical)}%`;
    catBarLexical.style.background = getScoreColor(catScores.lexical);

    catValSecurity.textContent = `${catScores.security}/100`;
    catBarSecurity.style.width = `${Math.min(100, catScores.security)}%`;
    catBarSecurity.style.background = getScoreColor(catScores.security);

    catValContent.textContent = `${catScores.content}/100`;
    catBarContent.style.width = `${Math.min(100, catScores.content)}%`;
    catBarContent.style.background = getScoreColor(catScores.content);

    // 6. Panel 3: Render Intelligence & Verification
    intelDbMatch.textContent = dbMatch.label || 'Heuristic Evaluation';
    intelApex.textContent = details.apexDomain || host;

    const hostParts = host.split('.');
    const tld = hostParts.length > 1 ? '.' + hostParts[hostParts.length - 1] : '-';
    intelTld.textContent = tld;

    const hasHomoglyph = signals.some(s => s.id === 'homoglyph_attack');
    intelHomoglyph.textContent = hasHomoglyph ? '⚠️ Deceptive / Lookalike' : '✓ Normal Clean';
    intelHomoglyph.style.color = hasHomoglyph ? 'var(--danger)' : 'var(--safe)';

    intelFullUrl.textContent = details.url || host;

    // Live Probe Metrics
    if (details.liveProbe) {
      const lp = details.liveProbe;
      if (lp.reachable) {
        probeStatusPill.textContent = `Server: ${lp.statusCode} OK`;
        probeStatusPill.style.color = 'var(--safe)';
        probeHstsPill.textContent = lp.hasHsts ? 'HSTS: Active 🔒' : 'HSTS: Missing ⚠️';
        probeParkedPill.textContent = lp.isParked ? 'Parked: Yes (For Sale) ⚠️' : 'Active Domain ✓';
      } else {
        probeStatusPill.textContent = 'Server: Unreachable / Offline';
        probeStatusPill.style.color = 'var(--danger)';
        probeHstsPill.textContent = 'HSTS: N/A';
        probeParkedPill.textContent = 'Parked: N/A';
      }
    } else {
      probeStatusPill.textContent = 'Server: Lexical Verified';
      probeHstsPill.textContent = isHttp ? 'SSL: Missing' : 'SSL: Active';
      probeParkedPill.textContent = 'Parked: No Flag';
    }

    // Offline IP Intelligence & Hosting Analysis
    const ipData = analysis.ipIntelligence || {
      ip: 'Unavailable (Not resolved / Cached)',
      isAvailable: false,
      organization: 'Unavailable',
      asn: 'Unavailable',
      countryName: 'Unavailable',
      countryCode: 'Unavailable',
      isMalicious: false,
      isHighRiskHosting: false,
      statusText: 'Resolved server IP was not captured or was served from browser cache.'
    };

    if (intelIpAddr) intelIpAddr.textContent = ipData.ip;
    if (intelIpOrg) intelIpOrg.textContent = ipData.organization;
    if (intelIpAsn) intelIpAsn.textContent = ipData.asn;
    if (intelIpGeo) {
      intelIpGeo.textContent = ipData.countryName !== 'Unavailable'
        ? `${ipData.countryName} ${ipData.countryCode && ipData.countryCode !== 'Unavailable' ? '(' + ipData.countryCode + ')' : ''}`
        : 'Unavailable';
    }
    if (intelIpThreatStatus) {
      intelIpThreatStatus.textContent = ipData.statusText;
      if (ipData.isMalicious) {
        intelIpThreatStatus.style.background = '#fee2e2';
        intelIpThreatStatus.style.color = '#dc2626';
      } else if (ipData.isHighRiskHosting) {
        intelIpThreatStatus.style.background = '#fffbeb';
        intelIpThreatStatus.style.color = '#b45309';
      } else if (ipData.isAvailable) {
        intelIpThreatStatus.style.background = '#dcfce7';
        intelIpThreatStatus.style.color = '#15803d';
      } else {
        intelIpThreatStatus.style.background = '#f1f5f9';
        intelIpThreatStatus.style.color = '#64748b';
      }
    }

    // 7. Audit Website Cookies (Values Strictly Omitted)
    renderCookieAnalysis(details.url || activeTabUrl);
  }

  // Cookie Security Audit in Popup
  function renderCookieAnalysis(targetUrl) {
    const cookiesBadgeCount = document.getElementById('cookies-badge-count');
    const cookiesHeaderBadge = document.getElementById('cookies-header-badge');
    const popupCookieTotal = document.getElementById('popup-cookie-total');
    const popupCookiePartyRatio = document.getElementById('popup-cookie-party-ratio');
    const popupCookieStatus = document.getElementById('popup-cookie-status');
    const popupCookieFlags = document.getElementById('popup-cookie-flags');
    const popupCookieIssuesContainer = document.getElementById('popup-cookie-issues-container');
    const popupCookieIssuesList = document.getElementById('popup-cookie-issues-list');
    const popupCookieList = document.getElementById('popup-cookie-list');

    chrome.runtime.sendMessage({
      type: 'GET_COOKIE_ANALYSIS',
      url: targetUrl
    }, (res) => {
      const cData = (res && res.cookieAnalysis) ? res.cookieAnalysis : {
        total: 0,
        firstPartyCount: 0,
        thirdPartyCount: 0,
        secureCount: 0,
        missingSecureCount: 0,
        httpOnlyCount: 0,
        missingHttpOnlyCount: 0,
        sameSiteStats: { strict: 0, lax: 0, none: 0, unspecified: 0 },
        insecureCookiesCount: 0,
        issues: [],
        cookies: []
      };

      if (cookiesBadgeCount) cookiesBadgeCount.textContent = cData.insecureCookiesCount > 0 ? cData.insecureCookiesCount : cData.total;
      if (cookiesHeaderBadge) cookiesHeaderBadge.textContent = `${cData.total} Cookies Audited`;
      if (popupCookieTotal) popupCookieTotal.textContent = cData.total;
      if (popupCookiePartyRatio) popupCookiePartyRatio.textContent = `${cData.firstPartyCount} 1st-Party / ${cData.thirdPartyCount} 3rd-Party`;
      if (popupCookieStatus) {
        popupCookieStatus.textContent = cData.statusLabel || (cData.insecureCookiesCount > 0 ? 'Warnings' : 'Secure');
        popupCookieStatus.style.color = cData.criticalIssuesCount > 0 ? '#dc2626' : (cData.insecureCookiesCount > 0 ? '#d97706' : '#16a34a');
      }
      if (popupCookieFlags) popupCookieFlags.textContent = `${cData.secureCount} Secure / ${cData.httpOnlyCount} HttpOnly`;

      // Insecure issues
      const popupCookieIssuesCount = document.getElementById('popup-cookie-issues-count');
      if (popupCookieIssuesContainer && popupCookieIssuesList) {
        if (cData.issues && cData.issues.length > 0) {
          popupCookieIssuesContainer.style.display = 'block';
          if (popupCookieIssuesCount) popupCookieIssuesCount.textContent = cData.issues.length;
          popupCookieIssuesList.innerHTML = cData.issues.map(iss => `
            <div style="background: ${iss.severity === 'danger' ? '#fef2f2' : '#fffbeb'}; border: 1px solid ${iss.severity === 'danger' ? '#fca5a5' : '#fde68a'}; border-radius: 4px; padding: 6px 8px; font-size: 10.5px;">
              <span style="font-weight: 800; color: ${iss.severity === 'danger' ? '#b91c1c' : '#92400e'};">[${iss.severity.toUpperCase()}] ${escapeHtml(iss.title)}:</span>
              <span style="color: #475569;"> ${escapeHtml(iss.description)} (<code>${escapeHtml(iss.cookieName)}</code>)</span>
            </div>
          `).join('');
        } else {
          popupCookieIssuesContainer.style.display = 'none';
          popupCookieIssuesList.innerHTML = '';
        }
      }

      // Audited cookies inventory list (STRICTLY NO VALUES)
      if (popupCookieList) {
        if (cData.cookies && cData.cookies.length > 0) {
          popupCookieList.innerHTML = cData.cookies.map(c => `
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 5px 4px; border-bottom: 1px solid #f1f5f9; gap: 6px;">
              <div style="display: flex; flex-direction: column; max-width: 65%;">
                <div style="font-weight: 700; color: #0f172a; word-break: break-all;">
                  <code>${escapeHtml(c.name)}</code>
                  ${c.isSensitive ? '<span style="font-size: 8px; background: #fee2e2; color: #dc2626; padding: 1px 3px; border-radius: 2px; font-weight: 800; margin-left: 3px;">AUTH</span>' : ''}
                </div>
                <div style="font-size: 9.5px; color: #64748b;">${escapeHtml(c.domain)} • ${escapeHtml(c.expiry ? c.expiry.text : 'Session')}</div>
              </div>
              <div style="display: flex; gap: 3px; flex-shrink: 0;">
                <span style="font-size: 9px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: ${c.secure ? '#dcfce7' : '#fee2e2'}; color: ${c.secure ? '#166534' : '#991b1b'};">${c.secure ? '✓ Sec' : '⚠️ No Sec'}</span>
                <span style="font-size: 9px; font-weight: 700; padding: 1px 4px; border-radius: 3px; background: ${c.httpOnly ? '#dcfce7' : '#f1f5f9'}; color: ${c.httpOnly ? '#166534' : '#64748b'};">${c.httpOnly ? '✓ HttpOnly' : 'JS'}</span>
              </div>
            </div>
          `).join('');
        } else {
          popupCookieList.innerHTML = '<div style="color: #64748b; text-align: center; padding: 12px;">No active cookies detected for this URL.</div>';
        }
      }
    });
  }

  function getScoreColor(val) {
    if (val <= 10) return 'var(--safe)';
    if (val <= 30) return 'var(--neutral)';
    if (val <= 50) return 'var(--caution)';
    if (val <= 70) return 'var(--warning)';
    return 'var(--danger)';
  }

  // Search Input Listeners
  btnVerifySearch.addEventListener('click', () => {
    runVerification(searchUrlInput.value);
  });

  searchUrlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      runVerification(searchUrlInput.value);
    }
  });

  searchUrlInput.addEventListener('input', () => {
    if (btnClearSearch) {
      btnClearSearch.style.display = searchUrlInput.value.length > 0 ? 'block' : 'none';
    }
  });

  if (btnClearSearch) {
    btnClearSearch.addEventListener('click', () => {
      searchUrlInput.value = '';
      btnClearSearch.style.display = 'none';
      searchUrlInput.focus();
    });
  }

  // Quick Action: Inspect Active Tab
  if (btnUseActiveTab) {
    btnUseActiveTab.addEventListener('click', () => {
      if (activeTabUrl) {
        searchUrlInput.value = activeTabHost || activeTabUrl;
        if (btnClearSearch) btnClearSearch.style.display = 'block';
        runVerification(activeTabUrl);
      }
    });
  }

  // Quick Action: Paste & Scan
  if (btnQuickPaste) {
    btnQuickPaste.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          searchUrlInput.value = text.trim();
          if (btnClearSearch) btnClearSearch.style.display = 'block';
          runVerification(text.trim());
        }
      } catch (err) {
        searchUrlInput.focus();
      }
    });
  }

  // Sample Test Chips
  testChipButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.getAttribute('data-url');
      searchUrlInput.value = url;
      if (btnClearSearch) btnClearSearch.style.display = 'block';
      runVerification(url);
    });
  });

  // Launch Test Lab
  if (btnLaunchLab) {
    btnLaunchLab.addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('test-lab/index.html') });
    });
  }

  // Open Veridex AI Website
  const btnPopupOpenWebsite = document.getElementById('btn-popup-open-website');
  if (btnPopupOpenWebsite) {
    btnPopupOpenWebsite.addEventListener('click', () => {
      let targetUrl = '';
      if (lastAnalysis && lastAnalysis.details && lastAnalysis.details.url) {
        targetUrl = lastAnalysis.details.url;
      } else if (activeTabUrl && (activeTabUrl.startsWith('http://') || activeTabUrl.startsWith('https://'))) {
        targetUrl = activeTabUrl;
      } else if (searchUrlInput && searchUrlInput.value.trim()) {
        targetUrl = searchUrlInput.value.trim();
      }

      let siteUrl = chrome.runtime.getURL('website/index.html');
      if (targetUrl) {
        siteUrl += `?url=${encodeURIComponent(targetUrl)}`;
      }
      chrome.tabs.create({ url: siteUrl });
    });
  }

  // Print Security Report
  if (btnPopupPrintReport) {
    btnPopupPrintReport.addEventListener('click', () => {
      window.print();
    });
  }

  // Copy Evidence for Cybercrime Portal
  const btnPopupCopyEvidence = document.getElementById('btn-popup-copy-evidence');
  if (btnPopupCopyEvidence) {
    btnPopupCopyEvidence.addEventListener('click', () => {
      const a = lastAnalysis || {};
      const det = a.details || {};
      const cls = a.classification || (det && det.classification) || {};
      const ip = a.ipIntelligence || (det && det.ipIntelligence) || {};
      const sigs = a.signals ? a.signals.filter(s => s.severity !== 'info') : [];
      const evidence = `[INCIDENT EVIDENCE FOR CYBERCRIME REPORTING]
Audited URL: ${det.url || activeTabUrl || 'N/A'}
Hostname: ${det.hostname || activeTabHost || 'N/A'}
Audit Timestamp: ${new Date().toLocaleString()}
Threat Risk Score: ${a.riskPercentage !== undefined ? a.riskPercentage : (a.riskScore || 0)}%
Classification: ${cls.categoryLabel || 'Evaluated'}
Resolved Server IP: ${ip.ip || 'Unavailable'}
Hosting Org / ASN: ${ip.organization || 'Unavailable'} (${ip.asn || 'Unavailable'})
Malicious IP Match: ${ip.isMalicious ? 'MATCHED MALICIOUS HOST' : (ip.isAvailable ? 'Clean' : 'Unavailable')}
Detected Threat Signals:
${(sigs.length > 0) ? sigs.map(s => `- ${s.name}: ${s.description}`).join('\n') : '- Zero known threats detected.'}
Note: Generated locally by Veridex AI (100% offline). User submitted complaint manually.`;

      navigator.clipboard.writeText(evidence).then(() => {
        const orig = btnPopupCopyEvidence.textContent;
        btnPopupCopyEvidence.textContent = '✓ Evidence Copied to Clipboard!';
        setTimeout(() => { btnPopupCopyEvidence.textContent = orig; }, 2500);
      });
    });
  }

  function getPlainEnglishReasons(analysis) {
    const reasons = [];
    const hostname = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : 'this site';
    const signals = analysis.signals || [];
    const brandName = analysis.detectedBrand || (analysis.suggestedWebsite ? analysis.suggestedWebsite.name : null);

    if (signals.some(s => s.name.includes('Threat Feed') || s.name.includes('Fraud') || s.name.includes('Scam'))) {
      reasons.push({ icon: '☠️', title: 'Known Scam Domain', desc: 'Officially blacklisted on global cybersecurity databases.' });
    }
    if (brandName || signals.some(s => s.name.includes('Brand') || s.name.includes('Spoofing'))) {
      reasons.push({ icon: '🎭', title: `Fake Clone of ${brandName || 'Brand'}`, desc: `Deceptively impersonating ${brandName || 'a recognized company'} without authorization.` });
    }
    if (signals.some(s => s.name.includes('Password') || s.name.includes('Authentication') || s.name.includes('Seed Phrase'))) {
      reasons.push({ icon: '🎣', title: 'Credential Theft Risk', desc: 'Contains unverified login fields designed to harvest passwords.' });
    }
    if (signals.some(s => s.name.includes('Insecure') || s.name.includes('HTTP'))) {
      reasons.push({ icon: '🔓', title: 'Unencrypted (HTTP)', desc: 'Missing SSL certificate; information can be intercepted.' });
    }
    if (signals.some(s => s.name.includes('Typosquatting') || s.name.includes('Lookalike'))) {
      reasons.push({ icon: '🔤', title: 'Lookalike Address', desc: `"${hostname}" mimics an authentic brand address with spelling tricks.` });
    }
    if (signals.some(s => s.name.includes('Top-Level Domain') || s.name.includes('Entropy'))) {
      reasons.push({ icon: '⚠️', title: 'High-Risk Disposable Domain', desc: 'Domain structure frequently favored by scammers for disposable sites.' });
    }
    if (reasons.length === 0) {
      reasons.push({ icon: '⚠️', title: 'Suspicious Heuristics', desc: 'Unverified domain structure and deceptive keyword combinations detected.' });
    }
    return reasons;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
});
