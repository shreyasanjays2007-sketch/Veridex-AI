/**
 * Veridex AI - In-Page Warning Modal, Floating Pin & Interactive Security Report
 * 
 * 1. VeridexWarningModal:
 *    - Automatic warning popup for detected fake or malicious websites.
 *    - Preserved exactly as before: side-by-side comparison, plain-English reasons,
 *      suggested authentic website alternative, return and continue anyway options.
 * 
 * 2. VeridexFloatingBadge (Floating Pin Redesign):
 *    - Compact circular indicator (38px diameter).
 *    - Displays ONLY the Veridex logo inside.
 *    - Green circle: Safe / No threats detected.
 *    - Red circle: Suspicious or malicious website detected.
 *    - Completely unobtrusive; does not obstruct website content.
 *    - Movable / draggable anywhere across the screen.
 * 
 * 3. VeridexSecurityReport (Interactive Security Report):
 *    - Opens when the user clicks the floating pin.
 *    - Full security report including URL risk score, behaviour analysis,
 *      offline IP intelligence & hosting risk, and detected threat signals.
 *    - Honest display of unavailable info (no fake estimates).
 *    - Full printable report functionality (window.print & structured copy).
 */

class VeridexWarningModal {
  constructor() {
    this.overlayId = 'veridex-warning-overlay';
  }

  /**
   * Displays the security warning popup over the current webpage
   * @param {Object} analysis - The Veridex analysis result object
   */
  show(analysis) {
    if (!analysis) return;
    // If already showing, shake to draw attention
    const existing = document.getElementById(this.overlayId);
    if (existing) {
      const card = existing.querySelector('#veridex-modal-card');
      if (card) {
        card.classList.add('veridex-shake');
        setTimeout(() => card.classList.remove('veridex-shake'), 600);
      }
      return;
    }

    const isDanger = analysis.level === 'danger';
    const cardClass = isDanger ? 'danger-level' : 'warning-level';
    const iconSymbol = isDanger ? '🚨' : '⚠️';
    const statusLabel = isDanger ? 'Critical Threat (Unsafe)' : 'Suspicious Website (Unsafe)';
    const hostname = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : window.location.hostname;
    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 85);

    // Suggested Authentic Destination
    const suggested = analysis.suggestedWebsite || {
      name: 'National Cyber Crime Reporting Portal',
      url: 'https://cybercrime.gov.in',
      host: 'cybercrime.gov.in'
    };

    // Plain English Reasons for why this site is NOT safe
    const plainReasons = this._getPlainEnglishReasons(analysis);
    const reasonsHtml = plainReasons.map(r => `
      <div class="veridex-reason-item">
        <div class="veridex-reason-icon">${r.icon}</div>
        <div class="veridex-reason-content">
          <div class="veridex-reason-title">${this._escapeHtml(r.title)}</div>
          <div class="veridex-reason-desc">${this._escapeHtml(r.desc)}</div>
        </div>
      </div>
    `).join('');

    // Suggested explanation
    const suggestedExplanation = this._getSuggestedExplanation(analysis, suggested);

    const overlay = document.createElement('div');
    overlay.id = this.overlayId;

    overlay.innerHTML = `
      <div id="veridex-modal-card" class="${cardClass}" role="alertdialog" aria-modal="true">
        <!-- TOP HEADER -->
        <div class="veridex-header-row">
          <div class="veridex-alert-icon">${iconSymbol}</div>
          <div class="veridex-header-text">
            <span class="veridex-brand-badge">⚡ Veridex AI Cyber Defense</span>
            <h2 class="veridex-title">Unsafe Website Detected</h2>
            <div class="veridex-subtitle">Veridex AI blocked access to a dangerous or deceptive webpage.</div>
          </div>
        </div>

        <!-- RISK SCORE BANNER -->
        <div class="veridex-risk-meter">
          <div class="veridex-score-display">
            <span class="veridex-score-number">${riskPct}%</span>
            <div class="veridex-score-labels">
              <span class="veridex-score-title">Calculated Risk Score</span>
              <span class="veridex-score-label">${statusLabel}</span>
            </div>
          </div>
          <div class="veridex-meter-tag">High-Risk Destination</div>
        </div>

        <!-- VISUAL SIDE-BY-SIDE COMPARISON -->
        <div class="veridex-comparison-box">
          <div class="veridex-compare-col unsafe">
            <div class="veridex-compare-tag">❌ Website You Reached (Unsafe)</div>
            <div class="veridex-compare-host" title="${this._escapeHtml(hostname)}">${this._escapeHtml(hostname)}</div>
            <div class="veridex-compare-status">🚫 Imposter / Threat Detected</div>
          </div>
          <div class="veridex-compare-arrow">➔</div>
          <div class="veridex-compare-col safe">
            <div class="veridex-compare-tag">✅ Suggested Authentic Destination</div>
            <div class="veridex-compare-host" title="${this._escapeHtml(suggested.url)}">${this._escapeHtml(suggested.name)} (${this._escapeHtml(suggested.host || 'Official')})</div>
            <div class="veridex-compare-status">🛡️ Verified Legitimate Entity</div>
          </div>
        </div>

        <!-- SECTION 1: WHY THE SEARCHED SITE IS NOT SAFE -->
        <div class="veridex-section-container danger-box">
          <div class="veridex-section-header">
            <span>🔍 Why the site you searched for (${this._escapeHtml(hostname)}) is NOT safe:</span>
          </div>
          <div class="veridex-reasons-list">
            ${reasonsHtml}
          </div>
        </div>

        <!-- SECTION 2: WHICH MIGHT BE THE SUGGESTED WEBSITE AND WHY -->
        <div class="veridex-section-container suggested-box">
          <div class="veridex-suggested-header">
            <span class="veridex-suggested-pill">🛡️ Suggested Authentic Website</span>
            <span class="veridex-verified-tag">✓ Official Registry Verified</span>
          </div>
          <div class="veridex-suggested-body">
            <div class="veridex-suggested-name">${this._escapeHtml(suggested.name)}</div>
            <div class="veridex-suggested-url-bar">${this._escapeHtml(suggested.url)}</div>
            
            <div class="veridex-suggested-explanation">
              <p class="veridex-which-text">${suggestedExplanation.whichText}</p>
              <p class="veridex-why-text">${suggestedExplanation.whyText}</p>
            </div>

            <!-- PRIMARY SUGGESTED BUTTON -->
            <button id="veridex-btn-suggested" class="veridex-btn-suggested">
              <span>${suggestedExplanation.buttonLabel}</span>
            </button>
          </div>
        </div>

        <!-- ACTIONS ROW -->
        <div class="veridex-actions-container">
          <div class="veridex-buttons-row">
            <!-- OPTION 2: CONTINUE ANYWAY -->
            <button id="veridex-btn-bypass" class="veridex-btn-continue-anyway" title="Ignore warning and open this website">
              <span>⚠️ Continue to this unsafe site anyway</span>
            </button>
            <!-- OPTION 3: RETURN TO SAFETY -->
            <button id="veridex-btn-back" class="veridex-btn-back">
              <span>← Return to Safety</span>
            </button>
          </div>
          
          <div class="veridex-footer-row">
            <div class="veridex-footer-actions">
              <button id="veridex-btn-print" class="veridex-btn-secondary" title="Print this security warning">
                🖨️ Print Warning
              </button>
              <button id="veridex-btn-details" class="veridex-btn-secondary">
                📋 Copy Risk Report
              </button>
              <a href="https://cybercrime.gov.in/" target="_blank" rel="noopener noreferrer" class="veridex-btn-secondary veridex-cyber-link" id="veridex-btn-report-cyber" title="Report to National Cyber Crime Reporting Portal (Helpline 1930)">
                🏛️ Report Cybercrime (1930)
              </a>
              <button id="veridex-btn-open-website" class="veridex-btn-secondary" title="Open Veridex AI Web Verification Portal">
                🌐 Veridex AI Website
              </button>
            </div>
            <span class="veridex-secure-note">🔒 On-Device AI • 100% Offline Processing</span>
          </div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    // Event Listener 1: Continue to Suggested Correct Website
    const btnSuggested = document.getElementById('veridex-btn-suggested');
    if (btnSuggested) {
      btnSuggested.addEventListener('click', () => {
        window.location.href = suggested.url;
      });
    }

    // Event Listener 2: Continue anyway (Unsafe)
    const btnBypass = document.getElementById('veridex-btn-bypass');
    if (btnBypass) {
      btnBypass.addEventListener('click', () => {
        chrome.runtime.sendMessage({
          type: 'WHITELIST_SESSION_DOMAIN',
          hostname: hostname
        });
        overlay.remove();
      });
    }

    // Event Listener 3: Take Me Back to Safety
    const btnBack = document.getElementById('veridex-btn-back');
    if (btnBack) {
      btnBack.addEventListener('click', () => {
        this.goBackToSafety();
      });
    }

    // Print Warning Report
    const btnPrint = document.getElementById('veridex-btn-print');
    if (btnPrint) {
      btnPrint.addEventListener('click', () => {
        window.print();
      });
    }

    // Copy Risk Report
    const btnDetails = document.getElementById('veridex-btn-details');
    if (btnDetails) {
      btnDetails.addEventListener('click', (e) => {
        const reportText = `[Veridex AI Threat Alert]\nDestination: ${window.location.href}\nRisk Score: ${riskPct}%\nThreat Level: ${statusLabel}\nSuggested Official Destination: ${suggested.url} (${suggested.name})\nWhy Unsafe:\n` +
          plainReasons.map(r => `• ${r.title}: ${r.desc}`).join('\n');
        navigator.clipboard.writeText(reportText).then(() => {
          e.target.innerText = '✓ Copied to Clipboard!';
          setTimeout(() => { e.target.innerText = '📋 Copy Risk Report'; }, 2000);
        });
      });
    }

    // Event Listener 5: Open Veridex AI Website
    const btnOpenWebModal = document.getElementById('veridex-btn-open-website');
    if (btnOpenWebModal) {
      btnOpenWebModal.addEventListener('click', () => {
        const currentUrl = (this.currentAnalysis && this.currentAnalysis.details && this.currentAnalysis.details.url)
          || window.location.href;
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'OPEN_WEBSITE', url: currentUrl });
        } else if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
          const siteUrl = chrome.runtime.getURL(`website/index.html?url=${encodeURIComponent(currentUrl)}`);
          window.open(siteUrl, '_blank');
        }
      });
    }
  }

  /**
   * Translates technical signals into understandable, plain-English explanations
   */
  _getPlainEnglishReasons(analysis) {
    const reasons = [];
    const hostname = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : window.location.hostname;
    const signals = analysis.signals || [];
    const brandName = analysis.detectedBrand || (analysis.suggestedWebsite ? analysis.suggestedWebsite.name : null);

    // 1. Confirmed Threat Database / Scam Domain
    if (signals.some(s => s.name.includes('Threat Feed') || s.name.includes('Fraud') || s.name.includes('Scam'))) {
      reasons.push({
        icon: '☠️',
        title: 'Documented Scam / Malicious Website',
        desc: `This exact web address ("${hostname}") is flagged on active global cybersecurity watchlists for fraud, fake promotions, or credential theft.`
      });
    }

    // 2. Malicious Server IP Match
    if (signals.some(s => s.id === 'malicious_ip_threat_match' || s.name.includes('Malicious Host IP'))) {
      const ip = analysis.ipIntelligence ? analysis.ipIntelligence.ip : 'remote host';
      reasons.push({
        icon: '🚨',
        title: 'Malicious Server IP Match',
        desc: `The server IP address (${ip}) matches verified phishing infrastructure, botnet C2, or credential theft servers in the offline database.`
      });
    }

    // 3. Brand Impersonation / Fake Clone
    if (brandName || signals.some(s => s.name.includes('Brand') || s.name.includes('Spoofing'))) {
      const targetBrand = brandName || 'a recognized company';
      reasons.push({
        icon: '🎭',
        title: `Deceptive Impersonation of ${targetBrand}`,
        desc: `This website is deceptively copying the name and branding of ${targetBrand}, but it is registered to an unknown third party and is NOT genuine.`
      });
    }

    // 4. Credential or Password Harvesting
    if (signals.some(s => s.name.includes('Password') || s.name.includes('Authentication') || s.name.includes('Seed Phrase'))) {
      reasons.push({
        icon: '🎣',
        title: 'Phishing for Passwords & Personal Details',
        desc: 'This site contains login or password entry boxes on an unverified domain. Any username, password, or credit card entered here will be stolen.'
      });
    }

    // 5. Insecure HTTP Connection
    if (signals.some(s => s.name.includes('Insecure') || s.name.includes('HTTP'))) {
      reasons.push({
        icon: '🔓',
        title: 'Insecure & Unencrypted Connection',
        desc: 'This webpage is missing basic SSL encryption (plain HTTP). Your connection is unprotected, meaning anyone on your network can intercept what you type.'
      });
    }

    // 6. Lookalike / Typosquatted Domain
    if (signals.some(s => s.name.includes('Typosquatting') || s.name.includes('Lookalike') || s.name.includes('Homoglyph'))) {
      reasons.push({
        icon: '🔤',
        title: 'Deceptive Lookalike Web Address',
        desc: `The address "${hostname}" uses intentional spelling tricks (replacing or omitting letters) to mislead you into thinking it is a legitimate site.`
      });
    }

    // 7. High-Risk Extension (.xyz, .top, bulletproof host)
    if (signals.some(s => s.name.includes('Top-Level Domain') || s.name.includes('Entropy') || s.name.includes('Bulletproof') || s.name.includes('IP Hostname'))) {
      reasons.push({
        icon: '⚠️',
        title: 'High-Risk Disposable Infrastructure',
        desc: 'The domain or server hosting is heavily favored by threat actors for quick, disposable attack websites.'
      });
    }

    // 8. Psychological Pressure / Urgency
    if (signals.some(s => s.name.includes('Urgency') || s.name.includes('Countdown') || s.name.includes('Pressure'))) {
      reasons.push({
        icon: '⏳',
        title: 'Fake Urgency & Panic Manipulation',
        desc: 'The page displays fake countdown timers or alarmist warnings ("Account suspended immediately!") to manipulate you into submitting credentials.'
      });
    }

    // Fallback if no specific high-level category matched
    if (reasons.length === 0) {
      reasons.push({
        icon: '⚠️',
        title: 'Dangerous Heuristics & Keywords Detected',
        desc: 'Veridex AI detected suspicious deceptive patterns, deceptive keyword combinations, and unverified registry ownership.'
      });
    }

    return reasons;
  }

  /**
   * Generates a plain-English explanation for the suggested website
   */
  _getSuggestedExplanation(analysis, suggested) {
    const hostname = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : window.location.hostname;
    return {
      whichText: `Target Service Identified: You appear to be looking for the official <strong>${this._escapeHtml(suggested.name)}</strong> service.`,
      whyText: `Why this is suggested: <strong>${this._escapeHtml(suggested.url)}</strong> is the verified authentic destination. The site you reached (<em>${this._escapeHtml(hostname)}</em>) is an unverified clone or deceptive destination.`,
      buttonLabel: `🛡️ Continue to Official ${this._escapeHtml(suggested.name)} Website (${this._escapeHtml(suggested.host || suggested.name)})`
    };
  }

  /**
   * Safely navigates the user away from the malicious destination
   */
  goBackToSafety() {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://www.google.com';
    }
  }

  _escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

/**
 * VeridexSecurityReport - Comprehensive Interactive Security & Threat Audit Report
 * Shown ONLY when the user clicks the floating pin.
 * Includes URL risk score, behaviour analysis, offline IP intelligence, and detected threats.
 * Includes full printable report functionality.
 */
class VeridexSecurityReport {
  constructor() {
    this.modalId = 'veridex-security-report-modal';
  }

  /**
   * Renders and opens the complete interactive security report dashboard
   * @param {Object} analysis - The Veridex analysis result object
   */
  show(analysis) {
    if (!analysis) return;
    const existing = document.getElementById(this.modalId);
    if (existing) {
      existing.remove();
    }

    const hostname = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : window.location.hostname;
    const url = (analysis.details && analysis.details.url) ? analysis.details.url : window.location.href;
    const protocol = (analysis.details && analysis.details.protocol) ? analysis.details.protocol : window.location.protocol;
    const isHttps = protocol === 'https:';

    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 0);
    const isUnsafe = analysis.isUnsafe || analysis.verdict === 'suspicious' || riskPct >= 35;
    const isVerifiedReal = analysis.databaseMatch && analysis.databaseMatch.isReal;

    const classification = analysis.classification || (analysis.details && analysis.details.classification) || (typeof classifyDomain !== 'undefined' ? classifyDomain(hostname, analysis.details && analysis.details.apexDomain, { riskPercentage: riskPct, verdict: analysis.verdict }) : {
      category: 'unknown',
      categoryLabel: 'Unknown / Unverified Website',
      badge: 'ℹ️ Unknown Website',
      badgeClass: 'neutral',
      disclaimer: 'Veridex AI operates offline using curated threat feeds, structural heuristics, and verified domain registries. While extensive, this local database cannot and does not claim to recognise every government entity or emerging phishing website worldwide. Users should always exercise independent caution.'
    });

    const disclaimerText = (classification && classification.disclaimer) || analysis.disclaimer || (analysis.details && analysis.details.disclaimer) || 'Veridex AI operates offline using curated threat feeds, structural heuristics, and verified domain registries. While extensive, this local database cannot and does not claim to recognise every government entity or emerging phishing website worldwide. Users should always exercise independent caution.';

    let themeClass = 'neutral';
    let verdictLabel = analysis.levelLabel || 'Neutral';
    if (classification.category === 'verified_government') {
      themeClass = 'gov-safe';
      verdictLabel = '🏛️ Verified Government Domain';
    } else if (classification.category === 'known_phishing') {
      themeClass = 'danger';
      verdictLabel = '⛔ Confirmed Phishing (Threat Feed)';
    } else if (isVerifiedReal || (analysis.level === 'safe' && riskPct <= 5)) {
      themeClass = 'safe';
      verdictLabel = '✓ Verified Safe (Official Registry)';
    } else if (riskPct <= 20) {
      themeClass = 'neutral';
      verdictLabel = 'ℹ️ Low Risk (Unverified)';
    } else if (riskPct <= 34) {
      themeClass = 'caution';
      verdictLabel = '⚠️ Elevated Caution';
    } else if (riskPct < 60) {
      themeClass = 'warning';
      verdictLabel = '🚨 Suspicious (Unsafe)';
    } else {
      themeClass = 'danger';
      verdictLabel = '⛔ Critical Threat (Unsafe)';
    }

    // IP Intelligence & Hosting Analysis (Offline)
    const ipData = analysis.ipIntelligence || (typeof lookupIpIntelligence !== 'undefined' ? lookupIpIntelligence(null) : {
      ip: 'Unavailable (Not resolved / Cached)',
      isAvailable: false,
      isPrivate: false,
      isMalicious: false,
      maliciousMatch: null,
      asn: 'Unavailable',
      organization: 'Unavailable',
      hostingType: 'Unavailable',
      countryName: 'Unavailable',
      statusText: 'Resolved server IP was not captured or was served from browser cache.'
    });

    // Behaviour Analysis Indicators
    const dom = (analysis.details && analysis.details.domSignals) ? analysis.details.domSignals : {
      hasPasswordField: false,
      hasCreditCardField: false,
      hasSeedPhraseInputs: false,
      hasUrgencyPatterns: false,
      hasCountdown: false,
      externalFormActions: []
    };

    // Detected Signals
    const signals = analysis.signals || [];
    const threatSignals = signals.filter(s => s.severity !== 'info');

    // Cookie Security & Privacy Analysis (Offline & 100% Redacted)
    let cookieData = (analysis.cookieAnalysis) || (analysis.details && analysis.details.cookieAnalysis) || null;
    if (!cookieData && typeof CookieAnalyzer !== 'undefined') {
      try {
        if (typeof document !== 'undefined' && document.cookie) {
          cookieData = CookieAnalyzer.parseDocumentCookies(document.cookie, url);
        } else {
          cookieData = CookieAnalyzer.analyzeCookies([], url);
        }
      } catch (e) {
        cookieData = CookieAnalyzer.analyzeCookies([], url);
      }
    }
    if (!cookieData) {
      cookieData = {
        total: 0,
        firstPartyCount: 0,
        thirdPartyCount: 0,
        sessionCount: 0,
        persistentCount: 0,
        secureCount: 0,
        missingSecureCount: 0,
        httpOnlyCount: 0,
        missingHttpOnlyCount: 0,
        sameSiteStats: { strict: 0, lax: 0, none: 0, unspecified: 0 },
        insecureCookiesCount: 0,
        criticalIssuesCount: 0,
        overallStatus: 'secure',
        statusLabel: 'Zero Cookies Detected',
        statusBadge: '✓ Zero Cookies',
        statusBadgeClass: 'safe',
        summaryText: 'No cookies detected on this destination.',
        cookies: [],
        issues: [],
        disclaimer: 'Zero-Telemetry Notice: Veridex AI never displays, logs, or transmits actual cookie values.'
      };
    }

    // Date formatted string
    const now = new Date();
    const dateStr = now.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });

    // Suggested Official Website
    const suggested = analysis.suggestedWebsite;

    // Formatted Incident Evidence for Cybercrime Reporting
    const evidenceText = `[INCIDENT EVIDENCE FOR CYBERCRIME REPORTING]
Audited URL: ${url}
Resolved Hostname: ${hostname}
Audit Timestamp: ${dateStr}
Calculated Threat Risk: ${riskPct}% (${analysis.levelLabel || 'Evaluated'})
Website Classification: ${classification.categoryLabel || 'Evaluated'}
Resolved Server IP: ${ipData.ip}
Hosting Provider: ${ipData.organization} (ASN: ${ipData.asn})
Geographical Location: ${ipData.countryName || 'Unavailable'}
Malicious IP Match: ${ipData.isMalicious ? 'MATCHED MALICIOUS HOST' : (ipData.isAvailable ? 'Clean' : 'Unavailable')}
Cookie Security State: ${cookieData.statusLabel} (${cookieData.total} audited, ${cookieData.issues ? cookieData.issues.length : 0} warnings, values strictly redacted)
Detected Threat Signals:
${(threatSignals && threatSignals.length > 0) ? threatSignals.map(s => `- ${s.name}: ${s.description}`).join('\n') : '- Zero known threats detected.'}
Note: Generated locally by Veridex AI (100% offline). User submitted complaint manually.`;

    const overlay = document.createElement('div');
    overlay.id = this.modalId;

    overlay.innerHTML = `
      <div id="veridex-report-card" class="${themeClass}">
        <!-- REPORT TOP BAR -->
        <div class="vx-report-header">
          <div class="vx-report-brand">
            <svg viewBox="0 0 128 128" width="28" height="28" class="vx-report-logo-icon">
              <defs>
                <linearGradient id="vxLogoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stop-color="#00f2fe" />
                  <stop offset="50%" stop-color="#4facfe" />
                  <stop offset="100%" stop-color="#0052d4" />
                </linearGradient>
              </defs>
              <path d="M 64 22 C 85 22, 98 28, 98 46 C 98 75, 64 102, 64 102 C 64 102, 30 75, 30 46 C 30 28, 43 22, 64 22 Z" 
                    fill="url(#vxLogoGrad)" stroke="#38bdf8" stroke-width="3" />
              <path d="M 46 58 L 58 70 L 82 46" fill="none" stroke="#ffffff" stroke-width="7" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
            <div>
              <div class="vx-report-main-title">VERIDEX AI CYBER DEFENSE</div>
              <div class="vx-report-sub-title">Complete Security & Threat Audit Report • Offline Architecture</div>
            </div>
          </div>
          
          <div class="vx-report-header-actions">
            <button id="vx-report-cybercrime-top" class="vx-btn-action-sm vx-btn-cyber-alert" title="Report Cybercrime to Official Portal (1930)">
              🚨 Report Cybercrime
            </button>
            <button id="vx-report-print-top" class="vx-btn-action-sm" title="Print full security report">
              🖨️ Print Report
            </button>
            <button id="vx-report-copy-top" class="vx-btn-action-sm" title="Copy audit summary to clipboard">
              📋 Copy
            </button>
            <button id="vx-report-close-top" class="vx-btn-close-sm" title="Close Report">✕</button>
          </div>
        </div>

        <div class="vx-report-meta-strip">
          <span><strong>Audited:</strong> ${this._escapeHtml(hostname)}</span>
          <span>•</span>
          <span><strong>Timestamp:</strong> ${dateStr}</span>
          <span>•</span>
          <span class="vx-classification-pill ${classification.badgeClass || themeClass}">${this._escapeHtml(classification.badge || verdictLabel)}</span>
        </div>

        <!-- REPORT EXECUTIVE SUMMARY ROW -->
        <div class="vx-report-summary-box ${themeClass}">
          <div class="vx-score-col">
            <div class="vx-score-radial">
              <span class="vx-score-big">${riskPct}%</span>
              <span class="vx-score-sub">Risk Score</span>
            </div>
          </div>
          <div class="vx-summary-col">
            <div class="vx-summary-destination">
              <span class="vx-proto-tag ${isHttps ? 'https' : 'http'}">${isHttps ? '🔒 HTTPS' : '⚠️ HTTP INSECURE'}</span>
              <span class="vx-url-text" title="${this._escapeHtml(url)}">${this._escapeHtml(url)}</span>
            </div>
            <p class="vx-summary-desc">${this._escapeHtml(analysis.summary || 'Security assessment completed.')}</p>
          </div>
        </div>

        <!-- DETAILED SECURITY AUDIT REPORT SECTIONS -->
        <div id="vx-report-sections-container" class="vx-report-sections-container">

          <!-- SECTION DETAIL 1: IP INTELLIGENCE & HOSTING -->
          <div id="vx-section-detail-ip" class="vx-report-section-detail">
            <div class="vx-report-section">
              <div class="vx-section-title">
                <span>🌐 1. IP Intelligence & Hosting Risk Analysis</span>
                <span class="vx-section-tag">Offline Registry • Zero Telemetry</span>
              </div>
              <p class="vx-section-intro">
                Server IP and autonomous system verification is performed 100% offline. Unavailable information is displayed honestly rather than generating artificial estimates.
              </p>

              <div class="vx-ip-grid">
                <div class="vx-ip-cell">
                  <span class="vx-ip-label">Resolved Server IP</span>
                  <span class="vx-ip-val ${ipData.isAvailable ? 'mono' : 'muted'}">${this._escapeHtml(ipData.ip)}</span>
                </div>

                <div class="vx-ip-cell">
                  <span class="vx-ip-label">Hosting Provider / Organization</span>
                  <span class="vx-ip-val ${ipData.organization !== 'Unavailable' ? '' : 'muted'}">${this._escapeHtml(ipData.organization)}</span>
                </div>

                <div class="vx-ip-cell">
                  <span class="vx-ip-label">Autonomous System (ASN)</span>
                  <span class="vx-ip-val ${ipData.asn !== 'Unavailable' ? 'mono' : 'muted'}">${this._escapeHtml(ipData.asn)}</span>
                </div>

                <div class="vx-ip-cell">
                  <span class="vx-ip-label">Geographical Location</span>
                  <span class="vx-ip-val ${ipData.countryName !== 'Unavailable' ? '' : 'muted'}">
                    ${this._escapeHtml(ipData.countryName)} ${ipData.countryCode && ipData.countryCode !== 'Unavailable' ? `(${this._escapeHtml(ipData.countryCode)})` : ''}
                  </span>
                </div>

                <div class="vx-ip-cell">
                  <span class="vx-ip-label">Malicious IP Threat Check</span>
                  <span class="vx-ip-val ${ipData.isMalicious ? 'threat-text' : (ipData.isAvailable ? 'safe-text' : 'muted')}">
                    ${ipData.isMalicious ? `🚨 MATCHED: ${this._escapeHtml(ipData.maliciousMatch ? ipData.maliciousMatch.threatType : 'Threat Feed')}` : (ipData.isAvailable ? '✓ Clean (Not in Malicious IP DB)' : 'Unavailable')}
                  </span>
                </div>

                <div class="vx-ip-cell">
                  <span class="vx-ip-label">Hosting Classification</span>
                  <span class="vx-ip-val ${ipData.isHighRiskHosting ? 'threat-text' : ''}">
                    ${this._escapeHtml(ipData.hostingType)}
                  </span>
                </div>
              </div>

              <div class="vx-ip-note-box ${ipData.isMalicious ? 'danger' : (ipData.isHighRiskHosting ? 'caution' : '')}">
                <span>ℹ️</span>
                <span>${this._escapeHtml(ipData.statusText)}</span>
              </div>
            </div>
          </div>

          <!-- SECTION DETAIL 2: BEHAVIOUR & DOM ANALYSIS -->
          <div id="vx-section-detail-behaviour" class="vx-report-section-detail">
            <div class="vx-report-section">
              <div class="vx-section-title">
                <span>🔍 2. Behaviour & DOM Security Analysis</span>
                <span class="vx-section-tag">Live DOM Scanners</span>
              </div>

              <div class="vx-behaviour-grid">
                <div class="vx-beh-item ${dom.hasPasswordField ? (isVerifiedReal ? 'clean' : 'warning') : 'clean'}">
                  <span class="vx-beh-icon">${dom.hasPasswordField ? (isVerifiedReal ? '🔒' : '⚠️') : '✓'}</span>
                  <div>
                    <div class="vx-beh-name">Password / Authentication Fields</div>
                    <div class="vx-beh-desc">
                      ${dom.hasPasswordField ? (isVerifiedReal ? 'Standard login form on authentic verified domain' : 'Password field present on unverified domain — High credential theft risk') : 'No password or credential input fields detected on page'}
                    </div>
                  </div>
                </div>

                <div class="vx-beh-item ${dom.hasCreditCardField ? 'danger' : 'clean'}">
                  <span class="vx-beh-icon">${dom.hasCreditCardField ? '🚨' : '✓'}</span>
                  <div>
                    <div class="vx-beh-name">Credit Card & Financial Inputs</div>
                    <div class="vx-beh-desc">
                      ${dom.hasCreditCardField ? 'Credit card number / CVV input field detected' : 'No credit card or payment card inputs detected'}
                    </div>
                  </div>
                </div>

                <div class="vx-beh-item ${dom.hasSeedPhraseInputs ? 'danger' : 'clean'}">
                  <span class="vx-beh-icon">${dom.hasSeedPhraseInputs ? '🚨' : '✓'}</span>
                  <div>
                    <div class="vx-beh-name">Crypto Recovery Seed Phrase Harvester</div>
                    <div class="vx-beh-desc">
                      ${dom.hasSeedPhraseInputs ? 'CRITICAL: 12 or 24-word recovery mnemonic capture form detected' : 'No crypto seed phrase or wallet recovery forms detected'}
                    </div>
                  </div>
                </div>

                <div class="vx-beh-item ${dom.hasUrgencyPatterns ? 'warning' : 'clean'}">
                  <span class="vx-beh-icon">${dom.hasUrgencyPatterns ? '⏳' : '✓'}</span>
                  <div>
                    <div class="vx-beh-name">Psychological Urgency & Scam Text</div>
                    <div class="vx-beh-desc">
                      ${dom.hasUrgencyPatterns ? 'Manipulative pressure language ("Account will be suspended immediately") detected' : 'No coercive urgency or panic manipulation patterns detected'}
                    </div>
                  </div>
                </div>

                <div class="vx-beh-item ${dom.hasCountdown ? 'danger' : 'clean'}">
                  <span class="vx-beh-icon">${dom.hasCountdown ? '⏱️' : '✓'}</span>
                  <div>
                    <div class="vx-beh-name">Fake Countdown Pressure Timers</div>
                    <div class="vx-beh-desc">
                      ${dom.hasCountdown ? 'Active countdown clock paired with urgency threats detected' : 'No fake countdown coercion timers detected'}
                    </div>
                  </div>
                </div>

                <div class="vx-beh-item ${(dom.externalFormActions && dom.externalFormActions.length > 0) ? 'warning' : 'clean'}">
                  <span class="vx-beh-icon">${(dom.externalFormActions && dom.externalFormActions.length > 0) ? '📤' : '✓'}</span>
                  <div>
                    <div class="vx-beh-name">Form Submission Destinations</div>
                    <div class="vx-beh-desc">
                      ${(dom.externalFormActions && dom.externalFormActions.length > 0) ? `Form submits data externally to: ${this._escapeHtml(dom.externalFormActions.join(', '))}` : 'All forms submit internally to current destination'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- SECTION DETAIL 3: THREAT SIGNALS & HEURISTICS -->
          <div id="vx-section-detail-signals" class="vx-report-section-detail">
            <div class="vx-report-section">
              <div class="vx-section-title">
                <span>🛡️ 3. Detected Threat Signals & Heuristic Indicators</span>
                <span class="vx-section-tag">${threatSignals.length} Threats / ${signals.length} Evaluated</span>
              </div>

              <div class="vx-signals-list">
                ${threatSignals.length > 0 ? threatSignals.map(sig => `
                  <div class="vx-sig-row ${sig.severity === 'high' ? 'high' : 'medium'}">
                    <div class="vx-sig-badge">${sig.severity === 'high' ? 'THREAT' : 'CAUTION'}</div>
                    <div class="vx-sig-info">
                      <div class="vx-sig-name">
                        ${this._escapeHtml(sig.name)} 
                        ${sig.points ? `<span class="vx-sig-pts">(+${sig.points}% Risk)</span>` : ''}
                      </div>
                      <div class="vx-sig-desc">${this._escapeHtml(sig.description)}</div>
                    </div>
                  </div>
                `).join('') : `
                  <div class="vx-clean-box">
                    <span class="vx-clean-icon">✓</span>
                    <div>
                      <div class="vx-clean-title">Zero Malicious Threat Signatures Detected</div>
                      <div class="vx-clean-desc">No typosquatting, lookalike characters, blacklisted threat IPs, or credential harvesting heuristics triggered on this destination.</div>
                    </div>
                  </div>
                `}
              </div>
            </div>
          </div>

          <!-- SECTION DETAIL 4: COOKIE SECURITY ANALYSIS -->
          <div id="vx-section-detail-cookies" class="vx-report-section-detail">
            <div class="vx-report-section">
              <div class="vx-section-title">
                <span>🍪 4. Cookie Security & Privacy Analysis</span>
                <span class="vx-section-tag">Zero Telemetry • Values Redacted</span>
              </div>

              <!-- PRIVACY & REDACTION BANNER -->
              <div class="vx-cookie-privacy-banner">
                <span class="vx-cookie-banner-icon">🛡️</span>
                <div class="vx-cookie-banner-text">
                  <strong>Zero-Telemetry Privacy Guarantee:</strong>
                  <p>Veridex AI evaluates cookie configurations 100% locally in memory. <strong>Actual cookie values are never displayed, logged, or transmitted.</strong> Only security flags (Secure, HttpOnly, SameSite, domain, and expiry) are audited to uncover insecure configurations and cross-site tracking.</p>
                </div>
              </div>

              <!-- COOKIE METRICS SUMMARY GRID -->
              <div class="vx-cookie-stats-grid">
                <div class="vx-cookie-stat-card">
                  <div class="vx-cstat-top">
                    <span class="vx-cstat-num">${cookieData.total}</span>
                    <span class="vx-cstat-pill">${cookieData.firstPartyCount} First-Party</span>
                  </div>
                  <div class="vx-cstat-label">Total Cookies Audited</div>
                  <div class="vx-cstat-sub">${cookieData.thirdPartyCount} Third-Party Tracker${cookieData.thirdPartyCount !== 1 ? 's' : ''}</div>
                </div>

                <div class="vx-cookie-stat-card">
                  <div class="vx-cstat-top">
                    <span class="vx-cstat-num ${cookieData.secureCount === cookieData.total && cookieData.total > 0 ? 'safe-text' : (cookieData.missingSecureCount > 0 ? 'threat-text' : '')}">
                      ${cookieData.secureCount}/${cookieData.total}
                    </span>
                    <span class="vx-cstat-pill ${cookieData.missingSecureCount > 0 ? 'danger' : 'safe'}">
                      ${cookieData.missingSecureCount > 0 ? `${cookieData.missingSecureCount} Insecure` : 'Encrypted'}
                    </span>
                  </div>
                  <div class="vx-cstat-label">Secure Flag (HTTPS Only)</div>
                  <div class="vx-cstat-sub">${cookieData.missingSecureCount > 0 ? 'Missing on some cookies' : 'Encrypted transmission'}</div>
                </div>

                <div class="vx-cookie-stat-card">
                  <div class="vx-cstat-top">
                    <span class="vx-cstat-num">
                      ${cookieData.httpOnlyCount}/${cookieData.total}
                    </span>
                    <span class="vx-cstat-pill ${cookieData.httpOnlyCount > 0 ? 'safe' : 'neutral'}">
                      ${cookieData.httpOnlyCount} Protected
                    </span>
                  </div>
                  <div class="vx-cstat-label">HttpOnly Flag (XSS Shield)</div>
                  <div class="vx-cstat-sub">${cookieData.missingHttpOnlyCount} Accessible via JS</div>
                </div>

                <div class="vx-cookie-stat-card">
                  <div class="vx-cstat-top">
                    <span class="vx-cstat-num">${cookieData.sameSiteStats ? (cookieData.sameSiteStats.strict + cookieData.sameSiteStats.lax) : 0}</span>
                    <span class="vx-cstat-pill neutral">CSRF Defense</span>
                  </div>
                  <div class="vx-cstat-label">SameSite Policies</div>
                  <div class="vx-cstat-sub">Strict: ${cookieData.sameSiteStats ? cookieData.sameSiteStats.strict : 0} • Lax: ${cookieData.sameSiteStats ? cookieData.sameSiteStats.lax : 0} • None: ${cookieData.sameSiteStats ? cookieData.sameSiteStats.none : 0}</div>
                </div>
              </div>

              <!-- INSECURE CONFIGURATIONS COLLAPSIBLE FOLDER -->
              ${cookieData.issues && cookieData.issues.length > 0 ? `
                <details class="vx-cookie-folder" id="vx-cookie-insecure-folder">
                  <summary class="vx-cookie-folder-summary">
                    <span class="vx-folder-left">
                      <span class="vx-folder-icon">📁</span>
                      <span class="vx-folder-title">Identified Insecure Configurations</span>
                      <span class="vx-folder-count">(${cookieData.issues.length} detected)</span>
                    </span>
                    <span class="vx-folder-right">
                      <span class="vx-issues-badge">${cookieData.criticalIssuesCount || 0} High Risk</span>
                      <span class="vx-folder-chevron">▼</span>
                    </span>
                  </summary>
                  <div class="vx-cookie-folder-content">
                    <div class="vx-cookie-issues-list">
                      ${cookieData.issues.map(iss => `
                        <div class="vx-cookie-issue-item ${iss.severity}">
                          <span class="vx-issue-badge ${iss.severity}">${iss.severity === 'danger' ? 'CRITICAL' : 'WARNING'}</span>
                          <div class="vx-issue-body">
                            <div class="vx-issue-title">
                              ${this._escapeHtml(iss.title)}
                              <code class="vx-cookie-code-name">${this._escapeHtml(iss.cookieName)}</code>
                            </div>
                            <div class="vx-issue-desc">${this._escapeHtml(iss.description)}</div>
                          </div>
                        </div>
                      `).join('')}
                    </div>
                  </div>
                </details>
              ` : `
                <div class="vx-clean-box">
                  <span class="vx-clean-icon">✓</span>
                  <div>
                    <div class="vx-clean-title">No Insecure Cookie Configurations Detected</div>
                    <div class="vx-clean-desc">All evaluated cookies have valid security flags, appropriate SameSite settings, and clean retention lifetimes.</div>
                  </div>
                </div>
              `}

              <!-- DETAILED AUDITED COOKIE INVENTORY (VALUES STRICTLY OMITTED) -->
              <div class="vx-cookie-inventory-card">
                <div class="vx-inventory-header">
                  <span>📋 Audited Cookie Inventory (${cookieData.cookies ? cookieData.cookies.length : 0})</span>
                  <span class="vx-inventory-redacted-tag">🔒 Values Strictly Redacted</span>
                </div>

                ${(cookieData.cookies && cookieData.cookies.length > 0) ? `
                  <div class="vx-cookie-table-container">
                    <table class="vx-cookie-table">
                      <thead>
                        <tr>
                          <th>Cookie Name</th>
                          <th>Domain Scope</th>
                          <th>Expiry</th>
                          <th>Secure</th>
                          <th>HttpOnly</th>
                          <th>SameSite</th>
                          <th>Origin</th>
                        </tr>
                      </thead>
                      <tbody>
                        ${cookieData.cookies.map(c => `
                          <tr class="${c.severity === 'danger' ? 'row-danger' : (c.severity === 'warning' ? 'row-warning' : '')}">
                            <td class="col-name">
                              <div class="vx-cookie-name-cell">
                                <code class="vx-cname">${this._escapeHtml(c.name)}</code>
                                ${c.isSensitive ? '<span class="vx-tag-auth" title="Sensitive Session/Auth Token">AUTH</span>' : ''}
                              </div>
                            </td>
                            <td class="col-domain">
                              <span class="vx-cdomain">${this._escapeHtml(c.domain)}</span>
                            </td>
                            <td class="col-expiry">
                              <span class="vx-cexpiry ${c.expiry && c.expiry.isExcessive ? 'threat-text' : ''}">${this._escapeHtml(c.expiry ? c.expiry.text : 'Session')}</span>
                            </td>
                            <td class="col-flag">
                              ${c.secure ? '<span class="vx-flag-pill safe">✓ Secure</span>' : '<span class="vx-flag-pill danger">⚠️ Insecure</span>'}
                            </td>
                            <td class="col-flag">
                              ${c.httpOnly ? '<span class="vx-flag-pill safe">✓ HttpOnly</span>' : '<span class="vx-flag-pill neutral">⚠️ JS Accessible</span>'}
                            </td>
                            <td class="col-samesite">
                              <span class="vx-samesite-tag ${this._escapeHtml(c.sameSite)}">${this._escapeHtml(c.sameSite)}</span>
                            </td>
                            <td class="col-origin">
                              ${c.isThirdParty ? '<span class="vx-party-tag third">3rd-Party</span>' : '<span class="vx-party-tag first">1st-Party</span>'}
                            </td>
                          </tr>
                        `).join('')}
                      </tbody>
                    </table>
                  </div>
                ` : `
                  <div class="vx-empty-cookies-box">
                    <span>ℹ️ No active cookies were detected on this page or cookies were cleared.</span>
                  </div>
                `}
              </div>
            </div>
          </div>

          <!-- SECTION DETAIL 5: GOVERNMENT CYBERCRIME REPORTING -->
          <div id="vx-section-detail-cybercrime" class="vx-report-section-detail">
            <div class="vx-report-section vx-cybercrime-section" id="vx-section-cybercrime">
              <div class="vx-section-title">
                <span>🏛️ 5. Report Cybercrime (Government Reporting Channels)</span>
                <span class="vx-section-tag gov-tag">Official Indian Cyber Defense</span>
              </div>

              <div class="vx-cybercrime-card">
                <div class="vx-cybercrime-banner">
                  <div class="vx-cybercrime-icon">🇮🇳</div>
                  <div class="vx-cybercrime-banner-text">
                    <div class="vx-cybercrime-title">National Cyber Crime Reporting Portal (Government of India)</div>
                    <div class="vx-cybercrime-sub">Citizen Financial Cyber Fraud Reporting System • Ministry of Home Affairs</div>
                  </div>
                </div>

                <!-- MANDATORY CLEAR NOTICE: PERSONAL SUBMISSION & ZERO TELEMETRY -->
                <div class="vx-cybercrime-notice">
                  <div class="vx-notice-icon">🛡️</div>
                  <div class="vx-notice-body">
                    <strong>Important Notice — Personal Submission Required:</strong>
                    <p>
                      Veridex AI operates 100% offline on your device and <strong>does not automatically transmit browsing data, URLs, or personal information</strong> to any server or authority.
                      Complaints cannot be lodged automatically on your behalf. <strong>You must submit your complaint yourself through official government channels</strong> listed below.
                    </p>
                  </div>
                </div>

                <!-- ACTION BUTTONS: PORTAL LINK + CALL 1930 -->
                <div class="vx-cybercrime-actions">
                  <a href="https://cybercrime.gov.in/" target="_blank" rel="noopener noreferrer" class="vx-btn-gov-portal" id="vx-btn-gov-portal">
                    <span class="vx-btn-icon">🌐</span>
                    <div class="vx-btn-text">
                      <span class="vx-btn-main">Visit Official Cybercrime Portal</span>
                      <span class="vx-btn-url">https://cybercrime.gov.in/</span>
                    </div>
                    <span class="vx-btn-ext">↗</span>
                  </a>

                  <a href="tel:1930" class="vx-btn-gov-helpline" id="vx-btn-gov-call">
                    <span class="vx-btn-icon">📞</span>
                    <div class="vx-btn-text">
                      <span class="vx-btn-main">Call Cyber Helpline 1930</span>
                      <span class="vx-btn-desc">Financial Fraud Emergency Helpline (Toll-Free)</span>
                    </div>
                  </a>
                </div>

                <!-- HOW TO FILE COMPLAINT GUIDE -->
                <div class="vx-cybercrime-steps">
                  <div class="vx-steps-title">📋 How to File Your Official Complaint:</div>
                  <ol class="vx-steps-list">
                    <li>
                      <strong>For Financial Frauds (Immediate Action):</strong> Call <strong>1930</strong> immediately within the "golden hour" to report unauthorized financial debits so police and banks can attempt to freeze fraudulent transfers.
                    </li>
                    <li>
                      <strong>For Phishing, Impersonation & Online Scams:</strong> Visit <a href="https://cybercrime.gov.in/" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a> and select <em>"Report Cyber Crime"</em> to log an official FIR or incident.
                    </li>
                    <li>
                      <strong>Attach Veridex Evidence:</strong> Click <em>"Copy Incident Evidence"</em> below to copy the audited URL, risk signals, and server IP details to paste directly into your official complaint form.
                    </li>
                  </ol>
                </div>

                <!-- ONE-CLICK EVIDENCE COPY FOR USER'S COMPLAINT -->
                <div class="vx-evidence-box">
                  <div class="vx-evidence-header">
                    <span>📋 Audit Evidence for Your Complaint (Personal Copy)</span>
                    <button id="vx-btn-copy-evidence" class="vx-btn-copy-evidence" type="button">
                      <span>📋 Copy Incident Evidence</span>
                    </button>
                  </div>
                  <pre class="vx-evidence-text">${this._escapeHtml(evidenceText)}</pre>
                </div>

                <!-- HONEST DATASET & SCOPE DISCLAIMER -->
                <div class="vx-disclaimer-strip">
                  <span class="vx-disc-icon">ℹ️</span>
                  <span>${this._escapeHtml(disclaimerText)}</span>
                </div>
              </div>
            </div>
          </div>

          ${suggested ? `
            <!-- SECTION DETAIL 6: RECOMMENDED AUTHENTIC DESTINATION -->
            <div id="vx-section-detail-suggested" class="vx-report-section-detail">
              <div class="vx-report-section suggested-dest-section">
                <div class="vx-section-title">
                  <span>🛡️ Recommended Authentic Destination</span>
                </div>
                <div class="vx-suggested-card-inner">
                  <div>
                    <div class="vx-sug-name">${this._escapeHtml(suggested.name)} (Official Genuine Website)</div>
                    <div class="vx-sug-url">${this._escapeHtml(suggested.url)}</div>
                    <div class="vx-sug-why">Veridex AI verified that ${this._escapeHtml(suggested.url)} is the authentic legitimate registry entity.</div>
                  </div>
                  <button id="vx-btn-goto-suggested" class="vx-btn-suggested-action">
                    🛡️ Open Official Destination
                  </button>
                </div>
              </div>
            </div>
          ` : ''}

        </div>

        <!-- REPORT FOOTER ACTIONS -->
        <div class="vx-report-footer">
          <div class="vx-footer-left">
            <button id="vx-report-cybercrime-bottom" class="vx-btn-action-sm vx-btn-cyber-alert" title="Jump to Government Cybercrime Reporting section">
              🚨 Report Cybercrime (1930)
            </button>
            <button id="vx-report-print-bottom" class="vx-btn-primary">
              🖨️ Print Complete Report
            </button>
            <button id="vx-report-copy-bottom" class="vx-btn-secondary">
              📋 Copy Plain-Text Audit
            </button>
            <button id="vx-report-open-website" class="vx-btn-secondary" title="Open Veridex AI Website">
              🌐 Veridex AI Website
            </button>
          </div>
          <button id="vx-report-close-bottom" class="vx-btn-close">
            Close Report
          </button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    // Close handlers
    const closeBtns = [
      overlay.querySelector('#vx-report-close-top'),
      overlay.querySelector('#vx-report-close-bottom')
    ];
    closeBtns.forEach(btn => {
      if (btn) btn.onclick = () => overlay.remove();
    });

    // Close on outside click
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.remove();
      }
    });

    // Jump to Cybercrime section (top and bottom buttons)
    const cyberNavBtns = [
      overlay.querySelector('#vx-report-cybercrime-top'),
      overlay.querySelector('#vx-report-cybercrime-bottom')
    ];
    cyberNavBtns.forEach(btn => {
      if (btn) {
        btn.onclick = () => {
          const section = overlay.querySelector('#vx-section-detail-cybercrime') || overlay.querySelector('#vx-section-cybercrime');
          if (section) section.scrollIntoView({ behavior: 'smooth' });
        };
      }
    });

    // Copy Incident Evidence handler
    const btnCopyEvidence = overlay.querySelector('#vx-btn-copy-evidence');
    if (btnCopyEvidence) {
      btnCopyEvidence.onclick = () => {
        navigator.clipboard.writeText(evidenceText).then(() => {
          const original = btnCopyEvidence.innerHTML;
          btnCopyEvidence.innerHTML = '<span>✓ Evidence Copied!</span>';
          setTimeout(() => { btnCopyEvidence.innerHTML = original; }, 2500);
        });
      };
    }

    // Print handlers
    const printBtns = [
      overlay.querySelector('#vx-report-print-top'),
      overlay.querySelector('#vx-report-print-bottom')
    ];
    printBtns.forEach(btn => {
      if (btn) {
        btn.onclick = () => {
          this.printReport(analysis);
        };
      }
    });

    // Copy handlers
    const copyBtns = [
      overlay.querySelector('#vx-report-copy-top'),
      overlay.querySelector('#vx-report-copy-bottom')
    ];
    copyBtns.forEach(btn => {
      if (btn) {
        btn.onclick = () => {
          const auditText = this._generateTextReport(analysis, dateStr, ipData, dom, cookieData);
          navigator.clipboard.writeText(auditText).then(() => {
            const original = btn.innerText;
            btn.innerText = '✓ Copied!';
            setTimeout(() => { btn.innerText = original; }, 2000);
          });
        };
      }
    });

    // Suggested destination button
    const gotoSuggested = overlay.querySelector('#vx-btn-goto-suggested');
    if (gotoSuggested && suggested) {
      gotoSuggested.onclick = () => {
        window.location.href = suggested.url;
      };
    }

    // Open Veridex AI Website from detailed report
    const btnOpenWebReport = overlay.querySelector('#vx-report-open-website');
    if (btnOpenWebReport) {
      btnOpenWebReport.onclick = () => {
        const currentUrl = (analysis && analysis.details && analysis.details.url) || window.location.href;
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'OPEN_WEBSITE', url: currentUrl });
        } else if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
          const siteUrl = chrome.runtime.getURL(`website/index.html?url=${encodeURIComponent(currentUrl)}`);
          window.open(siteUrl, '_blank');
        }
      };
    }
  }

  /**
   * Invokes window.print() with printable layout
   */
  printReport(analysis) {
    window.print();
  }

  /**
   * Generates formatted text report for clipboard copy (strictly zero cookie values)
   */
  _generateTextReport(analysis, dateStr, ipData, dom, cookieData) {
    const hostname = (analysis.details && analysis.details.hostname) ? analysis.details.hostname : window.location.hostname;
    const url = (analysis.details && analysis.details.url) ? analysis.details.url : window.location.href;
    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : (analysis.riskScore || 0);
    const cookies = cookieData || { total: 0, firstPartyCount: 0, thirdPartyCount: 0, secureCount: 0, missingSecureCount: 0, httpOnlyCount: 0, missingHttpOnlyCount: 0, sameSiteStats: { strict: 0, lax: 0, none: 0, unspecified: 0 }, issues: [] };

    return [
      '===============================================================',
      'VERIDEX AI CYBER DEFENSE - SECURITY & THREAT AUDIT REPORT',
      '===============================================================',
      `Audited Destination: ${url}`,
      `Host: ${hostname}`,
      `Audit Timestamp: ${dateStr}`,
      `Risk Score: ${riskPct}% (${analysis.levelLabel || 'Evaluated'})`,
      `Summary: ${analysis.summary || 'Assessment completed.'}`,
      '',
      '1. IP INTELLIGENCE & HOSTING RISK (OFFLINE REGISTRY)',
      '---------------------------------------------------------------',
      `Server IP: ${ipData.ip}`,
      `Hosting Provider: ${ipData.organization}`,
      `Autonomous System: ${ipData.asn}`,
      `Geographical Location: ${ipData.countryName} (${ipData.countryCode})`,
      `Malicious IP Database Status: ${ipData.isMalicious ? 'MATCHED MALICIOUS HOST' : (ipData.isAvailable ? 'Clean' : 'Unavailable')}`,
      `Hosting Type: ${ipData.hostingType}`,
      `Note: ${ipData.statusText}`,
      '',
      '2. BEHAVIOURAL & DOM SECURITY AUDIT',
      '---------------------------------------------------------------',
      `Password / Auth Input: ${dom.hasPasswordField ? 'Detected' : 'None'}`,
      `Credit Card Inputs: ${dom.hasCreditCardField ? 'Detected' : 'None'}`,
      `Crypto Seed Phrase Inputs: ${dom.hasSeedPhraseInputs ? 'Detected' : 'None'}`,
      `Psychological Urgency Text: ${dom.hasUrgencyPatterns ? 'Detected' : 'None'}`,
      `Fake Countdown Timers: ${dom.hasCountdown ? 'Detected' : 'None'}`,
      `External Form Destinations: ${dom.externalFormActions && dom.externalFormActions.length > 0 ? dom.externalFormActions.join(', ') : 'None (Internal)'}`,
      '',
      `3. DETECTED THREAT SIGNALS (${(analysis.signals || []).length})`,
      '---------------------------------------------------------------',
      (analysis.signals && analysis.signals.length > 0) ? analysis.signals.map(s => `- [${s.severity.toUpperCase()}] ${s.name} (+${s.points || 0}%): ${s.description}`).join('\n') : 'No threat signals detected.',
      '',
      '4. COOKIE SECURITY & PRIVACY AUDIT (VALUES STRICTLY REDACTED)',
      '---------------------------------------------------------------',
      `Total Cookies Audited: ${cookies.total} (${cookies.firstPartyCount} First-Party, ${cookies.thirdPartyCount} Third-Party)`,
      `Secure Flag (Encrypted): ${cookies.secureCount} Secure / ${cookies.missingSecureCount} Missing Secure`,
      `HttpOnly Flag (XSS Shield): ${cookies.httpOnlyCount} HttpOnly / ${cookies.missingHttpOnlyCount} Missing HttpOnly`,
      `SameSite Policies: Strict=${cookies.sameSiteStats ? cookies.sameSiteStats.strict : 0}, Lax=${cookies.sameSiteStats ? cookies.sameSiteStats.lax : 0}, None=${cookies.sameSiteStats ? cookies.sameSiteStats.none : 0}, Unspecified=${cookies.sameSiteStats ? cookies.sameSiteStats.unspecified : 0}`,
      `Insecure Configurations: ${cookies.issues && cookies.issues.length > 0 ? cookies.issues.map(iss => `\n  - [${iss.severity.toUpperCase()}] ${iss.title} (${iss.cookieName}): ${iss.description}`).join('') : 'None (All evaluated cookies verified)'}`,
      'Privacy Notice: Actual cookie values are NEVER displayed, stored, or transmitted.',
      '',
      '===============================================================',
      'Generated by Veridex AI - 100% On-Device Cybersecurity Architecture',
      '==============================================================='
    ].join('\n');
  }

  _escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

class VeridexFloatingBadge {
  constructor() {
    this.badgeId = 'veridex-floating-badge';
    this.currentAnalysis = null;
    this.isUnsafe = false;
    this.securityReport = new VeridexSecurityReport();
  }

  /**
   * Renders the small circular floating pin on screen
   */
  render({ analysis, isUnsafe }) {
    this.currentAnalysis = analysis || {};
    this.isUnsafe = isUnsafe;

    // Check if pin already exists
    let badge = document.getElementById(this.badgeId);
    if (!badge) {
      badge = document.createElement('div');
      badge.id = this.badgeId;
      document.documentElement.appendChild(badge);
      this._makeDraggable(badge);
    }

    // Configure green circle vs red circle
    badge.className = isUnsafe ? 'veridex-badge-unsafe' : 'veridex-badge-safe';

    const tooltipText = isUnsafe
      ? 'Veridex AI: Suspicious or malicious website detected! Click to view complete security report, or drag to move.'
      : 'Veridex AI: Safe / No threats detected. Click to view complete security report, or drag to move.';

    badge.setAttribute('title', tooltipText);
    badge.setAttribute('role', 'button');
    badge.setAttribute('tabindex', '0');
    badge.setAttribute('aria-label', tooltipText);

    // Displays ONLY the Veridex logo inside a small circular indicator
    badge.innerHTML = `
      <div class="veridex-pin-inner">
        <svg viewBox="0 0 128 128" width="22" height="22" class="veridex-pin-logo">
          <defs>
            <linearGradient id="vxPinGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#00f2fe" />
              <stop offset="50%" stop-color="#4facfe" />
              <stop offset="100%" stop-color="#0052d4" />
            </linearGradient>
          </defs>
          <!-- Shield Base -->
          <path d="M 64 22 C 85 22, 98 28, 98 46 C 98 75, 64 102, 64 102 C 64 102, 30 75, 30 46 C 30 28, 43 22, 64 22 Z" 
                fill="url(#vxPinGrad)" stroke="#38bdf8" stroke-width="3" />
          <!-- Checkmark / Pulse Wing -->
          <path d="M 46 58 L 58 70 L 82 46" fill="none" stroke="#ffffff" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </div>
    `;
  }

  /**
   * Adds smooth pointer drag-and-drop capability across the entire screen
   */
  _makeDraggable(element) {
    let isDragging = false;
    let hasMoved = false;
    let startX = 0;
    let startY = 0;
    let initialLeft = 0;
    let initialTop = 0;

    const onPointerDown = (e) => {
      // Only drag on primary mouse button or touch
      if (e.button !== undefined && e.button !== 0) return;

      isDragging = true;
      hasMoved = false;
      startX = e.clientX;
      startY = e.clientY;

      const rect = element.getBoundingClientRect();
      initialLeft = rect.left;
      initialTop = rect.top;

      // Lock to explicit left/top coordinates and release right/bottom
      element.style.setProperty('left', `${initialLeft}px`, 'important');
      element.style.setProperty('top', `${initialTop}px`, 'important');
      element.style.setProperty('right', 'auto', 'important');
      element.style.setProperty('bottom', 'auto', 'important');

      try {
        element.setPointerCapture(e.pointerId);
      } catch (err) {}

      element.classList.add('is-dragging');

      window.addEventListener('pointermove', onPointerMove);
      window.addEventListener('pointerup', onPointerUp);
      window.addEventListener('pointercancel', onPointerUp);
    };

    const onPointerMove = (e) => {
      if (!isDragging) return;

      const dx = e.clientX - startX;
      const dy = e.clientY - startY;

      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
        hasMoved = true;
      }

      let newLeft = initialLeft + dx;
      let newTop = initialTop + dy;

      // Clamp within viewport
      const badgeWidth = element.offsetWidth || 38;
      const badgeHeight = element.offsetHeight || 38;
      const maxLeft = Math.max(10, window.innerWidth - badgeWidth - 10);
      const maxTop = Math.max(10, window.innerHeight - badgeHeight - 10);

      newLeft = Math.max(10, Math.min(maxLeft, newLeft));
      newTop = Math.max(10, Math.min(maxTop, newTop));

      element.style.setProperty('left', `${newLeft}px`, 'important');
      element.style.setProperty('top', `${newTop}px`, 'important');
      element.style.setProperty('right', 'auto', 'important');
      element.style.setProperty('bottom', 'auto', 'important');
    };

    const onPointerUp = (e) => {
      if (!isDragging) return;
      isDragging = false;
      element.classList.remove('is-dragging');

      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
      window.removeEventListener('pointercancel', onPointerUp);

      try {
        element.releasePointerCapture(e.pointerId);
      } catch (err) {}

      if (!hasMoved) {
        // Simple click without dragging -> Open Complete Security Report!
        this._handleClick();
      }
    };

    element.addEventListener('pointerdown', onPointerDown);
  }

  /**
   * Action when clicking the pin:
   * Opens the complete Veridex Security Report
   */
  _handleClick() {
    this.securityReport.show(this.currentAnalysis);
  }
}

if (typeof window !== 'undefined') {
  window.VeridexWarningModal = VeridexWarningModal;
  window.VeridexSecurityReport = VeridexSecurityReport;
  window.VeridexFloatingBadge = VeridexFloatingBadge;
}
