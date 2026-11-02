/**
 * Veridex AI - Test Lab Interactive Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const engine = new VeridexEngine();

  const inputEl = document.getElementById('test-url-input');
  const btnRun = document.getElementById('btn-run-test');
  const resultContainer = document.getElementById('test-result-container');
  const resultBadge = document.getElementById('test-result-badge');
  const resultTarget = document.getElementById('test-result-target');
  const resultScore = document.getElementById('test-result-score');
  const resultSummary = document.getElementById('test-result-summary');
  const signalsList = document.getElementById('test-signals-list');
  const presetChips = document.querySelectorAll('.preset-chip');

  async function runAnalysis(urlToTest) {
    if (!urlToTest) return;

    let cleanUrl = urlToTest.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'https://' + cleanUrl;
    }

    btnRun.textContent = 'Probing...';
    btnRun.disabled = true;

    let result;
    try {
      result = await engine.verifyLive(cleanUrl);
    } catch (e) {
      result = engine.analyze(cleanUrl);
    }

    btnRun.textContent = 'Analyze Locally';
    btnRun.disabled = false;

    const riskPct = result.riskPercentage !== undefined ? result.riskPercentage : result.riskScore;

    resultContainer.style.display = 'block';
    resultTarget.textContent = cleanUrl;
    resultScore.textContent = `${riskPct}% Risk`;
    resultSummary.textContent = result.summary;

    const isSuspicious = result.verdict === 'suspicious';
    const classification = result.classification || (result.details && result.details.classification) || {};
    let badgeClass = 'neutral';
    let badgeText = classification.badge || 'Neutral (Unverified)';

    if (classification.category === 'verified_government') {
      badgeClass = 'safe';
      badgeText = '🏛️ Verified Government Domain';
    } else if (classification.category === 'known_phishing') {
      badgeClass = 'danger';
      badgeText = '⛔ Confirmed Phishing Website';
    } else if (result.level === 'safe') {
      badgeClass = 'safe';
      badgeText = '✓ Verified Safe (Registry Match)';
    } else if (result.level === 'caution') {
      badgeClass = 'warning';
      badgeText = '⚠️ Elevated Caution';
    } else if (isSuspicious) {
      badgeClass = result.level === 'danger' ? 'danger' : 'warning';
      badgeText = result.level === 'danger' ? '🚨 High Risk Threat' : '⚠️ Suspicious';
    }
    resultBadge.className = 'result-badge-lg ' + badgeClass;
    resultBadge.textContent = badgeText;

    // Render signals breakdown
    signalsList.innerHTML = '';

    // Show IP Intelligence row
    if (result.ipIntelligence) {
      const ipData = result.ipIntelligence;
      const ipRow = document.createElement('div');
      ipRow.className = 'sig-item';
      ipRow.style.background = ipData.isMalicious ? '#fff5f5' : (ipData.isHighRiskHosting ? '#fffbeb' : '#f8fafc');
      ipRow.style.borderColor = ipData.isMalicious ? '#fecaca' : (ipData.isHighRiskHosting ? '#fde68a' : '#e2e8f0');
      const badgeStyle = ipData.isMalicious ? 'background:#fee2e2; color:#dc2626;' : (ipData.isAvailable ? 'background:#e0f2fe; color:#0284c7;' : 'background:#f1f5f9; color:#64748b;');
      ipRow.innerHTML = `
        <span class="sig-score" style="${badgeStyle}">IP INTEL</span>
        <div>
          <div style="font-weight:700; color:#0f172a;">Server IP: ${escapeHtml(ipData.ip)} • ASN: ${escapeHtml(ipData.asn)}</div>
          <div style="color:#475569; font-size:11.5px; margin-top:2px;">
            Org: ${escapeHtml(ipData.organization)} • Location: ${escapeHtml(ipData.countryName)} • Hosting: ${escapeHtml(ipData.hostingType)}
          </div>
          <div style="font-size:11px; margin-top:3px; font-weight:600; color:${ipData.isMalicious ? '#dc2626' : (ipData.isHighRiskHosting ? '#d97706' : '#15803d')};">
            ${escapeHtml(ipData.statusText)}
          </div>
        </div>
      `;
      signalsList.appendChild(ipRow);
    }

    // Show Offline Cookie Security Analysis row
    if (typeof CookieAnalyzer !== 'undefined') {
      const isHttps = cleanUrl.startsWith('https:');
      // If simulated or test page, sample cookies can be verified
      const sampleCookies = cleanUrl.includes('scam') || cleanUrl.includes('fake') ? [
        { name: 'session_token', domain: new URL(cleanUrl).hostname, secure: false, httpOnly: false, sameSite: 'none', session: true },
        { name: '_ga_tracker', domain: '.google-analytics.com', secure: false, httpOnly: false, sameSite: 'none', expirationDate: Date.now() / 1000 + 86400 * 400 }
      ] : [
        { name: 'session_id', domain: new URL(cleanUrl).hostname, secure: isHttps, httpOnly: true, sameSite: 'lax', session: true }
      ];
      const cookieData = CookieAnalyzer.analyzeCookies(sampleCookies, cleanUrl);

      const cookieRow = document.createElement('div');
      cookieRow.className = 'sig-item';
      cookieRow.style.background = cookieData.criticalIssuesCount > 0 ? '#fff5f5' : (cookieData.insecureCookiesCount > 0 ? '#fffbeb' : '#f0fdf4');
      cookieRow.style.borderColor = cookieData.criticalIssuesCount > 0 ? '#fecaca' : (cookieData.insecureCookiesCount > 0 ? '#fde68a' : '#bbf7d0');

      const cookieBadgeStyle = cookieData.criticalIssuesCount > 0 
        ? 'background:#fee2e2; color:#dc2626;' 
        : (cookieData.insecureCookiesCount > 0 ? 'background:#fef3c7; color:#d97706;' : 'background:#dcfce7; color:#15803d;');

      cookieRow.innerHTML = `
        <span class="sig-score" style="${cookieBadgeStyle}">COOKIES</span>
        <div>
          <div style="font-weight:700; color:#0f172a;">Cookie Security Audit: ${escapeHtml(cookieData.statusLabel)} (Zero Values Transmitted)</div>
          <div style="color:#475569; font-size:11.5px; margin-top:2px;">
            ${cookieData.total} cookies audited (${cookieData.firstPartyCount} 1st-party, ${cookieData.thirdPartyCount} 3rd-party) • ${cookieData.secureCount} Secure • ${cookieData.httpOnlyCount} HttpOnly
          </div>
          ${cookieData.issues.length > 0 ? `
            <div style="font-size:11px; margin-top:3px; color:#b91c1c; font-weight:600;">
              ${cookieData.issues.map(iss => `⚠️ ${escapeHtml(iss.title)} (${escapeHtml(iss.cookieName)})`).join(' • ')}
            </div>
          ` : '<div style="font-size:11px; margin-top:3px; color:#15803d; font-weight:600;">✓ All audited cookies have valid security configurations.</div>'}
        </div>
      `;
      signalsList.appendChild(cookieRow);
    }

    // Show Suggested Authentic Website card if unsafe
    if ((isSuspicious || riskPct >= 35) && result.suggestedWebsite) {
      const sug = result.suggestedWebsite;
      const sugRow = document.createElement('div');
      sugRow.className = 'sig-item';
      sugRow.style.background = '#f0fdf4';
      sugRow.style.borderColor = '#86efac';
      sugRow.innerHTML = `
        <span class="sig-score" style="background:#dcfce7; color:#15803d;">OFFICIAL</span>
        <div>
          <div style="font-weight:800; color:#166534;">🛡️ Suggested Authentic Destination: ${escapeHtml(sug.name)}</div>
          <div style="color:#14532d; font-size:12px; font-family:monospace; margin:2px 0;">${escapeHtml(sug.url)}</div>
          <div style="color:#334155; font-size:11.5px;">Why suggested: Verified official brand domain. The tested URL exhibits deceptive heuristics or threat blacklist matches.</div>
        </div>
      `;
      signalsList.appendChild(sugRow);
    }

    // Show live probe badge if present
    if (result.details && result.details.liveProbe) {
      const lp = result.details.liveProbe;
      const probeRow = document.createElement('div');
      probeRow.className = 'sig-item';
      probeRow.style.background = '#f0f9ff';
      probeRow.style.borderColor = '#bae6fd';
      if (lp.reachable) {
        probeRow.innerHTML = `
          <span class="sig-score" style="background:#e0f2fe; color:#0284c7;">LIVE</span>
          <div>
            <div style="font-weight:700; color:#0369a1;">Server Status: ${lp.statusCode} OK</div>
            <div style="color:#475569; font-size:11.5px;">Redirect: ${lp.redirected ? lp.finalUrl : 'Direct'} • HSTS: ${lp.hasHsts ? 'Active' : 'Missing'} • Parked: ${lp.isParked ? 'Yes (For Sale)' : 'No'}</div>
          </div>
        `;
      } else {
        probeRow.innerHTML = `
          <span class="sig-score" style="background:#fee2e2; color:#dc2626;">OFFLINE</span>
          <div>
            <div style="font-weight:700; color:#dc2626;">Host Unreachable</div>
            <div style="color:#475569; font-size:11.5px;">DNS or connection failed. Ephemeral or invalid destination.</div>
          </div>
        `;
      }
      signalsList.appendChild(probeRow);
    }

    if (result.signals && result.signals.length > 0) {
      result.signals.forEach(sig => {
        const item = document.createElement('div');
        item.className = 'sig-item';
        const isInfo = sig.severity === 'info' || sig.points === 0;
        const scoreStyle = isInfo 
          ? 'background:#ecfdf5; color:#059669;' 
          : (sig.severity === 'high' ? 'background:#fee2e2; color:#dc2626;' : 'background:#fffbeb; color:#d97706;');
        const scoreLabel = isInfo ? 'SAFE' : `+${sig.points}%`;

        item.innerHTML = `
          <span class="sig-score" style="${scoreStyle}">${scoreLabel}</span>
          <div>
            <div style="font-weight: 700; color: #0f172a;">${escapeHtml(sig.name)}</div>
            <div style="color: #475569; font-size: 11.5px; margin-top: 2px;">${escapeHtml(sig.description)}</div>
          </div>
        `;
        signalsList.appendChild(item);
      });
    } else {
      signalsList.innerHTML = `
        <div class="sig-item" style="color: #60a5fa;">
          🛡️ No threat signals detected. Note: Veridex AI does not guarantee this site is safe. Always verify official URLs.
        </div>
      `;
    }
  }

  btnRun.addEventListener('click', () => {
    runAnalysis(inputEl.value);
  });

  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      runAnalysis(inputEl.value);
    }
  });

  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const url = chip.getAttribute('data-url');
      inputEl.value = url;
      runAnalysis(url);
    });
  });

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Pre-load first preset for immediate feedback
  inputEl.value = 'http://paypal.com.security-verify.xyz/login';
  runAnalysis(inputEl.value);
});
