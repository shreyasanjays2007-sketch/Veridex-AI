/**
 * Veridex AI - Offline Cookie Security & Privacy Analyzer
 * Audits website cookie configurations, attributes, and potential vulnerabilities:
 * - Cookie names, domains, paths, expiry
 * - Security flags: Secure, HttpOnly, SameSite (Strict, Lax, None)
 * - First-party vs. Third-party tracking classification
 * - Identification of insecure configurations (missing Secure, missing HttpOnly, CSRF exposure, excessive lifetime)
 * 
 * CRITICAL PRIVACY & SECURITY DIRECTIVE:
 * - NEVER display, store, or transmit actual cookie values.
 * - All analysis is performed 100% offline and locally in-memory. Zero telemetry.
 */

// Helper: extract apex/registered domain for third-party detection
let _extractApex = null;
if (typeof extractApexDomain !== 'undefined') {
  _extractApex = extractApexDomain;
} else if (typeof require !== 'undefined') {
  try {
    const tld = require('./tld-risk.js');
    _extractApex = tld.extractApexDomain;
  } catch (e) {}
}

const CookieAnalyzer = {
  DISCLAIMER: 'Zero-Telemetry Notice: Veridex AI never displays, logs, or transmits actual cookie values. All cookie metadata is evaluated 100% locally and offline in memory.',

  // Common sensitive keyword patterns in cookie names (auth, session, identity)
  SENSITIVE_COOKIE_PATTERNS: [
    /session/i,
    /auth/i,
    /token/i,
    /jwt/i,
    /login/i,
    /user/i,
    /account/i,
    /pass/i,
    /cred/i,
    /secret/i,
    /key/i,
    /id$/i,
    /sid$/i,
    /uid$/i,
    /ssid/i,
    /csrf/i,
    /xsrf/i,
    /identity/i,
    /connect\.sid/i,
    /phpsessid/i,
    /jsessionid/i,
    /aspsessionid/i
  ],

  // Known third-party tracking / analytics cookie prefixes or names
  KNOWN_TRACKER_PATTERNS: [
    /^_ga/i,
    /^_gid/i,
    /^_gat/i,
    /^_fbp/i,
    /^_fbc/i,
    /^__cf_bm/i,
    /^_clck/i,
    /^_clsk/i,
    /^__utm/i,
    /^ide$/i,
    /^test_cookie$/i,
    /^fr$/i,
    /^muc_ads/i,
    /^personalization_id/i,
    /^bcookie/i,
    /^li_sugr/i,
    /^bscookie/i,
    /^anj/i,
    /^uuid2/i
  ],

  /**
   * Helper: extract apex domain from hostname or URL
   */
  getApexDomain(input) {
    if (!input) return '';
    try {
      let hostname = input;
      if (input.includes('://')) {
        hostname = new URL(input).hostname;
      }
      hostname = hostname.replace(/^\./, '').toLowerCase();

      if (_extractApex) {
        return _extractApex(hostname);
      }

      const parts = hostname.split('.');
      if (parts.length <= 2) return hostname;
      return parts.slice(-2).join('.');
    } catch (e) {
      return input.toLowerCase();
    }
  },

  /**
   * Determines if a cookie domain is third-party relative to the site's apex domain
   */
  isThirdPartyDomain(cookieDomain, siteUrlOrHost) {
    if (!cookieDomain || !siteUrlOrHost) return false;
    const cleanCookieDomain = cookieDomain.replace(/^\./, '').toLowerCase();
    const siteApex = this.getApexDomain(siteUrlOrHost);
    const cookieApex = this.getApexDomain(cleanCookieDomain);

    if (!siteApex || !cookieApex) return false;
    return siteApex !== cookieApex;
  },

  /**
   * Formats expiration date into human-readable label and calculates days remaining
   */
  formatExpiry(expirationDate, isSession) {
    if (isSession || !expirationDate) {
      return {
        text: 'Session (Expires when browser closes)',
        isSession: true,
        daysRemaining: null,
        isExcessive: false
      };
    }

    try {
      // expirationDate in Chrome Cookies API is in seconds (UNIX epoch)
      const epochMs = expirationDate > 1e11 ? expirationDate : expirationDate * 1000;
      const expDate = new Date(epochMs);
      const now = new Date();
      const diffMs = expDate.getTime() - now.getTime();
      const diffDays = Math.round(diffMs / (1000 * 60 * 60 * 24));

      const isExcessive = diffDays > 390; // Over 13 months / 1 year

      let relativeText = '';
      if (diffDays < 0) {
        relativeText = 'Expired';
      } else if (diffDays === 0) {
        relativeText = 'Expires today';
      } else if (diffDays === 1) {
        relativeText = 'Expires in 1 day';
      } else if (diffDays < 30) {
        relativeText = `Expires in ${diffDays} days`;
      } else if (diffDays < 365) {
        const months = Math.round(diffDays / 30);
        relativeText = `Expires in ~${months} month${months > 1 ? 's' : ''} (${diffDays} days)`;
      } else {
        const years = (diffDays / 365).toFixed(1);
        relativeText = `Expires in ~${years} years (${diffDays} days)`;
      }

      const dateStr = expDate.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });

      return {
        text: `${dateStr} (${relativeText})`,
        isSession: false,
        daysRemaining: diffDays,
        isExcessive,
        dateFormatted: dateStr,
        rawTimestamp: epochMs
      };
    } catch (e) {
      return {
        text: 'Unknown / Custom Expiry',
        isSession: false,
        daysRemaining: null,
        isExcessive: false
      };
    }
  },

  /**
   * Checks if a cookie name implies sensitive authentication or session credentials
   */
  isSensitiveName(cookieName) {
    if (!cookieName) return false;
    return this.SENSITIVE_COOKIE_PATTERNS.some(rx => rx.test(cookieName));
  },

  /**
   * Audits an individual sanitized cookie metadata object for security vulnerabilities
   */
  auditCookieSecurity(cookie, isSiteHttps) {
    const issues = [];
    let severity = 'clean'; // 'clean' | 'warning' | 'danger'
    const name = cookie.name || '';
    const isSensitive = this.isSensitiveName(name);

    // 1. Check Secure flag
    if (!cookie.secure) {
      if (isSiteHttps) {
        if (isSensitive) {
          issues.push({
            type: 'MISSING_SECURE_SENSITIVE',
            severity: 'danger',
            title: 'Critical: Insecure Transmission on Auth Cookie',
            description: `Cookie "${name}" appears to store session/auth tokens but lacks the "Secure" flag on an HTTPS website. It can be transmitted over unencrypted plaintext HTTP connections, vulnerable to network interception (Man-in-the-Middle).`
          });
          severity = 'danger';
        } else {
          issues.push({
            type: 'MISSING_SECURE',
            severity: 'warning',
            title: 'Missing Secure Flag',
            description: `Cookie "${name}" lacks the "Secure" flag on an HTTPS site and can be transmitted over unencrypted connections.`
          });
          if (severity !== 'danger') severity = 'warning';
        }
      }
    }

    // 2. Check HttpOnly flag
    if (!cookie.httpOnly) {
      if (isSensitive) {
        issues.push({
          type: 'MISSING_HTTPONLY_SENSITIVE',
          severity: 'danger',
          title: 'High Risk: Session Cookie Exposed to JavaScript (XSS Risk)',
          description: `Cookie "${name}" appears to be an authentication or session identifier but lacks the "HttpOnly" flag. Any malicious script or Cross-Site Scripting (XSS) attack on this page can steal this token directly.`
        });
        severity = 'danger';
      }
    }

    // 3. Check SameSite attribute
    const sameSiteNorm = (cookie.sameSite || 'unspecified').toLowerCase();
    if (sameSiteNorm === 'no_restriction' || sameSiteNorm === 'none') {
      if (!cookie.secure) {
        issues.push({
          type: 'SAMESITE_NONE_WITHOUT_SECURE',
          severity: 'danger',
          title: 'Invalid: SameSite=None without Secure Flag',
          description: `Cookie "${name}" has SameSite=None without the Secure flag. Modern browsers reject this cookie or flag it as unsafe.`
        });
        severity = 'danger';
      } else {
        issues.push({
          type: 'SAMESITE_NONE_CROSS_SITE',
          severity: 'warning',
          title: 'Cross-Site Context (SameSite=None)',
          description: `Cookie "${name}" is transmitted across third-party cross-site contexts, enabling cross-domain access.`
        });
        if (severity !== 'danger') severity = 'warning';
      }
    } else if (sameSiteNorm === 'unspecified') {
      issues.push({
        type: 'MISSING_SAMESITE',
        severity: 'warning',
        title: 'Missing Explicit SameSite Attribute',
        description: `Cookie "${name}" does not specify SameSite (defaults to browser Lax). Explicitly declaring SameSite=Strict or SameSite=Lax prevents Cross-Site Request Forgery (CSRF).`
      });
      if (severity !== 'danger') severity = 'warning';
    }

    // 4. Check Third-Party Tracking
    if (cookie.isThirdParty) {
      issues.push({
        type: 'THIRD_PARTY_TRACKER',
        severity: 'warning',
        title: 'Third-Party Tracking Cookie',
        description: `Originated from an external domain (${cookie.domain}), allowing third-party trackers to correlate your browsing history across multiple sites.`
      });
      if (severity !== 'danger') severity = 'warning';
    }

    // 5. Check Excessive Lifetime
    if (cookie.expiry && cookie.expiry.isExcessive) {
      issues.push({
        type: 'EXCESSIVE_LIFETIME',
        severity: 'warning',
        title: 'Excessive Cookie Lifetime (> 1 Year)',
        description: `Cookie persists for ${cookie.expiry.daysRemaining} days, exceeding recommended privacy retention boundaries and enabling long-term tracking.`
      });
      if (severity !== 'danger') severity = 'warning';
    }

    // 6. Check Prefix Violations (__Secure- and __Host-)
    if (name.startsWith('__Secure-')) {
      if (!cookie.secure) {
        issues.push({
          type: 'PREFIX_VIOLATION_SECURE',
          severity: 'danger',
          title: 'Cookie Prefix Security Violation (__Secure-)',
          description: `Cookie name begins with "__Secure-" but lacks the Secure flag, violating browser prefix security enforcement.`
        });
        severity = 'danger';
      }
    }
    if (name.startsWith('__Host-')) {
      const violatesHost = !cookie.secure || cookie.path !== '/' || (cookie.domain && cookie.domain.startsWith('.'));
      if (violatesHost) {
        issues.push({
          type: 'PREFIX_VIOLATION_HOST',
          severity: 'danger',
          title: 'Cookie Prefix Security Violation (__Host-)',
          description: `Cookie name begins with "__Host-" but violates host prefix rules (must have Secure=true, path="/", and cannot specify a domain with a leading dot).`
        });
        severity = 'danger';
      }
    }

    return {
      severity,
      issues
    };
  },

  /**
   * Primary Entry Point:
   * Audits an array of cookies for a given target website URL.
   * STRICT DIRECTIVE: NEVER displays, includes, or transmits cookie values.
   * 
   * @param {Array} rawCookies - Array of cookie objects (from chrome.cookies or simulated)
   * @param {string} siteUrl - Current website URL (e.g. "https://example.com/login")
   * @returns {Object} Complete cookie analysis report
   */
  analyzeCookies(rawCookies = [], siteUrl = '') {
    const isHttps = siteUrl ? siteUrl.startsWith('https:') : true;
    const siteApex = this.getApexDomain(siteUrl);

    let total = 0;
    let firstPartyCount = 0;
    let thirdPartyCount = 0;
    let sessionCount = 0;
    let persistentCount = 0;
    let secureCount = 0;
    let httpOnlyCount = 0;
    let sameSiteStrict = 0;
    let sameSiteLax = 0;
    let sameSiteNone = 0;
    let sameSiteUnspecified = 0;
    let insecureCookiesCount = 0;
    let criticalIssuesCount = 0;

    const auditedCookies = [];
    const allIssues = [];

    if (Array.isArray(rawCookies)) {
      total = rawCookies.length;

      for (const raw of rawCookies) {
        if (!raw || !raw.name) continue;

        // STRICT REDACTION: Do not copy or store raw.value under any circumstance!
        const isSession = Boolean(raw.session || !raw.expirationDate);
        const expiry = this.formatExpiry(raw.expirationDate, isSession);
        const isThirdParty = Boolean(raw.isThirdParty || this.isThirdPartyDomain(raw.domain, siteUrl));

        const sanitized = {
          name: String(raw.name),
          domain: String(raw.domain || siteApex || 'current-host'),
          path: String(raw.path || '/'),
          secure: Boolean(raw.secure),
          httpOnly: Boolean(raw.httpOnly),
          sameSite: (raw.sameSite || 'unspecified').toString().toLowerCase(),
          isSession,
          expiry,
          isThirdParty,
          isSensitive: this.isSensitiveName(raw.name),
          hostOnly: Boolean(raw.hostOnly)
        };

        // Audit cookie security
        const audit = this.auditCookieSecurity(sanitized, isHttps);
        sanitized.severity = audit.severity;
        sanitized.issues = audit.issues;

        // Statistics
        if (sanitized.isThirdParty) thirdPartyCount++;
        else firstPartyCount++;

        if (sanitized.isSession) sessionCount++;
        else persistentCount++;

        if (sanitized.secure) secureCount++;
        if (sanitized.httpOnly) httpOnlyCount++;

        if (sanitized.sameSite === 'strict') sameSiteStrict++;
        else if (sanitized.sameSite === 'lax') sameSiteLax++;
        else if (sanitized.sameSite === 'none' || sanitized.sameSite === 'no_restriction') sameSiteNone++;
        else sameSiteUnspecified++;

        if (audit.issues.length > 0) {
          insecureCookiesCount++;
          audit.issues.forEach(iss => {
            allIssues.push({
              cookieName: sanitized.name,
              cookieDomain: sanitized.domain,
              ...iss
            });
            if (iss.severity === 'danger') criticalIssuesCount++;
          });
        }

        auditedCookies.push(sanitized);
      }
    }

    // Determine overall cookie security posture
    let overallStatus = 'secure'; // 'secure' | 'caution' | 'insecure'
    let statusLabel = 'Clean / In Good Order';
    let statusBadge = '✓ Cookie Security Good';
    let statusBadgeClass = 'safe';

    if (criticalIssuesCount > 0) {
      overallStatus = 'insecure';
      statusLabel = `${criticalIssuesCount} Critical Security Issue${criticalIssuesCount > 1 ? 's' : ''} Detected`;
      statusBadge = `🚨 ${criticalIssuesCount} Insecure Issue${criticalIssuesCount > 1 ? 's' : ''}`;
      statusBadgeClass = 'danger';
    } else if (insecureCookiesCount > 0 || thirdPartyCount > 0) {
      overallStatus = 'caution';
      statusLabel = `${insecureCookiesCount} Cookie Warning${insecureCookiesCount > 1 ? 's' : ''} (Minor/Tracking)`;
      statusBadge = `⚠️ ${insecureCookiesCount} Cookie Warning${insecureCookiesCount > 1 ? 's' : ''}`;
      statusBadgeClass = 'caution';
    } else if (total === 0) {
      statusLabel = 'Zero Cookies Detected (Clean)';
      statusBadge = '✓ Zero Cookies';
      statusBadgeClass = 'safe';
    }

    const summaryText = total === 0
      ? 'No active cookies were detected on this webpage.'
      : `Audited ${total} cookie${total > 1 ? 's' : ''} (${firstPartyCount} first-party, ${thirdPartyCount} third-party). ${insecureCookiesCount} cookie${insecureCookiesCount !== 1 ? 's have' : ' has'} security warnings.`;

    return {
      total,
      firstPartyCount,
      thirdPartyCount,
      sessionCount,
      persistentCount,
      secureCount,
      missingSecureCount: total - secureCount,
      httpOnlyCount,
      missingHttpOnlyCount: total - httpOnlyCount,
      sameSiteStats: {
        strict: sameSiteStrict,
        lax: sameSiteLax,
        none: sameSiteNone,
        unspecified: sameSiteUnspecified
      },
      insecureCookiesCount,
      criticalIssuesCount,
      overallStatus,
      statusLabel,
      statusBadge,
      statusBadgeClass,
      summaryText,
      cookies: auditedCookies,
      issues: allIssues,
      disclaimer: this.DISCLAIMER,
      timestamp: new Date().toISOString()
    };
  },

  /**
   * Fallback parser for document.cookie in DOM context when chrome.cookies API is unavailable.
   * NEVER extracts or exposes cookie values.
   */
  parseDocumentCookies(cookieStr = '', siteUrl = '') {
    if (!cookieStr || typeof cookieStr !== 'string') {
      return this.analyzeCookies([], siteUrl);
    }

    const pairs = cookieStr.split(';');
    const rawCookies = [];

    for (const pair of pairs) {
      const trimmed = pair.trim();
      if (!trimmed) continue;
      const eqIdx = trimmed.indexOf('=');
      const name = eqIdx > -1 ? trimmed.slice(0, eqIdx).trim() : trimmed;
      if (!name) continue;

      // Note: document.cookie only reveals name and value for non-HttpOnly cookies.
      // We strictly discard value and analyze name heuristics.
      rawCookies.push({
        name,
        domain: siteUrl ? this.getApexDomain(siteUrl) : 'current-host',
        path: '/',
        secure: siteUrl ? siteUrl.startsWith('https:') : false,
        httpOnly: false, // In JS document.cookie context, HttpOnly cookies are hidden by browser design
        sameSite: 'unspecified',
        session: true,
        isFromDocumentCookie: true
      });
    }

    const analysis = this.analyzeCookies(rawCookies, siteUrl);
    analysis.isLimitedDomScan = true;
    analysis.domNotice = 'Extracted via DOM document.cookie. HttpOnly cookies are hidden from JavaScript (proper browser security). Full metadata inspection requires Extension Cookies API.';
    return analysis;
  }
};

// Export for Node.js, Service Worker, and Browser Window environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CookieAnalyzer };
}
if (typeof self !== 'undefined') {
  self.CookieAnalyzer = CookieAnalyzer;
}
if (typeof window !== 'undefined') {
  window.CookieAnalyzer = CookieAnalyzer;
}
