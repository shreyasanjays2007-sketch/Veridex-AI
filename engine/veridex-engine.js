/**
 * Veridex AI - Advanced Scam & Phishing Detection & Live Verification Engine
 * Detects fake and scam websites, typos, lookalikes, combosquatting, wrong TLDs,
 * and subdomain camouflage with accurate, varying multi-factor risk scoring.
 */

// Handle environment imports
let brandsList = typeof VERIDEX_BRANDS !== 'undefined' ? VERIDEX_BRANDS : [];
let verifiedRealDomains = typeof VERIFIED_REAL_DOMAINS !== 'undefined' ? VERIFIED_REAL_DOMAINS : new Set();
let verifiedGovDomains = typeof VERIFIED_GOVERNMENT_DOMAINS !== 'undefined' ? VERIFIED_GOVERNMENT_DOMAINS : new Set();
let knownScamDomains = typeof KNOWN_SCAM_DOMAINS !== 'undefined' ? KNOWN_SCAM_DOMAINS : new Set();
let _isVerifiedReal = typeof isVerifiedRealDomain !== 'undefined' ? isVerifiedRealDomain : null;
let _isVerifiedGovernment = typeof isVerifiedGovernmentDomain !== 'undefined' ? isVerifiedGovernmentDomain : null;
let _detectGovernmentSpoofing = typeof detectGovernmentSpoofing !== 'undefined' ? detectGovernmentSpoofing : null;
let _classifyDomain = typeof classifyDomain !== 'undefined' ? classifyDomain : null;
let _normalizeDomain = typeof normalizeDomain !== 'undefined' ? normalizeDomain : null;
let _classificationCategories = typeof CLASSIFICATION_CATEGORIES !== 'undefined' ? CLASSIFICATION_CATEGORIES : null;
let _veridexDisclaimer = typeof VERIDEX_DISCLAIMER !== 'undefined' ? VERIDEX_DISCLAIMER : 'Veridex AI operates offline using curated threat feeds, structural heuristics, and verified domain registries. While extensive, this local database cannot and does not claim to recognise every government entity or emerging phishing website worldwide. Users should always exercise independent caution.';
let _isKnownScam = typeof isKnownScamDomain !== 'undefined' ? isKnownScamDomain : null;
let _getSuggestedOfficialWebsite = typeof getSuggestedOfficialWebsite !== 'undefined' ? getSuggestedOfficialWebsite : null;

let tldSet = typeof HIGH_RISK_TLDS !== 'undefined' ? HIGH_RISK_TLDS : new Set();
let explicitScamWords = typeof EXPLICIT_SCAM_KEYWORDS !== 'undefined' ? EXPLICIT_SCAM_KEYWORDS : [];
let phishActionWords = typeof PHISH_ACTION_WORDS !== 'undefined' ? PHISH_ACTION_WORDS : [];
let phishTargetWords = typeof PHISH_TARGET_WORDS !== 'undefined' ? PHISH_TARGET_WORDS : [];

let _extractApexDomain = typeof extractApexDomain !== 'undefined' ? extractApexDomain : null;
let _calculateShannonEntropy = typeof calculateShannonEntropy !== 'undefined' ? calculateShannonEntropy : null;
let _analyzeHomoglyphs = typeof analyzeHomoglyphs !== 'undefined' ? analyzeHomoglyphs : null;
let _levenshteinDistance = typeof levenshteinDistance !== 'undefined' ? levenshteinDistance : null;

// IP Intelligence & Offline Hosting Analysis
let _lookupIpIntelligence = typeof lookupIpIntelligence !== 'undefined' ? lookupIpIntelligence : null;
let _extractIpFromHost = typeof extractIpFromHost !== 'undefined' ? extractIpFromHost : null;
let _isIpAddress = typeof isIpAddress !== 'undefined' ? isIpAddress : null;

// Cookie Security Analyzer
let _CookieAnalyzer = typeof CookieAnalyzer !== 'undefined' ? CookieAnalyzer : null;

// Machine Learning Inference Engine
let _VeridexMLEngine = typeof VeridexMLEngine !== 'undefined' ? VeridexMLEngine : null;

if (typeof require !== 'undefined') {
  try {
    const brandsModule = require('./brand-database.js');
    const tldModule = require('./tld-risk.js');
    let mlModule = null;
    try {
      mlModule = require('./veridex-ml-model.js');
    } catch (e) {}
    if (mlModule && !_VeridexMLEngine) _VeridexMLEngine = mlModule.VeridexMLEngine;
    let ipModule = null;
    try {
      ipModule = require('./ip-intelligence.js');
    } catch (e) {}
    let cookieModule = null;
    try {
      cookieModule = require('./cookie-analyzer.js');
    } catch (e) {}

    if (cookieModule && !_CookieAnalyzer) _CookieAnalyzer = cookieModule.CookieAnalyzer;

    if (brandsList.length === 0) brandsList = brandsModule.VERIDEX_BRANDS || [];
    if (verifiedRealDomains.size === 0) verifiedRealDomains = brandsModule.VERIFIED_REAL_DOMAINS || new Set();
    if (verifiedGovDomains.size === 0) verifiedGovDomains = brandsModule.VERIFIED_GOVERNMENT_DOMAINS || new Set();
    if (knownScamDomains.size === 0) knownScamDomains = brandsModule.KNOWN_SCAM_DOMAINS || new Set();
    if (!_isVerifiedReal) _isVerifiedReal = brandsModule.isVerifiedRealDomain;
    if (!_isVerifiedGovernment) _isVerifiedGovernment = brandsModule.isVerifiedGovernmentDomain;
    if (!_detectGovernmentSpoofing) _detectGovernmentSpoofing = brandsModule.detectGovernmentSpoofing;
    if (!_classifyDomain) _classifyDomain = brandsModule.classifyDomain;
    if (!_normalizeDomain) _normalizeDomain = brandsModule.normalizeDomain;
    if (!_classificationCategories) _classificationCategories = brandsModule.CLASSIFICATION_CATEGORIES;
    if (!_veridexDisclaimer && brandsModule.VERIDEX_DISCLAIMER) _veridexDisclaimer = brandsModule.VERIDEX_DISCLAIMER;
    if (!_isKnownScam) _isKnownScam = brandsModule.isKnownScamDomain;
    if (!_getSuggestedOfficialWebsite) _getSuggestedOfficialWebsite = brandsModule.getSuggestedOfficialWebsite;

    if (tldSet.size === 0) tldSet = tldModule.HIGH_RISK_TLDS || new Set();
    if (explicitScamWords.length === 0) explicitScamWords = tldModule.EXPLICIT_SCAM_KEYWORDS || [];
    if (phishActionWords.length === 0) phishActionWords = tldModule.PHISH_ACTION_WORDS || [];
    if (phishTargetWords.length === 0) phishTargetWords = tldModule.PHISH_TARGET_WORDS || [];
    if (!_extractApexDomain) _extractApexDomain = tldModule.extractApexDomain;
    if (!_calculateShannonEntropy) _calculateShannonEntropy = tldModule.calculateShannonEntropy;
    if (!_analyzeHomoglyphs) _analyzeHomoglyphs = tldModule.analyzeHomoglyphs;
    if (!_levenshteinDistance) _levenshteinDistance = tldModule.levenshteinDistance;

    if (ipModule) {
      if (!_lookupIpIntelligence) _lookupIpIntelligence = ipModule.lookupIpIntelligence;
      if (!_extractIpFromHost) _extractIpFromHost = ipModule.extractIpFromHost;
      if (!_isIpAddress) _isIpAddress = ipModule.isIpAddress;
    }
  } catch (e) {
    console.error("Veridex Engine Error:", e);
  }
}

// Fallback aliases if running in browser global scope
if (!_extractApexDomain && typeof extractApexDomain !== 'undefined') _extractApexDomain = extractApexDomain;
if (!_calculateShannonEntropy && typeof calculateShannonEntropy !== 'undefined') _calculateShannonEntropy = calculateShannonEntropy;
if (!_analyzeHomoglyphs && typeof analyzeHomoglyphs !== 'undefined') _analyzeHomoglyphs = analyzeHomoglyphs;
if (!_levenshteinDistance && typeof levenshteinDistance !== 'undefined') _levenshteinDistance = levenshteinDistance;
if (!_isVerifiedReal && typeof isVerifiedRealDomain !== 'undefined') _isVerifiedReal = isVerifiedRealDomain;
if (!_isVerifiedGovernment && typeof isVerifiedGovernmentDomain !== 'undefined') _isVerifiedGovernment = isVerifiedGovernmentDomain;
if (!_detectGovernmentSpoofing && typeof detectGovernmentSpoofing !== 'undefined') _detectGovernmentSpoofing = detectGovernmentSpoofing;
if (!_classifyDomain && typeof classifyDomain !== 'undefined') _classifyDomain = classifyDomain;
if (!_normalizeDomain && typeof normalizeDomain !== 'undefined') _normalizeDomain = normalizeDomain;
if (!_classificationCategories && typeof CLASSIFICATION_CATEGORIES !== 'undefined') _classificationCategories = CLASSIFICATION_CATEGORIES;
if (!_veridexDisclaimer && typeof VERIDEX_DISCLAIMER !== 'undefined') _veridexDisclaimer = VERIDEX_DISCLAIMER;
if (!_isKnownScam && typeof isKnownScamDomain !== 'undefined') _isKnownScam = isKnownScamDomain;
if (!_getSuggestedOfficialWebsite && typeof getSuggestedOfficialWebsite !== 'undefined') _getSuggestedOfficialWebsite = getSuggestedOfficialWebsite;
if (!_lookupIpIntelligence && typeof lookupIpIntelligence !== 'undefined') _lookupIpIntelligence = lookupIpIntelligence;
if (!_extractIpFromHost && typeof extractIpFromHost !== 'undefined') _extractIpFromHost = extractIpFromHost;
if (!_isIpAddress && typeof isIpAddress !== 'undefined') _isIpAddress = isIpAddress;
if (!_VeridexMLEngine && typeof VeridexMLEngine !== 'undefined') _VeridexMLEngine = VeridexMLEngine;

// High-confidence Top Level Domain risk classification
const SUSPICIOUS_CHEAP_TLDS = new Set([
  'site', 'online', 'space', 'website', 'store', 'club', 'pro', 'fun', 'host', 'press'
]);

class VeridexEngine {
  constructor() {
    this.thresholds = {
      caution: 22, // Elevated vigilance (22% - 34%)
      warning: 35, // Suspicious threshold (>= 35%)
      danger: 60   // Severe Threat (>= 60%)
    };
    try {
      this.mlEngine = _VeridexMLEngine ? new _VeridexMLEngine() : null;
    } catch (e) {
      this.mlEngine = null;
    }
  }

  /**
   * Live Network & Content Verification (Async)
   */
  async verifyLive(urlString) {
    if (!urlString || typeof urlString !== 'string') {
      return this.analyze(urlString);
    }

    let cleanUrl = urlString.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'https://' + cleanUrl;
    }

    let probe = {
      reachable: false,
      statusCode: null,
      finalUrl: cleanUrl,
      redirected: false,
      hasHsts: false,
      hasCsp: false,
      isParked: false,
      domSignals: {
        hasPasswordField: false,
        hasCreditCardField: false,
        externalFormActions: [],
        pageTitle: '',
        hasUrgencyPatterns: false,
        hasCountdown: false
      }
    };

    if (typeof fetch === 'function') {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3500);

        const res = await fetch(cleanUrl, {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VeridexAI/2.0'
          },
          signal: controller.signal
        });

        clearTimeout(timeout);
        probe.reachable = true;
        probe.statusCode = res.status;
        probe.finalUrl = res.url;
        probe.redirected = res.url !== cleanUrl;

        // Inspect response headers
        probe.hasHsts = res.headers.has('strict-transport-security');
        probe.hasCsp = res.headers.has('content-security-policy');

        const text = await res.text();
        const html = text.slice(0, 45000).toLowerCase();

        // Check if page is a parked / for-sale domain
        const parkingTerms = [
          'domain is for sale', 'buy this domain', 'is parked',
          'data-parking', 'parking-render', 'aftermarket.com',
          'sedo.com', 'sedoparking', 'dan.com', 'godaddy.com/domainsearch'
        ];
        if (parkingTerms.some(term => html.includes(term))) {
          probe.isParked = true;
        }

        // Check page title
        const titleMatch = text.slice(0, 10000).match(/<title[^>]*>([^<]+)<\/title>/i);
        if (titleMatch) {
          probe.domSignals.pageTitle = titleMatch[1].trim();
        }

        // Check forms & credential fields
        if (/<input[^>]+type=["']?password["']?/i.test(html)) {
          probe.domSignals.hasPasswordField = true;
        }
        if (/<input[^>]+(?:name|autocomplete|id)=["']?[^"']*(?:card|cc-num|cvv)[^"']*/i.test(html)) {
          probe.domSignals.hasCreditCardField = true;
        }

        // Check urgency & countdown
        if (html.includes('countdown') || html.includes('timer') || html.includes('expires in')) {
          probe.domSignals.hasCountdown = true;
        }
        if (html.includes('suspended') || html.includes('urgent action') || html.includes('immediate verify')) {
          probe.domSignals.hasUrgencyPatterns = true;
        }

        // Form action exfiltration
        const formMatches = [...text.slice(0, 30000).matchAll(/<form[^>]+action=["']([^"']+)["']/gi)];
        for (const fm of formMatches) {
          try {
            const dest = new URL(fm[1], res.url);
            if (dest.hostname && dest.hostname !== new URL(res.url).hostname) {
              probe.domSignals.externalFormActions.push(dest.hostname);
            }
          } catch (e) {}
        }

      } catch (err) {
        probe.reachable = false;
        probe.error = err.message;
      }
    }

    return this.analyze(cleanUrl, probe.domSignals, probe);
  }

  /**
   * Primary Evaluation Engine: Multi-Factor Varying Risk Scoring
   * Evaluates across 4 dimensions:
   * 1. Domain Reputation & Global Database Status
   * 2. Lexical & Brand Deception Analysis
   * 3. Connection & Transport Layer Security
   * 4. In-Page Behavioral & DOM Heuristics
   * 5. Offline IP Intelligence & Hosting Risk Analysis
   */
  analyze(urlString, domSignals = null, liveProbe = null, serverIp = null) {
    const signals = [];

    if (!urlString || typeof urlString !== 'string') {
      return this._createResult(0, 'neutral', 'safe', 'Internal or blank destination', [], {
        url: urlString || '',
        hostname: 'localhost',
        categoryScores: { domain: 0, lexical: 0, security: 0, content: 0 },
        ipIntelligence: _lookupIpIntelligence ? _lookupIpIntelligence(null) : null
      });
    }

    const cleanUrl = urlString.trim();
    const lowerUrl = cleanUrl.toLowerCase();

    // Skip internal browser system schemes
    if (lowerUrl.startsWith('chrome://') || lowerUrl.startsWith('edge://') ||
        lowerUrl.startsWith('about:') || lowerUrl.startsWith('chrome-extension://')) {
      return this._createResult(0, 'neutral', 'safe', 'Internal browser system page', [], {
        url: cleanUrl,
        hostname: 'browser-system',
        isInternal: true,
        categoryScores: { domain: 0, lexical: 0, security: 0, content: 0 },
        ipIntelligence: _lookupIpIntelligence ? _lookupIpIntelligence(null) : null
      });
    }

    let parsedUrl;
    try {
      const urlToParse = (cleanUrl.startsWith('http://') || cleanUrl.startsWith('https://'))
        ? cleanUrl
        : 'https://' + cleanUrl;
      parsedUrl = new URL(urlToParse);
    } catch (e) {
      signals.push({
        id: 'malformed_url',
        severity: 'high',
        category: 'lexical',
        name: 'Malformed URL Syntax',
        description: 'The URL syntax is malformed or obscured to evade scanner detection.',
        points: 75
      });
      return this._createResult(75, 'suspicious', 'danger', 'Malformed URL structure', signals, {
        url: cleanUrl,
        categoryScores: { domain: 30, lexical: 80, security: 30, content: 0 },
        ipIntelligence: _lookupIpIntelligence ? _lookupIpIntelligence(null) : null
      });
    }

    const protocol = parsedUrl.protocol;
    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const search = parsedUrl.search.toLowerCase();
    const port = parsedUrl.port;
    const apexDomain = _extractApexDomain ? _extractApexDomain(hostname) : hostname;
    const apexBase = apexDomain.split('.')[0];
    const hostParts = hostname.split('.');
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';

    // Resolve IP Intelligence (Offline)
    let targetIp = null;
    if (typeof serverIp === 'string' && serverIp.trim()) {
      targetIp = serverIp.trim();
    } else if (typeof liveProbe === 'string' && liveProbe.trim()) {
      targetIp = liveProbe.trim();
    } else if (liveProbe && typeof liveProbe === 'object' && liveProbe.ip) {
      targetIp = liveProbe.ip;
    } else if (_extractIpFromHost) {
      targetIp = _extractIpFromHost(hostname);
    }
    const ipIntelligence = _lookupIpIntelligence ? _lookupIpIntelligence(targetIp) : null;

    // Track category sub-scores (0 to 100 each)
    let domainScore = 0;
    let lexicalScore = 0;
    let securityScore = 0;
    let contentScore = 0;

    // 1. Government Spoofing & Deceptive Impersonation Check
    const govSpoofCheck = _detectGovernmentSpoofing ? _detectGovernmentSpoofing(hostname, apexDomain) : { isSpoofing: false };
    if (govSpoofCheck.isSpoofing) {
      signals.push({
        id: 'government_deceptive_spoofing',
        severity: 'high',
        category: 'domain',
        name: 'Government Entity Deceptive Spoofing',
        description: govSpoofCheck.reason,
        points: govSpoofCheck.points || 94
      });
      domainScore += (govSpoofCheck.points || 94);
    }

    // 2. Official Government Allowlist Verification (Indian & Global Verified Portals)
    const isVerifiedGov = _isVerifiedGovernment ? _isVerifiedGovernment(hostname, apexDomain) : (verifiedGovDomains.has(hostname) || verifiedGovDomains.has(apexDomain));
    if (isVerifiedGov && !govSpoofCheck.isSpoofing) {
      const databaseMatch = {
        isReal: true,
        isGov: true,
        isFake: false,
        status: 'verified_government',
        label: 'Verified Official Government Portal',
        description: 'Domain is an authenticated official government entity confirmed in the Veridex Trusted Government Allowlist.'
      };
      signals.push({
        id: 'verified_government_domain',
        severity: 'info',
        category: 'domain',
        name: 'Official Government Portal Verified',
        description: `Domain '${hostname}' is authenticated in the Veridex Trusted Government Allowlist of official public ministries and national portals.`,
        points: 0
      });

      const classification = _classifyDomain ? _classifyDomain(hostname, apexDomain, {
        isGovernment: true,
        isKnownScam: false,
        isVerifiedReal: true,
        isGovSpoof: false,
        riskPercentage: 0,
        verdict: 'neutral'
      }) : null;

      return this._createResult(0, 'neutral', 'safe', 'Official Government Portal — Confirmed Authenticated Government Entity', signals, {
        url: cleanUrl,
        hostname,
        apexDomain,
        protocol,
        level: 'safe',
        levelLabel: 'Verified Government Portal',
        isCanonicalBrand: true,
        databaseMatch,
        classification,
        disclaimer: _veridexDisclaimer,
        categoryScores: { domain: 0, lexical: 0, security: 0, content: 0 },
        liveProbe: liveProbe || null,
        ipIntelligence: ipIntelligence || null
      });
    }

    // 3. Global Database Check: Verified Real vs Known Scam
    const isVerifiedReal = _isVerifiedReal ? _isVerifiedReal(hostname, apexDomain) : verifiedRealDomains.has(apexDomain);
    const isKnownScam = _isKnownScam ? _isKnownScam(hostname, apexDomain) : knownScamDomains.has(apexDomain);

    let databaseMatch = {
      isReal: false,
      isFake: false,
      status: 'unverified',
      label: 'Heuristic & Behavioral Analysis',
      description: 'Domain evaluated using real-time algorithmic heuristics.'
    };

    // If matches Verified Real Database (0 False-Positive Guarantee)
    if (isVerifiedReal && !govSpoofCheck.isSpoofing) {
      databaseMatch = {
        isReal: true,
        isFake: false,
        status: 'verified_real',
        label: 'Verified Authentic Domain',
        description: 'Domain is recognized and validated in the Veridex Global Verified Registry.'
      };
      signals.push({
        id: 'verified_real_domain',
        severity: 'info',
        category: 'domain',
        name: 'Verified Authentic Registry Match',
        description: `Domain '${hostname}' is authenticated in the Veridex Global Safe Database of legitimate institutions.`,
        points: 0
      });

      const classification = _classifyDomain ? _classifyDomain(hostname, apexDomain, {
        isGovernment: false,
        isKnownScam: false,
        isVerifiedReal: true,
        isGovSpoof: false,
        riskPercentage: 0,
        verdict: 'neutral'
      }) : null;

      // Verified domains have 0% baseline risk
      return this._createResult(0, 'neutral', 'safe', 'Verified Authentic Domain — Confirmed Safe Registry Match', signals, {
        url: cleanUrl,
        hostname,
        apexDomain,
        protocol,
        level: 'safe',
        levelLabel: 'Verified Safe',
        isCanonicalBrand: true,
        databaseMatch,
        classification,
        disclaimer: _veridexDisclaimer,
        categoryScores: { domain: 0, lexical: 0, security: 0, content: 0 },
        liveProbe: liveProbe || null,
        ipIntelligence: ipIntelligence || null
      });
    }

    // If matches Known Scam Database
    if (isKnownScam) {
      databaseMatch = {
        isReal: false,
        isFake: true,
        status: 'known_fake',
        label: 'Confirmed Phishing / Scam Domain',
        description: 'Domain matches an active fraudulent campaign or confirmed deceptive phishing portal in Threat Intelligence.'
      };
      signals.push({
        id: 'known_scam_threat',
        severity: 'high',
        category: 'domain',
        name: 'Confirmed Fraudulent Domain (Threat Feed)',
        description: `Domain '${hostname}' is logged in the Veridex Threat Intelligence Feed as an active scam, fake login, or fraud destination.`,
        points: 92
      });
      domainScore += 92;
    }

    // 2. Minimal Variation & Brand Impersonation Detection (Typos, Hyphenation, TLD Spoofing, Subdomains)
    const brandCheck = this._detectBrandSpoofing(hostname, apexDomain, apexBase, tld);
    if (brandCheck.detected) {
      signals.push({
        id: 'brand_spoofing',
        severity: 'high',
        category: 'lexical',
        name: `Brand Impersonation (${brandCheck.brandName})`,
        description: brandCheck.reason,
        points: brandCheck.points
      });
      lexicalScore += brandCheck.points;
    } else if (brandCheck.isCanonical) {
      signals.push({
        id: 'canonical_brand_domain',
        severity: 'info',
        category: 'domain',
        name: `Official ${brandCheck.brandName} Domain`,
        description: `Authenticated official web property for ${brandCheck.brandName}.`,
        points: 0
      });
    }

    // 3. Explicit Fraud & Scam Keyword Evidence (e.g. scam.com, fake-login, robux, etc.)
    if (!brandCheck.isCanonical) {
      const foundScamWord = explicitScamWords.find(word => {
        return apexBase === word || apexBase.includes(word) || hostname.includes(word);
      });

      if (foundScamWord) {
        const isExact = apexBase === foundScamWord;
        const pts = isExact ? 80 : 75;
        signals.push({
          id: 'explicit_scam_keyword',
          severity: 'high',
          category: 'lexical',
          name: `Fraud / Scam Keyword Detected ('${foundScamWord}')`,
          description: `The domain explicitly includes the fraudulent keyword '${foundScamWord}'. Unverified domains with this keyword represent high-confidence deceptive or scam schemes.`,
          points: pts
        });
        lexicalScore += pts;
      }
    }

    // 4. Compound Phishing Keyword Pairing (Action + Target terms)
    if (!brandCheck.isCanonical) {
      const matchedActions = phishActionWords.filter(w => apexBase.includes(w) || hostname.includes(w));
      const matchedTargets = phishTargetWords.filter(w => apexBase.includes(w) || hostname.includes(w));

      if (matchedActions.length >= 1 && matchedTargets.length >= 1) {
        const pts = 72;
        signals.push({
          id: 'compound_phishing_keywords',
          severity: 'high',
          category: 'lexical',
          name: 'Deceptive Authentication Keyword Pairing',
          description: `Domain pairs credential action terms [${matchedActions.slice(0, 2).join(', ')}] with sensitive targets [${matchedTargets.slice(0, 2).join(', ')}], a classic credential harvesting pattern.`,
          points: pts
        });
        lexicalScore += pts;
      } else if (matchedActions.length >= 2 || matchedTargets.length >= 2) {
        const pts = 48;
        signals.push({
          id: 'multiple_sensitive_keywords',
          severity: 'medium',
          category: 'lexical',
          name: 'Stitched Security Terminology',
          description: 'Domain stitches multiple authentication/security terms together on an unverified domain.',
          points: pts
        });
        lexicalScore += pts;
      } else if (matchedActions.length === 1 || matchedTargets.length === 1) {
        // Minor varying risk factor for single sensitive term on unverified domain
        const pts = 14;
        signals.push({
          id: 'sensitive_keyword_presence',
          severity: 'low',
          category: 'lexical',
          name: 'Sensitive Authentication Keyword Present',
          description: `Domain contains sensitive term '${(matchedActions[0] || matchedTargets[0])}' on an unverified host.`,
          points: pts
        });
        lexicalScore += pts;
      }
    }

    // 5. Homoglyph Lookalike / Punycode Attacks
    if (_analyzeHomoglyphs) {
      const homoglyphAnalysis = _analyzeHomoglyphs(hostname);
      if (homoglyphAnalysis.hasHomoglyphs) {
        const pts = 82;
        signals.push({
          id: 'homoglyph_attack',
          severity: 'high',
          category: 'lexical',
          name: 'Homoglyph / Punycode Deception',
          description: 'Domain uses deceptive lookalike characters (Cyrillic lookalikes or Punycode xn--) to visually mimic another domain.',
          points: pts
        });
        lexicalScore += pts;
      }
    }

    // 6. TLD & Registrar Abuse Risk Tiers (Varying risk by TLD reputation)
    if (!brandCheck.isCanonical) {
      if (tldSet.has(tld)) {
        const pts = 32;
        signals.push({
          id: 'high_risk_tld',
          severity: 'medium',
          category: 'domain',
          name: `High-Risk Top-Level Domain (.${tld})`,
          description: `Top-level domain '.${tld}' has statistically high abuse and disposable fraud registration rates.`,
          points: pts
        });
        domainScore += pts;
      } else if (SUSPICIOUS_CHEAP_TLDS.has(tld)) {
        const pts = 18;
        signals.push({
          id: 'suspicious_cheap_tld',
          severity: 'low',
          category: 'domain',
          name: `Budget Generic Domain Extension (.${tld})`,
          description: `Domain extension '.${tld}' is frequently utilized in short-lived promotional and automated campaigns.`,
          points: pts
        });
        domainScore += pts;
      } else {
        // Standard baseline reputation for generic/ccTLDs (.com, .org, .net, .in, etc.)
        domainScore += 6;
      }
    }

    // 7. Shannon Entropy (Randomness / DGA domain generation)
    if (!brandCheck.isCanonical && _calculateShannonEntropy) {
      const entropy = _calculateShannonEntropy(apexBase);
      if (entropy > 3.85 && apexBase.length >= 10) {
        const pts = Math.min(38, Math.round((entropy - 3.4) * 28));
        signals.push({
          id: 'high_entropy_domain',
          severity: 'medium',
          category: 'lexical',
          name: 'High Entropy Domain (Algorithmic / DGA)',
          description: `Domain exhibits high character randomness (Shannon Entropy: ${entropy.toFixed(2)}), typical of automated disposable phishing campaigns.`,
          points: pts
        });
        lexicalScore += pts;
      }
    }

    // 8. Structural Heuristics: Hyphens, Numbers, Subdomain Camouflage
    if (!brandCheck.isCanonical) {
      const hyphenCount = (hostname.match(/-/g) || []).length;
      if (hyphenCount >= 3) {
        const pts = 22;
        signals.push({
          id: 'excessive_hyphens',
          severity: 'medium',
          category: 'lexical',
          name: 'Excessive Hyphenated Prefixing',
          description: `Hostname contains ${hyphenCount} hyphens, commonly used to stitch brand names and security terms together.`,
          points: pts
        });
        lexicalScore += pts;
      } else if (hyphenCount === 2) {
        lexicalScore += 8;
      } else if (hyphenCount === 1) {
        lexicalScore += 4;
      }

      // Check numbers in domain
      if (/\d/.test(apexBase) && !/^\d+$/.test(apexBase)) {
        domainScore += 6;
      }

      // Excessive Subdomain Stacking (e.g. login.secure.verify.server.com)
      if (hostParts.length >= 4) {
        const pts = 16;
        signals.push({
          id: 'excessive_subdomains',
          severity: 'low',
          category: 'domain',
          name: 'Deep Multi-Level Subdomain Structure',
          description: `Host structure has ${hostParts.length} levels, frequently used to obscure true apex destination.`,
          points: pts
        });
        domainScore += pts;
      }
    }

    // 9. Path & Query Parameter Phishing Traps
    if (!brandCheck.isCanonical) {
      const suspiciousPathWords = ['/login', '/signin', '/sign-in', '/verify', '/verification', '/auth', '/update', '/billing', '/account', '/wp-admin', '/admin'];
      const matchedPath = suspiciousPathWords.find(pw => pathname.includes(pw));
      if (matchedPath) {
        const pts = 18;
        signals.push({
          id: 'credential_path_heuristic',
          severity: 'medium',
          category: 'lexical',
          name: `Authentication Path on Unverified Host ('${matchedPath}')`,
          description: `Page path targets authentication or credential collection on an unverified domain.`,
          points: pts
        });
        lexicalScore += pts;
      }

      // Query parameter redirection/token lures
      if (search.includes('redirect=') || search.includes('return=') || search.includes('url=http') || search.includes('token=')) {
        lexicalScore += 12;
      }

      // Suspicious executable or archive downloads in URL
      if (pathname.endsWith('.exe') || pathname.endsWith('.scr') || pathname.endsWith('.bat') || pathname.endsWith('.apk')) {
        const pts = 36;
        signals.push({
          id: 'executable_download_heuristic',
          severity: 'high',
          category: 'lexical',
          name: 'Direct Executable / Script Payload URL',
          description: 'URL directly points to an executable application or installer payload.',
          points: pts
        });
        lexicalScore += pts;
      }
    }

    // 10. Connection & Transport Security (HTTP vs HTTPS, Raw IP, Non-Standard Ports)
    if (protocol === 'http:' && !hostname.startsWith('127.') && hostname !== 'localhost') {
      const pts = 20;
      signals.push({
        id: 'unencrypted_http',
        severity: 'medium',
        category: 'security',
        name: 'Insecure Connection (Plain HTTP)',
        description: 'Connection is unencrypted plain-text HTTP. Data submitted here is exposed to network interception.',
        points: pts
      });
      securityScore += pts;
    } else if (protocol === 'https:') {
      // Small positive trust credit for valid HTTPS
      securityScore = Math.max(0, securityScore - 4);
    }

    // Raw IP Address Hostname
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
    if (isIpv4 || isIpv6) {
      const isPrivate = hostname.startsWith('127.') || hostname === 'localhost' || hostname === '0.0.0.0';
      const pts = isPrivate ? 15 : 76;
      signals.push({
        id: 'ip_hostname',
        severity: isPrivate ? 'medium' : 'high',
        category: 'security',
        name: 'Raw IP Hostname Navigation',
        description: `Site uses a raw IP address (${hostname}) instead of a verified domain name. Commercial services do not ask users to browse via raw IP addresses.`,
        points: pts
      });
      securityScore += pts;
    }

    // 11. Offline IP Intelligence & Hosting Threat Match
    if (ipIntelligence) {
      if (ipIntelligence.isMalicious) {
        const pts = 85;
        signals.push({
          id: 'malicious_ip_threat_match',
          severity: 'high',
          category: 'security',
          name: `Confirmed Malicious Host IP (${ipIntelligence.maliciousMatch ? ipIntelligence.maliciousMatch.threatType : 'Threat Feed'})`,
          description: `Server IP (${ipIntelligence.ip}) matches confirmed malicious/phishing infrastructure in the offline threat database.`,
          points: pts
        });
        securityScore += pts;
      } else if (ipIntelligence.isHighRiskHosting && !brandCheck.isCanonical) {
        const pts = 30;
        signals.push({
          id: 'bulletproof_hosting_risk',
          severity: 'medium',
          category: 'security',
          name: `High-Risk / Bulletproof Hosting (${ipIntelligence.organization})`,
          description: `Server IP (${ipIntelligence.ip}) is hosted on network ${ipIntelligence.asn} (${ipIntelligence.countryName}) frequently associated with bulletproof abuse.`,
          points: pts
        });
        securityScore += pts;
      }
    }

    // Non-standard web ports (e.g. :8080, :8443, :8888, :3000)
    if (port && port !== '80' && port !== '443') {
      const pts = 14;
      signals.push({
        id: 'non_standard_port',
        severity: 'low',
        category: 'security',
        name: `Non-Standard Web Port (:${port})`,
        description: `Traffic directed through non-standard port ${port}, often seen in transient phishing proxies.`,
        points: pts
      });
      securityScore += pts;
    }

    // 11. Live Probe Evidence (Parked domain, security headers)
    if (liveProbe && !brandCheck.isCanonical) {
      if (liveProbe.isParked) {
        const pts = 24;
        signals.push({
          id: 'parked_domain',
          severity: 'medium',
          category: 'domain',
          name: 'Parked / Inactive Domain (For Sale)',
          description: `Live verification confirms this domain is currently parked or listed for sale (not an authenticated active service).`,
          points: pts
        });
        domainScore += pts;
      }

      if (liveProbe.reachable && liveProbe.hasHsts) {
        securityScore = Math.max(0, securityScore - 5);
      }
    }

    // 12. DOM & Behavioral Signals (Forms, passwords, titles, urgency)
    if (domSignals) {
      const domEvaluation = this._analyzeDomSignals(domSignals, hostname, apexDomain, protocol);
      for (const sig of domEvaluation.signals) {
        signals.push(sig);
        contentScore += sig.points;
      }
    }

    // 13. Advanced Machine Learning Inference (Random Forest 40-Vector Ensemble)
    let mlPrediction = null;
    if (this.mlEngine && !isVerifiedGov && !isVerifiedReal && !brandCheck.isCanonical) {
      try {
        mlPrediction = this.mlEngine.predict(urlString, domSignals);
        if (mlPrediction && mlPrediction.factors && mlPrediction.factors.length > 0) {
          for (const factor of mlPrediction.factors) {
            if (factor.includes('Banking/Wallet KYC')) {
              signals.push({
                id: 'ml_banking_kyc_phishing',
                severity: 'danger',
                category: 'lexical',
                name: 'Fake Banking & Wallet KYC Phishing Portal',
                description: factor,
                points: 88
              });
              lexicalScore = Math.max(lexicalScore, 88);
            } else if (factor.includes('Digital Arrest')) {
              signals.push({
                id: 'ml_digital_arrest_extortion',
                severity: 'danger',
                category: 'content',
                name: 'Digital Arrest / TRAI Cyber Extortion Threat',
                description: factor,
                points: 92
              });
              contentScore = Math.max(contentScore, 92);
            } else if (factor.includes('India Post')) {
              signals.push({
                id: 'ml_courier_smishing',
                severity: 'danger',
                category: 'lexical',
                name: 'Fake India Post / Courier Delivery Smishing',
                description: factor,
                points: 86
              });
              lexicalScore = Math.max(lexicalScore, 86);
            } else if (factor.includes('UPI / QR scam')) {
              signals.push({
                id: 'ml_upi_qr_scam',
                severity: 'danger',
                category: 'lexical',
                name: 'UPI / QR Payment Scam Trap',
                description: factor,
                points: 85
              });
              lexicalScore = Math.max(lexicalScore, 85);
            }
          }
        }
      } catch (e) {
        // Fallback gracefully without interrupting heuristics
      }
    }

    // Normalize category scores (0 to 100)
    domainScore = Math.min(100, Math.max(0, domainScore));
    lexicalScore = Math.min(100, Math.max(0, lexicalScore));
    securityScore = Math.min(100, Math.max(0, securityScore));
    contentScore = Math.min(100, Math.max(0, contentScore));

    // Calculate Comprehensive Varying Risk Percentage
    let signalPointsSum = 0;
    for (const sig of signals) {
      if (sig.severity !== 'info') {
        signalPointsSum += (sig.points || 0);
      }
    }

    let totalRisk = 0;
    if (signalPointsSum > 0) {
      // Dynamic multi-factor accumulation: combines primary threat vector and compounding factors
      totalRisk = Math.min(98, signalPointsSum + 4);
    } else if (protocol === 'https:') {
      // Clean, unflagged standard website on HTTPS
      totalRisk = 8;
    } else {
      totalRisk = 24;
    }

    let riskPercentage = Math.min(98, Math.max(0, Math.round(totalRisk)));

    // Canonical brand domains with zero negative signals guarantee 0%
    if (brandCheck.isCanonical && signals.every(s => s.severity === 'info')) {
      riskPercentage = 0;
    }

    // Determine Graduated Risk Level & Verdict
    let verdict = 'neutral';
    let level = 'neutral';
    let levelLabel = 'Unverified (Clean)';
    let summary = 'Unverified Web Destination — No immediate threat heuristics detected';

    if (riskPercentage >= this.thresholds.danger) {
      verdict = 'suspicious';
      level = 'danger';
      levelLabel = 'Critical Threat';
      summary = `High Risk Threat (${riskPercentage}% Risk) — Phishing & Fraud Indicators Detected`;
    } else if (riskPercentage >= this.thresholds.warning) {
      verdict = 'suspicious';
      level = 'warning';
      levelLabel = 'Suspicious Website';
      summary = `Suspicious Website (${riskPercentage}% Risk) — Caution Advised`;
    } else if (riskPercentage >= this.thresholds.caution) {
      verdict = 'neutral';
      level = 'caution';
      levelLabel = 'Elevated Vigilance';
      summary = `Caution Advised (${riskPercentage}% Risk) — Multiple Risk Heuristics Flagged`;
    } else if (isVerifiedReal || (brandCheck.isCanonical && signals.every(s => s.severity === 'info'))) {
      verdict = 'neutral';
      level = 'safe';
      levelLabel = 'Verified Safe';
      summary = `Verified Safe (${riskPercentage}% Risk) — Confirmed in Global Verified Safe Registry`;
    } else {
      verdict = 'neutral';
      level = 'neutral';
      levelLabel = 'Low Risk (Unverified)';
      summary = `Low Risk (${riskPercentage}% Risk) — Heuristics Normal (Unverified Domain)`;
    }

    // Compute comprehensive website classification category
    const classification = _classifyDomain ? _classifyDomain(hostname, apexDomain, {
      isGovernment: isVerifiedGov,
      isKnownScam: isKnownScam,
      isVerifiedReal: isVerifiedReal,
      isGovSpoof: govSpoofCheck.isSpoofing,
      riskPercentage,
      verdict
    }) : null;

    // Resolve suggested official website if spoofing or unsafe
    let suggestedWebsite = null;
    if (govSpoofCheck.isSpoofing) {
      if (_getSuggestedOfficialWebsite) {
        suggestedWebsite = _getSuggestedOfficialWebsite(hostname);
      }
    } else if (brandCheck.detected && brandCheck.brandName) {
      if (_getSuggestedOfficialWebsite) {
        suggestedWebsite = _getSuggestedOfficialWebsite(hostname, brandCheck.brandName);
      }
    } else if (isKnownScam || verdict === 'suspicious') {
      if (_getSuggestedOfficialWebsite) {
        suggestedWebsite = _getSuggestedOfficialWebsite(hostname);
      }
    }

    return this._createResult(riskPercentage, verdict, level, summary, signals, {
      url: cleanUrl,
      hostname,
      apexDomain,
      protocol,
      level,
      levelLabel,
      isCanonicalBrand: brandCheck.isCanonical,
      suggestedWebsite,
      databaseMatch,
      classification,
      disclaimer: _veridexDisclaimer,
      categoryScores: {
        domain: Math.round(domainScore),
        lexical: Math.round(lexicalScore),
        security: Math.round(securityScore),
        content: Math.round(contentScore)
      },
      liveProbe: liveProbe || null,
      ipIntelligence: ipIntelligence || null,
      ml: mlPrediction || null
    });
  }

  /**
   * Deep Minimal Variation & Brand Impersonation Detector
   */
  _detectBrandSpoofing(hostname, apexDomain, apexBase, tld) {
    // Phase 1: Canonical Verification
    for (const brand of brandsList) {
      const isDirectCanonical = brand.canonical.some(c => hostname === c || hostname.endsWith('.' + c));
      const isCcTldCanonical = brand.allowCcTld && apexBase === brand.nameKey;

      if (isDirectCanonical || isCcTldCanonical) {
        return { detected: false, isCanonical: true, brandName: brand.name };
      }
    }

    // Phase 2: Detect Variations against Known Brands
    for (const brand of brandsList) {
      const target = brand.nameKey;

      // Type A: Exact brand name registered on unauthorized TLD (e.g. paypal.xyz, chase.top, apple.work)
      if (apexBase === target) {
        return {
          detected: true,
          isCanonical: false,
          brandName: brand.name,
          points: 88,
          reason: `Unauthorized TLD registration: '${apexDomain}' uses the official name of ${brand.name}, but on an unauthorized domain extension (.${tld}). Official ${brand.name} does not use this domain.`
        };
      }

      // Type B: Subdomain Camouflage (e.g. paypal.com.attacker.xyz or login.chase.com.security.biz)
      if (hostname.includes(target) && apexBase !== target) {
        return {
          detected: true,
          isCanonical: false,
          brandName: brand.name,
          points: 85,
          reason: `Subdomain camouflage: Brand name '${brand.name}' is embedded in the address, but the real destination is '${apexDomain}', not official ${brand.name}.`
        };
      }

      // Type C: Combosquatting / Hyphen stitches (e.g. paypal-login, chase-security, apple-verify)
      const isStitched = apexBase.startsWith(target + '-') ||
                         apexBase.endsWith('-' + target) ||
                         apexBase.includes('-' + target + '-') ||
                         apexBase.startsWith('www-' + target) ||
                         apexBase.startsWith('login-' + target) ||
                         apexBase.startsWith('secure-' + target);
      if (isStitched && apexBase !== target) {
        return {
          detected: true,
          isCanonical: false,
          brandName: brand.name,
          points: 82,
          reason: `Combosquatting detected: Brand '${brand.name}' is stitched with extra terms in '${apexBase}', a standard deceptive phishing technique.`
        };
      }

      // Type D: Known minimal variation typos in brand keyword list (e.g. arnazon, paypa1, goog1e, roblux)
      for (const kw of brand.keywords) {
        if (kw !== target && (apexBase === kw || apexBase.includes(kw) || hostname.includes(kw))) {
          return {
            detected: true,
            isCanonical: false,
            brandName: brand.name,
            points: 86,
            reason: `Minimal variation detected: '${kw}' mimics '${brand.name}' with deceptive character substitution (e.g., '1' for 'l', 'rn' for 'm').`
          };
        }
      }

      // Type E: Algorithmic Levenshtein Distance
      if (_levenshteinDistance) {
        const dist = _levenshteinDistance(apexBase, target);
        if ((dist === 1 && apexBase.length >= 3) || (dist === 2 && apexBase.length >= 6)) {
          const similarityPct = Math.round((1 - dist / Math.max(apexBase.length, target.length)) * 100);
          return {
            detected: true,
            isCanonical: false,
            brandName: brand.name,
            points: 84,
            reason: `Typosquatting detected: '${apexBase}' is a minimal variation (${similarityPct}% match, edit distance: ${dist}) of official '${brand.name}'.`
          };
        }
      }
    }

    return { detected: false, isCanonical: false };
  }

  /**
   * Evaluates In-Page DOM signals
   */
  _analyzeDomSignals(dom, hostname, apexDomain, protocol) {
    const signals = [];

    // Password field on HTTP
    if (dom.hasPasswordField && protocol === 'http:') {
      signals.push({
        id: 'insecure_password_field',
        severity: 'high',
        category: 'content',
        name: 'Insecure Password Input Form',
        description: 'Password input field on an unencrypted HTTP connection.',
        points: 40
      });
    }

    // External Form Exfiltration
    if (dom.externalFormActions && dom.externalFormActions.length > 0) {
      const untrustedActions = dom.externalFormActions.filter(actionHost => {
        return actionHost !== hostname && !actionHost.endsWith('.' + apexDomain);
      });

      if (untrustedActions.length > 0) {
        signals.push({
          id: 'external_form_action',
          severity: 'high',
          category: 'content',
          name: 'Cross-Domain Credential Exfiltration',
          description: `Form on this page submits data to external host (${untrustedActions[0]}).`,
          points: 45
        });
      }
    }

    // Page Title Impersonation
    if (dom.pageTitle) {
      const lowerTitle = dom.pageTitle.toLowerCase();
      for (const brand of brandsList) {
        const hasBrandTitle = brand.keywords.some(kw => lowerTitle.includes(kw));
        const isOfficial = brand.canonical.some(c => hostname === c || hostname.endsWith('.' + c));
        if (hasBrandTitle && !isOfficial) {
          signals.push({
            id: 'title_brand_mismatch',
            severity: 'high',
            category: 'content',
            name: `Page Title Impersonation (${brand.name})`,
            description: `Page title claims to be '${brand.name}', but domain is '${hostname}'.`,
            points: 40
          });
          break;
        }
      }
    }

    // Urgency Coercion
    if (dom.hasUrgencyPatterns) {
      const pts = dom.hasCountdown ? 45 : 30;
      signals.push({
        id: 'psychological_urgency',
        severity: dom.hasCountdown ? 'high' : 'medium',
        category: 'content',
        name: dom.hasCountdown ? 'Urgent Countdown Coercion Scam' : 'Urgency Pressure Lure',
        description: dom.hasCountdown
          ? 'Page uses an active countdown timer with pressure text to force hasty decisions.'
          : 'Page uses manipulative pressure language (e.g. account suspension threats).',
        points: pts
      });
    }

    // Credit card input on HTTP
    if (dom.hasCreditCardField && protocol === 'http:') {
      signals.push({
        id: 'insecure_credit_card_input',
        severity: 'high',
        category: 'content',
        name: 'Insecure Credit Card Input Form',
        description: 'Credit card input field detected on unencrypted HTTP.',
        points: 42
      });
    }

    // Crypto seed phrase harvesting
    if (dom.hasSeedPhraseInputs) {
      signals.push({
        id: 'crypto_seed_phrase_harvest',
        severity: 'high',
        category: 'content',
        name: 'Secret Recovery / Seed Phrase Capture',
        description: 'Webpage contains form inputs asking for 12/24-word recovery seed phrases.',
        points: 75
      });
    }

    return { signals };
  }

  _createResult(riskPercentage, verdict, level, summary, signals, details) {
    const isSuspicious = verdict === 'suspicious';

    const recommendations = [];
    if (isSuspicious) {
      recommendations.push('Do NOT enter passwords, credit card numbers, or personal credentials.');
      recommendations.push('Check the exact spelling in the address bar for character substitutions.');
      recommendations.push('Access the service directly through its verified official application.');
    } else if (level === 'caution') {
      recommendations.push('Exercise caution: unverified domain with multiple elevated heuristics.');
      recommendations.push('Verify SSL certificate and domain authenticity before submitting information.');
    } else {
      recommendations.push('No critical phishing heuristics triggered.');
      recommendations.push('Always practice normal vigilance before submitting sensitive credentials.');
    }

    return {
      appName: 'Veridex AI',
      timestamp: Date.now(),
      riskPercentage,
      riskScore: riskPercentage,
      verdict,
      level,
      levelLabel: details.levelLabel || (isSuspicious ? 'Suspicious' : 'Neutral'),
      summary,
      signals,
      recommendations,
      databaseMatch: details.databaseMatch || {
        isReal: false,
        isFake: false,
        status: 'unverified',
        label: 'Algorithmic Heuristics'
      },
      classification: details.classification || (_classifyDomain ? _classifyDomain(details.hostname, details.apexDomain, { riskPercentage, verdict }) : null),
      disclaimer: details.disclaimer || _veridexDisclaimer,
      categoryScores: details.categoryScores || {
        domain: 0,
        lexical: 0,
        security: 0,
        content: 0
      },
      details,
      isThreat: isSuspicious,
      isUnsafe: isSuspicious || riskPercentage >= this.thresholds.warning,
      suggestedWebsite: details.suggestedWebsite || null,
      ipIntelligence: details.ipIntelligence || null
    };
  }

  /**
   * Audits cookies for security configurations and privacy
   * Never displays or transmits actual values
   */
  analyzeCookies(cookies, url) {
    const analyzer = _CookieAnalyzer || (typeof CookieAnalyzer !== 'undefined' ? CookieAnalyzer : null);
    if (analyzer && analyzer.analyzeCookies) {
      return analyzer.analyzeCookies(cookies, url);
    }
    return null;
  }
}

// Export for Service Worker, Content Script, and Node
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VeridexEngine };
}
if (typeof self !== 'undefined') {
  self.VeridexEngine = VeridexEngine;
}
if (typeof window !== 'undefined') {
  window.VeridexEngine = VeridexEngine;
}
if (typeof globalThis !== 'undefined') {
  globalThis.VeridexEngine = VeridexEngine;
}
