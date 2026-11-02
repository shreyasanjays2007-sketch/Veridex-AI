const { VeridexEngine } = require('./engine/veridex-engine.js');
const brandDb = require('./engine/brand-database.js');
const { CookieAnalyzer } = require('./engine/cookie-analyzer.js');
const fs = require('fs');
const engine = new VeridexEngine();

const testCases = [
  {
    name: "Typosquatting (arnazon)",
    url: "https://arnazon.com/signin",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 40
  },
  {
    name: "Subdomain Brand Spoofing (paypal.com.attacker.xyz)",
    url: "http://paypal.com.attacker.xyz/login",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 50
  },
  {
    name: "Raw IP Hostname",
    url: "http://198.51.100.24/portal",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 40
  },
  {
    name: "High Entropy Domain (DGA)",
    url: "http://qxj982zk-lm109.cc/token",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 20
  },
  {
    name: "Normal Site (alexrivera-dev.org)",
    url: "https://alexrivera-dev.org/posts",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 30
  },
  {
    name: "DOM Signal - Seed Phrase Harvesting",
    url: "https://my-crypto-hub.io/restore",
    dom: { hasSeedPhraseInputs: true },
    expectedVerdict: "suspicious",
    minScore: 60
  },
  {
    name: "DOM Signal - Urgency & Fake Countdown",
    url: "https://shopping-deals-today.shop",
    dom: { hasUrgencyPatterns: true, hasCountdown: true },
    expectedVerdict: "suspicious",
    minScore: 25
  },
  {
    name: "Offline Malicious IP Match (Threat Database)",
    url: "https://portal-auth-sample.net",
    dom: null,
    ip: "185.220.101.5",
    expectedVerdict: "suspicious",
    minScore: 80
  },
  {
    name: "Offline IP Honest Reporting (Unavailable info not fabricated)",
    url: "https://example-site.org",
    dom: null,
    ip: null,
    expectedVerdict: "neutral",
    maxScore: 30,
    customCheck: (res) => res.ipIntelligence && !res.ipIntelligence.isAvailable && res.ipIntelligence.organization === 'Unavailable'
  },
  {
    name: "Verified Indian Government Portal (cybercrime.gov.in)",
    url: "https://cybercrime.gov.in",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 0,
    customCheck: (res) => res.classification && res.classification.category === 'verified_government' && res.classification.isGovernment === true
  },
  {
    name: "Verified Official NIC Portal (incometax.gov.in)",
    url: "https://incometax.gov.in",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 0,
    customCheck: (res) => res.classification && res.classification.category === 'verified_government'
  },
  {
    name: "Deceptive Government Subdomain Spoofing (cybercrime.gov.in.attacker.xyz)",
    url: "https://cybercrime.gov.in.attacker.xyz",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 85,
    customCheck: (res) => res.signals && res.signals.some(s => s.id === 'government_deceptive_spoofing' || s.id === 'known_scam_threat')
  },
  {
    name: "Deceptive Stitched Government Lookalike (fake-gov.in)",
    url: "http://fake-gov.in",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 85,
    customCheck: (res) => res.classification && res.classification.category === 'known_phishing'
  },
  {
    name: "Unknown / Unverified Website Classification (alexrivera-dev.org)",
    url: "https://alexrivera-dev.org",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 20,
    customCheck: (res) => res.classification && res.classification.category === 'unknown' && res.classification.isUnknown === true
  },
  {
    name: "Dataset Validation & Normalization Integrity",
    url: "https://cybercrime.gov.in",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 0,
    customCheck: () => {
      const govVal = brandDb.validateDataset('Gov Allowlist', brandDb.VERIFIED_GOVERNMENT_DOMAINS);
      const scamVal = brandDb.validateDataset('Scam Feeds', brandDb.KNOWN_SCAM_DOMAINS);
      const normCheck = brandDb.normalizeDomain('HTTPS://WWW.CyberCrime.GOV.IN:443/report?id=123#frag', { stripWww: true }) === 'cybercrime.gov.in';
      return govVal.invalid === 0 && scamVal.invalid === 0 && normCheck;
    }
  },
  {
    name: "Cookie Analysis - Value Redaction Guarantee (Zero Values)",
    url: "https://my-local-testsite.org",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 30,
    customCheck: () => {
      const rawCookiesWithValues = [
        { name: 'session_token', value: 'SECRET_PLAINTEXT_PASSWORD_12345', domain: 'my-local-testsite.org', secure: true, httpOnly: true, sameSite: 'strict', session: true },
        { name: 'user_auth', value: 'BEARER_JWT_TOKEN_ABCXYZ', domain: 'my-local-testsite.org', secure: true, httpOnly: true, sameSite: 'lax', session: true }
      ];
      const result = CookieAnalyzer.analyzeCookies(rawCookiesWithValues, 'https://my-local-testsite.org');
      
      // Ensure total count is correct
      const countMatch = result.total === 2;
      // CRITICAL CHECK: value must NEVER exist on any object or result property!
      const valuesRedacted = result.cookies.every(c => c.value === undefined && !('value' in c));
      const jsonStr = JSON.stringify(result);
      const noLeakedSecrets = !jsonStr.includes('SECRET_PLAINTEXT_PASSWORD') && !jsonStr.includes('BEARER_JWT_TOKEN');
      
      return countMatch && valuesRedacted && noLeakedSecrets;
    }
  },
  {
    name: "Cookie Analysis - Insecure Configuration Detection",
    url: "https://insecure-shop.com",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 30,
    customCheck: () => {
      const rawCookies = [
        // Insecure 1: Auth cookie missing Secure flag on HTTPS site
        { name: 'auth_session_id', value: 'val1', domain: 'insecure-shop.com', secure: false, httpOnly: true, sameSite: 'lax' },
        // Insecure 2: Session cookie missing HttpOnly (XSS risk)
        { name: 'login_jwt', value: 'val2', domain: 'insecure-shop.com', secure: true, httpOnly: false, sameSite: 'strict' },
        // Insecure 3: SameSite=None without Secure flag
        { name: 'tracking_id', value: 'val3', domain: 'insecure-shop.com', secure: false, httpOnly: false, sameSite: 'none' },
        // Insecure 4: Third-party tracking cookie with excessive lifetime (> 1 year)
        { name: '_tracker_ad', value: 'val4', domain: '.adnetwork-thirdparty.net', secure: true, httpOnly: false, sameSite: 'none', expirationDate: (Date.now() / 1000) + (86400 * 500) }
      ];

      const result = CookieAnalyzer.analyzeCookies(rawCookies, 'https://insecure-shop.com');
      const hasMissingSecure = result.issues.some(i => i.type === 'MISSING_SECURE_SENSITIVE' || i.type === 'MISSING_SECURE');
      const hasMissingHttpOnly = result.issues.some(i => i.type === 'MISSING_HTTPONLY_SENSITIVE');
      const hasSameSiteNoneInsecure = result.issues.some(i => i.type === 'SAMESITE_NONE_WITHOUT_SECURE');
      const hasThirdParty = result.issues.some(i => i.type === 'THIRD_PARTY_TRACKER');
      const hasExcessiveLife = result.issues.some(i => i.type === 'EXCESSIVE_LIFETIME');

      return hasMissingSecure && hasMissingHttpOnly && hasSameSiteNoneInsecure && hasThirdParty && hasExcessiveLife && result.overallStatus === 'insecure';
    }
  },
  {
    name: "Detailed Report Structure & Direct Section Layout Integrity",
    url: "https://cybercrime.gov.in",
    dom: null,
    expectedVerdict: "neutral",
    maxScore: 0,
    customCheck: () => {
      const modalSrc = fs.readFileSync('D:\\veridex-ai\\content\\warning-modal.js', 'utf8');
      
      // 1. Report Sections Container with Direct Section Visibility (5 preview boxes removed)
      const hasSectionsContainer = modalSrc.includes('id="vx-report-sections-container"');
      const hasIpSection = modalSrc.includes('id="vx-section-detail-ip"');
      const hasDomSection = modalSrc.includes('id="vx-section-detail-behaviour"');
      const hasSignalsSection = modalSrc.includes('id="vx-section-detail-signals"');
      const hasCookiesSection = modalSrc.includes('id="vx-section-detail-cookies"');
      const hasCyberSection = modalSrc.includes('id="vx-section-detail-cybercrime"');
      
      // 2. Cookie Security Insecure Configurations Folder Structure
      const hasCookieSection = modalSrc.includes('Cookie Security & Privacy Analysis');
      const hasCookieFolder = modalSrc.includes('vx-cookie-folder') && modalSrc.includes('Identified Insecure Configurations');
      
      // 3. Existing handlers and elements strictly preserved
      const hasCybercrimeTop = modalSrc.includes('id="vx-report-cybercrime-top"');
      const hasPrintTop = modalSrc.includes('id="vx-report-print-top"');
      const hasCopyEvidence = modalSrc.includes('id="vx-btn-copy-evidence"');
      const hasGovPortal = modalSrc.includes('id="vx-btn-gov-portal"');
      const hasGovHelpline = modalSrc.includes('id="vx-btn-gov-call"');
      const hasCloseTop = modalSrc.includes('id="vx-report-close-top"');

      return hasSectionsContainer && hasIpSection && hasDomSection && hasSignalsSection &&
             hasCookiesSection && hasCyberSection && hasCookieSection && hasCookieFolder &&
             hasCybercrimeTop && hasPrintTop && hasCopyEvidence && hasGovPortal && hasGovHelpline && hasCloseTop;
    }
  },
  {
    name: "Trained ML Vector - UPI / QR Scam Trap (claim-phonepe-cashback)",
    url: "https://claim-phonepe-cashback-500.xyz/upi-pay",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 80,
    customCheck: (res) => res.signals && res.signals.some(s => s.id === 'ml_upi_qr_scam')
  },
  {
    name: "Trained ML Vector - Banking KYC Phishing (sbi-kyc-verification.com)",
    url: "http://sbi-kyc-verification.com/login",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 85,
    customCheck: (res) => res.signals && res.signals.some(s => s.id === 'ml_banking_kyc_phishing')
  },
  {
    name: "Trained ML Vector - Courier Smishing (indiapost-parcel-delivery.top)",
    url: "http://indiapost-parcel-delivery.top/update-address",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 80,
    customCheck: (res) => res.signals && res.signals.some(s => s.id === 'ml_courier_smishing')
  },
  {
    name: "Trained ML Vector - Digital Arrest / TRAI Extortion (trai-sim-deactivation)",
    url: "http://trai-sim-deactivation-notice.com/case/9912",
    dom: null,
    expectedVerdict: "suspicious",
    minScore: 85,
    customCheck: (res) => res.signals && res.signals.some(s => s.id === 'ml_digital_arrest_extortion')
  }
];

let passed = 0;
for (const tc of testCases) {
  const res = engine.analyze(tc.url, tc.dom, null, tc.ip);
  const verdictMatches = res.verdict === tc.expectedVerdict;
  const scoreMatches = (tc.minScore !== undefined ? res.riskScore >= tc.minScore : true) &&
                       (tc.maxScore !== undefined ? res.riskScore <= tc.maxScore : true);
  const customMatches = tc.customCheck ? tc.customCheck(res) : true;

  if (verdictMatches && scoreMatches && customMatches) {
    console.log(`[PASS] ${tc.name}: Score=${res.riskScore}, Verdict=${res.verdict}`);
    passed++;
  } else {
    console.error(`[FAIL] ${tc.name}: Expected ${tc.expectedVerdict}, got ${res.verdict} (Score: ${res.riskScore})`);
    if (!customMatches) console.error(`  -> Custom validation failed for ${tc.name}`);
  }
}

console.log(`\nResult: ${passed}/${testCases.length} tests passed.`);
if (passed !== testCases.length) process.exit(1);
