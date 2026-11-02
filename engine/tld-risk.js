/**
 * Veridex AI - TLD Risk, Homoglyphs, Scam Keywords & Entropy Utilities
 */

// High-risk TLDs statistically identified with high phishing & scam abuse rates
const HIGH_RISK_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq',      // Legacy free TLDs heavily abused
  'top', 'work', 'click', 'fit', 'buzz',
  'rest', 'surf', 'loan', 'racing', 'icu',
  'cyou', 'monster', 'hair', 'skin', 'beauty',
  'vip', 'quest', 'cam', 'sbs', 'cfd',
  'zip', 'mov', 'site', 'online', 'space',
  'pw', 'cc', 'ws', 'su', 'tokyo',
  'xyz', 'shop', 'link', 'live', 'bid',
  'trade', 'date', 'stream', 'download', 'party',
  'win', 'science', 'cricket', 'gdn', 'club'
]);

// Explicit scam, fraud, and malicious scheme keywords
// Any unverified domain containing these words is an immediate severe red flag
const EXPLICIT_SCAM_KEYWORDS = [
  'scam', 'phish', 'phishing', 'fraud', 'fake',
  'spoof', 'exploit', 'hack', 'keygen', 'warez',
  'drainer', 'stealer', 'malware', 'trojan', 'ransomware',
  'robux', 'free-robux', 'roblux', 'vbucks', 'free-vbucks',
  'free-nitro', 'giftcard-generator', 'crypto-doubler',
  'bitcoin-generator', 'wallet-drain', 'seed-phrase',
  'recovery-phrase', 'private-key-restore'
];

// High-risk compound action and target keywords stitched in phishing domains
const PHISH_ACTION_WORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'auth', 'authenticate',
  'verify', 'verification', 'validation', 'confirm', 'confirmation',
  'update', 'restore', 'unlock', 'recover', 'recovery', 'resolve',
  'manage', 'security', 'secure', 'alert', 'notice', 'sync',
  'claim', 'redeem', 'bonus', 'airdrop', 'reward', 'giveaway',
  'tracking', 'redelivery', 'customs', 'shipment'
];

const PHISH_TARGET_WORDS = [
  'account', 'banking', 'wallet', 'billing', 'card', 'payment',
  'profile', 'portal', 'support', 'helpdesk', 'service', 'center',
  'client', 'customer', 'member', 'identity', 'passcode', 'otp',
  'parcel', 'package', 'delivery', 'postal', 'courier'
];

// Common Homoglyph substitutions (Latin vs Cyrillic / Greek / Numbers)
const HOMOGLYPH_MAP = {
  'а': 'a', // Cyrillic small a
  'а́': 'a',
  'с': 'c', // Cyrillic small es
  'е': 'e', // Cyrillic small ie
  'і': 'i', // Ukrainian i
  'ї': 'i',
  'ј': 'j', // Cyrillic je
  'о': 'o', // Cyrillic small o
  'р': 'p', // Cyrillic small er
  'ѕ': 's', // Cyrillic dze
  'у': 'y', // Cyrillic u
  'х': 'x', // Cyrillic ha
  '0': 'o', // Number zero
  '1': 'l', // Number one (or i)
  '3': 'e', // Number 3 for e
  '5': 's', // Number 5 for s
  '@': 'a',
  '$': 's'
};

// Common multi-part public suffixes for domain parsing (including NIC and Indian government domains)
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.in', 'net.in', 'org.in', 'gov.in', 'nic.in', 'res.in', 'ac.in', 'edu.in', 'mil.in',
  'co.nz', 'co.za', 'co.jp', 'com.br',
  'com.cn', 'com.mx', 'com.sg', 'gov.sg', 'com.tw',
  'com.tr', 'co.id', 'com.ph', 'com.my',
  'gov.ca', 'gc.ca'
]);

/**
 * Calculates Shannon Entropy of a string.
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const clean = str.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (clean.length === 0) return 0;

  const frequencies = {};
  for (let i = 0; i < clean.length; i++) {
    const char = clean[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = clean.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Normalizes homoglyphs and detects if the string contains lookalike characters
 */
function analyzeHomoglyphs(str) {
  let normalized = '';
  let hasHomoglyphs = false;
  const foundReplacements = [];

  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (HOMOGLYPH_MAP[char]) {
      hasHomoglyphs = true;
      foundReplacements.push({ original: char, normalized: HOMOGLYPH_MAP[char] });
      normalized += HOMOGLYPH_MAP[char];
    } else {
      normalized += char;
    }
  }

  const isPunycode = str.toLowerCase().includes('xn--');

  return {
    hasHomoglyphs: hasHomoglyphs || isPunycode,
    isPunycode,
    normalized,
    foundReplacements
  };
}

/**
 * Computes Levenshtein distance between two strings
 */
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Extracts apex domain (e.g. example.com from sub.example.co.in or sub.example.com)
 */
function extractApexDomain(hostname) {
  if (!hostname) return '';
  const host = hostname.toLowerCase().split(':')[0]; // strip port

  // Handle raw IP addresses
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    return host;
  }

  const parts = host.split('.');
  if (parts.length <= 2) return host;

  // Check multi-part suffix like co.uk, co.in
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }

  return parts.slice(-2).join('.');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    HIGH_RISK_TLDS,
    EXPLICIT_SCAM_KEYWORDS,
    PHISH_ACTION_WORDS,
    PHISH_TARGET_WORDS,
    HOMOGLYPH_MAP,
    MULTI_PART_SUFFIXES,
    calculateShannonEntropy,
    analyzeHomoglyphs,
    levenshteinDistance,
    extractApexDomain
  };
}
if (typeof self !== 'undefined') {
  self.HIGH_RISK_TLDS = HIGH_RISK_TLDS;
  self.EXPLICIT_SCAM_KEYWORDS = EXPLICIT_SCAM_KEYWORDS;
  self.PHISH_ACTION_WORDS = PHISH_ACTION_WORDS;
  self.PHISH_TARGET_WORDS = PHISH_TARGET_WORDS;
  self.HOMOGLYPH_MAP = HOMOGLYPH_MAP;
  self.MULTI_PART_SUFFIXES = MULTI_PART_SUFFIXES;
  self.calculateShannonEntropy = calculateShannonEntropy;
  self.analyzeHomoglyphs = analyzeHomoglyphs;
  self.levenshteinDistance = levenshteinDistance;
  self.extractApexDomain = extractApexDomain;
}
if (typeof window !== 'undefined') {
  window.HIGH_RISK_TLDS = HIGH_RISK_TLDS;
  window.EXPLICIT_SCAM_KEYWORDS = EXPLICIT_SCAM_KEYWORDS;
  window.PHISH_ACTION_WORDS = PHISH_ACTION_WORDS;
  window.PHISH_TARGET_WORDS = PHISH_TARGET_WORDS;
  window.HOMOGLYPH_MAP = HOMOGLYPH_MAP;
  window.MULTI_PART_SUFFIXES = MULTI_PART_SUFFIXES;
  window.calculateShannonEntropy = calculateShannonEntropy;
  window.analyzeHomoglyphs = analyzeHomoglyphs;
  window.levenshteinDistance = levenshteinDistance;
  window.extractApexDomain = extractApexDomain;
}
if (typeof globalThis !== 'undefined') {
  globalThis.HIGH_RISK_TLDS = HIGH_RISK_TLDS;
  globalThis.EXPLICIT_SCAM_KEYWORDS = EXPLICIT_SCAM_KEYWORDS;
  globalThis.PHISH_ACTION_WORDS = PHISH_ACTION_WORDS;
  globalThis.PHISH_TARGET_WORDS = PHISH_TARGET_WORDS;
  globalThis.HOMOGLYPH_MAP = HOMOGLYPH_MAP;
  globalThis.MULTI_PART_SUFFIXES = MULTI_PART_SUFFIXES;
  globalThis.calculateShannonEntropy = calculateShannonEntropy;
  globalThis.analyzeHomoglyphs = analyzeHomoglyphs;
  globalThis.levenshteinDistance = levenshteinDistance;
  globalThis.extractApexDomain = extractApexDomain;
}
