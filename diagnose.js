const { VeridexEngine } = require('./engine/veridex-engine.js');
const engine = new VeridexEngine();

const testUrls = [
  // User's specific reported test cases & Known Scams
  { url: 'www.scam.com', expected: 'suspicious', minScore: 70 },
  { url: 'https://scam.com', expected: 'suspicious', minScore: 70 },
  { url: 'http://fake-apple-login.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://paypal-security-update.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://chase-bank-verify.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://package-delivery-usps.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://free-robux-generator.net', expected: 'suspicious', minScore: 75 },
  { url: 'http://crypto-airdrop-claim.xyz', expected: 'suspicious', minScore: 75 },
  { url: 'http://netflix-billing-update.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://amazon-prime-renewal.top', expected: 'suspicious', minScore: 75 },
  { url: 'http://account-verification-alert.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://login-security-portal.net', expected: 'suspicious', minScore: 75 },
  { url: 'http://www-paypal.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://steamcommuniity.com', expected: 'suspicious', minScore: 75 },
  { url: 'http://wallet-connect-auth.network', expected: 'suspicious', minScore: 75 },

  // Authentic Global Real Websites (Database Match & Zero False Positives)
  { url: 'https://www.google.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://www.google.co.in', expected: 'neutral', maxScore: 5 },
  { url: 'https://en.wikipedia.org/wiki/Scam', expected: 'neutral', maxScore: 5 },
  { url: 'https://github.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://www.amazon.in', expected: 'neutral', maxScore: 5 },
  { url: 'https://chase.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://paypal.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://apple.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://scamwatch.gov.au', expected: 'neutral', maxScore: 5 },
  { url: 'https://snopes.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://www.bbc.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://nytimes.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://cloudflare.com', expected: 'neutral', maxScore: 5 },
  { url: 'https://discord.com', expected: 'neutral', maxScore: 5 },

  // Varying Risk Tests (Clean sites vs Insecure HTTP vs High-Risk TLD)
  { url: 'https://alexrivera-dev.org/posts', expected: 'neutral', minScore: 5, maxScore: 20 },
  { url: 'http://example-blog.com', expected: 'neutral', minScore: 20, maxScore: 34 },
  { url: 'https://discount-shop.xyz', expected: 'suspicious', minScore: 35, maxScore: 60 },

  // Indian Government Portals & Spoofing Detection
  { url: 'https://cybercrime.gov.in', expected: 'neutral', maxScore: 0 },
  { url: 'https://incometax.gov.in', expected: 'neutral', maxScore: 0 },
  { url: 'https://cybercrime.gov.in.attacker.xyz', expected: 'suspicious', minScore: 85 },
  { url: 'http://fake-gov.in', expected: 'suspicious', minScore: 85 }
];

console.log("=== VERIDEX AI COMPREHENSIVE VERIFICATION & VARYING RISK TEST ===");
let passed = 0;
const scores = [];

for (const t of testUrls) {
  const r = engine.analyze(t.url);
  const verdictOk = r.verdict === t.expected;
  const minOk = t.minScore !== undefined ? r.riskPercentage >= t.minScore : true;
  const maxOk = t.maxScore !== undefined ? r.riskPercentage <= t.maxScore : true;
  const ok = verdictOk && minOk && maxOk;

  if (ok) passed++;
  scores.push(r.riskPercentage);

  console.log(`${ok ? '✓ PASS' : '✗ FAIL'}: ${t.url} -> ${r.riskPercentage}% Risk [${r.verdict.toUpperCase()}] (${r.levelLabel})`);
  if (r.signals.length > 0) {
    console.log(`   Signals: ${r.signals.map(s => s.name).join(', ')}`);
  }
}

// Verify varying risk: ensure scores are not constant!
const uniqueScores = new Set(scores);
console.log(`\nScore Diversity: ${uniqueScores.size} unique score levels generated across test suite.`);
console.log(`Score spectrum: Min = ${Math.min(...scores)}%, Max = ${Math.max(...scores)}%`);

if (uniqueScores.size < 4) {
  console.error("FAIL: Risk scores lack dynamic variation!");
  process.exit(1);
}

console.log(`\nOverall: ${passed}/${testUrls.length} tests passed.`);
if (passed !== testUrls.length) process.exit(1);
