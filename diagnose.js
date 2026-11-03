const { VeridexEngine } = require('./engine/veridex-engine.js');
const engine = new VeridexEngine();

const testUrls = [
  // User's specific reported test cases & Known Scams (Must be variable strictly from 85% to 100%)
  { url: 'www.scam.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'https://scam.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://fake-apple-login.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://paypal-security-update.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://chase-bank-verify.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://package-delivery-usps.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://free-robux-generator.net', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://crypto-airdrop-claim.xyz', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://netflix-billing-update.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://amazon-prime-renewal.top', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://account-verification-alert.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://login-security-portal.net', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://www-paypal.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://steamcommuniity.com', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://wallet-connect-auth.network', expected: 'suspicious', minScore: 85, maxScore: 100 },

  // Authentic Global Real Websites (Database Match & Zero False Positives -> Strictly 0% Risk)
  { url: 'https://www.google.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://www.google.co.in', expected: 'neutral', maxScore: 0 },
  { url: 'https://en.wikipedia.org/wiki/Scam', expected: 'neutral', maxScore: 0 },
  { url: 'https://github.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://www.amazon.in', expected: 'neutral', maxScore: 0 },
  { url: 'https://chase.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://paypal.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://apple.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://scamwatch.gov.au', expected: 'neutral', maxScore: 0 },
  { url: 'https://snopes.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://www.bbc.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://nytimes.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://cloudflare.com', expected: 'neutral', maxScore: 0 },
  { url: 'https://discord.com', expected: 'neutral', maxScore: 0 },

  // Clean unknown websites (Authentic -> Strictly 0% Risk)
  { url: 'https://alexrivera-dev.org/posts', expected: 'neutral', maxScore: 0 },

  // Insecure HTTP Caution (Unencrypted connection caution -> 20% to 35%)
  { url: 'http://example-blog.com', expected: 'neutral', minScore: 20, maxScore: 35 },

  // High-Risk TLD (Suspicious TLD caution -> 35% to 60%)
  { url: 'https://discount-shop.xyz', expected: 'suspicious', minScore: 35, maxScore: 60 },

  // Indian Government Portals & Spoofing Detection
  { url: 'https://cybercrime.gov.in', expected: 'neutral', maxScore: 0 },
  { url: 'https://incometax.gov.in', expected: 'neutral', maxScore: 0 },
  { url: 'https://cybercrime.gov.in.attacker.xyz', expected: 'suspicious', minScore: 85, maxScore: 100 },
  { url: 'http://fake-gov.in', expected: 'suspicious', minScore: 85, maxScore: 100 }
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

// Verify varying risk: ensure fake scores are variable and dynamic
const fakeScores = scores.filter(s => s >= 85);
const uniqueFakeScores = new Set(fakeScores);
console.log(`\nScore Diversity: ${new Set(scores).size} total unique score levels generated across test suite.`);
console.log(`Fake Site Score Spectrum: Min = ${Math.min(...fakeScores)}%, Max = ${Math.max(...fakeScores)}%, Unique Fake Scores = ${uniqueFakeScores.size} [${Array.from(uniqueFakeScores).sort((a,b)=>a-b).join(', ')}%]`);
console.log(`Score spectrum: Min = ${Math.min(...scores)}%, Max = ${Math.max(...scores)}%`);

if (uniqueFakeScores.size < 3) {
  console.error("FAIL: Fake risk scores lack dynamic variation between 85% and 100%!");
  process.exit(1);
}

console.log(`\nOverall: ${passed}/${testUrls.length} tests passed.`);
if (passed !== testUrls.length) process.exit(1);
