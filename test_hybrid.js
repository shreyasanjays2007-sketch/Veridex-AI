const fs = require('fs');
const { VeridexEngine } = require('./engine/veridex-engine.js');
const engine = new VeridexEngine();

console.log('=== VERIFYING HYBRID AI DETECTION LAYER ===\n');

// 1. Verify HTML DOM elements
const pop = fs.readFileSync(__dirname + '/popup/popup.html', 'utf8');
const web = fs.readFileSync(__dirname + '/website/index.html', 'utf8');

const pop_ids = [
  'popup-hybrid-bar', 'popup-heur-score', 'popup-ml-score', 'popup-combined-score',
  'popup-ai-explanation-box', 'popup-ai-confidence', 'popup-ai-headline', 'popup-ai-summary',
  'popup-ai-drivers', 'popup-ai-driver-list', 'popup-ai-safety', 'popup-ai-safety-list'
];
const web_ids = [
  'website-hybrid-bar', 'web-heur-score', 'web-ml-score', 'web-combined-score',
  'website-ai-explanation-card', 'web-ai-confidence', 'web-ai-headline', 'web-ai-summary',
  'web-card-heur-score', 'web-card-ml-score', 'web-card-combined-score',
  'web-ai-rationale', 'web-ai-advice', 'web-ai-drivers-box', 'web-ai-drivers-list',
  'web-ai-safety-box', 'web-ai-safety-list'
];

pop_ids.forEach(id => {
  if (!pop.includes(`id="${id}"`)) throw new Error('Missing in popup.html: ' + id);
});
console.log('✓ All 12 Popup Hybrid AI DOM elements verified');

web_ids.forEach(id => {
  if (!web.includes(`id="${id}"`)) throw new Error('Missing in website/index.html: ' + id);
});
console.log('✓ All 17 Website Hybrid AI DOM elements verified');

// 2. Verify Hybrid Engine Analysis on Diverse URLs
const samples = [
  { url: 'https://cybercrime.gov.in', expectedVerdict: 'neutral', maxRisk: 0, desc: 'Verified Government' },
  { url: 'https://sbi.co.in', expectedVerdict: 'neutral', maxRisk: 0, desc: 'Verified Safe Bank' },
  { url: 'http://sbi-kyc-verification.com/login', expectedVerdict: 'suspicious', minRisk: 85, desc: 'Fake Banking KYC' },
  { url: 'http://claim-phonepe-cashback-500.xyz/upi-pay', expectedVerdict: 'suspicious', minRisk: 85, desc: 'UPI / QR Scam' },
  { url: 'http://indiapost-parcel-delivery.top/update-address', expectedVerdict: 'suspicious', minRisk: 85, desc: 'India Post Smishing' },
  { url: 'http://trai-sim-deactivation-notice.com/case/9912', expectedVerdict: 'suspicious', minRisk: 85, desc: 'Digital Arrest / TRAI' },
  { url: 'https://alexrivera-dev.org/posts', expectedVerdict: 'neutral', maxRisk: 20, desc: 'Unverified Clean Blog' }
];

samples.forEach(s => {
  const res = engine.analyze(s.url);
  console.log(`\n• [${s.desc}] ${s.url}`);
  console.log(`  Combined Risk: ${res.riskPercentage}% [${res.verdict.toUpperCase()}]`);
  console.log(`  Heuristic: ${res.heuristicScore}% | ML Model: ${res.mlScore}%`);
  console.log(`  AI Headline: ${res.aiExplanation ? res.aiExplanation.headline : 'N/A'}`);
  console.log(`  AI Confidence: ${res.aiExplanation ? res.aiExplanation.confidence : 'N/A'}`);

  if (s.expectedVerdict && res.verdict !== s.expectedVerdict) {
    throw new Error(`Verdict mismatch for ${s.url}: got ${res.verdict}, expected ${s.expectedVerdict}`);
  }
  if (s.minRisk !== undefined && res.riskPercentage < s.minRisk) {
    throw new Error(`Risk below min for ${s.url}: ${res.riskPercentage} < ${s.minRisk}`);
  }
  if (s.maxRisk !== undefined && res.riskPercentage > s.maxRisk) {
    throw new Error(`Risk above max for ${s.url}: ${res.riskPercentage} > ${s.maxRisk}`);
  }
  if (!res.hybrid) throw new Error('Missing res.hybrid');
  if (!res.aiExplanation) throw new Error('Missing res.aiExplanation');
});

console.log('\n=== ALL HYBRID AI DETECTION TESTS PASSED (100%) ===');
