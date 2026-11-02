"""
Veridex AI - Automated Unit & Heuristic Verification Test Suite
Runs through positive and negative test cases to verify engine accuracy.
"""

import sys
import os

# Ensure engine can be imported or executed
def test_engine_heuristics():
    print("=" * 60)
    print(" Veridex AI Engine Heuristic Self-Test")
    print("=" * 60)

    # Let's run a node test script that loads the JS modules directly
    test_js = """
    const { VeridexEngine } = require('./engine/veridex-engine.js');
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
      }
    ];

    let passed = 0;
    for (const tc of testCases) {
      const res = engine.analyze(tc.url, tc.dom);
      const verdictMatches = res.verdict === tc.expectedVerdict;
      const scoreMatches = (tc.minScore ? res.riskScore >= tc.minScore : true) &&
                           (tc.maxScore ? res.riskScore <= tc.maxScore : true);

      if (verdictMatches && scoreMatches) {
        console.log(`[PASS] ${tc.name}: Score=${res.riskScore}, Verdict=${res.verdict}`);
        passed++;
      } else {
        console.error(`[FAIL] ${tc.name}: Expected ${tc.expectedVerdict}, got ${res.verdict} (Score: ${res.riskScore})`);
      }
    }

    console.log(`\\nResult: ${passed}/${testCases.length} tests passed.`);
    if (passed !== testCases.length) process.exit(1);
    """

    with open("D:\\veridex-ai\\test_runner.js", "w", encoding="utf-8") as f:
        f.write(test_js)

if __name__ == '__main__':
    test_engine_heuristics()
