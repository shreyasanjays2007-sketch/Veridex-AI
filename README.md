# 🛡️ Veridex AI — Scam & Phishing Detection Extension

**Veridex AI** is an intelligent, privacy-preserving, on-device browser extension designed to detect phishing websites, typosquatting, deceptive scams, and fraudulent web patterns in real-time.

---

##  Workflow Architecture

```
                      1. User clicks a website link
                   (e.g., suspicious shopping or bank link)
                                     │
                                     ▼
                      2. Veridex AI runs in background
                  (Checks URL & available DOM signals locally)
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
          [ Suspicious ]                       [ No Warning Triggered ]
     Show prominent warning popup            Show a neutral status;
     and explain the specific risk           never guarantee site is safe
```

---

##  Key Capabilities

1. **Generalized Phishing & Fake Site Detection (Not Limited to Blocklists)**:
   - **Homograph & Punycode Analysis**: Detects internationalized character lookalikes (e.g. Cyrillic `а` / `е` / `о` mimicking Latin letters).
   - **Brand Impersonation & Typosquatting**: Calculates Levenshtein distance and subdomain masquerading against popular targeted services (PayPal, Apple, Google, Microsoft, Chase, Bank of America, Binance, Amazon, etc.).
   - **Shannon Entropy (DGA Detection)**: Identifies randomly generated domain names used in disposable phishing campaigns.
   - **Raw IP Hostname Detection**: Flags non-standard IP navigation (e.g. `http://198.51.100.24/...`).
   - **Abused TLD Profiling**: Flags high-risk top-level domains frequently associated with fraud (`.top`, `.work`, `.click`, `.buzz`, `.tk`, etc.).
   - **Excessive Hyphenation & Deep Subdomains**: Catches subdomain nesting tricks designed to disguise the actual apex domain.

2. **In-Page Behavioral & DOM Heuristics**:
   - Password inputs on unencrypted HTTP connections.
   - Cross-domain form action exfiltration (credentials submitting to untrusted third-party hosts).
   - Brand title spoofing (page `<title>` claiming to be a financial institution while hosted on an unverified domain).
   - Coercive psychological urgency ("Account suspended in 24 hours", "You have won! Claim now", countdown timers).
   - Crypto seed phrase harvesting (detects requests for 12/24-word recovery phrases).

3. **In-Page Warning Alert Modal**:
   - High-visibility cyber defense modal appears automatically when threats are identified.
   - Details the risk level, numeric score (0-100), and plain-English breakdown of all detected red flags.
   - Offers safe navigation back (`Take Me Back to Safety`), copyable risk reports, or explicit session dismissals.

4. **Strict Neutral Status Implementation**:
   - As requested: *"Show a neutral status; don't guarantee the site is safe."*
   - When no heuristics are triggered, Veridex AI displays **Neutral Status (Unverified)**.
   - Explicitly reminds users that no automated system can guarantee 100% safety, preventing false senses of security.

5. **100% On-Device & Privacy First**:
   - All heuristics, parsing, string matching, and scoring execute locally in the browser.
   - Zero telemetry, zero browsing history sent to external cloud servers.

6. **Interactive URL Scanner in Toolbar Popup**:
   - Quick input tool in the extension popup allowing users to paste and analyze suspicious links before clicking.

---

##  Project Structure

```
D:\veridex-ai\
├── manifest.json              # Chrome Manifest V3 configuration
├── README.md                  # Complete architecture & documentation
├── INSTALL_GUIDE.md           # Visual step-by-step installation instructions
├── generate_icons.py          # Icon generation script
├── test_runner.js             # Automated heuristic unit test runner
│
├── icons/                     # Extension icons (16, 32, 48, 128)
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   ├── icon128.png
│   └── icon.svg
│
├── engine/                    # Core client-side detection engine
│   ├── brand-database.js      # Canonical brand definitions & targets
│   ├── tld-risk.js            # TLD risk sets, entropy & homoglyph helpers
│   └── veridex-engine.js      # VeridexEngine class with multi-factor scoring
│
├── background/
│   └── service-worker.js      # MV3 service worker monitoring navigations
│
├── content/                   # Content scripts injected into visited pages
│   ├── content.js             # DOM signal extractor & message dispatcher
│   ├── warning-modal.js       # In-page warning alert modal controller
│   └── warning-modal.css      # Alert modal styling & glassmorphic themes
│
├── popup/                     # Extension popup interface
│   ├── popup.html             # UI with Current Page, Scanner, and Settings
│   ├── popup.css              # Cyber-defense dark theme styling
│   └── popup.js               # Popup interactions & live tab status
│
├── options/                   # Settings page
│   ├── options.html
│   ├── options.css
│   └── options.js
│
└── test-lab/                  # Controlled testing suite & scenarios
    ├── index.html             # Interactive testing hub & workflow diagram
    ├── test-lab.css
    ├── test-lab.js
    ├── server.py              # Local HTTP test server
    └── scenarios/
        ├── fake-banking.html  # PayPal brand spoofing with form harvester
        ├── scam-shopping.html # Flash sale urgency countdown & card input
        ├── fake-crypto.html   # MetaMask seed phrase phishing
        ├── idn-homoglyph.html # Cyrillic lookalike homoglyph attack
        └── neutral-sample.html# Benign blog demonstrating neutral status
```

---

##  Quick Start & Deployment

1. Open your browser and go to `chrome://extensions` (or `edge://extensions`).
2. Turn ON **Developer mode** (top-right toggle).
3. Click **Load unpacked** (top-left).
4. Select `D:\veridex-ai`.
5. Pin the extension to your browser toolbar.
6. Open `D:\veridex-ai\test-lab\index.html` to test live phishing scenarios and verify warning popups!
