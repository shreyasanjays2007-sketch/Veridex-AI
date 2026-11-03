"""
Veridex AI - Model Exporter to Zero-Dependency JavaScript
Converts trained scikit-learn models into an ultra-fast, lightweight pure JavaScript inference engine
with full support for UPI/QR scams, Banking KYC, India Post smishing, Digital Arrest / TRAI extortion,
and one-click reporting to cybercrime.gov.in and the 1930 helpline.
"""

import os
import json
import joblib
from feature_extractor import VeridexFeatureExtractor

def tree_to_dict(tree, feature_names):
    """Recursively serializes a scikit-learn DecisionTreeClassifier into a compact nested dict."""
    tree_ = tree.tree_
    
    def recurse(node):
        if tree_.feature[node] != -2:  # Not a leaf
            feat_idx = int(tree_.feature[node])
            threshold = float(round(tree_.threshold[node], 4))
            left = recurse(tree_.children_left[node])
            right = recurse(tree_.children_right[node])
            return {
                "f": feat_idx,
                "t": threshold,
                "l": left,
                "r": right
            }
        else:
            val = tree_.value[node][0]
            total = float(val.sum())
            prob_phish = float(round(val[1] / total, 4)) if total > 0 else 0.0
            return {"p": prob_phish}
            
    return recurse(0)

def export_forest_to_json(rf_model, feature_names, max_trees: int = 50) -> dict:
    """Exports the most significant trees from the Random Forest into a lightweight model format."""
    trees_data = []
    estimators = rf_model.estimators_[:max_trees]
    for tree in estimators:
        trees_data.append(tree_to_dict(tree, feature_names))
        
    return {
        "version": "1.1.0",
        "model_type": "RandomForestEnsemble",
        "num_trees": len(trees_data),
        "feature_names": feature_names,
        "trees": trees_data
    }

def generate_javascript_code(model_json: dict) -> str:
    """Generates a standalone, zero-dependency JavaScript class implementing on-device ML scoring."""
    json_str = json.dumps(model_json, separators=(',', ':'))
    
    js_template = f"""/**
 * Veridex AI — On-Device Pure JavaScript Machine Learning Inference Engine
 * Zero external dependencies. Executes 100% locally in browser content scripts or service worker.
 * Includes Indian cyber-crime defense (UPI/QR, SBI/HDFC/Paytm KYC, India Post, Digital Arrest)
 * and One-Click Cybercrime Reporting to cybercrime.gov.in & Helpline 1930.
 */

const VERIDEX_ML_DATA = {json_str};

class VeridexMLEngine {{
  constructor(modelData = VERIDEX_ML_DATA) {{
    this.model = modelData;
    this.featureNames = this.model.feature_names;
    this.trees = this.model.trees;
    this.reportHelpline = "1930";
    this.reportPortalUrl = "https://cybercrime.gov.in";
  }}

  shannonEntropy(str) {{
    if (!str) return 0.0;
    const freq = {{}};
    for (let i = 0; i < str.length; i++) {{
      const c = str[i];
      freq[c] = (freq[c] || 0) + 1;
    }}
    let entropy = 0;
    const len = str.length;
    for (const char in freq) {{
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }}
    return entropy;
  }}

  levenshtein(s1, s2) {{
    if (s1.length < s2.length) return this.levenshtein(s2, s1);
    if (s2.length === 0) return s1.length;
    let prev = [];
    for (let j = 0; j <= s2.length; j++) prev[j] = j;
    for (let i = 0; i < s1.length; i++) {{
      const curr = [i + 1];
      for (let j = 0; j < s2.length; j++) {{
        const ins = prev[j + 1] + 1;
        const del = curr[j] + 1;
        const sub = prev[j] + (s1[i] !== s2[j] ? 1 : 0);
        curr[j + 1] = Math.min(ins, del, sub);
      }}
      prev = curr;
    }}
    return prev[s2.length];
  }}

  getApexDomain(hostname) {{
    const parts = (hostname || '').toLowerCase().split('.');
    if (parts.length >= 2) {{
      if (parts.length >= 3 && ['co', 'gov', 'nic', 'ac', 'edu', 'org'].includes(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) {{
        return parts.slice(-3).join('.');
      }}
      return parts.slice(-2).join('.');
    }}
    return hostname;
  }}

  extractFeatures(urlString, domSignals = {{}}) {{
    let clean = (urlString || '').trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {{
      clean = 'http://' + clean;
    }}

    let hostname = '';
    let path = '';
    let query = '';
    let port = '';
    let protocol = 'http:';

    try {{
      const u = new URL(clean);
      hostname = (u.hostname || '').toLowerCase();
      path = u.pathname || '';
      query = u.search || '';
      port = u.port || '';
      protocol = u.protocol || 'http:';
    }} catch (e) {{
      hostname = (clean.split('/')[2] || clean).toLowerCase();
    }}

    const urlLen = clean.length;
    const hostLen = hostname.length;
    const pathLen = path.length + (query ? query.length : 0);

    const countChar = (str, char) => (str.split(char).length - 1);

    const numDots = countChar(clean, '.');
    const numHyphens = countChar(clean, '-');
    const numUnderscores = countChar(clean, '_');
    const numSlashes = countChar(clean, '/');
    const numQuestionmarks = countChar(clean, '?');
    const numEquals = countChar(clean, '=');
    const numAtSymbols = countChar(clean, '@');

    const digitsInHost = (hostname.match(/\\d/g) || []).length;
    const digitRatioHost = hostLen > 0 ? digitsInHost / hostLen : 0;
    const totalDigits = (clean.match(/\\d/g) || []).length;

    const subdomains = hostname.split('.');
    const numSubdomains = Math.max(0, subdomains.length - 2);

    const isHttps = protocol === 'https:' ? 1.0 : 0.0;
    const isRawIp = /^(\\d{{1,3}}\\.)*3\\d{{1,3}}$/.test(hostname) ? 1.0 : 0.0;
    const hasPort = port && port !== '80' && port !== '443' ? 1.0 : 0.0;
    const hasPunycode = hostname.includes('xn--') ? 1.0 : 0.0;
    const hasDoubleSlashPath = path.includes('//') ? 1.0 : 0.0;

    const entropyHost = this.shannonEntropy(hostname);
    const entropyPath = this.shannonEntropy(path);

    const suspiciousKws = [
      'login', 'signin', 'verify', 'account', 'update', 'secure', 'banking',
      'wallet', 'recovery', 'restore', 'seedphrase', 'airdrop', 'claim', 'bonus',
      'free', 'crypto', 'password', 'billing', 'paypal', 'appleid', 'fake', 'scam', 'robux', 'delivery', 'portal', 'alert',
      'kyc', 'pancard', 'pan-card', 'aadhaar', 'debit-freeze', 'unblock', 'netbanking',
      'upi', 'upipay', 'cashback', 'scratch-card', 'scan-qr', 'receive-money', 'upi-refund',
      'indiapost', 'speedpost', 'parcel-stuck', 'address-update', 'redelivery',
      'digital-arrest', 'trai', 'sim-deactivation', 'sim-block', 'cbi-warrant', 'narcotics'
    ];
    const lowerHost = hostname.toLowerCase();
    const lowerPath = (path + '?' + query).toLowerCase();
    let kwHost = 0;
    let kwPath = 0;
    for (const kw of suspiciousKws) {{
      if (lowerHost.includes(kw)) kwHost++;
      if (lowerPath.includes(kw)) kwPath++;
    }}

    const highRiskTlds = new Set(['top', 'xyz', 'club', 'work', 'click', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq', 'shop', 'site', 'cc', 'network', 'live', 'link', 'online', 'space']);
    const tld = subdomains.length > 0 ? subdomains[subdomains.length - 1].toLowerCase() : '';
    const isHighRiskTld = highRiskTlds.has(tld) ? 1.0 : 0.0;

    const brands = [
      'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'chase', 'binance', 'metamask', 'usps', 'steam', 'steamcommunity', 'roblox',
      'sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'paytm', 'phonepe', 'icici', 'pnb', 'kotak', 'axisbank',
      'indiapost', 'speedpost', 'bluedart', 'dtdc', 'delhivery', 'trai', 'cbi'
    ];
    let minBrandDist = 999;
    const hostParts = hostname.split(/[.\\-_]/);
    for (const brand of brands) {{
      for (const part of hostParts) {{
        if (part.length >= 3 && part !== 'www') {{
          const d = this.levenshtein(part, brand);
          if (brand.length <= 4 && d > 1) continue;
          if (d < minBrandDist) minBrandDist = d;
        }}
      }}
    }}
    minBrandDist = Math.min(minBrandDist, 10);

    const apex = this.getApexDomain(hostname);
    const officialBrandMap = {{
      paypal: ['paypal.com', 'paypal.me'],
      apple: ['apple.com', 'icloud.com'],
      google: ['google.com', 'google.co.in', 'google.co.uk'],
      microsoft: ['microsoft.com', 'live.com', 'office.com'],
      amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk'],
      netflix: ['netflix.com'],
      chase: ['chase.com'],
      sbi: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
      onlinesbi: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
      hdfc: ['hdfcbank.com', 'hdfc.com'],
      hdfcbank: ['hdfcbank.com', 'hdfc.com'],
      paytm: ['paytm.com', 'paytmbank.com'],
      phonepe: ['phonepe.com'],
      indiapost: ['indiapost.gov.in'],
      speedpost: ['indiapost.gov.in'],
      trai: ['trai.gov.in'],
      cbi: ['cbi.gov.in'],
      bluedart: ['bluedart.com'],
      dtdc: ['dtdc.in', 'dtdc.com'],
      delhivery: ['delhivery.com']
    }};

    let isBrandImpersonation = 0.0;
    for (const b in officialBrandMap) {{
      if (hostname.includes(b)) {{
        if (!officialBrandMap[b].includes(apex)) {{
          isBrandImpersonation = 1.0;
          break;
        }}
      }}
    }}

    let hasBrandSubdomain = 0.0;
    if (subdomains.length > 2) {{
      const subStr = subdomains.slice(0, -2).join('.');
      for (const target of brands) {{
        if (subStr.includes(target) && !apex.includes(target)) {{
          hasBrandSubdomain = 1.0;
          break;
        }}
      }}
    }}

    const isGov = (/\\.(gov|gov\\.[a-z]{{2}}|nic\\.in|mil)$/i.test(apex)) ? 1.0 : 0.0;
    let isDeceptiveGov = 0.0;
    if (isGov === 0.0) {{
      if (hostname.includes('gov') || hostname.includes('nic')) isDeceptiveGov = 1.0;
    }} else if (hasBrandSubdomain === 1.0) {{
      isDeceptiveGov = 1.0;
    }}

    const topReputable = new Set([
      'google.com', 'google.co.in', 'wikipedia.org', 'github.com', 'amazon.com',
      'amazon.in', 'chase.com', 'paypal.com', 'apple.com', 'scamwatch.gov.au',
      'snopes.com', 'bbc.com', 'nytimes.com', 'cloudflare.com', 'discord.com',
      'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'paytm.com', 'phonepe.com',
      'indiapost.gov.in', 'trai.gov.in', 'bluedart.com', 'dtdc.in', 'delhivery.com',
      'cybercrime.gov.in', 'incometax.gov.in', 'uidai.gov.in'
    ]);
    const isTopReputable = (topReputable.has(apex) && hasBrandSubdomain === 0.0 && isBrandImpersonation === 0.0) ? 1.0 : 0.0;

    // Specialized Indian Threat Detectors
    const bankBrands = ['sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'paytm', 'phonepe', 'icici', 'pnb'];
    const kycTerms = ['kyc', 'pan', 'aadhaar', 'unblock', 'debit-freeze', 'netbanking', 'login', 'verify'];
    let isIndianBankingKyc = 0.0;
    for (const bb of bankBrands) {{
      if (hostname.includes(bb) && !(officialBrandMap[bb] || []).includes(apex)) {{
        if (kycTerms.some(kt => lowerHost.includes(kt) || lowerPath.includes(kt))) {{
          isIndianBankingKyc = 1.0;
          break;
        }}
      }}
    }}

    const upiTerms = ['upi', 'upipay', 'cashback', 'reward', 'scratch-card', 'receive-money', 'upi-refund', 'scan-qr'];
    let isUpiQrScam = 0.0;
    if (upiTerms.some(ut => lowerHost.includes(ut) || lowerPath.includes(ut))) {{
      if (isTopReputable === 0.0 && isGov === 0.0) isUpiQrScam = 1.0;
    }}

    const courierBrands = ['indiapost', 'speedpost', 'bluedart', 'dtdc', 'delhivery'];
    const courierTerms = ['parcel', 'track', 'address', 'redelivery', 'customs', 'delivery'];
    let isCourierSpoof = 0.0;
    for (const cb of courierBrands) {{
      if ((hostname.includes(cb) || lowerPath.includes(cb)) && !(officialBrandMap[cb] || []).includes(apex)) {{
        if (courierTerms.some(ct => lowerHost.includes(ct) || lowerPath.includes(ct))) {{
          isCourierSpoof = 1.0;
          break;
        }}
      }}
    }}

    const arrestTerms = ['digital-arrest', 'trai', 'cbi', 'arrest-warrant', 'narcotics', 'sim-block', 'sim-deactivation', 'court-summons'];
    let hasDigitalArrest = 0.0;
    if (arrestTerms.some(at => lowerHost.includes(at) || lowerPath.includes(at))) {{
      if (!['trai.gov.in', 'cbi.gov.in', 'cybercrime.gov.in'].includes(apex)) hasDigitalArrest = 1.0;
    }}

    const dom = domSignals || {{}};
    const domPassword = (dom.hasPasswordField || dom.has_password_field) ? 1.0 : 0.0;
    const domCc = (dom.hasCreditCardField || dom.has_credit_card_field) ? 1.0 : 0.0;
    const domUrgencySeed = (dom.hasUrgencyPatterns || dom.hasSeedPhraseInputs || dom.hasCountdown) ? 1.0 : 0.0;
    const domUpiQr = (dom.hasUpiQrScam || dom.claimsQrReceivesMoney || dom.hasFakeQrScanner) ? 1.0 : 0.0;
    const domKycPan = (dom.hasKycPanHarvesting || dom.requestsPanAadhaarOtp) ? 1.0 : 0.0;
    const domCourierFee = (dom.hasCourierSmishingFee || dom.requestsSmallRedeliveryFee) ? 1.0 : 0.0;
    const domDigitalArrest = (dom.hasDigitalArrestLanguage || dom.hasTraiSimBlockThreat || dom.hasCbiPoliceExtortion) ? 1.0 : 0.0;

    return [
      urlLen, hostLen, pathLen,
      numDots, numHyphens, numUnderscores, numSlashes, numQuestionmarks, numEquals, numAtSymbols,
      totalDigits, digitRatioHost, numSubdomains,
      isHttps, isRawIp, hasPort, hasPunycode, hasDoubleSlashPath,
      entropyHost, entropyPath,
      kwHost, kwPath,
      isHighRiskTld, minBrandDist, hasBrandSubdomain, isBrandImpersonation, isGov, isDeceptiveGov, isTopReputable,
      isIndianBankingKyc, isUpiQrScam, isCourierSpoof, hasDigitalArrest,
      domPassword, domCc, domUrgencySeed, domUpiQr, domKycPan, domCourierFee, domDigitalArrest
    ];
  }}

  evaluateTree(node, features) {{
    let curr = node;
    while (curr.p === undefined) {{
      const val = features[curr.f];
      curr = (val <= curr.t) ? curr.l : curr.r;
    }}
    return curr.p;
  }}

  predict(urlString, domSignals = {{}}) {{
    const features = this.extractFeatures(urlString, domSignals);
    let sumProb = 0;
    for (const tree of this.trees) {{
      sumProb += this.evaluateTree(tree, features);
    }}
    const rawProb = sumProb / this.trees.length;

    let finalProb = rawProb;
    // 1. Verified authentic top domains & authentic government portals
    const isTopRep = (features[28] === 1.0);
    const isGenuineGov = (features[26] === 1.0 && features[27] === 0.0 && features[24] === 0.0);

    if (isTopRep || isGenuineGov) {{
      finalProb = Math.min(finalProb, 0.005);
    }} else {{
      // 2. Specialized threat overrides for non-allowlisted domains
      if (features[29] === 1.0 || features[37] === 1.0) finalProb = Math.max(finalProb, 0.92); // Banking KYC
      if (features[32] === 1.0 || features[39] === 1.0) finalProb = Math.max(finalProb, 0.95); // Digital Arrest
      if (features[31] === 1.0 || features[38] === 1.0) finalProb = Math.max(finalProb, 0.90); // India Post Smishing
      if (features[30] === 1.0 || features[36] === 1.0) finalProb = Math.max(finalProb, 0.88); // UPI / QR Scam
      if (features[25] === 1.0) finalProb = Math.max(finalProb, 0.85); // Brand Impersonation
      if (features[27] === 1.0) finalProb = Math.max(finalProb, 0.88); // Deceptive Gov Spoof
      if (features[23] >= 1.0 && features[23] <= 2.0) finalProb = Math.max(finalProb, 0.85); // Typosquatting (distance 1 or 2)
      if (features[22] === 1.0) finalProb = Math.max(finalProb, 0.45); // High-risk TLD
      if (features[13] === 0.0) finalProb = Math.max(finalProb, 0.22); // Insecure HTTP
    }}

    const riskScore = Math.round(finalProb * 100);
    const verdict = riskScore >= 40 ? 'suspicious' : 'neutral';

    let levelLabel = 'Minimal Risk';
    if (riskScore >= 75) levelLabel = 'Critical Danger';
    else if (riskScore >= 55) levelLabel = 'High Suspicion';
    else if (riskScore >= 40) levelLabel = 'Moderate Concern';
    else if (riskScore >= 20) levelLabel = 'Low Concern';

    const factors = [];
    if (features[29] === 1.0 || features[37] === 1.0) factors.push('Fake Banking/Wallet KYC page (SBI / HDFC / Paytm / PhonePe pan-link or unblock fraud)');
    if (features[32] === 1.0 || features[39] === 1.0) factors.push('Digital Arrest or TRAI SIM disconnection extortion threat detected');
    if (features[31] === 1.0 || features[38] === 1.0) factors.push('Fake India Post / Courier delivery smishing (fraudulent redelivery fee or address update)');
    if (features[30] === 1.0 || features[36] === 1.0) factors.push('UPI / QR scam lure (fake cashback, deceptive scan-to-receive, or refund trap)');
    if (features[25] === 1.0) factors.push('Brand name stitched/masquerading on unauthorized domain');
    if (features[27] === 1.0) factors.push('Deceptive government lookalike or stitched spoofing detected');
    if (features[22] === 1.0) factors.push('Abused high-risk TLD detected');
    if (features[24] === 1.0) factors.push('Subdomain brand masquerading / deceptive spoofing');
    if (features[23] >= 1 && features[23] <= 2) factors.push('Typosquatting brand lookalike');
    if (features[14] === 1.0) factors.push('Raw numeric IP address used as website host');
    if (features[18] >= 3.6) factors.push('High Shannon entropy (DGA / randomly generated domain)');
    if (features[20] >= 1) factors.push('Suspicious credential/security keyword in hostname');
    if (features[33] === 1.0 && features[13] === 0.0) factors.push('Insecure password input on unencrypted HTTP');

    return {{
      url: urlString,
      riskScore,
      probability: Number(finalProb.toFixed(4)),
      verdict,
      levelLabel,
      factors,
      reporting: {{
        helpline: this.reportHelpline,
        portalUrl: this.reportPortalUrl,
        buttonHtml: `<a href="${{this.reportPortalUrl}}" target="_blank" rel="noopener noreferrer" style="background:#dc2626;color:#fff;padding:8px 16px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-flex;align-items:center;gap:6px;">🚨 Report Fraud (Call ${{this.reportHelpline}})</a>`
      }},
      features
    }};
  }}
}}

if (typeof module !== 'undefined' && module.exports) {{
  module.exports = {{ VeridexMLEngine, VERIDEX_ML_DATA }};
}}
if (typeof self !== 'undefined') {{
  self.VeridexMLEngine = VeridexMLEngine;
  self.VERIDEX_ML_DATA = VERIDEX_ML_DATA;
}}
if (typeof window !== 'undefined') {{
  window.VeridexMLEngine = VeridexMLEngine;
  window.VERIDEX_ML_DATA = VERIDEX_ML_DATA;
}}
if (typeof globalThis !== 'undefined') {{
  globalThis.VeridexMLEngine = VeridexMLEngine;
  globalThis.VERIDEX_ML_DATA = VERIDEX_ML_DATA;
}}
"""
    return js_template

def export_all(raw_model_path: str, output_js_path: str, output_json_path: str):
    print("Exporting trained model to browser-ready JavaScript and JSON...")
    best_model = joblib.load(raw_model_path)
    extractor = VeridexFeatureExtractor()
    
    model_json = export_forest_to_json(best_model, extractor.FEATURE_NAMES, max_trees=50)
    
    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(model_json, f, indent=2)
    print(f"JSON model exported to: {output_json_path} ({os.path.getsize(output_json_path) / 1024:.1f} KB)")
    
    js_code = generate_javascript_code(model_json)
    with open(output_js_path, "w", encoding="utf-8") as f:
        f.write(js_code)
    print(f"Zero-dependency JS model exported to: {output_js_path} ({os.path.getsize(output_js_path) / 1024:.1f} KB)")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    raw_m = os.path.join(base_dir, "veridex_raw_model.joblib")
    out_js = os.path.join(base_dir, "veridex-ml-model.js")
    out_json = os.path.join(base_dir, "veridex_ml_weights.json")
    if os.path.exists(raw_m):
        export_all(raw_m, out_js, out_json)
    else:
        print(f"Model file {raw_m} not found yet. Run train.py first.")
