"""
Veridex AI - Comprehensive Verification Test Suite
Tests the trained ML model against every URL and expected verdict in diagnose (1).js and test_runner (1).js,
plus specialized tests for:
- UPI and QR scams
- Fake SBI / HDFC / Paytm / PhonePe KYC pages
- Fake India Post and courier delivery pages
- "Digital arrest" and TRAI extortion language
- Authentic Indian banking, logistics, and government portals (0 false positives)
"""

import os
os.environ["PYTHONWARNINGS"] = "ignore"
import sys
import warnings
warnings.simplefilter('ignore')
warnings.filterwarnings('ignore')
import joblib

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from predict import analyze_url

TEST_SUITE = [
    # ---------------------------------------------------------
    # 1. UPI & QR Scam Pages
    # ---------------------------------------------------------
    { "url": "https://claim-phonepe-cashback-500.xyz/upi-pay", "expected": "suspicious", "min": 80, "cat": "UPI/QR Scam" },
    { "url": "http://scan-qr-to-receive-money.online/qr-intent", "expected": "suspicious", "min": 80, "cat": "UPI/QR Scam" },
    { "url": "http://paytm-refund-instant-portal.click/claim", "expected": "suspicious", "min": 80, "cat": "UPI/QR Scam" },
    { "url": "https://gpay-reward-scratch-win.shop/scratch", "expected": "suspicious", "min": 80, "cat": "UPI/QR Scam" },
    { "url": "https://instant-scratch-card.top", "dom": { "hasUpiQrScam": True }, "expected": "suspicious", "min": 85, "cat": "UPI/QR Scam (DOM)" },

    # ---------------------------------------------------------
    # 2. Fake SBI / HDFC / Paytm / PhonePe KYC Fraud
    # ---------------------------------------------------------
    { "url": "http://sbi-kyc-verification.com/login", "expected": "suspicious", "min": 85, "cat": "Banking KYC Phish" },
    { "url": "https://onlinesbi-pan-update.net/auth", "expected": "suspicious", "min": 85, "cat": "Banking KYC Phish" },
    { "url": "http://hdfc-netbanking-rewards.xyz/redeem", "expected": "suspicious", "min": 85, "cat": "Banking KYC Phish" },
    { "url": "http://paytm-kyc-expiry-alert.org/pan-link", "expected": "suspicious", "min": 85, "cat": "Banking KYC Phish" },
    { "url": "http://phonepe-cashback-claim.in/scratch-card", "expected": "suspicious", "min": 85, "cat": "Banking KYC Phish" },
    { "url": "https://secure-kyc-portal.net/form", "dom": { "hasKycPanHarvesting": True }, "expected": "suspicious", "min": 85, "cat": "Banking KYC (DOM)" },

    # ---------------------------------------------------------
    # 3. Fake India Post & Courier Smishing
    # ---------------------------------------------------------
    { "url": "http://indiapost-parcel-delivery.top/update-address", "expected": "suspicious", "min": 85, "cat": "Courier Smishing" },
    { "url": "http://speedpost-address-update.xyz/redelivery", "expected": "suspicious", "min": 85, "cat": "Courier Smishing" },
    { "url": "http://delhivery-reschedule-fee.in/pay-5-rupees", "expected": "suspicious", "min": 85, "cat": "Courier Smishing" },
    { "url": "http://bluedart-dispatch-status.cc/address", "expected": "suspicious", "min": 80, "cat": "Courier Smishing" },
    { "url": "https://parcel-redelivery-portal.org", "dom": { "hasCourierSmishingFee": True }, "expected": "suspicious", "min": 85, "cat": "Courier Smishing (DOM)" },

    # ---------------------------------------------------------
    # 4. "Digital Arrest" & TRAI Extortion Language
    # ---------------------------------------------------------
    { "url": "http://trai-sim-deactivation-notice.com/case/9912", "expected": "suspicious", "min": 85, "cat": "Digital Arrest / TRAI" },
    { "url": "http://cbi-digital-arrest-warrant.net/verify", "expected": "suspicious", "min": 85, "cat": "Digital Arrest / TRAI" },
    { "url": "http://police-cyber-cell-arrest-notice.xyz/statement", "expected": "suspicious", "min": 85, "cat": "Digital Arrest / TRAI" },
    { "url": "https://video-statement-investigation.cc", "dom": { "hasDigitalArrestLanguage": True }, "expected": "suspicious", "min": 90, "cat": "Digital Arrest (DOM)" },

    # ---------------------------------------------------------
    # 5. Authentic Indian Banking, Logistics & Regulators (Zero False Positives)
    # ---------------------------------------------------------
    { "url": "https://sbi.co.in", "expected": "neutral", "max": 5, "cat": "Authentic Indian Bank" },
    { "url": "https://onlinesbi.sbi", "expected": "neutral", "max": 5, "cat": "Authentic Indian Bank" },
    { "url": "https://hdfcbank.com", "expected": "neutral", "max": 5, "cat": "Authentic Indian Bank" },
    { "url": "https://paytm.com", "expected": "neutral", "max": 5, "cat": "Authentic Indian Wallet" },
    { "url": "https://phonepe.com", "expected": "neutral", "max": 5, "cat": "Authentic Indian Wallet" },
    { "url": "https://indiapost.gov.in", "expected": "neutral", "max": 5, "cat": "Authentic India Post" },
    { "url": "https://trai.gov.in", "expected": "neutral", "max": 5, "cat": "Authentic TRAI Portal" },
    { "url": "https://bluedart.com", "expected": "neutral", "max": 5, "cat": "Authentic Courier" },
    { "url": "https://delhivery.com", "expected": "neutral", "max": 5, "cat": "Authentic Courier" },
    { "url": "https://dtdc.in", "expected": "neutral", "max": 5, "cat": "Authentic Courier" },
    { "url": "https://cybercrime.gov.in", "expected": "neutral", "max": 5, "cat": "Authentic Gov Cybercrime" },
    { "url": "https://incometax.gov.in", "expected": "neutral", "max": 5, "cat": "Authentic Gov Incometax" },

    # ---------------------------------------------------------
    # 6. Global Phishing & Scam Scenarios (from diagnose (1).js)
    # ---------------------------------------------------------
    { "url": "www.scam.com", "expected": "suspicious", "min": 70, "cat": "Reported Scam" },
    { "url": "https://scam.com", "expected": "suspicious", "min": 70, "cat": "Reported Scam" },
    { "url": "http://fake-apple-login.com", "expected": "suspicious", "min": 75, "cat": "Brand Phish" },
    { "url": "http://paypal-security-update.com", "expected": "suspicious", "min": 75, "cat": "Brand Phish" },
    { "url": "http://chase-bank-verify.com", "expected": "suspicious", "min": 75, "cat": "Brand Phish" },
    { "url": "http://package-delivery-usps.com", "expected": "suspicious", "min": 75, "cat": "Courier Phish" },
    { "url": "http://free-robux-generator.net", "expected": "suspicious", "min": 75, "cat": "Gaming Scam" },
    { "url": "http://crypto-airdrop-claim.xyz", "expected": "suspicious", "min": 75, "cat": "Crypto Airdrop" },
    { "url": "http://netflix-billing-update.com", "expected": "suspicious", "min": 75, "cat": "Subscription Phish" },
    { "url": "http://amazon-prime-renewal.top", "expected": "suspicious", "min": 75, "cat": "Brand Phish" },
    { "url": "http://account-verification-alert.com", "expected": "suspicious", "min": 75, "cat": "Urgency Scam" },
    { "url": "http://login-security-portal.net", "expected": "suspicious", "min": 75, "cat": "Portal Phish" },
    { "url": "http://www-paypal.com", "expected": "suspicious", "min": 75, "cat": "Brand Stitching" },
    { "url": "http://steamcommuniity.com", "expected": "suspicious", "min": 75, "cat": "Typosquatting" },
    { "url": "http://wallet-connect-auth.network", "expected": "suspicious", "min": 75, "cat": "Crypto Phish" },
    { "url": "http://fake-gov.in", "expected": "suspicious", "min": 85, "cat": "Gov Lookalike" },
    { "url": "https://cybercrime.gov.in.attacker.xyz", "expected": "suspicious", "min": 85, "cat": "Gov Subdomain Spoof" },

    # ---------------------------------------------------------
    # 7. Global Authentic Websites (Zero False Positives)
    # ---------------------------------------------------------
    { "url": "https://www.google.com", "expected": "neutral", "max": 10, "cat": "Authentic Tech" },
    { "url": "https://www.google.co.in", "expected": "neutral", "max": 10, "cat": "Authentic Tech" },
    { "url": "https://en.wikipedia.org/wiki/Scam", "expected": "neutral", "max": 10, "cat": "Authentic Media" },
    { "url": "https://github.com", "expected": "neutral", "max": 10, "cat": "Authentic Tech" },
    { "url": "https://www.amazon.in", "expected": "neutral", "max": 10, "cat": "Authentic Tech" },
    { "url": "https://chase.com", "expected": "neutral", "max": 10, "cat": "Authentic Bank" },
    { "url": "https://paypal.com", "expected": "neutral", "max": 10, "cat": "Authentic FinTech" },
    { "url": "https://apple.com", "expected": "neutral", "max": 10, "cat": "Authentic Tech" },
    { "url": "https://scamwatch.gov.au", "expected": "neutral", "max": 10, "cat": "Authentic Gov" },
    { "url": "https://snopes.com", "expected": "neutral", "max": 10, "cat": "Authentic News" },
    { "url": "https://www.bbc.com", "expected": "neutral", "max": 10, "cat": "Authentic News" },
    { "url": "https://nytimes.com", "expected": "neutral", "max": 10, "cat": "Authentic News" },
    { "url": "https://cloudflare.com", "expected": "neutral", "max": 10, "cat": "Authentic Tech" },
    { "url": "https://discord.com", "expected": "neutral", "max": 10, "cat": "Authentic Tech" },
    { "url": "https://alexrivera-dev.org/posts", "expected": "neutral", "max": 35, "cat": "Authentic Blog" },
    { "url": "http://example-blog.com", "expected": "neutral", "max": 35, "cat": "Authentic Blog" },
    { "url": "https://discount-shop.xyz", "expected": "suspicious", "min": 35, "cat": "Suspicious TLD" }
]

def run_tests():
    import warnings
    warnings.filterwarnings('ignore')
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "veridex_model.joblib")
    model = joblib.load(model_path)
    
    print("=" * 80)
    print("🛡️  VERIDEX AI - ADVANCED CYBER-THREAT DIAGNOSTIC TEST SUITE")
    print("=" * 80)
    
    passed = 0
    scores = []
    category_stats = {}
    
    for tc in TEST_SUITE:
        cat = tc.get("cat", "General")
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "passed": 0}
        category_stats[cat]["total"] += 1

        dom = tc.get("dom")
        res = analyze_url(tc["url"], model, dom_signals=dom, verbose=False)
        score = res["risk_percentage"]
        verdict = res["verdict"]
        scores.append(score)
        
        verdict_ok = (verdict == tc["expected"])
        min_ok = ("min" not in tc or score >= tc["min"])
        max_ok = ("max" not in tc or score <= tc["max"])
        is_pass = verdict_ok and min_ok and max_ok
        
        status = "[PASS]" if is_pass else "[FAIL]"
        if is_pass:
            passed += 1
            category_stats[cat]["passed"] += 1
            
        print(f" {status} [{cat:<22}] {tc['url']:<48} -> Risk: {score:5.1f}% [{verdict.upper()}]")
        if not is_pass:
            print(f"       Details: min_ok={min_ok}, max_ok={max_ok}, verdict_ok={verdict_ok}")
            
    print("-" * 80)
    print("Category Breakdown:")
    for c, st in category_stats.items():
        print(f"  • {c:<28}: {st['passed']}/{st['total']} passed ({st['passed']/st['total']*100:.0f}%)")
        
    print("-" * 80)
    print(f"Final Test Result: {passed}/{len(TEST_SUITE)} tests passed ({passed/len(TEST_SUITE)*100:.1f}%)")
    unique_scores = len(set(scores))
    print(f"Risk Score Spectrum: Min={min(scores):.1f}%, Max={max(scores):.1f}%, Unique Levels={unique_scores}")
    print("=" * 80)
    
    if passed == len(TEST_SUITE):
        print("ALL TESTS PASSED WITH 100% SUCCESS RATE!")
    else:
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
