"""
Veridex AI - Advanced ML URL Prediction & Risk Analysis CLI
Runs on-device ML inference with deep detection for UPI/QR scams, Banking KYC,
India Post smishing, and Digital Arrest / TRAI extortion.
Includes one-click reporting to cybercrime.gov.in and the 1930 helpline.
"""

import os
os.environ["PYTHONWARNINGS"] = "ignore"
import sys
import warnings
warnings.simplefilter('ignore')
warnings.filterwarnings('ignore')
import json
import argparse
import joblib

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from feature_extractor import VeridexFeatureExtractor

# Official National Cybercrime Reporting Coordinates
CYBERCRIME_PORTAL_URL = "https://cybercrime.gov.in"
CYBERCRIME_HELPLINE = "1930"

def format_risk_bar(score: float, width: int = 24) -> str:
    filled = int(round((score / 100.0) * width))
    bar = "=" * filled + "-" * (width - filled)
    return bar

def analyze_url(url: str, model, metadata: dict = None, dom_signals: dict = None, verbose: bool = True) -> dict:
    extractor = VeridexFeatureExtractor()
    features = extractor.extract_features(url, dom_signals)
    feat_dict = extractor.extract_dict(url, dom_signals)
    
    # Predict probability with calibrated model
    prob = float(model.predict_proba([features])[0][1])
    risk_pct = round(prob * 100.0, 1)
    
    # 1. Authentic top reputable domains & authentic government portals
    is_top_rep = (feat_dict.get("is_top_reputable_domain") == 1.0)
    is_genuine_gov = (
        feat_dict.get("is_gov_domain") == 1.0 and 
        feat_dict.get("is_deceptive_gov_spoof") == 0.0 and 
        feat_dict.get("has_brand_in_subdomain") == 0.0
    )

    if is_top_rep or is_genuine_gov:
        risk_pct = min(risk_pct, 0.5)
        prob = min(prob, 0.005)
    else:
        # 2. Critical Specialized Security Overrides for Non-Allowlisted Domains
        # A) Indian Banking / FinTech KYC Spoofing
        if feat_dict.get("is_indian_banking_kyc_spoof") == 1.0 or feat_dict.get("dom_has_kyc_pan_harvesting") == 1.0:
            risk_pct = max(risk_pct, 92.0)
            prob = max(prob, 0.92)

        # B) Digital Arrest & TRAI Extortion
        if feat_dict.get("has_digital_arrest_or_trai_language") == 1.0 or feat_dict.get("dom_has_digital_arrest_extortion") == 1.0:
            risk_pct = max(risk_pct, 95.0)
            prob = max(prob, 0.95)

        # C) Fake India Post & Courier Smishing
        if feat_dict.get("is_india_post_courier_spoof") == 1.0 or feat_dict.get("dom_has_courier_smishing_fee") == 1.0:
            risk_pct = max(risk_pct, 90.0)
            prob = max(prob, 0.90)

        # D) UPI & QR Scams
        if feat_dict.get("is_upi_qr_scam") == 1.0 or feat_dict.get("dom_has_upi_qr_scam") == 1.0:
            risk_pct = max(risk_pct, 88.0)
            prob = max(prob, 0.88)

        # E) Global Brand Impersonation & Government Spoofing
        if feat_dict.get("is_brand_impersonation") == 1.0:
            risk_pct = max(risk_pct, 85.0)
            prob = max(prob, 0.85)

        if feat_dict.get("is_deceptive_gov_spoof") == 1.0:
            risk_pct = max(risk_pct, 88.0)
            prob = max(prob, 0.88)
            
        if feat_dict.get("min_brand_edit_distance") in (1.0, 2.0):
            risk_pct = max(risk_pct, 85.0)
            prob = max(prob, 0.85)

        if feat_dict.get("num_keywords_host", 0) >= 2:
            risk_pct = max(risk_pct, 78.0)
            prob = max(prob, 0.78)

        url_lower = url.lower()
        if "scam.com" in url_lower or "robux" in url_lower or "fake" in url_lower:
            risk_pct = max(risk_pct, 85.0)
            prob = max(prob, 0.85)

        if feat_dict.get("dom_has_urgency_or_seedphrase") == 1.0 and ("seed" in url_lower or "crypto" in url_lower or "wallet" in url_lower):
            risk_pct = max(risk_pct, 92.0)
            prob = max(prob, 0.92)

        # High-risk TLD baseline
        if feat_dict.get("is_high_risk_tld") == 1.0:
            risk_pct = max(risk_pct, 45.0)
            prob = max(prob, 0.45)

        # Insecure HTTP on generic domain
        if feat_dict.get("is_https") == 0.0:
            risk_pct = max(risk_pct, 22.0)
            prob = max(prob, 0.22)

    # Classify verdict
    if risk_pct >= 75.0:
        verdict = "suspicious"
        severity = "CRITICAL THREAT"
        status_symbol = "[CRITICAL]"
    elif risk_pct >= 55.0:
        verdict = "suspicious"
        severity = "HIGH RISK"
        status_symbol = "[HIGH]"
    elif risk_pct >= 40.0:
        verdict = "suspicious"
        severity = "MODERATE SUSPICION"
        status_symbol = "[WARNING]"
    elif risk_pct >= 20.0:
        verdict = "neutral"
        severity = "LOW CONCERN (UNVERIFIED)"
        status_symbol = "[NEUTRAL]"
    else:
        verdict = "neutral"
        severity = "MINIMAL RISK"
        status_symbol = "[SAFE]"

    # Identify top trigger factors
    triggers = []
    if feat_dict.get("is_indian_banking_kyc_spoof") == 1.0 or feat_dict.get("dom_has_kyc_pan_harvesting") == 1.0:
        triggers.append("Fake Banking/Wallet KYC page (SBI / HDFC / Paytm / PhonePe pan-link or unblock fraud)")
    if feat_dict.get("has_digital_arrest_or_trai_language") == 1.0 or feat_dict.get("dom_has_digital_arrest_extortion") == 1.0:
        triggers.append("Digital Arrest or TRAI SIM disconnection extortion threat detected")
    if feat_dict.get("is_india_post_courier_spoof") == 1.0 or feat_dict.get("dom_has_courier_smishing_fee") == 1.0:
        triggers.append("Fake India Post / Courier delivery smishing (fraudulent redelivery fee or address update)")
    if feat_dict.get("is_upi_qr_scam") == 1.0 or feat_dict.get("dom_has_upi_qr_scam") == 1.0:
        triggers.append("UPI / QR scam lure (fake cashback, deceptive scan-to-receive, or refund trap)")
    if feat_dict.get("is_brand_impersonation") == 1.0:
        triggers.append("Brand name stitched/masquerading on unauthorized domain")
    if feat_dict.get("is_deceptive_gov_spoof") == 1.0:
        triggers.append("Deceptive government lookalike or stitched spoofing detected")
    if feat_dict.get("has_brand_in_subdomain") == 1.0:
        triggers.append("Subdomain brand masquerading / deceptive spoofing")
    if feat_dict.get("min_brand_edit_distance", 10) in (1, 2):
        triggers.append("Typosquatting brand lookalike (edit distance 1-2)")
    if feat_dict.get("is_raw_ip") == 1.0:
        triggers.append("Raw IPv4 address used as destination host")
    if feat_dict.get("entropy_hostname", 0) >= 3.6:
        triggers.append(f"High hostname Shannon entropy ({feat_dict['entropy_hostname']:.2f}) -> DGA pattern")
    if feat_dict.get("is_high_risk_tld") == 1.0:
        triggers.append("Abused high-risk top level domain")
    if feat_dict.get("num_keywords_host", 0) >= 1:
        triggers.append(f"Suspicious credential/security keyword in hostname ({int(feat_dict['num_keywords_host'])})")
    if feat_dict.get("dom_has_password_field") == 1.0 and feat_dict.get("is_https") == 0.0:
        triggers.append("Password input on unencrypted HTTP connection")
    if feat_dict.get("dom_has_urgency_or_seedphrase") == 1.0:
        triggers.append("Page requests crypto recovery seed phrase or employs coercive urgency countdown")
    if feat_dict.get("has_punycode") == 1.0:
        triggers.append("Internationalized Cyrillic/homoglyph punycode lookalike (xn--)")

    result = {
        "url": url,
        "risk_percentage": risk_pct,
        "probability": prob,
        "verdict": verdict,
        "severity": severity,
        "triggers": triggers,
        "reporting": {
            "portal_url": CYBERCRIME_PORTAL_URL,
            "helpline": CYBERCRIME_HELPLINE,
            "action": "Report incident to National Cyber Crime Reporting Portal (1930)"
        },
        "key_features": {
            "is_https": bool(feat_dict["is_https"]),
            "hostname_entropy": round(feat_dict["entropy_hostname"], 3),
            "num_subdomains": int(feat_dict["num_subdomains"]),
            "is_high_risk_tld": bool(feat_dict["is_high_risk_tld"]),
            "min_brand_dist": int(feat_dict["min_brand_edit_distance"]),
            "is_raw_ip": bool(feat_dict["is_raw_ip"]),
            "is_indian_kyc_spoof": bool(feat_dict["is_indian_banking_kyc_spoof"]),
            "is_upi_qr_scam": bool(feat_dict["is_upi_qr_scam"]),
            "is_courier_spoof": bool(feat_dict["is_india_post_courier_spoof"]),
            "has_digital_arrest": bool(feat_dict["has_digital_arrest_or_trai_language"])
        }
    }

    if verbose:
        bar = format_risk_bar(risk_pct)
        print("\n" + "-" * 70)
        print(f"[*] VERIDEX AI SCAN REPORT: {url}")
        print("-" * 70)
        print(f" Risk Meter : [{bar}] {risk_pct:5.1f}%")
        print(f" Threat Level: {status_symbol} {severity}")
        print(f" Verdict     : {verdict.upper()} (Strict neutral status if unverified)")
        
        if triggers:
            print("\n Detected Indicators of Compromise (IoCs):")
            for t in triggers:
                print(f"   [!] {t}")
        else:
            print("\n Detected Indicators of Compromise: None detected.")
            
        print("\n Key URL Telemetry:")
        for k, v in result["key_features"].items():
            print(f"   * {k:<24}: {v}")

        # Show prominent one-click report coordinates when threats are detected
        if verdict == "suspicious":
            print("\n" + "=" * 70)
            print("🚨 ONE-CLICK REPORT CYBER FRAUD TO LAW ENFORCEMENT:")
            print(f"   • National Cyber Crime Helpline : {CYBERCRIME_HELPLINE} (Toll-Free, 24x7)")
            print(f"   • Official Reporting Portal     : {CYBERCRIME_PORTAL_URL}")
            print(f"   • Action                        : Link directly to report this fraud")
            print("=" * 70)
        print("-" * 70)

    return result

def main():
    parser = argparse.ArgumentParser(description="Veridex AI Machine Learning Prediction Engine")
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--batch", help="Path to text file containing URLs to analyze line-by-line")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "veridex_model.joblib")
    meta_path = os.path.join(base_dir, "model_metadata.json")

    if not os.path.exists(model_path):
        print(f"Error: Model file '{model_path}' not found. Please run train.py first.")
        sys.exit(1)

    model = joblib.load(model_path)
    metadata = {}
    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

    if args.batch:
        if not os.path.exists(args.batch):
            print(f"Batch file not found: {args.batch}")
            sys.exit(1)
        with open(args.batch, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        results = [analyze_url(u, model, metadata, verbose=not args.json) for u in urls]
        if args.json:
            print(json.dumps(results, indent=2))
    elif args.url:
        res = analyze_url(args.url, model, metadata, verbose=not args.json)
        if args.json:
            print(json.dumps(res, indent=2))
    else:
        print("Running quick verification demo on representative URLs:")
        demo_urls = [
            "https://cybercrime.gov.in",
            "https://sbi.co.in",
            "http://sbi-kyc-verification.com/login",
            "http://phonepe-cashback-claim.in/scratch-card",
            "http://indiapost-parcel-delivery.top/update-address",
            "http://trai-sim-deactivation-notice.com/case/9912",
            "http://cbi-digital-arrest-warrant.net/verify",
            "http://scan-qr-to-receive-money.online/qr-intent"
        ]
        for u in demo_urls:
            analyze_url(u, model, metadata, verbose=True)

if __name__ == "__main__":
    main()
