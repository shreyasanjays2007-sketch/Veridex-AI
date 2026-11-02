"""
Veridex AI - High-Quality Phishing & Benign URL Dataset Generator
Specialized in Global Threats & Indian Cyber-Crime Ecosystem:
UPI/QR fraud, Banking KYC (SBI/HDFC/Paytm/PhonePe), India Post/courier smishing, and Digital Arrest / TRAI extortion.
"""

import os
import csv
import random
from typing import List, Tuple, Dict, Any

# Authentic Global & Indian Trusted Domains
BENIGN_DOMAINS = [
    # Global Tech & Portals
    "google.com", "google.co.in", "youtube.com", "microsoft.com", "apple.com",
    "github.com", "wikipedia.org", "cloudflare.com", "amazon.com", "amazon.in",
    "bing.com", "linkedin.com", "yahoo.com", "reddit.com", "twitter.com",
    "instagram.com", "facebook.com", "netflix.com", "twitch.tv", "spotify.com",
    # Global Banking
    "chase.com", "paypal.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    # Indian Banking & Wallets (Authentic)
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "paytm.com", "phonepe.com",
    "icicibank.com", "axisbank.com", "kotak.com", "pnbindia.in", "cred.club",
    # Indian Postal & Courier Services (Authentic)
    "indiapost.gov.in", "bluedart.com", "dtdc.in", "delhivery.com",
    # Indian Government & Regulators (Authentic)
    "cybercrime.gov.in", "incometax.gov.in", "uidai.gov.in", "india.gov.in",
    "trai.gov.in", "cbi.gov.in", "rbi.org.in", "npci.org.in", "epfindia.gov.in",
    # Global News & Education
    "bbc.com", "nytimes.com", "snopes.com", "scamwatch.gov.au", "mit.edu", "dsu.edu.in",
    # Benign Blogs & Dev Sites
    "alexrivera-dev.org", "discord.com", "mozilla.org", "python.org", "kernel.org"
]

BENIGN_PATHS = [
    "", "/", "/about", "/contact", "/privacy-policy", "/terms", "/help",
    "/posts", "/blog/2026/cybersecurity-overview", "/docs/api/v2/reference",
    "/products/laptops?category=tech", "/wiki/Computer_security", "/en/home",
    "/dashboard/overview", "/explore", "/search?q=open-source+tools",
    "/articles/news-briefing-today", "/faq", "/track-consignment", "/personal-banking",
    "/fixed-deposits", "/upi-services/faqs", "/press-release"
]

# Real-world Threat Seeds (including UPI, Banking KYC, India Post, Digital Arrest)
PHISHING_SEEDS = [
    # Typosquatting & Global Phishing
    "arnazon.com", "paypa1.com", "paypai.com", "g00gle.com", "app1e.com", "micros0ft.com",
    "netf1ix.com", "steamcommuniity.com", "paypal.com.attacker.xyz", "198.51.100.24",
    "qxj982zk-lm109.cc", "scam.com", "fake-apple-login.com", "paypal-security-update.com",
    "chase-bank-verify.com", "package-delivery-usps.com", "free-robux-generator.net",
    "crypto-airdrop-claim.xyz", "netflix-billing-update.com", "amazon-prime-renewal.top",
    "account-verification-alert.com", "login-security-portal.net", "www-paypal.com",
    "wallet-connect-auth.network", "fake-gov.in", "cybercrime.gov.in.attacker.xyz",
    "portal-auth-sample.net", "discount-shop.xyz", "shopping-deals-today.shop",
    "my-crypto-hub.io",
    
    # 1. Fake SBI, HDFC, Paytm, PhonePe KYC Phishing
    "sbi-kyc-verification.com", "onlinesbi-pan-update.net", "sbi-reward-points-claim.xyz",
    "hdfc-netbanking-rewards.xyz", "hdfc-kyc-mandate.top", "paytm-kyc-expiry-alert.org",
    "paytm-wallet-unblock.net", "phonepe-cashback-claim.in", "phonepe-reward-scratch.top",
    "icicibank-pan-link.cc", "axisbank-netbanking-auth.work", "pnb-kyc-update-portal.click",
    
    # 2. Fake India Post & Courier Redelivery Smishing
    "indiapost-parcel-delivery.top", "speedpost-address-update.xyz", "indiapost-redelivery-fee.shop",
    "delhivery-reschedule-fee.in", "bluedart-dispatch-status.cc", "dtdc-courier-address-fix.net",
    "indiapost-customs-clearance.org", "track-indiapost-consignment.live",
    
    # 3. Digital Arrest & TRAI Extortion
    "trai-sim-deactivation-notice.com", "cbi-digital-arrest-warrant.net", "trai-disconnection-alert.xyz",
    "police-cyber-cell-arrest-notice.xyz", "narcotics-seizure-warrant.online", "court-summons-digital-arrest.top",
    "cybercrime-verification-officer.cc",
    
    # 4. UPI & QR Scams
    "claim-phonepe-cashback-500.xyz", "scan-qr-to-receive-money.online", "paytm-refund-instant-portal.click",
    "gpay-reward-scratch-win.shop", "upi-collect-refund-desk.link", "upi-instant-reward-claim.top"
]

PHISHING_PATHS = [
    "/signin", "/login", "/login.php?redirect=auth", "/verify-account?token=9281a",
    "/portal/secure/update", "/restore/wallet/seed-phrase", "/claim-airdrop-bonus",
    "/billing/payment-failure?id=99281", "/auth/step2-security", "/session-expired",
    # Specific Indian paths
    "/kyc-update/pan-card-link", "/claim-cashback?amount=2499", "/scan-qr-to-receive",
    "/parcel-held/pay-redelivery-fee", "/digital-arrest-notice/video-call",
    "/sim-block-avoid/verify-now", "/netbanking/login/debit-unfreeze", "/upi-pin-verify"
]

def generate_synthetic_dataset(num_samples: int = 15000, random_seed: int = 42) -> List[Dict[str, Any]]:
    """
    Generates a balanced, highly diverse dataset of legitimate and phishing/scam URLs.
    Includes comprehensive regional Indian threat patterns.
    """
    random.seed(random_seed)
    data = []
    
    # 1. Generate Benign URLs (~50%)
    num_benign = num_samples // 2
    for _ in range(num_benign):
        domain = random.choice(BENIGN_DOMAINS)
        path = random.choice(BENIGN_PATHS)
        scheme = "https://" if random.random() > 0.04 else "http://"
        
        if random.random() < 0.35:
            sub = random.choice(["www", "netbanking", "retail", "portal", "track", "help", "app", "m"])
            full_host = f"{sub}.{domain}"
        else:
            full_host = domain
            
        query = ""
        if random.random() < 0.25:
            q_key = random.choice(["id", "ref", "page", "category", "lang", "tab"])
            q_val = random.choice(["101", "home", "en", "banking", "track", "faq"])
            query = f"?{q_key}={q_val}"
            
        url = f"{scheme}{full_host}{path}{query}"
        
        dom = {
            "hasPasswordField": False,
            "hasCreditCardField": False,
            "hasUrgencyPatterns": False,
            "hasSeedPhraseInputs": False,
            "hasUpiQrScam": False,
            "hasKycPanHarvesting": False,
            "hasCourierSmishingFee": False,
            "hasDigitalArrestLanguage": False
        }
        # Legitimate login pages on banking portals have password fields over HTTPS
        if ("login" in path or "netbanking" in path) and scheme == "https://":
            dom["hasPasswordField"] = True
            
        data.append({
            "url": url,
            "label": 0,
            "dom": dom,
            "category": "benign"
        })

    # 2. Generate Phishing / Threat URLs (~50%)
    num_phish = num_samples - num_benign
    high_risk_tlds = ["xyz", "top", "work", "click", "buzz", "shop", "site", "online", "club", "cf", "tk", "cc", "live", "link"]
    
    categories = [
        "indian_kyc", "upi_qr", "courier_smishing", "digital_arrest",
        "typosquat", "subdomain_spoof", "ip_or_dga"
    ]
    
    for _ in range(num_phish):
        cat = random.choice(categories)
        scheme = "http://" if random.random() < 0.70 else "https://"
        dom = {
            "hasPasswordField": False,
            "hasCreditCardField": False,
            "hasUrgencyPatterns": False,
            "hasSeedPhraseInputs": False,
            "hasUpiQrScam": False,
            "hasKycPanHarvesting": False,
            "hasCourierSmishingFee": False,
            "hasDigitalArrestLanguage": False
        }

        if cat == "indian_kyc":
            brand = random.choice(["sbi", "onlinesbi", "hdfc", "hdfcbank", "paytm", "phonepe", "icici", "pnb"])
            action = random.choice(["kyc-update", "pan-link", "debit-freeze-unblock", "verify-aadhaar", "rewards-portal"])
            tld = random.choice(["com", "net", "org", "in"] + high_risk_tlds)
            host = f"{brand}-{action}.{tld}"
            path = random.choice(["/login", "/kyc-form", "/update-pan", "/auth/verify"])
            dom["hasPasswordField"] = True
            dom["hasKycPanHarvesting"] = True
            dom["hasUrgencyPatterns"] = True

        elif cat == "upi_qr":
            wallet = random.choice(["phonepe", "paytm", "gpay", "upi", "bhim"])
            action = random.choice(["cashback-reward", "scratch-card-win", "scan-qr-receive", "refund-instant", "claim-bonus"])
            tld = random.choice(high_risk_tlds + ["in", "online"])
            host = f"{wallet}-{action}-{random.randint(10, 999)}.{tld}"
            path = random.choice(["/claim", "/upi-pay", "/scratch-now", "/receive-money"])
            dom["hasUpiQrScam"] = True
            dom["hasUrgencyPatterns"] = True

        elif cat == "courier_smishing":
            courier = random.choice(["indiapost", "speedpost", "bluedart", "delhivery", "dtdc"])
            action = random.choice(["parcel-delivery", "address-update", "redelivery-fee", "customs-hold", "track-consignment"])
            tld = random.choice(high_risk_tlds + ["in", "top", "shop"])
            host = f"{courier}-{action}.{tld}"
            path = random.choice(["/update-address", "/pay-fee", "/redelivery", "/track"])
            dom["hasCourierSmishingFee"] = True
            dom["hasCreditCardField"] = True
            dom["hasUrgencyPatterns"] = True

        elif cat == "digital_arrest":
            agency = random.choice(["trai", "cbi", "cyber-crime-cell", "police-notice", "narcotics-control"])
            threat = random.choice(["digital-arrest", "sim-deactivation", "arrest-warrant", "money-laundering", "court-summons"])
            tld = random.choice(["com", "net", "org"] + high_risk_tlds)
            host = f"{agency}-{threat}.{tld}"
            path = random.choice(["/notice/view", "/statement/record", "/case-file", "/verify-assets"])
            dom["hasDigitalArrestLanguage"] = True
            dom["hasUrgencyPatterns"] = True

        elif cat == "typosquat":
            brand = random.choice(["paypal", "apple", "amazon", "netflix", "sbi", "hdfc", "paytm"])
            mutated = brand.replace('l', '1').replace('o', '0').replace('m', 'rn') if random.random() < 0.5 else f"{brand}-secure"
            tld = random.choice(["com", "net"] + high_risk_tlds)
            host = f"{mutated}.{tld}"
            path = random.choice(PHISHING_PATHS)
            dom["hasPasswordField"] = True

        elif cat == "subdomain_spoof":
            target = random.choice(["sbi.co.in", "hdfcbank.com", "cybercrime.gov.in", "paytm.com", "indiapost.gov.in"])
            attacker = f"attacker-{random.randint(10, 99)}.{random.choice(high_risk_tlds)}"
            host = f"secure-auth.{target}.{attacker}"
            path = random.choice(PHISHING_PATHS)
            dom["hasPasswordField"] = True

        else: # ip_or_dga or direct seed
            seed = random.choice(PHISHING_SEEDS)
            host = seed
            path = random.choice(PHISHING_PATHS)
            if "crypto" in host or "seed" in path:
                dom["hasSeedPhraseInputs"] = True
            if "kyc" in host or "pan" in host:
                dom["hasKycPanHarvesting"] = True
            if "arrest" in host or "trai" in host:
                dom["hasDigitalArrestLanguage"] = True
            if "parcel" in host or "indiapost" in host:
                dom["hasCourierSmishingFee"] = True
            if "qr" in host or "upi" in host:
                dom["hasUpiQrScam"] = True
            dom["hasUrgencyPatterns"] = True

        url = f"{scheme}{host}{path}"
        data.append({
            "url": url,
            "label": 1,
            "dom": dom,
            "category": cat
        })

    random.shuffle(data)
    return data

def save_dataset_csv(data: List[Dict[str, Any]], output_path: str):
    """Saves the generated dataset to CSV format."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "url", "label", "category",
            "has_password", "has_cc", "has_urgency", "has_seedphrase",
            "has_upi_qr", "has_kyc_pan", "has_courier_fee", "has_digital_arrest"
        ])
        for row in data:
            d = row["dom"]
            writer.writerow([
                row["url"],
                row["label"],
                row.get("category", "unknown"),
                1 if d.get("hasPasswordField") else 0,
                1 if d.get("hasCreditCardField") else 0,
                1 if d.get("hasUrgencyPatterns") else 0,
                1 if d.get("hasSeedPhraseInputs") else 0,
                1 if d.get("hasUpiQrScam") else 0,
                1 if d.get("hasKycPanHarvesting") else 0,
                1 if d.get("hasCourierSmishingFee") else 0,
                1 if d.get("hasDigitalArrestLanguage") else 0
            ])
    print(f"Dataset saved successfully to: {output_path} ({len(data)} records)")

if __name__ == "__main__":
    out_file = os.path.join(os.path.dirname(__file__), "dataset.csv")
    ds = generate_synthetic_dataset(15000)
    save_dataset_csv(ds, out_file)
