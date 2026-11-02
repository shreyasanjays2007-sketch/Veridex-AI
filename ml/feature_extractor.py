"""
Veridex AI - Advanced ML Feature Extraction Engine
Extracts 40 lexical, structural, statistical, brand impersonation, and regional Indian cyber-threat signals.
Specialized in UPI/QR scams, Banking/Wallet KYC fraud (SBI/HDFC/Paytm/PhonePe), India Post/courier smishing,
and Digital Arrest / TRAI extortion patterns.
"""

import math
import re
from urllib.parse import urlparse

# Global & Regional Indian Suspicious Keywords
SUSPICIOUS_KEYWORDS = [
    # General Phishing & Auth
    'login', 'signin', 'log-in', 'sign-in', 'verify', 'verification', 'authenticate',
    'account', 'update', 'secure', 'security', 'banking', 'confirm', 'wallet',
    'recovery', 'restore', 'seedphrase', 'airdrop', 'claim', 'bonus', 'free',
    'gift', 'prize', 'reward', 'crypto', 'support', 'helpdesk', 'service',
    'password', 'credential', 'billing', 'invoice', 'payment', 'appleid', 'paypal',
    'fake', 'scam', 'robux', 'renewal', 'delivery', 'portal', 'alert',
    # Indian Banking & KYC Fraud
    'kyc', 'kyc-update', 'pancard', 'pan-card', 'aadhaar', 'debit-freeze',
    'account-blocked', 'netbanking', 'unblock-account', 'reward-points',
    # UPI & QR Scams
    'upi', 'upipay', 'upi-pay', 'cashback-reward', 'scratch-card',
    'scan-qr', 'receive-money', 'upi-refund', 'collect-request', 'instant-cashback',
    # Courier & India Post Smishing
    'indiapost', 'speedpost', 'parcel-stuck', 'address-update', 'redelivery',
    'redelivery-fee', 'customs-duty', 'track-parcel', 'courier-service',
    # Digital Arrest & TRAI / Law Enforcement Extortion
    'digital-arrest', 'trai-notice', 'sim-deactivation', 'sim-block',
    'cbi-warrant', 'arrest-warrant', 'narcotics-seizure', 'money-laundering',
    'cyber-crime-cell', 'court-summons', 'video-statement'
]

# High-risk TLDs heavily abused in malicious campaigns
HIGH_RISK_TLDS = {
    'top', 'xyz', 'club', 'work', 'click', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq',
    'fit', 'rest', 'ru', 'cn', 'su', 'stream', 'bid', 'cam', 'quest', 'monster',
    'surf', 'icu', 'vip', 'fun', 'win', 'zone', 'shop', 'site', 'cc', 'network',
    'link', 'live', 'online', 'space', 'today'
}

# Monitored Brands (Global + Indian Banking, Wallets, Couriers, and Regulators)
TARGETED_BRANDS = [
    # Global Tech & Finance
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'chase',
    'bankofamerica', 'wellsfargo', 'binance', 'metamask', 'coinbase', 'instagram',
    'facebook', 'twitter', 'linkedin', 'dropbox', 'adobe', 'steam', 'steamcommunity',
    'roblox', 'usps',
    # Indian Banking & FinTech
    'sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'paytm', 'phonepe', 'gpay', 'googlepay',
    'cred', 'icicibank', 'icici', 'pnb', 'kotak', 'axisbank',
    # Indian Couriers & Postal
    'indiapost', 'speedpost', 'bluedart', 'dtdc', 'delhivery',
    # Regulators & Authorities
    'trai', 'cbi', 'cybercrime', 'incometax', 'uidai'
]

# Canonical Official Domains for Monitored Entities
OFFICIAL_BRAND_DOMAINS = {
    'paypal': {'paypal.com', 'paypal.me'},
    'apple': {'apple.com', 'icloud.com'},
    'google': {'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.ca'},
    'microsoft': {'microsoft.com', 'live.com', 'office.com', 'azure.com'},
    'amazon': {'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de'},
    'netflix': {'netflix.com'},
    'chase': {'chase.com'},
    'bankofamerica': {'bankofamerica.com'},
    'wellsfargo': {'wellsfargo.com'},
    'binance': {'binance.com', 'binance.us'},
    'metamask': {'metamask.io'},
    'coinbase': {'coinbase.com'},
    'steam': {'steampowered.com', 'steamcommunity.com'},
    'steamcommunity': {'steamcommunity.com', 'steampowered.com'},
    'usps': {'usps.com'},
    'roblox': {'roblox.com'},
    # Indian Banking & Wallets
    'sbi': {'sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'},
    'onlinesbi': {'sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'},
    'hdfc': {'hdfcbank.com', 'hdfc.com'},
    'hdfcbank': {'hdfcbank.com', 'hdfc.com'},
    'paytm': {'paytm.com', 'paytmbank.com'},
    'phonepe': {'phonepe.com'},
    'gpay': {'google.com', 'pay.google.com'},
    'googlepay': {'google.com', 'pay.google.com'},
    'cred': {'cred.club'},
    'icici': {'icicibank.com'},
    'icicibank': {'icicibank.com'},
    'pnb': {'pnbindia.in'},
    'kotak': {'kotak.com'},
    'axisbank': {'axisbank.com'},
    # Couriers & Regulators
    'indiapost': {'indiapost.gov.in'},
    'speedpost': {'indiapost.gov.in'},
    'bluedart': {'bluedart.com'},
    'dtdc': {'dtdc.in', 'dtdc.com'},
    'delhivery': {'delhivery.com'},
    'trai': {'trai.gov.in'},
    'cbi': {'cbi.gov.in'},
    'cybercrime': {'cybercrime.gov.in'},
    'incometax': {'incometax.gov.in'},
    'uidai': {'uidai.gov.in'}
}

# Verified government / high-trust domain regexes
GOVERNMENT_TLD_PATTERNS = [
    r'\.gov$', r'\.gov\.[a-z]{2}$', r'\.mil$', r'\.nic\.in$', r'\.gov\.in$'
]

# Known authentic top reputable canonical domains (zero-false-positive allowlist anchors)
TOP_REPUTABLE_DOMAINS = {
    'google.com', 'google.co.in', 'wikipedia.org', 'github.com', 'amazon.com',
    'amazon.in', 'chase.com', 'paypal.com', 'apple.com', 'scamwatch.gov.au',
    'snopes.com', 'bbc.com', 'nytimes.com', 'cloudflare.com', 'discord.com',
    'microsoft.com', 'youtube.com', 'linkedin.com', 'twitter.com', 'facebook.com',
    'instagram.com', 'reddit.com', 'mozilla.org', 'python.org', 'kernel.org',
    # Authentic Indian Services
    'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'paytm.com', 'phonepe.com',
    'indiapost.gov.in', 'trai.gov.in', 'bluedart.com', 'dtdc.in', 'delhivery.com',
    'cybercrime.gov.in', 'incometax.gov.in', 'uidai.gov.in', 'india.gov.in'
}

def shannon_entropy(string: str) -> float:
    """Calculates the Shannon entropy of a string (higher = more random/DGA-like)."""
    if not string:
        return 0.0
    freq = {}
    for char in string:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(string)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]

def is_typosquat_match(part: str, brand: str) -> bool:
    d = levenshtein_distance(part, brand)
    if len(brand) <= 4:
        return d == 1 and abs(len(part) - len(brand)) <= 1
    else:
        return d in (1, 2)

def min_brand_distance(hostname: str) -> tuple[int, str]:
    """Finds the closest targeted brand to tokens in the hostname and returns distance and brand."""
    cleaned = re.sub(r'[^a-z0-9]', '', hostname.lower())
    min_dist = 999
    closest_brand = ''
    
    parts = re.split(r'[\.\-\_]', hostname.lower())
    for brand in TARGETED_BRANDS:
        for part in parts:
            if not part or len(part) < 3:
                continue
            dist = levenshtein_distance(part, brand)
            # For short 3-4 letter acronyms like 'cbi', 'sbi', 'pnb', only count distance <= 1
            if len(brand) <= 4 and dist > 1:
                continue
            if dist < min_dist:
                min_dist = dist
                closest_brand = brand
        # Also check against cleaned full hostname if sufficiently long
        if len(cleaned) >= 4:
            dist_full = levenshtein_distance(cleaned, brand)
            if len(brand) <= 4 and dist_full > 1:
                pass
            elif dist_full < min_dist:
                min_dist = dist_full
                closest_brand = brand
            
    return min_dist, closest_brand

class VeridexFeatureExtractor:
    """
    Extracts 40 standardized numeric features from a URL + optional DOM signals.
    These features represent the foundational vectors used by the ML model.
    """
    
    FEATURE_NAMES = [
        "url_length",
        "hostname_length",
        "path_length",
        "num_dots",
        "num_hyphens",
        "num_underscores",
        "num_slashes",
        "num_questionmarks",
        "num_equals",
        "num_at_symbols",
        "num_digits",
        "digit_ratio_hostname",
        "num_subdomains",
        "is_https",
        "is_raw_ip",
        "has_port",
        "has_punycode",
        "has_double_slash_path",
        "entropy_hostname",
        "entropy_path",
        "num_keywords_host",
        "num_keywords_path",
        "is_high_risk_tld",
        "min_brand_edit_distance",
        "has_brand_in_subdomain",
        "is_brand_impersonation",
        "is_gov_domain",
        "is_deceptive_gov_spoof",
        "is_top_reputable_domain",
        "is_indian_banking_kyc_spoof",
        "is_upi_qr_scam",
        "is_india_post_courier_spoof",
        "has_digital_arrest_or_trai_language",
        "dom_has_password_field",
        "dom_has_credit_card_field",
        "dom_has_urgency_or_seedphrase",
        "dom_has_upi_qr_scam",
        "dom_has_kyc_pan_harvesting",
        "dom_has_courier_smishing_fee",
        "dom_has_digital_arrest_extortion"
    ]

    def get_apex_domain(self, hostname: str) -> str:
        parts = hostname.lower().split('.')
        if len(parts) >= 2:
            if len(parts) >= 3 and parts[-2] in ('co', 'gov', 'nic', 'ac', 'edu', 'org') and len(parts[-1]) == 2:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return hostname

    def extract_features(self, url: str, dom_signals: dict = None) -> list[float]:
        """Extracts numerical feature vector for the given URL and optional DOM signals."""
        if not url:
            url = ""
            
        clean_url = url.strip()
        if not (clean_url.startswith('http://') or clean_url.startswith('https://')):
            clean_url = 'http://' + clean_url

        try:
            parsed = urlparse(clean_url)
            hostname = (parsed.hostname or '').lower()
            path = parsed.path or ''
            query = parsed.query or ''
        except Exception:
            hostname = ''
            path = ''
            query = ''

        # 1. Lengths
        url_len = float(len(clean_url))
        host_len = float(len(hostname))
        path_len = float(len(path) + (len(query) + 1 if query else 0))

        # 2. Character counts
        num_dots = float(clean_url.count('.'))
        num_hyphens = float(clean_url.count('-'))
        num_underscores = float(clean_url.count('_'))
        num_slashes = float(clean_url.count('/'))
        num_questionmarks = float(clean_url.count('?'))
        num_equals = float(clean_url.count('='))
        num_at_symbols = float(clean_url.count('@'))

        # 3. Digit metrics
        digits_in_host = sum(c.isdigit() for c in hostname)
        digit_ratio_host = float(digits_in_host) / max(len(hostname), 1)
        total_digits = float(sum(c.isdigit() for c in clean_url))

        # 4. Hostname structural features
        subdomains = hostname.split('.')
        num_subdomains = float(max(0, len(subdomains) - 2))

        is_https = 1.0 if parsed.scheme.lower() == 'https' else 0.0

        # Raw IP check
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        is_raw_ip = 1.0 if re.match(ip_pattern, hostname) else 0.0

        # Port presence
        has_port = 1.0 if parsed.port and parsed.port not in (80, 443) else 0.0

        # Punycode / IDN check
        has_punycode = 1.0 if 'xn--' in hostname else 0.0

        # Double slash in path
        has_double_slash_path = 1.0 if '//' in path else 0.0

        # 5. Shannon Entropy
        entropy_host = shannon_entropy(hostname)
        entropy_path_val = shannon_entropy(path)

        # 6. Keyword matching (Separated Host vs Path)
        lower_host = hostname.lower()
        lower_path = (path + '?' + query).lower()
        kw_host = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_host)
        kw_path = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_path)

        # 7. TLD Risk
        tld = subdomains[-1].lower() if subdomains else ''
        is_high_risk_tld = 1.0 if tld in HIGH_RISK_TLDS else 0.0

        # 8. Brand Distance & Subdomain Brand Spoofing
        min_dist, closest_brand = min_brand_distance(hostname)
        min_brand_dist = float(min(min_dist, 10))

        apex = self.get_apex_domain(hostname)

        # Subdomain brand spoofing
        has_brand_subdomain = 0.0
        if len(subdomains) > 2:
            subdomain_str = ".".join(subdomains[:-2])
            for target in TARGETED_BRANDS:
                if target in subdomain_str and target not in apex:
                    has_brand_subdomain = 1.0
                    break

        # 9. Brand Impersonation / Stitching in Apex or Hostname
        is_brand_impersonation = 0.0
        for brand, official_set in OFFICIAL_BRAND_DOMAINS.items():
            if brand in hostname:
                if apex not in official_set:
                    is_brand_impersonation = 1.0
                    break

        # 10. Authentic Government domain check
        is_gov = 0.0
        for pattern in GOVERNMENT_TLD_PATTERNS:
            if re.search(pattern, apex):
                is_gov = 1.0
                break

        # 11. Deceptive Government Spoofing Check
        is_deceptive_gov = 0.0
        if is_gov == 0.0:
            if 'gov' in hostname or 'nic' in hostname:
                is_deceptive_gov = 1.0
        elif has_brand_subdomain == 1.0:
            is_deceptive_gov = 1.0

        # 12. Top Reputable Domain Anchor
        is_top_reputable = 1.0 if (apex in TOP_REPUTABLE_DOMAINS and has_brand_subdomain == 0.0 and is_brand_impersonation == 0.0) else 0.0

        # 13. Specialized Indian Threat Detectors
        # A) Fake Indian Banking / FinTech KYC Spoofing (SBI/HDFC/Paytm/PhonePe)
        bank_brands = ['sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'paytm', 'phonepe', 'icici', 'pnb', 'kotak', 'axisbank']
        kyc_terms = ['kyc', 'pan', 'aadhaar', 'unblock', 'debit-freeze', 'netbanking', 'login', 'verify']
        is_indian_banking_kyc_spoof = 0.0
        for bb in bank_brands:
            if bb in hostname:
                if apex not in OFFICIAL_BRAND_DOMAINS.get(bb, set()):
                    if any(kt in lower_host or kt in lower_path for kt in kyc_terms):
                        is_indian_banking_kyc_spoof = 1.0
                        break

        # B) UPI & QR Scams
        upi_terms = ['upi', 'upipay', 'cashback', 'reward', 'scratch-card', 'receive-money', 'upi-refund', 'scan-qr']
        is_upi_qr_scam = 0.0
        if any(ut in lower_host or ut in lower_path for ut in upi_terms):
            if is_top_reputable == 0.0 and is_gov == 0.0:
                is_upi_qr_scam = 1.0

        # C) Fake India Post & Courier Phishing
        courier_brands = ['indiapost', 'speedpost', 'bluedart', 'dtdc', 'delhivery']
        courier_terms = ['parcel', 'track', 'address', 'redelivery', 'customs', 'delivery', 'dispatch']
        is_india_post_courier_spoof = 0.0
        for cb in courier_brands:
            if cb in hostname or cb in lower_path:
                if apex not in OFFICIAL_BRAND_DOMAINS.get(cb, set()):
                    if any(ct in lower_host or ct in lower_path for ct in courier_terms):
                        is_india_post_courier_spoof = 1.0
                        break

        # D) "Digital Arrest" & TRAI Extortion Language
        arrest_terms = ['digital-arrest', 'trai', 'cbi', 'arrest-warrant', 'narcotics', 'sim-block', 'sim-deactivation', 'court-summons']
        has_digital_arrest_lang = 0.0
        if any(at in lower_host or at in lower_path for at in arrest_terms):
            if apex not in {'trai.gov.in', 'cbi.gov.in', 'cybercrime.gov.in', 'india.gov.in'}:
                has_digital_arrest_lang = 1.0

        # 14. In-Page DOM Signals
        dom = dom_signals or {}
        dom_password = 1.0 if dom.get('hasPasswordField') or dom.get('has_password_field') else 0.0
        dom_cc = 1.0 if dom.get('hasCreditCardField') or dom.get('has_credit_card_field') else 0.0
        dom_urgency_seed = 1.0 if (
            dom.get('hasUrgencyPatterns') or dom.get('has_urgency') or
            dom.get('hasSeedPhraseInputs') or dom.get('has_seed_phrase') or
            dom.get('hasCountdown')
        ) else 0.0
        dom_upi_qr = 1.0 if (
            dom.get('hasUpiQrScam') or dom.get('has_upi_qr_scam') or
            dom.get('claimsQrReceivesMoney') or dom.get('hasFakeQrScanner') or
            dom.get('requestsUpiPinToReceive')
        ) else 0.0
        dom_kyc_pan = 1.0 if (
            dom.get('hasKycPanHarvesting') or dom.get('has_kyc_pan_harvesting') or
            dom.get('requestsPanAadhaarOtp') or dom.get('hasNetbankingHarvesting')
        ) else 0.0
        dom_courier_fee = 1.0 if (
            dom.get('hasCourierSmishingFee') or dom.get('has_courier_smishing_fee') or
            dom.get('requestsSmallRedeliveryFee') or dom.get('hasParcelAddressForm')
        ) else 0.0
        dom_digital_arrest = 1.0 if (
            dom.get('hasDigitalArrestLanguage') or dom.get('has_digital_arrest_language') or
            dom.get('hasTraiSimBlockThreat') or dom.get('hasCbiPoliceExtortion') or
            dom.get('showsFakeArrestWarrant')
        ) else 0.0

        features = [
            url_len,
            host_len,
            path_len,
            num_dots,
            num_hyphens,
            num_underscores,
            num_slashes,
            num_questionmarks,
            num_equals,
            num_at_symbols,
            total_digits,
            digit_ratio_host,
            num_subdomains,
            is_https,
            is_raw_ip,
            has_port,
            has_punycode,
            has_double_slash_path,
            entropy_host,
            entropy_path_val,
            float(kw_host),
            float(kw_path),
            is_high_risk_tld,
            min_brand_dist,
            has_brand_subdomain,
            is_brand_impersonation,
            is_gov,
            is_deceptive_gov,
            is_top_reputable,
            is_indian_banking_kyc_spoof,
            is_upi_qr_scam,
            is_india_post_courier_spoof,
            has_digital_arrest_lang,
            dom_password,
            dom_cc,
            dom_urgency_seed,
            dom_upi_qr,
            dom_kyc_pan,
            dom_courier_fee,
            dom_digital_arrest
        ]

        return features

    def extract_dict(self, url: str, dom_signals: dict = None) -> dict[str, float]:
        """Extracts features as a named dictionary for inspection and explanation."""
        feats = self.extract_features(url, dom_signals)
        return dict(zip(self.FEATURE_NAMES, feats))
