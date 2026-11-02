# 🛡️ Veridex AI — Advanced Phishing, Scam & Cyber-Extortion Detection Engine

This directory contains the machine learning training, calibration, inference, and multi-platform deployment pipeline for **Veridex AI**, specifically augmented with deep detection for modern Indian cyber-threat vectors: **UPI & QR scams**, **Banking & Wallet KYC phishing (SBI, HDFC, Paytm, PhonePe)**, **India Post & courier delivery smishing**, and **"Digital Arrest" / TRAI extortion campaigns**.

---

## 🚀 Key Detection Capabilities

### 1. 💳 UPI & QR Payment Scams
- Detects deceptive UPI intent links (`upi://pay`), fake cashback claim portals, scratch-card traps, and "Scan QR to Receive Money" lures (in UPI architecture, scanning a QR code or entering a PIN is strictly for paying, never for receiving funds).
- Examples flagged: `claim-phonepe-cashback-500.xyz`, `scan-qr-to-receive-money.online`, `paytm-refund-instant-portal.click`.

### 2. 🏦 Fake Banking & Wallet KYC Phishing (SBI / HDFC / Paytm / PhonePe)
- Monitors brand stitching and masquerading targeting leading Indian banks and FinTech wallets.
- Detects panic-inducing coercive hooks: *"Pan card not updated"*, *"Account blocked in 24 hours"*, *"Debit freeze alert"*, *"Netbanking reward points redemption"*.
- Examples flagged: `sbi-kyc-verification.com`, `onlinesbi-pan-update.net`, `hdfc-netbanking-rewards.xyz`, `paytm-kyc-expiry-alert.org`, `phonepe-cashback-claim.in`.

### 3. 📦 Fake India Post & Courier Smishing
- Detects SMS phishing (smishing) parcel traps impersonating India Post Speed Post, Blue Dart, DTDC, and Delhivery.
- Catches micro-payment extortion: *"Your parcel is held at the distribution center due to incomplete address. Pay ₹5 / ₹25 re-delivery fee to release: `indiapost-parcel-delivery.top`"*.
- Examples flagged: `indiapost-parcel-delivery.top`, `speedpost-address-update.xyz`, `delhivery-reschedule-fee.in`.

### 4. ⚖️ "Digital Arrest" & TRAI Extortion Language
- Identifies high-severity cyber extortion campaigns impersonating TRAI (Telecom Regulatory Authority of India), CBI, ED, Cyber Crime Cell, and Narcotics Control Bureau.
- Flags coercive extortion terminology: *"digital arrest"*, *"SIM card disconnected in 2 hours"*, *"parcel seized containing illegal narcotics"*, *"CBI money laundering warrant"*, *"video statement recording"*.
- Examples flagged: `trai-sim-deactivation-notice.com`, `cbi-digital-arrest-warrant.net`, `police-cyber-cell-arrest-notice.xyz`.

### 5. 🚨 One-Click Cybercrime Reporting & 1930 Helpline
- Integrates instant reporting coordinates for victims and users:
  - **National Cyber Crime Helpline**: **1930** (24x7 Toll-Free)
  - **Official Reporting Portal**: **[cybercrime.gov.in](https://cybercrime.gov.in)**
  - Prominently surfaced across the Python CLI report, JSON output, and the browser extension JavaScript runtime with a direct one-click button.

---

## 📊 Benchmark & Evaluation Results

| Threat Category | Test Cases | Pass Rate |
| :--- | :---: | :---: |
| **UPI & QR Scams (URL & DOM)** | 5 | **100%** |
| **Banking KYC Phish (SBI / HDFC / Paytm / PhonePe)** | 6 | **100%** |
| **India Post & Courier Smishing (URL & DOM)** | 5 | **100%** |
| **Digital Arrest & TRAI Extortion (URL & DOM)** | 4 | **100%** |
| **Authentic Indian Banks, Wallets & Couriers (0 False Positives)** | 12 | **100%** |
| **Global Phishing & Scam Scenarios** | 17 | **100%** |
| **Global Top Reputable & Benign Websites (0 False Positives)** | 17 | **100%** |
| **Total Comprehensive Test Suite** | **66** | **66 / 66 (100.0%)** |

---

## 📂 File Architecture

```
ml_model/
├── feature_extractor.py     # 40-dimensional feature extractor (UPI, KYC, Courier, Digital Arrest)
├── dataset_builder.py       # 15,000-sample balanced dataset synthesizer & CSV exporter
├── dataset.csv              # Curated training dataset (15,000 labeled URLs)
├── train.py                 # Multi-model training, calibration & benchmark pipeline
├── predict.py               # CLI scanner with 1930 helpline & one-click report link
├── export_to_js.py          # Zero-dependency JavaScript exporter for Chromium extension
├── test_ml_diagnose.py      # Full 66-case diagnostic test suite
├── veridex_model.joblib     # Calibrated production ML model artifact
├── veridex_raw_model.joblib # Random Forest tree ensemble
├── veridex-ml-model.js      # Zero-dependency JavaScript engine (~81 KB)
├── veridex_ml_weights.json  # Portable JSON weights (~332 KB)
├── feature_names.json       # 40 feature dimensions schema
├── model_metadata.json      # Training metadata & confusion matrix
└── README.md                # Comprehensive documentation
```

---

## ⚡ Quick Run Guide

### Scan Any Suspicious Link:
```bash
python predict.py "http://trai-sim-deactivation-notice.com/case/9912"
python predict.py "http://sbi-kyc-verification.com/login"
python predict.py "http://indiapost-parcel-delivery.top/update-address"
python predict.py "https://claim-phonepe-cashback-500.xyz/upi-pay"
```

### Run the 66-Case Comprehensive Test Suite:
```bash
python test_ml_diagnose.py
```

### Retrain and Export:
```bash
python train.py
python export_to_js.py
```
