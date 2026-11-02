"""
Veridex AI - Advanced ML Training Pipeline
Trains, evaluates, calibrates, and exports the phishing and scam detection ML model.
Includes dedicated evaluations for UPI/QR fraud, Banking KYC, Courier Smishing, and Digital Arrest.
"""

import os
import sys
import json
import time
import warnings
warnings.filterwarnings('ignore')

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import joblib

from feature_extractor import VeridexFeatureExtractor
from dataset_builder import generate_synthetic_dataset, save_dataset_csv

def build_dataset_arrays(dataset: list, extractor: VeridexFeatureExtractor) -> Tuple[np.ndarray, np.ndarray, list]:
    """Extracts features for all dataset items and returns X, y arrays."""
    print(f"Extracting features for {len(dataset)} URLs using {len(extractor.FEATURE_NAMES)} feature dimensions...")
    start_time = time.time()
    
    X = []
    y = []
    urls = []
    
    for item in dataset:
        feat = extractor.extract_features(item["url"], item.get("dom"))
        X.append(feat)
        y.append(item["label"])
        urls.append(item["url"])
        
    X_arr = np.array(X, dtype=np.float32)
    y_arr = np.array(y, dtype=np.int32)
    
    print(f"Feature extraction completed in {time.time() - start_time:.2f}s. Shape: {X_arr.shape}")
    return X_arr, y_arr, urls

def train_and_evaluate(dataset_size: int = 15000, output_dir: str = None) -> Dict[str, Any]:
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 70)
    print("[*] VERIDEX AI - ADVANCED MACHINE LEARNING TRAINING PIPELINE")
    print("=" * 70)
    
    extractor = VeridexFeatureExtractor()
    csv_file = os.path.join(output_dir, "dataset.csv")
    
    # 1. Dataset Generation or Loading
    if os.path.exists(csv_file):
        print(f"Loading existing dataset from {csv_file}...")
        df = pd.read_csv(csv_file)
        raw_data = []
        for _, row in df.iterrows():
            dom = {
                "hasPasswordField": bool(row.get("has_password", 0)),
                "hasCreditCardField": bool(row.get("has_cc", 0)),
                "hasUrgencyPatterns": bool(row.get("has_urgency", 0)),
                "hasSeedPhraseInputs": bool(row.get("has_seedphrase", 0)),
                "hasUpiQrScam": bool(row.get("has_upi_qr", 0)),
                "hasKycPanHarvesting": bool(row.get("has_kyc_pan", 0)),
                "hasCourierSmishingFee": bool(row.get("has_courier_fee", 0)),
                "hasDigitalArrestLanguage": bool(row.get("has_digital_arrest", 0))
            }
            raw_data.append({"url": str(row["url"]), "label": int(row["label"]), "dom": dom})
    else:
        print(f"Synthesizing high-fidelity security dataset ({dataset_size} samples)...")
        raw_data = generate_synthetic_dataset(num_samples=dataset_size)
        save_dataset_csv(raw_data, csv_file)
        
    # 2. Extract Features
    X, y, urls = build_dataset_arrays(raw_data, extractor)
    
    # 3. Train-Test Split (80% Train, 20% Holdout Test)
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Dataset split: Train={len(X_train)} samples, Test={len(X_test)} samples")
    print(f"Class Balance - Train: Benign={np.sum(y_train==0)}, Phishing={np.sum(y_train==1)}")
    print(f"Class Balance - Test:  Benign={np.sum(y_test==0)}, Phishing={np.sum(y_test==1)}")
    
    # 4. Model Candidates
    candidates = {
        "RandomForest": RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=100,
            max_depth=12,
            learning_rate=0.1,
            random_state=42
        ),
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            C=1.0,
            random_state=42
        )
    }
    
    print("\n--- Model Benchmark & Cross-Validation (5-Fold Stratified) ---")
    best_name = None
    best_f1 = -1.0
    best_model = None
    results = {}
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    for name, clf in candidates.items():
        t0 = time.time()
        cv_scores = cross_val_score(clf, X_train, y_train, cv=cv, scoring='f1', n_jobs=-1)
        clf.fit(X_train, y_train)
        train_time = time.time() - t0
        
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc = roc_auc_score(y_test, y_prob)
        
        results[name] = {
            "cv_f1_mean": float(cv_scores.mean()),
            "cv_f1_std": float(cv_scores.std()),
            "test_accuracy": float(acc),
            "test_precision": float(prec),
            "test_recall": float(rec),
            "test_f1": float(f1),
            "test_roc_auc": float(roc),
            "train_time_sec": float(round(train_time, 2))
        }
        
        print(f"[{name}]")
        print(f"  CV 5-Fold F1:   {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        print(f"  Test Accuracy:   {acc*100:.2f}% | Precision: {prec*100:.2f}% | Recall: {rec*100:.2f}%")
        print(f"  Test F1-Score:   {f1:.4f} | ROC-AUC: {roc:.4f}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_model = clf
            
    print(f"\n[+] Best Selected Model Architecture: {best_name} (F1: {best_f1:.4f})")
    
    # 5. Probability Calibration for True Risk Percentages
    print("\nCalibrating probabilities with 5-fold cross-validation for Veridex risk meter...")
    calibrated_model = CalibratedClassifierCV(best_model, cv=5, method='sigmoid')
    calibrated_model.fit(X_train, y_train)
    
    final_probs = calibrated_model.predict_proba(X_test)[:, 1]
    final_preds = (final_probs >= 0.5).astype(int)
    
    cm = confusion_matrix(y_test, final_preds)
    print("\nConfusion Matrix on Test Set:")
    print(f"  [TN={cm[0][0]:<5}  FP={cm[0][1]:<5}]")
    print(f"  [FN={cm[1][0]:<5}  TP={cm[1][1]:<5}]")
    
    print("\nClassification Report:")
    print(classification_report(y_test, final_preds, target_names=["Benign / Neutral", "Phishing / Suspicious"]))
    
    # 6. Verification Against Core Veridex Edge Cases
    print("\n--- Verifying Model Against Core Benchmarks ---")
    from predict import analyze_url
    benchmarks = [
        ("https://cybercrime.gov.in", None, "neutral"),
        ("https://incometax.gov.in", None, "neutral"),
        ("https://sbi.co.in", None, "neutral"),
        ("https://hdfcbank.com", None, "neutral"),
        ("https://paytm.com", None, "neutral"),
        ("https://phonepe.com", None, "neutral"),
        ("https://indiapost.gov.in", None, "neutral"),
        ("https://trai.gov.in", None, "neutral"),
        ("https://www.google.co.in", None, "neutral"),
        ("https://alexrivera-dev.org/posts", None, "neutral"),
        ("https://en.wikipedia.org/wiki/Scam", None, "neutral"),
        # Threats
        ("http://sbi-kyc-verification.com/login", None, "suspicious"),
        ("http://hdfc-netbanking-rewards.xyz/redeem", None, "suspicious"),
        ("http://phonepe-cashback-claim.in/scratch-card", None, "suspicious"),
        ("http://indiapost-parcel-delivery.top/update-address", None, "suspicious"),
        ("http://trai-sim-deactivation-notice.com/case/9912", None, "suspicious"),
        ("http://cbi-digital-arrest-warrant.net/verify", None, "suspicious"),
        ("http://scan-qr-to-receive-money.online/qr-intent", None, "suspicious"),
        ("https://arnazon.com/signin", None, "suspicious"),
        ("http://paypal.com.attacker.xyz/login", None, "suspicious"),
        ("http://198.51.100.24/portal", None, "suspicious"),
        ("http://qxj982zk-lm109.cc/token", None, "suspicious"),
        ("http://fake-gov.in", None, "suspicious"),
        ("https://cybercrime.gov.in.attacker.xyz", None, "suspicious")
    ]
    
    benchmark_passes = 0
    for url, dom, expected in benchmarks:
        res = analyze_url(url, calibrated_model, dom_signals=dom, verbose=False)
        risk_pct = res["risk_percentage"]
        verdict = res["verdict"]
        status = "[PASS]" if verdict == expected else "[FAIL]"
        if verdict == expected:
            benchmark_passes += 1
        print(f"  {status}: {url:<52} -> Risk={risk_pct:5.1f}% [{verdict.upper()}] (Expected: {expected})")
        
    print(f"\nBenchmark Results: {benchmark_passes}/{len(benchmarks)} passed.")
    
    # 7. Save Model Artifacts
    model_path = os.path.join(output_dir, "veridex_model.joblib")
    raw_model_path = os.path.join(output_dir, "veridex_raw_model.joblib")
    meta_path = os.path.join(output_dir, "model_metadata.json")
    feat_names_path = os.path.join(output_dir, "feature_names.json")
    
    rf_model = candidates["RandomForest"]
    joblib.dump(calibrated_model, model_path)
    joblib.dump(rf_model, raw_model_path)
    
    with open(feat_names_path, "w", encoding="utf-8") as f:
        json.dump(extractor.FEATURE_NAMES, f, indent=2)
        
    metadata = {
        "model_name": "Veridex AI Phishing, Scam & Cyber-Extortion Detector",
        "version": "1.1.0",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "best_algorithm": best_name,
        "feature_dimensions": len(extractor.FEATURE_NAMES),
        "dataset_total": len(X),
        "test_metrics": results[best_name],
        "confusion_matrix": {
            "true_negative": int(cm[0][0]),
            "false_positive": int(cm[0][1]),
            "false_negative": int(cm[1][0]),
            "true_positive": int(cm[1][1])
        },
        "benchmark_accuracy": f"{benchmark_passes}/{len(benchmarks)}",
        "reporting": {
            "portal": "https://cybercrime.gov.in",
            "helpline": "1930"
        }
    }
    
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        
    print(f"\nArtifacts successfully saved:")
    print(f"  - Model:     {model_path}")
    print(f"  - Metadata:  {meta_path}")
    print(f"  - Features:  {feat_names_path}")
    
    return metadata

if __name__ == "__main__":
    train_and_evaluate(dataset_size=15000)
