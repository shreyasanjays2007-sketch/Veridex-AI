# Veridex AI — Browser Installation & Testing Guide

This guide walks you through loading and running the **Veridex AI** browser extension in Google Chrome, Microsoft Edge, Brave, or any Chromium-compatible browser.

---

## ⚡ Quick 3-Step Installation (Unpacked Extension)

### Step 1: Open Browser Extensions Page
Open your browser and navigate to the extensions management screen:
- **Google Chrome**: Enter `chrome://extensions` in your address bar
- **Microsoft Edge**: Enter `edge://extensions` in your address bar
- **Brave Browser**: Enter `brave://extensions` in your address bar

### Step 2: Enable Developer Mode
Look for the **Developer mode** toggle in the top-right corner of the Extensions page and toggle it **ON**.

### Step 3: Load the Unpacked Extension
1. Click the **Load unpacked** button (top-left).
2. In the folder picker dialog, select the project directory:
   ```
   D:\veridex-ai
   ```
3. Click **Select Folder**.
4. You will see **Veridex AI - Scam & Phishing Detector** appear in your extension list with its shield icon!

---

## 📌 Pinning Veridex AI to the Toolbar

1. Click the **Puzzle Piece icon** (Extensions) in your browser toolbar (next to the address bar).
2. Locate **Veridex AI** in the dropdown.
3. Click the **Pin icon** (📌) to keep Veridex AI visible at all times.

---

## 🧪 Testing Veridex AI with the Controlled Test Lab

The project includes an interactive Test Lab with controlled simulated threat scenarios:

### Method A: Direct File Access
Open this path in your browser:
```
D:\veridex-ai\test-lab\index.html
```
*(Or right-click `D:\veridex-ai\test-lab\index.html` and choose "Open with" -> Google Chrome / Edge)*

### Method B: Via the Extension Popup
1. Click the **Veridex AI** shield icon in your browser toolbar.
2. Click the **Settings** tab.
3. Click the **🧪 Open Veridex Test Lab** button.

### Method C: Run the Local Python Test Server
Open a terminal in `D:\veridex-ai` and run:
```bash
python test-lab/server.py
```
Then visit:
```
http://localhost:8000/test-lab/index.html
```

---

## 🔍 Test Scenarios to Verify

| Test Scenario | Path / Link | Expected Veridex Behavior |
| :--- | :--- | :--- |
| **Fake Banking** | `test-lab/scenarios/fake-banking.html` | ⚠️ **Warning Modal**: Flags brand spoofing (PayPal), insecure password input, and form exfiltration. |
| **Scam Shopping** | `test-lab/scenarios/scam-shopping.html` | ⚠️ **Warning Modal**: Flags high-pressure urgency countdown and credit card harvesting. |
| **Crypto Phishing** | `test-lab/scenarios/fake-crypto.html` | ⚠️ **Warning Modal**: Flags critical 12-word recovery seed-phrase capture attempt. |
| **Homoglyph Deception** | `test-lab/scenarios/idn-homoglyph.html` | ⚠️ **Warning Modal**: Flags Cyrillic lookalike characters mimicking Latin Apple ID. |
| **Benign Website** | `test-lab/scenarios/neutral-sample.html` | 🛡️ **Neutral Status**: Unflagged, explicitly stating "Unverified - Not guaranteed safe". |

---

## 🛠️ Testing Arbitrary Links in the URL Scanner

1. Click the **Veridex AI** toolbar icon.
2. Select the **URL Scanner** tab.
3. Paste any URL (e.g., `http://paypal.com.account-update.xyz/login` or `http://192.168.1.150/portal`).
4. Click **Scan Link** to see the instant heuristic breakdown!
