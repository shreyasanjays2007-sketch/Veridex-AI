const fs = require('fs');
const MessageAnalyzer = require('./engine/message-analyzer.js');
const QRAnalyzer = require('./engine/qr-analyzer.js');
const { VeridexEngine } = require('./engine/veridex-engine.js');

const engine = new VeridexEngine();
const msgAnalyzer = new MessageAnalyzer(engine);
const qrAnalyzer = new QRAnalyzer(engine);

console.log('=== VERIFYING GOOGLE-STYLE TABS & WEBSITE PORTAL MODULES ===\n');

// 1. Verify HTML DOM Structure Integrity
const html = fs.readFileSync('D:/veridex-ai/website/index.html', 'utf8');

const requiredTabElements = [
  'id="portal-tabs-nav"',
  'id="tab-btn-dashboard"',
  'id="tab-btn-message"',
  'id="tab-btn-qrcode"',
  'id="tab-dashboard"',
  'id="tab-message"',
  'id="tab-qrcode"',
  // Preserved Dashboard Elements
  'id="search-url-input"',
  'id="hero-score-card"',
  'id="website-suggested-card"',
  'id="website-ai-explanation-card"',
  'id="dashboard-section"',
  'id="section-signals"',
  'id="section-breakdown"',
  'id="section-intel"',
  'id="section-cookies"',
  'id="section-cybercrime"',
  'id="section-report"',
  // Message Module Elements
  'id="message-text-input"',
  'id="btn-verify-message"',
  'id="message-results-grid"',
  'id="message-hero-card"',
  'id="message-score-value"',
  'id="message-explanation-headline"',
  'id="message-explanation-body"',
  // QR Module Elements
  'id="qr-dropzone"',
  'id="qr-file-input"',
  'id="qr-raw-payload-input"',
  'id="btn-verify-qr"',
  'id="qr-results-grid"',
  'id="qr-hero-card"',
  'id="qr-score-value"',
  'id="qr-inspector-params"',
  'id="qr-explanation-headline"',
  'id="qr-explanation-body"'
];

let missingDom = 0;
for (const el of requiredTabElements) {
  if (!html.includes(el)) {
    console.error(`✗ Missing DOM Element in website/index.html: ${el}`);
    missingDom++;
  }
}

if (missingDom === 0) {
  console.log(`✓ All ${requiredTabElements.length} Tab & Module DOM elements verified in website/index.html`);
} else {
  console.error(`FAIL: ${missingDom} DOM elements missing!`);
  process.exit(1);
}

// 2. Verify Message Analyzer Threat Percentages & Explanations
console.log('\n--- 2. Message Analyzer Test Suite ---');
const messageTests = [
  {
    name: 'Digital Arrest Scam Notice',
    text: 'CBI & TRAI Emergency Notice: Your SIM card will be disconnected and non-bailable arrest warrant executed within 2 hours under PMLA money laundering. Connect to Skype interrogation room immediately or police will arrive at your address.',
    expectScam: true,
    minThreat: 85,
    maxThreat: 100
  },
  {
    name: 'Fake SBI KYC Phishing SMS',
    text: 'Dear SBI user, your YONO account is suspended! Update your PAN card immediately to avoid permanent account deactivation: http://sbi-kyc-verification.com/login',
    expectScam: true,
    minThreat: 85,
    maxThreat: 100
  },
  {
    name: 'India Post Redelivery Smishing',
    text: 'India Post Alert: Your package delivery has been put on hold due to incomplete address. Please update your address and pay re-delivery fee within 24 hours: http://indiapost-parcel-delivery.top/update-address',
    expectScam: true,
    minThreat: 85,
    maxThreat: 100
  },
  {
    name: 'Electricity Disconnection Fraud',
    text: 'Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the power office because your previous month bill was not updated. Please immediately call our electricity officer at 9876543210.',
    expectScam: true,
    minThreat: 85,
    maxThreat: 100
  },
  {
    name: 'UPI Cashback Lottery Trap',
    text: 'Congratulations! You have received ₹4,999 cashback in your PhonePe reward wallet. Scan this QR code or click link to receive money directly into your bank account: http://claim-phonepe-cashback-500.xyz/upi-pay',
    expectScam: true,
    minThreat: 85,
    maxThreat: 100
  },
  {
    name: 'Authentic Bank Debit Notification',
    text: 'INR 450.00 debited from A/c XX4819 on 03-Nov-26 at Indian Oil Corp. Avail Bal: INR 12,450.32. Call 1800112211 if not done by you. - State Bank of India',
    expectScam: false,
    exactThreat: 0
  },
  {
    name: 'Authentic 2FA Google OTP',
    text: '849201 is your Google verification code. Do not share this code with anyone. Google will never call to ask for this code.',
    expectScam: false,
    exactThreat: 0
  },
  {
    name: 'Authentic Order Delivery Update',
    text: 'Your order #10829 from Amazon India is out for delivery with delivery partner Rajesh (Ekart). Track package securely in your official Amazon app.',
    expectScam: false,
    exactThreat: 0
  }
];

let msgPassed = 0;
for (const tc of messageTests) {
  const res = msgAnalyzer.analyze(tc.text);
  const scoreOk = tc.exactThreat !== undefined 
    ? res.threatPercentage === tc.exactThreat 
    : (res.threatPercentage >= tc.minThreat && res.threatPercentage <= tc.maxThreat);
  const hasExp = res.explanation && res.explanation.length > 30;

  if (scoreOk && hasExp) {
    msgPassed++;
    console.log(`✓ [PASS] ${tc.name}: Threat=${res.threatPercentage}% [${res.verdict.toUpperCase()}]`);
    console.log(`   Explanation: ${res.headline}`);
  } else {
    console.error(`✗ [FAIL] ${tc.name}: Threat=${res.threatPercentage}%, ScoreOk=${scoreOk}, HasExp=${hasExp}`);
  }
}

if (msgPassed === messageTests.length) {
  console.log(`✓ All ${messageTests.length}/${messageTests.length} Message Analyzer tests passed.`);
} else {
  console.error(`FAIL: ${messageTests.length - msgPassed} Message Analyzer tests failed.`);
  process.exit(1);
}

// 3. Verify QR Code & UPI Detector Suite
console.log('\n--- 3. QR Code & UPI Detector Test Suite ---');
const qrTests = [
  {
    name: 'Reverse UPI Trap (Scan to Receive 5000 Debit Fraud)',
    payload: 'upi://pay?pa=scammer99@oksbi&pn=Paytm+Refund+Desk&am=5000&cu=INR&tn=Refund+Claim',
    minThreat: 85,
    maxThreat: 100,
    checkReason: (res) => res.explanation.includes('Reverse UPI') && res.explanation.includes('DEBIT')
  },
  {
    name: 'Quishing Phishing Link (Fake PayPal Login QR)',
    payload: 'http://paypal-security-update.com/signin',
    minThreat: 85,
    maxThreat: 100,
    checkReason: (res) => res.explanation.includes('QUISHING')
  },
  {
    name: 'Authentic Utility Bill Payment QR',
    payload: 'upi://pay?pa=discom.bill99@ybl&pn=Electricity+Bill+Desk&am=1850&cu=INR',
    exactThreat: 0,
    checkReason: (res) => res.parsedDetails.vpa === 'discom.bill99@ybl'
  },
  {
    name: 'Authentic IRCTC Merchant Payment QR',
    payload: 'upi://pay?pa=irctc@icici&pn=IRCTC+Official&mc=4111&cu=INR',
    exactThreat: 0,
    checkReason: (res) => res.levelLabel.includes('Verified Merchant')
  },
  {
    name: 'Authentic Income Tax Portal QR',
    payload: 'https://incometax.gov.in',
    exactThreat: 0,
    checkReason: (res) => res.levelLabel === 'Verified Safe' || res.levelLabel === 'Verified Government Portal'
  },
  {
    name: 'Standard Wi-Fi Setup QR',
    payload: 'WIFI:T:WPA;S:VeridexOffice;P:secureNetPass88;;',
    exactThreat: 0,
    checkReason: (res) => res.payloadType === 'WIFI_CONFIG'
  }
];

let qrPassed = 0;
for (const tc of qrTests) {
  const res = qrAnalyzer.analyze(tc.payload);
  const scoreOk = tc.exactThreat !== undefined 
    ? res.threatPercentage === tc.exactThreat 
    : (res.threatPercentage >= tc.minThreat && res.threatPercentage <= tc.maxThreat);
  const reasonOk = tc.checkReason ? tc.checkReason(res) : true;
  const hasExp = res.explanation && res.explanation.length > 20;

  if (scoreOk && reasonOk && hasExp) {
    qrPassed++;
    console.log(`✓ [PASS] ${tc.name}: Threat=${res.threatPercentage}% [${res.levelLabel}]`);
    console.log(`   Findings: ${res.headline}`);
  } else {
    console.error(`✗ [FAIL] ${tc.name}: Threat=${res.threatPercentage}%, ScoreOk=${scoreOk}, ReasonOk=${reasonOk}`);
  }
}

if (qrPassed === qrTests.length) {
  console.log(`✓ All ${qrTests.length}/${qrTests.length} QR Code Detector tests passed.`);
} else {
  console.error(`FAIL: ${qrTests.length - qrPassed} QR Code Detector tests failed.`);
  process.exit(1);
}

console.log('\n=== ALL PORTAL TAB & MULTI-MODULE TESTS PASSED 100% ===');
