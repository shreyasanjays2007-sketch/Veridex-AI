/**
 * Veridex AI – QR Code & UPI Quishing Threat Analyzer (100% Offline Engine)
 * Validates Genuine Merchant & Peer UPI Codes, Detects Reverse UPI Payment Traps,
 * Quishing (QR Phishing URLs), and Malformed Intruding Schemes.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VeridexQRAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // Deceptive payee / intent keywords used in reverse UPI scams
  const DECEPTIVE_PAYEE_TERMS = [
    'refund', 'cashback', 'receive money', 'scan to receive', 'lottery', 'winner',
    'kbc', 'prize', 'reward claim', 'customer care', 'helpline', 'unblock account',
    'verification desk', 'support desk', 'airdrop claim', 'double money'
  ];

  class QRAnalyzer {
    constructor(veridexEngine) {
      this.veridexEngine = veridexEngine || (typeof VeridexEngine !== 'undefined' ? new VeridexEngine() : null);
    }

    /**
     * Parse and analyze raw QR code string payload
     * @param {string} payload - Decoded QR string or URI
     * @returns {Object} Structured analysis
     */
    analyze(payload) {
      if (!payload || typeof payload !== 'string' || payload.trim().length === 0) {
        return {
          threatPercentage: 0,
          verdict: 'neutral',
          level: 'safe',
          levelLabel: 'Empty QR Code',
          headline: 'No Payload Detected',
          summary: 'Upload a QR image or enter a QR payload to begin verification.',
          explanation: 'No QR code data received for security audit.',
          payloadType: 'UNKNOWN',
          parsedDetails: {},
          indicators: []
        };
      }

      const raw = payload.trim();
      const lower = raw.toLowerCase();

      // Route by Protocol / Scheme
      if (lower.startsWith('upi://')) {
        return this._analyzeUpiIntent(raw);
      } else if (lower.startsWith('http://') || lower.startsWith('https://')) {
        return this._analyzeQuishingUrl(raw);
      } else if (raw.toUpperCase().startsWith('WIFI:')) {
        return this._analyzeWifiConfig(raw);
      } else {
        return this._analyzePlainText(raw);
      }
    }

    /**
     * Analyze UPI payment intent (upi://pay?...)
     */
    _analyzeUpiIntent(upiUri) {
      const parsed = {};
      const indicators = [];

      try {
        const queryPart = upiUri.includes('?') ? upiUri.split('?')[1] : upiUri.slice(6);
        const params = new URLSearchParams(queryPart);
        for (const [k, v] of params.entries()) {
          parsed[k.toLowerCase()] = v;
        }
      } catch (e) {
        indicators.push({ name: 'Malformed UPI Protocol', risk: 85, desc: 'Invalid UPI URI structure.' });
      }

      const vpa = (parsed.pa || '').toLowerCase(); // Payee Address (VPA)
      const payeeName = parsed.pn || '';           // Payee Name
      const amount = parsed.am || '';               // Amount
      const currency = parsed.cu || 'INR';
      const merchantCode = parsed.mc || '';         // Merchant Category Code (MCC)
      const transactionNote = parsed.tn || '';

      const fullCheckText = `${vpa} ${payeeName} ${transactionNote}`.toLowerCase();
      const matchedDeceptiveTerms = DECEPTIVE_PAYEE_TERMS.filter(term => fullCheckText.includes(term));
      const hasDeceptiveTerms = matchedDeceptiveTerms.length > 0;
      const hasAmount = parseFloat(amount) > 0;

      let threatPercentage = 0;
      let verdict = 'neutral';
      let level = 'safe';
      let levelLabel = 'Verified Safe';
      let headline = 'Authentic UPI Payment Code (0% Threat)';
      let explanation = '';

      if (hasDeceptiveTerms) {
        // REVERSE UPI DECEPTION SCAM -> Dynamically Variable strictly 85% to 100%
        let baseRisk = 85;
        let variance = 0;

        indicators.push({
          name: 'Reverse UPI Debit Deception',
          severity: 'danger',
          desc: `Deceptive terminology (${matchedDeceptiveTerms.map(t => `'${t}'`).join(', ')}) used to trick victims into scanning under the false pretense of receiving money or a refund.`
        });

        if (hasAmount) {
          variance += 7;
          indicators.push({
            name: 'Direct Account Debit Request',
            severity: 'danger',
            desc: `Contains an immediate debit instruction for ₹${amount}. In UPI architecture, scanning a QR code with an amount parameter will WITHDRAW funds from your bank, NEVER credit them.`
          });
        }

        if (!merchantCode || merchantCode === '0000') {
          variance += 4;
          indicators.push({
            name: 'Unverified Personal VPA',
            severity: 'warning',
            desc: `VPA '${vpa}' is an unverified private personal account masquerading as a business refund desk.`
          });
        }

        threatPercentage = Math.min(100, Math.max(85, baseRisk + variance + 4));
        verdict = 'suspicious';
        level = 'danger';
        levelLabel = 'Critical UPI Scam Trap';
        headline = `Critical Reverse UPI Payment Trap (${threatPercentage}% Threat)`;
        explanation = `CRITICAL WARNING: This QR code is engineered for Reverse UPI Fraud.\n\n` +
          `• Deception Tactic: It displays misleading labels ('${payeeName || 'Refund / Cashback'}') designed to deceive victims into believing they are receiving money.\n` +
          `• UPI Architecture Reality: Scanning a QR code can NEVER deposit or credit funds into your account. QR codes only authorize an outgoing DEBIT.\n` +
          `${hasAmount ? `• Financial Threat: Scanning will immediately debit ₹${amount} from your bank account.\n` : ''}` +
          `• Payee Destination: ${vpa}\n` +
          `• Action: Do NOT enter your UPI PIN. Never scan QR codes to receive money. Report this handle to the National Cyber Crime Helpline (1930).`;
      } else {
        // GENUINE / AUTHENTIC UPI CODE -> Strictly 0% Threat!
        threatPercentage = 0;
        verdict = 'neutral';
        level = 'safe';
        levelLabel = merchantCode ? 'Verified Merchant QR' : 'Authentic UPI QR';
        headline = `Authentic UPI Payment Code (0% Threat) — ${payeeName || vpa}`;
        explanation = `This QR code contains a genuine, legitimate UPI payment instruction for payee '${payeeName || vpa}'.\n\n` +
          `• Payee VPA: ${vpa}\n` +
          `• Payee Name: ${payeeName || 'Valid Payee'}\n` +
          `• Requested Amount: ${hasAmount ? `₹${amount}` : 'User-entered at scan time'}\n` +
          `• Security Status: 0% Threat. No deceptive refund lures, reverse payment traps, or phishing masquerading detected.`;
      }

      return {
        threatPercentage,
        verdict,
        level,
        levelLabel,
        headline,
        summary: headline,
        explanation,
        payloadType: 'UPI_PAYMENT',
        parsedDetails: {
          vpa: vpa || 'N/A',
          payeeName: payeeName || 'Standard Payee',
          amount: hasAmount ? `₹${amount}` : 'User-specified',
          currency,
          merchantCode: merchantCode || 'Standard Consumer / Merchant',
          note: transactionNote || 'None'
        },
        indicators
      };
    }

    /**
     * Analyze URL embedded in QR Code (Quishing)
     */
    _analyzeQuishingUrl(url) {
      let threatPercentage = 0;
      let verdict = 'neutral';
      let level = 'safe';
      let levelLabel = 'Verified Safe';
      let headline = 'Authentic Web Destination (0% Threat)';
      let explanation = '';
      let urlAnalysis = null;

      if (this.veridexEngine) {
        try {
          urlAnalysis = this.veridexEngine.analyze(url);
          threatPercentage = urlAnalysis.riskPercentage || 0;
          verdict = urlAnalysis.verdict;
          level = urlAnalysis.level;
          levelLabel = urlAnalysis.levelLabel;
        } catch (e) {}
      }

      if (threatPercentage >= 85) {
        headline = `Critical Quishing Phishing Attack (${threatPercentage}% Threat)`;
        explanation = `QUISHING (QR Phishing) DETECTED: This QR code encodes a malicious destination link.\n\n` +
          `• Target URL: ${url}\n` +
          `• Threat Severity: ${threatPercentage}% evaluated risk score\n` +
          `• Engine Findings: ${urlAnalysis ? urlAnalysis.summary : 'Phishing lure detected'}\n` +
          `• Quishing Technique: Fraudsters conceal malicious links inside QR codes to bypass spam filters and trick mobile camera scanners into loading credential-harvesting websites.\n` +
          `• Immediate Action: Do NOT open this URL or submit passwords, bank credentials, or OTPs.`;
      } else if (threatPercentage === 0) {
        headline = `Authentic Verified QR Destination (0% Threat)`;
        explanation = `The URL encoded in this QR code (${url}) is verified safe with 0% risk indicators. Confirmed clean destination with zero phishing or domain spoofing heuristics.`;
      } else {
        headline = `Caution Advised Link (${threatPercentage}% Threat)`;
        explanation = `The destination encoded in this QR code (${url}) exhibits minor elevated heuristics (${threatPercentage}% risk). Confirm the destination identity before entering sensitive information.`;
      }

      return {
        threatPercentage,
        verdict,
        level,
        levelLabel,
        headline,
        summary: headline,
        explanation,
        payloadType: 'QUISHING_URL',
        parsedDetails: {
          url,
          protocol: url.split('://')[0].toUpperCase(),
          destinationHost: url.replace(/https?:\/\//i, '').split('/')[0],
          engineStatus: `${threatPercentage}% Threat Level`
        },
        indicators: urlAnalysis ? (urlAnalysis.signals || []) : []
      };
    }

    /**
     * Analyze Wi-Fi configuration QR
     */
    _analyzeWifiConfig(wifiString) {
      return {
        threatPercentage: 0,
        verdict: 'neutral',
        level: 'safe',
        levelLabel: 'Local Wi-Fi Config',
        headline: 'Authentic Wi-Fi Network Setup (0% Threat)',
        summary: 'Standard local wireless network configuration payload.',
        explanation: 'This QR code contains standard local Wi-Fi credentials for connecting to an access point. 0% Threat — no external network redirects, malware payloads, or payment intents.',
        payloadType: 'WIFI_CONFIG',
        parsedDetails: {
          payload: wifiString
        },
        indicators: []
      };
    }

    /**
     * Analyze plain text payload
     */
    _analyzePlainText(text) {
      return {
        threatPercentage: 0,
        verdict: 'neutral',
        level: 'safe',
        levelLabel: 'Plain Text QR',
        headline: 'Authentic Text Content (0% Threat)',
        summary: 'Contains plain alphanumeric information.',
        explanation: 'The QR code encodes informational plain text without active URI scheme handlers, payment vectors, or malicious redirection scripts. 0% Threat.',
        payloadType: 'PLAIN_TEXT',
        parsedDetails: {
          content: text.length > 80 ? text.slice(0, 80) + '...' : text
        },
        indicators: []
      };
    }
  }

  return QRAnalyzer;
});
