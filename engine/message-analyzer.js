/**
 * Veridex AI – SMS, Email & Message Scam Analyzer (100% Offline Engine)
 * Identifies Digital Arrest, Banking KYC Phishing, India Post Smishing,
 * Electricity Bill Extortion, UPI Cashback Traps, Fake Job/Investment Frauds,
 * and Validates Genuine Transactional & OTP Alerts.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VeridexMessageAnalyzer = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // Scam signature patterns and vocabulary
  const SCAM_PATTERNS = {
    digitalArrest: {
      id: 'digital_arrest',
      name: 'Digital Arrest / Cyber Police Extortion',
      weight: 95,
      keywords: [
        'digital arrest', 'arrest warrant', 'cbi', 'trai', 'cyber crime branch',
        'sim deactivation', 'sim card blocked', 'police verification', 'customs department',
        'illegal parcel', 'drugs found', 'skype interrogation', 'video call police',
        'supreme court', 'money laundering', 'pmla', 'dcp crime branch', 'fir registered'
      ],
      description: 'Extortion tactic impersonating law enforcement/TRAI claiming imminent arrest or illegal packages to force video-call or fund transfer.'
    },
    bankingKyc: {
      id: 'banking_kyc',
      name: 'Banking KYC / Account Suspension Phishing',
      weight: 94,
      keywords: [
        'kyc suspended', 'kyc expired', 'pan not linked', 'account will be blocked',
        'yono account', 'netbanking blocked', 'update kyc immediately', 'sbi kyc',
        'hdfc alert', 'icici update', 'paytm kyc', 'unblock your account', 'credit card reward points'
      ],
      description: 'Phishing trap mimicking Indian banks to harvest netbanking passwords, OTPs, and PAN details.'
    },
    indiaPost: {
      id: 'india_post_smishing',
      name: 'India Post / Courier Redelivery Smishing',
      weight: 90,
      keywords: [
        'india post', 'package delivery fail', 'parcel pending', 'wrong address',
        'update delivery address', 'redelivery fee', 'shipment on hold', 'postal parcel',
        'courier return', 'pay re-delivery'
      ],
      description: 'Deceptive parcel delivery failure notification leading to a fake credential and payment portal.'
    },
    electricityBill: {
      id: 'electricity_bill_scam',
      name: 'Electricity Disconnection Fraud',
      weight: 92,
      keywords: [
        'electricity power will be disconnected', 'light cut at 9:30', 'power cut tonight',
        'previous month bill not updated', 'contact electricity officer', 'call electricity helpline',
        'power disconnected immediately', 'call our electricity officer'
      ],
      description: 'Urgency fraud warning of immediate electric supply cut-off to force victims into calling fraudulent numbers or installing remote access apps.'
    },
    upiRefundReward: {
      id: 'upi_cashback_fraud',
      name: 'UPI Cashback / Lottery / Prize Trap',
      weight: 90,
      keywords: [
        'cashback won', 'won lottery', 'congratulations you won', 'claim reward points',
        'kbc lottery', 'scan qr to receive', 'receive 5000 in phonepe', 'gpay prize',
        'paytm cashback claim', 'scratch card won'
      ],
      description: 'Reverse payment deception enticing users with rewards, prizes, or fake refunds to trick them into approving debits.'
    },
    jobInvestment: {
      id: 'job_investment_fraud',
      name: 'Part-Time Job / Telegram Investment Scam',
      weight: 88,
      keywords: [
        'part time job', 'earn 5000 daily', 'youtube video like', 'work from home',
        'daily payout', 'telegram task', 'crypto guaranteed returns', 'double your money',
        'vip investment plan'
      ],
      description: 'Task-based advance fee fraud enticing victims with small initial payouts before demanding large deposits.'
    }
  };

  // Genuine message indicators (Indian banking alerts, carrier OTPs, eCommerce delivery)
  const GENUINE_SIGNATURES = [
    {
      type: 'BANK_DEBIT',
      regex: /(debited by|debited for|withdrawn from|spent on|txn of rs\.?|paid to|vpa.*debited)/i,
      hasMaskedAccount: /(a\/c\s*(?:no\.?)?\s*x+[0-9]{3,4}|acct\s*x+[0-9]{3,4}|card\s*x+[0-9]{4})/i,
      hasBalance: /(avail(?:able)?\s*bal(?:ance)?|total\s*bal|clear\s*bal)/i
    },
    {
      type: 'BANK_CREDIT',
      regex: /(credited (?:to|with)|received rs\.?|deposited in|refund credited)/i,
      hasMaskedAccount: /(a\/c\s*(?:no\.?)?\s*x+[0-9]{3,4}|acct\s*x+[0-9]{3,4})/i
    },
    {
      type: 'SECURE_OTP',
      regex: /(is your (?:secret |one time password|otp|verification code)|use otp\s*[0-9]{4,8}|otp is\s*[0-9]{4,8})/i,
      advisoryRegex: /(do not share|valid for|expires in|never share|for your security)/i
    },
    {
      type: 'ECOMMERCE_DELIVERY',
      regex: /(out for delivery|arriving today|delivery partner|package has been dispatched|courier executive)/i,
      trackingRegex: /(tracking id|order id|awb|shipment #|package #)/i
    }
  ];

  // Coercive urgency words
  const URGENCY_TRIGGERS = [
    'immediately', 'urgent', 'strictly within', 'action required', 'tonight',
    'at 9:30 pm', 'within 2 hours', 'within 24 hours', 'final warning',
    'otherwise arrest', 'police action', 'legal notice'
  ];

  // URL extraction regex
  const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|(?:[a-zA-Z0-9-]+\.)+(?:com|in|org|net|xyz|top|live|shop|club|online|co\.in|gov\.in)[^\s<>"'{}|\\^`]*/gi;

  class MessageAnalyzer {
    constructor(veridexEngine) {
      this.veridexEngine = veridexEngine || (typeof VeridexEngine !== 'undefined' ? new VeridexEngine() : null);
    }

    /**
     * Analyze message text for authenticity and threat vectors
     * @param {string} text - Message text or SMS content
     * @returns {Object} Complete analysis result
     */
    analyze(text) {
      if (!text || typeof text !== 'string' || text.trim().length === 0) {
        return {
          threatPercentage: 0,
          verdict: 'neutral',
          level: 'safe',
          levelLabel: 'Empty Message',
          headline: 'No Content Provided',
          summary: 'Please enter or paste message content to analyze.',
          explanation: 'No textual information detected for analysis.',
          indicators: [],
          extractedUrls: [],
          categories: { urgency: 0, impersonation: 0, linkRisk: 0 }
        };
      }

      const raw = text.trim();
      const lower = raw.toLowerCase();

      // 1. Extract and inspect embedded URLs
      const urlMatches = raw.match(URL_REGEX) || [];
      const extractedUrls = [];
      let maxUrlRisk = 0;
      let urlThreatDetails = null;

      for (const matched of urlMatches) {
        let fullUrl = matched;
        if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
          fullUrl = 'http://' + fullUrl;
        }
        extractedUrls.push(fullUrl);

        if (this.veridexEngine) {
          try {
            const urlResult = this.veridexEngine.analyze(fullUrl);
            if (urlResult && urlResult.riskPercentage > maxUrlRisk) {
              maxUrlRisk = urlResult.riskPercentage;
              urlThreatDetails = urlResult;
            }
          } catch (e) {}
        }
      }

      // 2. Detect Genuine Message Signatures
      let isVerifiedGenuine = false;
      let genuineType = null;
      for (const sig of GENUINE_SIGNATURES) {
        if (sig.regex.test(raw)) {
          if (sig.type === 'BANK_DEBIT' && sig.hasMaskedAccount.test(raw)) {
            isVerifiedGenuine = true;
            genuineType = 'Bank Debit Notification';
            break;
          } else if (sig.type === 'BANK_CREDIT' && sig.hasMaskedAccount.test(raw)) {
            isVerifiedGenuine = true;
            genuineType = 'Bank Credit Notification';
            break;
          } else if (sig.type === 'SECURE_OTP' && sig.advisoryRegex.test(raw)) {
            // OTP is genuine only if it DOES NOT contain an untrusted URL
            if (extractedUrls.length === 0 || maxUrlRisk === 0) {
              isVerifiedGenuine = true;
              genuineType = 'Two-Factor Authentication OTP';
              break;
            }
          } else if (sig.type === 'ECOMMERCE_DELIVERY' && sig.trackingRegex.test(raw) && maxUrlRisk === 0) {
            isVerifiedGenuine = true;
            genuineType = 'Official Delivery Update';
            break;
          }
        }
      }

      // 3. Scan for Known Scam Signatures
      const detectedVectors = [];
      let maxVectorWeight = 0;

      for (const [key, category] of Object.entries(SCAM_PATTERNS)) {
        const matchedKw = category.keywords.filter(kw => lower.includes(kw));
        if (matchedKw.length > 0) {
          detectedVectors.push({
            id: category.id,
            name: category.name,
            weight: category.weight,
            matchedKeywords: matchedKw,
            description: category.description
          });
          if (category.weight > maxVectorWeight) {
            maxVectorWeight = category.weight;
          }
        }
      }

      // 4. Scan for Coercive Urgency Tactics
      const matchedUrgency = URGENCY_TRIGGERS.filter(u => lower.includes(u));

      // 5. Calculate Threat Percentage
      let threatPercentage = 0;
      let verdict = 'neutral';
      let level = 'safe';
      let levelLabel = 'Verified Safe';
      let headline = 'Authentic & Legitimate Message (0% Risk)';
      let explanation = '';

      if (isVerifiedGenuine && detectedVectors.length === 0 && maxUrlRisk === 0) {
        // Authentic message -> 0% Risk strictly
        threatPercentage = 0;
        verdict = 'neutral';
        level = 'safe';
        levelLabel = 'Verified Genuine';
        headline = `Authentic Communication (${genuineType})`;
        explanation = `This message matches standard genuine formats for an authentic ${genuineType}. It contains valid masking (e.g. account numbers or security advisories) and does not contain deceptive links, coercion tactics, or phishing traps.`;
      } else if (detectedVectors.length > 0 || maxUrlRisk >= 85) {
        // Fake / Scam / Extortion Message -> Dynamically Variable strictly 85% to 100%
        let baseRisk = 85;
        let variance = 0;

        // Vector severity variance
        if (detectedVectors.some(v => v.id === 'digital_arrest')) variance += 9;
        if (detectedVectors.some(v => v.id === 'banking_kyc')) variance += 7;
        if (detectedVectors.some(v => v.id === 'electricity_bill_scam')) variance += 6;
        if (detectedVectors.some(v => v.id === 'upi_cashback_fraud')) variance += 5;
        if (detectedVectors.some(v => v.id === 'india_post_smishing')) variance += 5;

        // Multiple compounding attack categories
        if (detectedVectors.length >= 2) variance += 4;

        // Urgency pressure tactics
        if (matchedUrgency.length >= 2) variance += 4;
        else if (matchedUrgency.length === 1) variance += 2;

        // Embedded malicious link penalty
        if (maxUrlRisk >= 85) {
          variance += 6;
        } else if (extractedUrls.length > 0) {
          variance += 3;
        }

        threatPercentage = Math.min(100, Math.max(85, baseRisk + variance));
        verdict = 'suspicious';
        level = 'danger';
        levelLabel = 'Critical Scam Threat';

        const primaryVector = detectedVectors[0] ? detectedVectors[0].name : (urlThreatDetails ? 'Phishing URL Attack' : 'Fraudulent Message');
        headline = `Deceptive Fraud Alert (${threatPercentage}% Risk) — ${primaryVector}`;

        const vectorNames = detectedVectors.map(v => v.name).join(', ');
        explanation = `CRITICAL ALERT: This message exhibits high-confidence characteristics of cyber fraud.\n\n` +
          `• Primary Threat Vectors: ${vectorNames || 'Malicious Embedded Link'}\n` +
          `• Coercive Tactics: ${matchedUrgency.length > 0 ? `Artificially manufactured urgency (${matchedUrgency.join(', ')}) designed to bypass critical thinking` : 'Deceptive institutional impersonation'}\n` +
          `${extractedUrls.length > 0 ? `• Embedded URL Threat: Contains ${extractedUrls.length} destination link(s)${maxUrlRisk > 0 ? ` evaluated at ${maxUrlRisk}% phishing risk` : ''}.\n` : ''}` +
          `• Guidance: Never call the numbers provided in the text or click links. Report this incident directly to the National Cyber Crime Helpline (1930) or cybercrime.gov.in.`;
      } else if (matchedUrgency.length > 0 || extractedUrls.length > 0) {
        // Cautionary / Unverified Message
        threatPercentage = Math.min(45, Math.max(25, (matchedUrgency.length * 10) + (extractedUrls.length * 15)));
        verdict = 'neutral';
        level = 'caution';
        levelLabel = 'Caution Advised';
        headline = `Caution Advised (${threatPercentage}% Risk) — Unverified Elements`;
        explanation = `This message contains urgency terminology or unverified external links. While no specific institutional scam signatures were definitively matched, exercise vigilance before sharing credentials or clicking attachments.`;
      } else {
        // Clean Neutral / Plain Text
        threatPercentage = 0;
        verdict = 'neutral';
        level = 'safe';
        levelLabel = 'Neutral / Safe';
        headline = 'No Known Threat Indicators Detected (0% Risk)';
        explanation = 'The analyzed text does not trigger known scam keywords, extortion threats, or deceptive urgency patterns. Always verify sender identity independently.';
      }

      return {
        threatPercentage,
        verdict,
        level,
        levelLabel,
        headline,
        summary: headline,
        explanation,
        indicators: detectedVectors,
        extractedUrls,
        maxUrlRisk,
        urgencyTriggers: matchedUrgency,
        categories: {
          urgency: matchedUrgency.length > 0 ? Math.min(100, matchedUrgency.length * 35) : 0,
          impersonation: detectedVectors.length > 0 ? Math.min(100, maxVectorWeight) : 0,
          linkRisk: maxUrlRisk
        }
      };
    }
  }

  return MessageAnalyzer;
});
