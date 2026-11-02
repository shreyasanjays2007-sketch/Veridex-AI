/**
 * Veridex AI - In-Page Content Script
 * Extracts on-page DOM behavioral indicators, interacts with the background service worker,
 * and renders in-page warning alerts when threats are identified.
 */

(function () {
  'use strict';

  // Avoid running in small third-party ad iframes
  if (window.self !== window.top) return;

  const modalRenderer = new VeridexWarningModal();
  const floatingBadge = new VeridexFloatingBadge();

  /**
   * Scans current DOM for behavioral and structural scam indicators
   */
  function extractDomSignals() {
    const signals = {
      hasPasswordField: false,
      hasCreditCardField: false,
      hasSeedPhraseInputs: false,
      hasUrgencyPatterns: false,
      externalFormActions: [],
      pageTitle: document.title || '',
      mainHeading: '',
      hasCountdown: false
    };

    // Check headings
    const h1 = document.querySelector('h1');
    if (h1) {
      signals.mainHeading = h1.innerText.trim().slice(0, 100);
    }

    // Check password fields
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0) {
      signals.hasPasswordField = true;
    }

    // Check credit card input patterns
    const ccSelectors = [
      'input[autocomplete*="cc-number"]',
      'input[name*="cardnumber" i]',
      'input[name*="card_num" i]',
      'input[name*="cvv" i]',
      'input[placeholder*="card number" i]'
    ];
    if (document.querySelector(ccSelectors.join(','))) {
      signals.hasCreditCardField = true;
    }

    // Check Crypto Seed Phrase Harvesters (12 or 24 word mnemonic grids)
    const bodyText = (document.body ? document.body.innerText : '').toLowerCase();
    const cryptoKeywords = [
      'secret recovery phrase',
      'seed phrase',
      '12-word phrase',
      '24-word phrase',
      'import your wallet',
      'enter your recovery phrase'
    ];
    const hasCryptoText = cryptoKeywords.some(kw => bodyText.includes(kw));
    const multipleTextInputs = document.querySelectorAll('input[type="text"], textarea').length >= 12;
    if (hasCryptoText && multipleTextInputs) {
      signals.hasSeedPhraseInputs = true;
    }

    // Check Psychological Urgency & Scam pressure text
    const urgencyPatterns = [
      /account.*will be.*suspended/i,
      /unauthorized.*access.*detected/i,
      /immediate.*action.*required/i,
      /temporarily.*locked.*verify/i,
      /you.*won.*lottery/i,
      /claim.*prize.*within/i,
      /toll-free.*security.*helpline/i,
      /critical.*security.*alert.*call/i,
      /expires.*in.*[0-9]+.*minutes/i
    ];
    signals.hasUrgencyPatterns = urgencyPatterns.some(rx => rx.test(bodyText));

    // Check active countdown timers
    const timerElements = document.querySelectorAll('[class*="countdown" i], [id*="timer" i], [class*="clock" i]');
    if (timerElements.length > 0 && signals.hasUrgencyPatterns) {
      signals.hasCountdown = true;
    }

    // Check form destinations
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const action = form.getAttribute('action');
      if (action) {
        try {
          const actionUrl = new URL(action, window.location.href);
          if (actionUrl.hostname && actionUrl.hostname !== window.location.hostname) {
            signals.externalFormActions.push(actionUrl.hostname);
          }
        } catch (e) {
          // relative or invalid
        }
      }
    });

    return signals;
  }

  /**
  /**
   * Main scan execution
   */
  function runScan() {
    const domSignals = extractDomSignals();

    chrome.runtime.sendMessage(
      {
        type: 'DOM_SIGNALS_DETECTED',
        url: window.location.href,
        domSignals
      },
      (response) => {
        if (!response) return;

        const isUnsafe = response.action === 'SHOW_WARNING' || (response.analysis && response.analysis.isUnsafe);
        const analysis = response.analysis || {};

        // Request offline cookie security audit from background service worker
        try {
          chrome.runtime.sendMessage(
            {
              type: 'GET_COOKIE_ANALYSIS',
              url: window.location.href
            },
            (cookieResp) => {
              if (cookieResp && cookieResp.cookieAnalysis) {
                analysis.cookieAnalysis = cookieResp.cookieAnalysis;
              } else if (typeof CookieAnalyzer !== 'undefined') {
                analysis.cookieAnalysis = CookieAnalyzer.parseDocumentCookies(document.cookie, window.location.href);
              }

              // Update badge with attached cookie analysis
              floatingBadge.render({
                analysis: analysis,
                isUnsafe: isUnsafe
              });
            }
          );
        } catch (e) {
          if (typeof CookieAnalyzer !== 'undefined') {
            analysis.cookieAnalysis = CookieAnalyzer.parseDocumentCookies(document.cookie, window.location.href);
          }
        }

        // 1. Render the unobtrusive circular floating pin on screen
        floatingBadge.render({
          analysis: analysis,
          isUnsafe: isUnsafe
        });

        // 2. If detected as unsafe, automatically display the warning pop-up modal
        if (response.action === 'SHOW_WARNING' && response.analysis) {
          modalRenderer.show(response.analysis);
        }
      }
    );
  }

  // Execute scan when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runScan);
  } else {
    runScan();
  }
})();
