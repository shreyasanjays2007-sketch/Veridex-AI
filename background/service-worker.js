/**
 * Veridex AI - Background Service Worker (Manifest V3)
 * Continuously monitors tab navigations, coordinates heuristic analysis,
 * manages tab badge states, and handles communication with content scripts and popup UI.
 */

// Import detection engine dependencies into the service worker scope
importScripts(
  '../engine/brand-database.js',
  '../engine/tld-risk.js',
  '../engine/ip-intelligence.js',
  '../engine/cookie-analyzer.js',
  '../engine/veridex-ml-model.js',
  '../engine/ai-explanation.js',
  '../engine/veridex-engine.js'
);

const engine = new VeridexEngine();

// In-memory tab analysis cache: tabId -> analysisResult
const tabAnalysisStore = new Map();

// In-memory tab resolved server IP store: tabId -> resolved IP string
const tabIpStore = new Map();

// Session whitelisted origins/domains (temporarily dismissed by user)
const sessionWhitelist = new Set();

// Listen to webRequest response started to identify the remote server IP
if (chrome.webRequest && chrome.webRequest.onResponseStarted) {
  chrome.webRequest.onResponseStarted.addListener(
    (details) => {
      if (details.tabId > 0 && details.type === 'main_frame' && details.ip) {
        tabIpStore.set(details.tabId, details.ip);
        const existing = tabAnalysisStore.get(details.tabId);
        if (existing && details.url) {
          const updated = engine.analyze(details.url, null, null, details.ip);
          tabAnalysisStore.set(details.tabId, updated);
          updateBadge(details.tabId, updated);
        }
      }
    },
    { urls: ['<all_urls>'], types: ['main_frame'] }
  );
}

// Default settings
const DEFAULT_SETTINGS = {
  protectionEnabled: true,
  strictMode: false,
  showInPageWarning: true,
  desktopNotifications: true,
  scanOnHover: false
};

// Initialize settings on install
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get('veridex_settings');
  if (!current.veridex_settings) {
    await chrome.storage.local.set({ veridex_settings: DEFAULT_SETTINGS });
  }
  console.log('[Veridex AI] Service worker initialized successfully.');
});

/**
 * Retrieve user configuration
 */
async function getSettings() {
  const data = await chrome.storage.local.get('veridex_settings');
  return data.veridex_settings || DEFAULT_SETTINGS;
}

/**
 * Updates the extension badge on the browser toolbar
 */
function updateBadge(tabId, analysis) {
  if (!tabId || tabId < 0) return;

  if (analysis.verdict === 'suspicious') {
    const isDanger = analysis.level === 'danger';
    chrome.action.setBadgeBackgroundColor({
      tabId,
      color: isDanger ? '#ef4444' : '#f59e0b'
    });
    const riskPct = analysis.riskPercentage !== undefined ? analysis.riskPercentage : analysis.riskScore;
    chrome.action.setBadgeText({
      tabId,
      text: `${riskPct}%`
    });
    chrome.action.setTitle({
      tabId,
      title: `Veridex AI: ⚠️ ${analysis.summary} (${riskPct}% Risk)`
    });
  } else {
    // Neutral status - clear badge text to stay unobtrusive
    chrome.action.setBadgeText({
      tabId,
      text: ''
    });
    chrome.action.setTitle({
      tabId,
      title: 'Veridex AI: Neutral Status (Unverified - No Immediate Risk Indicators Found)'
    });
  }
}

/**
 * Handles tab navigation event
 */
async function handleNavigation(tabId, url) {
  if (!url || tabId < 0) return;

  const settings = await getSettings();
  if (!settings.protectionEnabled) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  // Check if whitelisted for this session
  try {
    const parsed = new URL(url);
    if (sessionWhitelist.has(parsed.hostname)) {
      console.log(`[Veridex AI] ${parsed.hostname} is session-whitelisted. Skipping alert.`);
      return;
    }
  } catch (e) {
    // Continue
  }

  // Step 1: Preliminary URL lexical and IP analysis
  const tabIp = tabIpStore.get(tabId) || null;
  const preliminaryAnalysis = engine.analyze(url, null, null, tabIp);
  tabAnalysisStore.set(tabId, preliminaryAnalysis);
  updateBadge(tabId, preliminaryAnalysis);

  // If high risk detected immediately from URL (e.g. typosquatting, raw IP, homoglyph)
  if (preliminaryAnalysis.verdict === 'suspicious' && settings.desktopNotifications && preliminaryAnalysis.level === 'danger') {
    chrome.notifications.create(`threat-${tabId}-${Date.now()}`, {
      type: 'basic',
      iconUrl: '../icons/icon128.png',
      title: 'Veridex AI — Phishing Alert',
      message: `${preliminaryAnalysis.summary} (${preliminaryAnalysis.details.hostname})`,
      priority: 2
    });
  }
}

// Monitor navigation starts
chrome.webNavigation.onCommitted.addListener((details) => {
  // Only process main frame navigations (not iframes)
  if (details.frameId === 0) {
    handleNavigation(details.tabId, details.url);
  }
});

// Monitor tab updates (for single page apps and hash changes)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    handleNavigation(tabId, changeInfo.url);
  }
});

// Clean up memory cache when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabAnalysisStore.delete(tabId);
  tabIpStore.delete(tabId);
});

// Handle incoming messages from popup and content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;

  switch (message.type) {
    // Content script detected DOM signals (forms, titles, urgency, etc.)
    case 'DOM_SIGNALS_DETECTED': {
      (async () => {
        const settings = await getSettings();
        if (!settings.protectionEnabled) {
          sendResponse({ action: 'ignore' });
          return;
        }

        const url = message.url || (sender.tab ? sender.tab.url : '');
        try {
          const parsed = new URL(url);
          if (sessionWhitelist.has(parsed.hostname)) {
            sendResponse({ action: 'whitelisted' });
            return;
          }
        } catch (e) {}

        // Re-analyze combining URL, rich DOM signals, and resolved server IP
        const tabIp = (tabId && tabIpStore.get(tabId)) || null;
        const comprehensiveAnalysis = engine.analyze(url, message.domSignals, null, tabIp);
        if (tabId) {
          tabAnalysisStore.set(tabId, comprehensiveAnalysis);
          updateBadge(tabId, comprehensiveAnalysis);
        }

        const isUnsafe = comprehensiveAnalysis.isUnsafe || comprehensiveAnalysis.verdict === 'suspicious' || (comprehensiveAnalysis.riskPercentage >= 35);
        const shouldWarn = isUnsafe && settings.showInPageWarning !== false;

        sendResponse({
          action: shouldWarn ? 'SHOW_WARNING' : 'SAFE',
          analysis: comprehensiveAnalysis
        });
      })();
      return true; // Keep message channel open for async response
    }

    // Popup requesting current active tab status
    case 'GET_ACTIVE_TAB_STATUS': {
      (async () => {
        let activeAnalysis = null;
        const tabIp = message.tabId ? tabIpStore.get(message.tabId) : null;
        if (message.tabId && tabAnalysisStore.has(message.tabId)) {
          activeAnalysis = tabAnalysisStore.get(message.tabId);
          // If server IP was subsequently discovered, update the analysis
          if (tabIp && (!activeAnalysis.ipIntelligence || !activeAnalysis.ipIntelligence.isAvailable)) {
            activeAnalysis = engine.analyze(activeAnalysis.details.url || message.url, null, null, tabIp);
            tabAnalysisStore.set(message.tabId, activeAnalysis);
          }
        } else if (message.url) {
          activeAnalysis = engine.analyze(message.url, null, null, tabIp);
        }

        sendResponse({ analysis: activeAnalysis });
      })();
      return true;
    }

    // Manual URL Scanner query from popup or test lab
    case 'SCAN_URL_MANUAL': {
      (async () => {
        try {
          const scanResult = await engine.verifyLive(message.url);
          sendResponse({ result: scanResult });
        } catch (e) {
          const scanResult = engine.analyze(message.url);
          sendResponse({ result: scanResult });
        }
      })();
      return true;
    }

    // User dismissed warning for this domain during this session
    case 'WHITELIST_SESSION_DOMAIN': {
      if (message.hostname) {
        sessionWhitelist.add(message.hostname.toLowerCase());
        if (tabId) {
          chrome.action.setBadgeText({ tabId, text: '' });
        }
      }
      sendResponse({ success: true });
      return true;
    }

    // Cookie Security Audit query (Offline, values never stored or transmitted)
    case 'GET_COOKIE_ANALYSIS': {
      (async () => {
        const targetUrl = message.url || (sender.tab ? sender.tab.url : '');
        try {
          if (chrome.cookies && chrome.cookies.getAll && targetUrl) {
            const rawCookies = await chrome.cookies.getAll({ url: targetUrl });
            // STRICT PRIVACY REDACTION: values are stripped immediately and never passed to analyzer or response
            const sanitized = (rawCookies || []).map(c => ({
              name: c.name,
              domain: c.domain,
              path: c.path,
              secure: c.secure,
              httpOnly: c.httpOnly,
              sameSite: c.sameSite,
              session: c.session,
              expirationDate: c.expirationDate,
              hostOnly: c.hostOnly
            }));
            const analysis = CookieAnalyzer.analyzeCookies(sanitized, targetUrl);
            sendResponse({ success: true, cookieAnalysis: analysis });
            return;
          }
        } catch (err) {
          console.warn('[Veridex AI] Error inspecting cookies via chrome.cookies:', err);
        }

        const fallback = CookieAnalyzer.analyzeCookies([], targetUrl);
        sendResponse({ success: false, cookieAnalysis: fallback });
      })();
      return true;
    }

    // Settings queries
    case 'GET_SETTINGS': {
      getSettings().then(settings => sendResponse({ settings }));
      return true;
    }

    case 'SAVE_SETTINGS': {
      chrome.storage.local.set({ veridex_settings: message.settings }, () => {
        sendResponse({ success: true });
      });
      return true;
    }

    // Open standalone Veridex AI website in a new tab
    case 'OPEN_WEBSITE': {
      let targetUrl = message.url || '';
      let siteUrl = chrome.runtime.getURL('website/index.html');
      if (targetUrl && (targetUrl.startsWith('http://') || targetUrl.startsWith('https://'))) {
        siteUrl += `?url=${encodeURIComponent(targetUrl)}`;
      }
      chrome.tabs.create({ url: siteUrl });
      sendResponse({ success: true, url: siteUrl });
      return true;
    }
  }
});
