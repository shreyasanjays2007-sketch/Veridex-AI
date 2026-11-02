const { VeridexEngine } = require('./engine/veridex-engine.js');

async function probeUrlLive(urlString) {
  let cleanUrl = urlString.trim();
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'https://' + cleanUrl;
  }

  let networkSignals = {
    reachable: false,
    statusCode: null,
    finalUrl: cleanUrl,
    redirected: false,
    hasHsts: false,
    hasCsp: false,
    hasFrameOptions: false,
    isParked: false,
    dom: {
      hasPasswordField: false,
      hasCreditCardField: false,
      externalFormActions: [],
      pageTitle: '',
      hasUrgencyPatterns: false
    }
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(cleanUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VeridexAI/1.0'
      },
      signal: controller.signal
    });

    clearTimeout(timeout);
    networkSignals.reachable = true;
    networkSignals.statusCode = res.status;
    networkSignals.finalUrl = res.url;
    networkSignals.redirected = res.url !== cleanUrl;

    // Check security headers
    networkSignals.hasHsts = res.headers.has('strict-transport-security');
    networkSignals.hasCsp = res.headers.has('content-security-policy');
    networkSignals.hasFrameOptions = res.headers.has('x-frame-options');

    // Read initial HTML text (up to 40KB)
    const text = await res.text();
    const htmlSlice = text.slice(0, 40000);

    // Extract title
    const titleMatch = htmlSlice.match(/<title[^>]*>([^<]+)<\/title>/i);
    if (titleMatch) {
      networkSignals.dom.pageTitle = titleMatch[1].trim();
    }

    // Check if domain is parked / for sale
    const lowerHtml = htmlSlice.toLowerCase();
    const parkingKeywords = ['domain is for sale', 'buy this domain', 'is parked', 'parking-render', 'aftermarket.com', 'sedoparking', 'godaddy.com/domainsearch'];
    if (parkingKeywords.some(kw => lowerHtml.includes(kw))) {
      networkSignals.isParked = true;
    }

    // Check for password inputs
    if (/<input[^>]+type=["']?password["']?/i.test(htmlSlice)) {
      networkSignals.dom.hasPasswordField = true;
    }

    // Check for credit card inputs
    if (/<input[^>]+(?:name|autocomplete|id)=["']?[^"']*(?:card|cc-num|cvv)[^"']*/i.test(htmlSlice)) {
      networkSignals.dom.hasCreditCardField = true;
    }

    // Check form actions
    const formMatches = [...htmlSlice.matchAll(/<form[^>]+action=["']([^"']+)["']/gi)];
    for (const fm of formMatches) {
      try {
        const dest = new URL(fm[1], res.url);
        if (dest.hostname && dest.hostname !== new URL(res.url).hostname) {
          networkSignals.dom.externalFormActions.push(dest.hostname);
        }
      } catch (e) {}
    }

  } catch (err) {
    networkSignals.reachable = false;
    networkSignals.error = err.message;
  }

  return networkSignals;
}

(async () => {
  console.log("=== TESTING LIVE NETWORK & CONTENT PROBING ===");
  const testList = ['www.scam.com', 'https://www.google.co.in', 'https://en.wikipedia.org/wiki/Scam'];

  for (const item of testList) {
    console.log(`\nProbing: ${item}...`);
    const probe = await probeUrlLive(item);
    console.log(`- Reachable: ${probe.reachable} (Status: ${probe.statusCode})`);
    console.log(`- Final URL: ${probe.finalUrl}`);
    console.log(`- Parked Domain: ${probe.isParked}`);
    console.log(`- Security Headers: HSTS=${probe.hasHsts}, CSP=${probe.hasCsp}`);
    console.log(`- Page Title: "${probe.dom.pageTitle}"`);
  }
})();
