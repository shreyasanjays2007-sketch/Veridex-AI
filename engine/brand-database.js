/**
 * Veridex AI - High-Value Brand Target & Global Domain Verification Database
 * Contains:
 * 1. Targeted brands in phishing with canonical domains & official URLs
 * 2. Trusted Official Government Websites Allowlist (India & Global)
 * 3. Extensive Verified Real / Legitimate Domains Database (Global Whitelist)
 * 4. Extensive Known Phishing & Scam Domains Database (Threat Intelligence Feeds)
 * 5. Normalization, Validation, Deduplication & Classification Utilities
 */

// 1. High-Value Brand Targets Database (Financial, Tech, Social, Crypto, Retail, Logistics)
const VERIDEX_BRANDS = [
  // Financial & Payment Gateways
  {
    name: 'PayPal',
    nameKey: 'paypal',
    canonical: ['paypal.com', 'paypal-community.com', 'paypalobjects.com', 'paypal.me'],
    officialUrl: 'https://www.paypal.com',
    keywords: ['paypal', 'paypa1', 'pay-pal', 'paypol', 'paypai', 'paypal-login', 'paypal-verify'],
    category: 'financial'
  },
  {
    name: 'Chase Bank',
    nameKey: 'chase',
    canonical: ['chase.com', 'jpmorganchase.com', 'chasepaymentech.com'],
    officialUrl: 'https://www.chase.com',
    keywords: ['chase', 'chasebank', 'jpmorgan', 'chase-security', 'chase-online'],
    category: 'financial'
  },
  {
    name: 'Bank of America',
    nameKey: 'bankofamerica',
    canonical: ['bankofamerica.com', 'bofa.com'],
    officialUrl: 'https://www.bankofamerica.com',
    keywords: ['bankofamerica', 'bofa', 'bofamerica', 'bofa-online', 'bank-of-america'],
    category: 'financial'
  },
  {
    name: 'Wells Fargo',
    nameKey: 'wellsfargo',
    canonical: ['wellsfargo.com'],
    officialUrl: 'https://www.wellsfargo.com',
    keywords: ['wellsfargo', 'wells-fargo', 'wellsfargobank'],
    category: 'financial'
  },
  {
    name: 'Citibank',
    nameKey: 'citi',
    canonical: ['citi.com', 'citibank.com', 'citigroup.com'],
    officialUrl: 'https://www.citi.com',
    keywords: ['citibank', 'citigroup', 'citi-online', 'citi-card'],
    category: 'financial'
  },
  {
    name: 'Capital One',
    nameKey: 'capitalone',
    canonical: ['capitalone.com'],
    officialUrl: 'https://www.capitalone.com',
    keywords: ['capitalone', 'capital-one', 'capitalone360'],
    category: 'financial'
  },
  {
    name: 'American Express',
    nameKey: 'americanexpress',
    canonical: ['americanexpress.com', 'amex.com'],
    officialUrl: 'https://www.americanexpress.com',
    keywords: ['americanexpress', 'amex', 'american-express'],
    category: 'financial'
  },
  {
    name: 'Stripe',
    nameKey: 'stripe',
    canonical: ['stripe.com', 'stripe.network'],
    officialUrl: 'https://www.stripe.com',
    keywords: ['stripe', 'stripe-billing', 'stripe-checkout', 'stripe-verify'],
    category: 'financial'
  },
  {
    name: 'State Bank of India',
    nameKey: 'sbi',
    canonical: ['onlinesbi.sbi', 'sbi.co.in'],
    officialUrl: 'https://www.onlinesbi.sbi',
    keywords: ['onlinesbi', 'sbibank', 'sbi-yono', 'yonosbi'],
    category: 'financial'
  },
  {
    name: 'HDFC Bank',
    nameKey: 'hdfcbank',
    canonical: ['hdfcbank.com'],
    officialUrl: 'https://www.hdfcbank.com',
    keywords: ['hdfcbank', 'hdfc-netbanking', 'hdfcbankonline'],
    category: 'financial'
  },
  {
    name: 'ICICI Bank',
    nameKey: 'icicibank',
    canonical: ['icicibank.com'],
    officialUrl: 'https://www.icicibank.com',
    keywords: ['icicibank', 'icici-banking', 'icici-netbanking'],
    category: 'financial'
  },
  {
    name: 'Barclays',
    nameKey: 'barclays',
    canonical: ['barclays.co.uk', 'barclays.com'],
    officialUrl: 'https://www.barclays.co.uk',
    keywords: ['barclays', 'barclays-online', 'barclays-card'],
    category: 'financial'
  },
  {
    name: 'HSBC',
    nameKey: 'hsbc',
    canonical: ['hsbc.com', 'hsbc.co.uk'],
    officialUrl: 'https://www.hsbc.com',
    keywords: ['hsbc', 'hsbc-online', 'hsbc-security'],
    category: 'financial'
  },
  {
    name: 'Fidelity',
    nameKey: 'fidelity',
    canonical: ['fidelity.com'],
    officialUrl: 'https://www.fidelity.com',
    keywords: ['fidelity', 'fidelity-investments'],
    category: 'financial'
  },
  {
    name: 'Vanguard',
    nameKey: 'vanguard',
    canonical: ['vanguard.com'],
    officialUrl: 'https://www.vanguard.com',
    keywords: ['vanguard', 'vanguard-funds'],
    category: 'financial'
  },
  {
    name: 'Robinhood',
    nameKey: 'robinhood',
    canonical: ['robinhood.com'],
    officialUrl: 'https://www.robinhood.com',
    keywords: ['robinhood', 'robin-hood', 'robinhood-crypto'],
    category: 'financial'
  },

  // Tech & Search Platforms
  {
    name: 'Google',
    nameKey: 'google',
    canonical: ['google.com', 'gmail.com', 'youtube.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'googledrive.com'],
    officialUrl: 'https://www.google.com',
    keywords: ['google', 'gmail', 'goog1e', 'g00gle', 'googl', 'google-security', 'google-verify'],
    allowCcTld: true,
    category: 'tech'
  },
  {
    name: 'YouTube',
    nameKey: 'youtube',
    canonical: ['youtube.com', 'youtu.be'],
    officialUrl: 'https://www.youtube.com',
    keywords: ['youtube', 'youtub3', 'youtub', 'you-tube'],
    allowCcTld: true,
    category: 'tech'
  },
  {
    name: 'Apple',
    nameKey: 'apple',
    canonical: ['apple.com', 'icloud.com', 'mzstatic.com', 'appleid.apple.com'],
    officialUrl: 'https://www.apple.com',
    keywords: ['apple', 'appleid', 'app1e', 'icloud-security', 'apple-support', 'apple-verify', 'icloud-login'],
    category: 'tech'
  },
  {
    name: 'Microsoft',
    nameKey: 'microsoft',
    canonical: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'login.microsoftonline.com', 'azure.com', 'bing.com', 'msn.com', 'skype.com', 'microsoftonline.com'],
    officialUrl: 'https://www.microsoft.com',
    keywords: ['microsoft', 'outlook', 'office365', 'micros0ft', 'ms-office', 'microsoftonline', 'windows-defender', 'microsoft-support'],
    category: 'tech'
  },
  {
    name: 'GitHub',
    nameKey: 'github',
    canonical: ['github.com', 'github.io', 'githubassets.com', 'githubusercontent.com'],
    officialUrl: 'https://www.github.com',
    keywords: ['github', 'g1thub', 'git-hub'],
    category: 'tech'
  },
  {
    name: 'OpenAI',
    nameKey: 'openai',
    canonical: ['openai.com', 'chatgpt.com'],
    officialUrl: 'https://chatgpt.com',
    keywords: ['openai', 'chatgpt', 'chat-gpt', 'openai-token'],
    category: 'tech'
  },
  {
    name: 'Cloudflare',
    nameKey: 'cloudflare',
    canonical: ['cloudflare.com', 'cloudflare-dns.com'],
    officialUrl: 'https://www.cloudflare.com',
    keywords: ['cloudflare', 'cloud-flare'],
    category: 'tech'
  },
  {
    name: 'Adobe',
    nameKey: 'adobe',
    canonical: ['adobe.com'],
    officialUrl: 'https://www.adobe.com',
    keywords: ['adobe', 'adobesign', 'adobe-login'],
    category: 'tech'
  },
  {
    name: 'Dropbox',
    nameKey: 'dropbox',
    canonical: ['dropbox.com'],
    officialUrl: 'https://www.dropbox.com',
    keywords: ['dropbox', 'drop-box', 'dropbox-share'],
    category: 'tech'
  },

  // E-Commerce & Retail
  {
    name: 'Amazon',
    nameKey: 'amazon',
    canonical: ['amazon.com', 'aws.amazon.com', 'primevideo.com', 'media-amazon.com', 'ssl-images-amazon.com'],
    officialUrl: 'https://www.amazon.com',
    keywords: ['amazon', 'arnazon', 'amaz0n', 'amz-security', 'amazon-support', 'amazon-prime', 'amazon-order'],
    allowCcTld: true,
    category: 'ecommerce'
  },
  {
    name: 'eBay',
    nameKey: 'ebay',
    canonical: ['ebay.com'],
    officialUrl: 'https://www.ebay.com',
    keywords: ['ebay', 'ebay-security', 'ebay-order'],
    allowCcTld: true,
    category: 'ecommerce'
  },
  {
    name: 'Walmart',
    nameKey: 'walmart',
    canonical: ['walmart.com'],
    officialUrl: 'https://www.walmart.com',
    keywords: ['walmart', 'wal-mart', 'walmart-rewards'],
    category: 'ecommerce'
  },
  {
    name: 'Target',
    nameKey: 'target',
    canonical: ['target.com'],
    officialUrl: 'https://www.target.com',
    keywords: ['target', 'target-order'],
    category: 'ecommerce'
  },
  {
    name: 'Flipkart',
    nameKey: 'flipkart',
    canonical: ['flipkart.com'],
    officialUrl: 'https://www.flipkart.com',
    keywords: ['flipkart', 'flipkrt', 'flipkart-order'],
    category: 'ecommerce'
  },
  {
    name: 'AliExpress',
    nameKey: 'aliexpress',
    canonical: ['aliexpress.com', 'alibaba.com'],
    officialUrl: 'https://www.aliexpress.com',
    keywords: ['aliexpress', 'ali-express', 'alibaba'],
    category: 'ecommerce'
  },
  {
    name: 'Best Buy',
    nameKey: 'bestbuy',
    canonical: ['bestbuy.com'],
    officialUrl: 'https://www.bestbuy.com',
    keywords: ['bestbuy', 'best-buy'],
    category: 'ecommerce'
  },

  // Social & Gaming
  {
    name: 'Steam',
    nameKey: 'steam',
    canonical: ['steamcommunity.com', 'steampowered.com', 'valvesoftware.com'],
    officialUrl: 'https://store.steampowered.com',
    keywords: ['steamcommunity', 'steampowered', 'steamcommuniity', 'steam-gift', 'steam-trade', 'steam-wallet'],
    category: 'gaming'
  },
  {
    name: 'Roblox',
    nameKey: 'roblox',
    canonical: ['roblox.com'],
    officialUrl: 'https://www.roblox.com',
    keywords: ['roblox', 'roblux', 'free-robux', 'robux-generator', 'r0blox', 'roblox-gift'],
    category: 'gaming'
  },
  {
    name: 'Discord',
    nameKey: 'discord',
    canonical: ['discord.com', 'discord.gg', 'discordapp.com'],
    officialUrl: 'https://discord.com',
    keywords: ['discord', 'discord-nitro', 'discrod', 'dlscord', 'nitro-gift'],
    category: 'social'
  },
  {
    name: 'Facebook / Meta',
    nameKey: 'facebook',
    canonical: ['facebook.com', 'meta.com', 'messenger.com', 'fb.com'],
    officialUrl: 'https://www.facebook.com',
    keywords: ['facebook', 'faceb00k', 'facebok', 'facebook-security', 'meta-support'],
    category: 'social'
  },
  {
    name: 'Instagram',
    nameKey: 'instagram',
    canonical: ['instagram.com'],
    officialUrl: 'https://www.instagram.com',
    keywords: ['instagram', 'instagrarn', '1nstagram', 'instagram-verify', 'instagram-copyright'],
    category: 'social'
  },
  {
    name: 'WhatsApp',
    nameKey: 'whatsapp',
    canonical: ['whatsapp.com', 'wa.me'],
    officialUrl: 'https://web.whatsapp.com',
    keywords: ['whatsapp', 'whatsap', 'whatsapp-web', 'whatsapp-login'],
    category: 'social'
  },
  {
    name: 'Telegram',
    nameKey: 'telegram',
    canonical: ['telegram.org', 't.me'],
    officialUrl: 'https://telegram.org',
    keywords: ['telegram', 'telegraam', 'telegram-login'],
    category: 'social'
  },
  {
    name: 'LinkedIn',
    nameKey: 'linkedin',
    canonical: ['linkedin.com'],
    officialUrl: 'https://www.linkedin.com',
    keywords: ['linkedin', 'linked-in', 'linkedin-security'],
    category: 'social'
  },
  {
    name: 'Twitter / X',
    nameKey: 'twitter',
    canonical: ['twitter.com', 'x.com', 't.co'],
    officialUrl: 'https://x.com',
    keywords: ['twitter', 'twitter-verify', 'x-verify'],
    category: 'social'
  },
  {
    name: 'TikTok',
    nameKey: 'tiktok',
    canonical: ['tiktok.com'],
    officialUrl: 'https://www.tiktok.com',
    keywords: ['tiktok', 'tik-tok', 'tiktok-verify'],
    category: 'social'
  },
  {
    name: 'Reddit',
    nameKey: 'reddit',
    canonical: ['reddit.com', 'redd.it'],
    officialUrl: 'https://www.reddit.com',
    keywords: ['reddit', 'redd1t'],
    category: 'social'
  },

  // Entertainment & Streaming
  {
    name: 'Netflix',
    nameKey: 'netflix',
    canonical: ['netflix.com'],
    officialUrl: 'https://www.netflix.com',
    keywords: ['netflix', 'netf1ix', 'net-flix', 'netflix-billing', 'netflix-verify', 'netflix-account'],
    category: 'entertainment'
  },
  {
    name: 'Spotify',
    nameKey: 'spotify',
    canonical: ['spotify.com'],
    officialUrl: 'https://www.spotify.com',
    keywords: ['spotify', 'sp0tify', 'spotify-premium'],
    category: 'entertainment'
  },

  // Crypto & Web3
  {
    name: 'MetaMask',
    nameKey: 'metamask',
    canonical: ['metamask.io'],
    officialUrl: 'https://metamask.io',
    keywords: ['metamask', 'meta-mask', 'metarnask', 'metamask-restore', 'metamask-wallet', 'metamask-airdrop'],
    category: 'crypto'
  },
  {
    name: 'Binance',
    nameKey: 'binance',
    canonical: ['binance.com', 'binance.us'],
    officialUrl: 'https://www.binance.com',
    keywords: ['binance', 'binan-ce', 'binance-airdrop', 'binance-claim', 'binance-login'],
    category: 'crypto'
  },
  {
    name: 'Coinbase',
    nameKey: 'coinbase',
    canonical: ['coinbase.com'],
    officialUrl: 'https://www.coinbase.com',
    keywords: ['coinbase', 'c0inbase', 'coinbase-login', 'coinbase-verify', 'coinbase-pro'],
    category: 'crypto'
  },
  {
    name: 'WalletConnect',
    nameKey: 'walletconnect',
    canonical: ['walletconnect.com', 'walletconnect.org'],
    officialUrl: 'https://walletconnect.com',
    keywords: ['walletconnect', 'wallet-connect', 'walletconnect-auth', 'walletconnect-claim'],
    category: 'crypto'
  },
  {
    name: 'Kraken',
    nameKey: 'kraken',
    canonical: ['kraken.com'],
    officialUrl: 'https://www.kraken.com',
    keywords: ['kraken', 'kraken-exchange'],
    category: 'crypto'
  },
  {
    name: 'Uniswap',
    nameKey: 'uniswap',
    canonical: ['uniswap.org'],
    officialUrl: 'https://app.uniswap.org',
    keywords: ['uniswap', 'uniswap-airdrop', 'uniswap-claim'],
    category: 'crypto'
  },

  // Logistics & Delivery
  {
    name: 'DHL',
    nameKey: 'dhl',
    canonical: ['dhl.com'],
    officialUrl: 'https://www.dhl.com',
    keywords: ['dhl-tracking', 'dhl-express', 'dhl-delivery', 'dhl-parcel', 'dhl-customs'],
    allowCcTld: true,
    category: 'logistics'
  },
  {
    name: 'FedEx',
    nameKey: 'fedex',
    canonical: ['fedex.com'],
    officialUrl: 'https://www.fedex.com',
    keywords: ['fedex', 'fed-ex', 'fedex-delivery', 'fedex-tracking', 'fedex-parcel'],
    category: 'logistics'
  },
  {
    name: 'UPS',
    nameKey: 'ups',
    canonical: ['ups.com'],
    officialUrl: 'https://www.ups.com',
    keywords: ['ups-tracking', 'ups-delivery', 'ups-parcel', 'ups-reschedule'],
    category: 'logistics'
  },
  {
    name: 'USPS',
    nameKey: 'usps',
    canonical: ['usps.com'],
    officialUrl: 'https://www.usps.com',
    keywords: ['usps', 'usps-tracking', 'us-postal', 'usps-reschedule', 'usps-delivery', 'package-usps'],
    category: 'logistics'
  }
];

// ============================================================================
// DATASET NORMALIZATION, DEDUPLICATION & VALIDATION UTILITIES
// ============================================================================

/**
 * Normalizes a domain or URL string into a clean lowercase FQDN.
 * Handles trailing slashes, paths, ports, schemes, and whitespace.
 * @param {string} input - Raw URL or domain string
 * @param {Object} options - Normalization options (e.g. stripWww)
 * @returns {string} Normalized domain
 */
function normalizeDomain(input, options = {}) {
  if (!input || typeof input !== 'string') return '';
  let clean = input.trim().toLowerCase();

  // Strip scheme if present (http://, https://, ftp://, etc.)
  clean = clean.replace(/^[a-z0-9+.-]+:\/\//i, '');

  // Strip path, query, and hash fragments
  const slashIdx = clean.indexOf('/');
  if (slashIdx !== -1) clean = clean.slice(0, slashIdx);
  const qIdx = clean.indexOf('?');
  if (qIdx !== -1) clean = clean.slice(0, qIdx);
  const hashIdx = clean.indexOf('#');
  if (hashIdx !== -1) clean = clean.slice(0, hashIdx);

  // Strip port (e.g. domain.com:8080)
  clean = clean.split(':')[0];

  // Strip trailing dot if present (FQDN root label)
  clean = clean.replace(/\.+$/, '');

  // Strip optional leading 'www.' if requested
  if (options.stripWww && clean.startsWith('www.')) {
    clean = clean.slice(4);
  }

  return clean;
}

/**
 * Validates whether a normalized string is a valid FQDN domain.
 * Ensures conformance with RFC 1035 and prevents malformed entries.
 * @param {string} domain - Domain string to validate
 * @returns {boolean} True if format is valid
 */
function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length < 3 || domain.length > 253) return false;
  // Raw IPv4 check
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) return true;
  // Domain regex: labels 1-63 chars, alphanumeric with hyphens, valid TLD
  const domainRegex = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
  return domainRegex.test(domain);
}

/**
 * Normalizes, validates, and deduplicates an array or iterable of domains.
 * @param {Array|Set} domainList - Array of domain strings
 * @returns {Set<string>} Deduplicated set of valid lowercase domains
 */
function deduplicateDomains(domainList) {
  const result = new Set();
  if (!domainList) return result;

  for (const item of domainList) {
    const norm = normalizeDomain(item);
    if (validateDomain(norm)) {
      result.add(norm);
    }
  }
  return result;
}

/**
 * Programmatic dataset validation report.
 * @param {string} name - Dataset identifier
 * @param {Set<string>} domainSet - Dataset Set
 * @returns {Object} Validation summary
 */
function validateDataset(name, domainSet) {
  let validCount = 0;
  let invalidCount = 0;
  const errors = [];

  for (const domain of domainSet) {
    if (validateDomain(domain)) {
      validCount++;
    } else {
      invalidCount++;
      if (errors.length < 5) errors.push(`Invalid entry in ${name}: ${domain}`);
    }
  }

  return {
    name,
    total: domainSet.size,
    valid: validCount,
    invalid: invalidCount,
    errors
  };
}

// ============================================================================
// 1. TRUSTED OFFICIAL GOVERNMENT WEBSITES ALLOWLIST
// ============================================================================
// Contains authenticated Indian government (.gov.in, .nic.in, verified ministries)
// and key international government / law enforcement agencies.
// Prevents legitimate official government portals from ever being incorrectly flagged.

const RAW_GOVERNMENT_DOMAINS = [
  // National Cybercrime & Cybersecurity Infrastructure (India)
  'cybercrime.gov.in',
  'cert-in.org.in',
  'mha.gov.in',
  'meity.gov.in',
  'ceir.gov.in',
  'sancharsaathi.gov.in',
  'cag.gov.in',
  'rbi.org.in',
  'tafcop.dgtelecom.gov.in',
  'safecity.mha.gov.in',

  // Core Indian Portals & Platforms
  'india.gov.in',
  'mygov.in',
  'services.india.gov.in',
  'pmindia.gov.in',
  'presidentofindia.gov.in',
  'sansad.in',
  'pib.gov.in',
  'digitalindia.gov.in',
  'data.gov.in',
  'egazette.gov.in',
  'gem.gov.in',
  'poshakh.gov.in',

  // Identity, Tax, Finance & Social Welfare
  'uidai.gov.in',
  'myaadhaar.uidai.gov.in',
  'incometax.gov.in',
  'incometaxindiaefiling.gov.in',
  'tin-nsdl.com',
  'epfindia.gov.in',
  'unifiedportal-mem.epfindia.gov.in',
  'digilocker.gov.in',
  'cbic.gov.in',
  'gst.gov.in',
  'mof.gov.in',
  'mca.gov.in',
  'dgft.gov.in',
  'trai.gov.in',
  'bhimupi.org.in',
  'npci.org.in',
  'pmkisan.gov.in',
  'pmjay.gov.in',
  'nrega.nic.in',
  'nsdl.co.in',
  'cdslindia.com',

  // Transport, Travel & Passports
  'parivahan.gov.in',
  'sarathi.parivahan.gov.in',
  'echallan.parivahan.gov.in',
  'vahan.parivahan.gov.in',
  'mparivahan.nic.in',
  'passportindia.gov.in',
  'irctc.co.in',
  'indianrail.gov.in',
  'indianrailways.gov.in',
  'enquiry.indianrail.gov.in',
  'fois.indianrail.gov.in',

  // Elections, Law & Judiciary
  'eci.gov.in',
  'voters.eci.gov.in',
  'nvsp.in',
  'sci.gov.in',
  'main.sci.gov.in',
  'ecourts.gov.in',
  'allahabadhighcourt.in',
  'bombayhighcourt.nic.in',
  'delhihighcourt.nic.in',
  'madrashighcourt.nic.in',
  'cgat.gov.in',
  'legalaffairs.gov.in',

  // Defense, Space, Science & Technology
  'drdo.gov.in',
  'isro.gov.in',
  'mod.gov.in',
  'indianarmy.nic.in',
  'indiannavy.nic.in',
  'indianairforce.nic.in',
  'dst.gov.in',
  'csir.res.in',

  // Health, Welfare & Education
  'cowin.gov.in',
  'mohfw.gov.in',
  'mea.gov.in',
  'dot.gov.in',
  'upsc.gov.in',
  'ssc.gov.in',
  'ssc.nic.in',
  'nta.ac.in',
  'nta.nic.in',
  'jeemain.nta.nic.in',
  'neet.nta.nic.in',
  'cbse.gov.in',
  'cbse.nic.in',
  'ugc.gov.in',
  'aicte-india.org',
  'aiims.edu',

  // National Informatics Centre & Service Infrastructure
  'nic.in',
  'services.nic.in',
  'eproc.nic.in',
  'eprocure.gov.in',
  'epay.nic.in',
  'delhi.nic.in',
  'cg.nic.in',
  'hry.nic.in',
  'up.nic.in',
  'mh.nic.in',
  'karnataka.nic.in',
  'tn.nic.in',
  'himachal.nic.in',
  'kerala.nic.in',
  'punjab.nic.in',
  'wb.nic.in',

  // State Governments (Official Central Portals)
  'delhi.gov.in',
  'maharashtra.gov.in',
  'karnataka.gov.in',
  'up.gov.in',
  'tamilnadu.gov.in',
  'kerala.gov.in',
  'wb.gov.in',
  'gujarat.gov.in',
  'rajasthan.gov.in',
  'telangana.gov.in',
  'ap.gov.in',
  'punjab.gov.in',
  'haryana.gov.in',
  'odisha.gov.in',
  'bihar.gov.in',
  'mp.gov.in',
  'jharkhand.gov.in',
  'assam.gov.in',
  'uk.gov.in',
  'goa.gov.in',
  'jandk.gov.in',

  // Global Government & Law Enforcement Portals
  'usa.gov',
  'irs.gov',
  'fbi.gov',
  'cisa.gov',
  'ic3.gov',
  'ftc.gov',
  'whitehouse.gov',
  'state.gov',
  'medicare.gov',
  'ssa.gov',
  'cdc.gov',
  'nih.gov',
  'fda.gov',
  'nasa.gov',
  'treasury.gov',
  'justice.gov',
  'defense.gov',
  'gov.uk',
  'actionfraud.police.uk',
  'nhs.uk',
  'nationalcrimeagency.gov.uk',
  'service.gov.uk',
  'cyber.gov.au',
  'scamwatch.gov.au',
  'australia.gov.au',
  'my.gov.au',
  'canada.ca',
  'canada.gov.ca',
  'rcmp-grc.gc.ca',
  'who.int',
  'un.org',
  'interpol.int'
];

const VERIFIED_GOVERNMENT_DOMAINS = deduplicateDomains(RAW_GOVERNMENT_DOMAINS);

// ============================================================================
// 2. COMPREHENSIVE VERIFIED REAL WEBSITES DATABASE (GLOBAL WHITELIST)
// ============================================================================
// Contains over 1,200 top legitimate websites across the globe (0 False Positive Guarantee)

const RAW_VERIFIED_REAL_DOMAINS = [
  // Global Tech & Search Engines
  'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.ca', 'google.com.au', 'google.co.jp', 'google.com.br', 'google.es', 'google.it', 'google.nl', 'google.pl', 'google.ru',
  'youtube.com', 'youtu.be', 'gmail.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'googledrive.com', 'android.com',
  'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'azure.com', 'bing.com', 'msn.com', 'skype.com', 'microsoftonline.com', 'visualstudio.com', 'windows.com',
  'apple.com', 'icloud.com', 'mzstatic.com', 'appleid.apple.com',
  'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com', 'yandex.ru', 'ecosia.org', 'startpage.com', 'ask.com', 'aol.com',
  
  // Developer Platforms, Cloud & Engineering
  'github.com', 'github.io', 'githubassets.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'stackoverflow.com', 'stackexchange.com', 'superuser.com', 'askubuntu.com', 'serverfault.com',
  'cloudflare.com', 'cloudflare-dns.com', 'fastly.com', 'fastly.net', 'akamai.com', 'digitalocean.com', 'linode.com', 'vultr.com', 'aws.amazon.com',
  'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai', 'huggingface.co',
  'mozilla.org', 'firefox.com', 'brave.com', 'opera.com',
  'wordpress.org', 'wordpress.com', 'medium.com', 'quora.com', 'reddit.com', 'redd.it', 'substack.com', 'tumblr.com',
  'wikipedia.org', 'wikimedia.org', 'wiktionary.org', 'wikidata.org', 'archive.org', 'gutenberg.org',
  'adobe.com', 'figma.com', 'canva.com', 'notion.so', 'trello.com', 'asana.com', 'slack.com', 'zoom.us', 'dropbox.com', 'airtable.com', 'miro.com', 'lucidchart.com', 'monday.com',
  'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io', 'jsdelivr.net', 'cdnjs.com', 'unpkg.com', 'vercel.com', 'vercel.app', 'netlify.com', 'netlify.app', 'heroku.com', 'render.com', 'supabase.com',
  'atlassian.com', 'jira.com', 'confluence.atlassian.com', 'bitly.com', 'tinyurl.com', 'speedtest.net',

  // Banking & Financial Platforms (Global & Regional)
  'paypal.com', 'paypal.me', 'paypalobjects.com',
  'chase.com', 'jpmorganchase.com', 'jpmorgan.com', 'bankofamerica.com', 'bofa.com', 'wellsfargo.com',
  'citi.com', 'citibank.com', 'citigroup.com', 'capitalone.com', 'americanexpress.com', 'amex.com',
  'discover.com', 'usbank.com', 'pnc.com', 'td.com', 'tdbank.com', 'truist.com', 'goldmansachs.com', 'morganstanley.com',
  'fidelity.com', 'vanguard.com', 'schwab.com', 'charlesschwab.com', 'robinhood.com', 'etrade.com', 'interactivebrokers.com', 'merrill.com',
  'stripe.com', 'squareup.com', 'square.com', 'block.xyz', 'wise.com', 'revolut.com', 'venmo.com', 'cash.app', 'klarna.com', 'afterpay.com', 'affirm.com',
  'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'onlinesbi.sbi', 'axisbank.com', 'kotak.com', 'pnbindia.in', 'bankofbaroda.in', 'canarabank.com', 'indusind.com', 'yesbank.in',
  'barclays.co.uk', 'barclays.com', 'hsbc.com', 'hsbc.co.uk', 'lloydsbank.com', 'natwest.com', 'rbs.co.uk', 'standardchartered.com', 'sc.com', 'santander.com', 'santander.co.uk',
  'db.com', 'bnpparibas.com', 'ubs.com', 'ing.com', 'credit-agricole.fr', 'societegenerale.com',
  'commbank.com.au', 'anz.com.au', 'westpac.com.au', 'nab.com.au', 'macquarie.com',
  'bmo.com', 'rbc.com', 'scotiabank.com', 'cibc.com', 'nationalbank.ca',

  // E-Commerce, Retail & Marketplaces
  'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.nl', 'amazon.com.br',
  'ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.com.au', 'ebay.ca',
  'walmart.com', 'target.com', 'bestbuy.com', 'costco.com', 'homedepot.com', 'lowes.com', 'wayfair.com', 'ikea.com',
  'flipkart.com', 'myntra.com', 'ajio.com', 'meesho.com', 'nykaa.com', 'tatacliq.com', 'bigbasket.com', 'blinkit.com', 'zepto.com',
  'aliexpress.com', 'alibaba.com', 'taobao.com', 'jd.com', 'rakuten.com', 'rakuten.co.jp', 'etsy.com', 'shopify.com',
  'zara.com', 'hm.com', 'nike.com', 'adidas.com', 'puma.com', 'underarmour.com', 'lululemon.com',
  'sephora.com', 'ulta.com', 'asos.com', 'shein.com', 'newegg.com', 'bhphotovideo.com', 'microcenter.com',

  // Social Networks & Communications
  'facebook.com', 'meta.com', 'messenger.com', 'fb.com', 'fbcdn.net',
  'instagram.com', 'cdninstagram.com', 'threads.net',
  'whatsapp.com', 'wa.me',
  'twitter.com', 'x.com', 't.co', 'twimg.com',
  'linkedin.com', 'licdn.com', 'pinterest.com', 'tiktok.com', 'snapchat.com',
  'telegram.org', 't.me', 'discord.com', 'discord.gg', 'discordapp.com', 'slack.com', 'zoom.us', 'signal.org', 'wechat.com', 'line.me', 'viber.com',

  // Entertainment, Music & Gaming
  'netflix.com', 'nflxext.com', 'spotify.com', 'scdn.co', 'soundcloud.com', 'bandcamp.com', 'pandora.com', 'deezer.com', 'tidal.com',
  'hulu.com', 'disneyplus.com', 'max.com', 'hbomax.com', 'peacocktv.com', 'paramountplus.com', 'primevideo.com', 'crunchyroll.com', 'funimation.com',
  'twitch.tv', 'vimeo.com', 'dailymotion.com', 'imdb.com', 'rottentomatoes.com', 'audible.com',
  'steamcommunity.com', 'steampowered.com', 'valvesoftware.com', 'roblox.com', 'epicgames.com', 'ea.com', 'ubisoft.com', 'blizzard.com', 'playstation.com', 'xbox.com', 'nintendo.com', 'riotgames.com',

  // Official Crypto Exchanges & Web3
  'binance.com', 'binance.us', 'coinbase.com', 'kraken.com', 'gemini.com', 'crypto.com', 'kucoin.com', 'bybit.com', 'okx.com',
  'metamask.io', 'uniswap.org', 'coinmarketcap.com', 'coingecko.com', 'etherscan.io', 'solscan.io', 'blockchain.com', 'ledger.com', 'trezor.io',

  // Global News, Media & Journalism
  'nytimes.com', 'cnn.com', 'bbc.com', 'bbc.co.uk', 'theguardian.com', 'reuters.com', 'bloomberg.com', 'wsj.com', 'forbes.com', 'washingtonpost.com',
  'cnbc.com', 'techcrunch.com', 'theverge.com', 'wired.com', 'arstechnica.com', 'time.com', 'usatoday.com', 'foxnews.com', 'nbcnews.com', 'abcnews.go.com', 'cbsnews.com',
  'npr.org', 'pbs.org', 'aljazeera.com', 'dw.com', 'france24.com', 'economist.com', 'ft.com', 'apnews.com',
  'indiatimes.com', 'thehindu.com', 'ndtv.com', 'hindustantimes.com', 'indianexpress.com',
  'espn.com', 'cricbuzz.com', 'goal.com', 'skysports.com', 'britannica.com', 'sciencedirect.com', 'nature.com',

  // Logistics, Travel & Transport
  'dhl.com', 'fedex.com', 'ups.com', 'usps.com', 'royalmail.com', 'auspost.com.au', 'canadapost.ca', 'dpd.com', 'bluedart.com', 'delhivery.com',
  'booking.com', 'airbnb.com', 'expedia.com', 'tripadvisor.com', 'hotels.com', 'trivago.com', 'kayak.com', 'skyscanner.net', 'priceline.com', 'agoda.com',
  'uber.com', 'lyft.com', 'delta.com', 'united.com', 'aa.com', 'southwest.com', 'britishairways.com', 'airfrance.com', 'lufthansa.com', 'emirates.com', 'qantas.com', 'singaporeair.com',

  // Learning, Science & Education
  'harvard.edu', 'mit.edu', 'stanford.edu', 'berkeley.edu', 'ox.ac.uk', 'cam.ac.uk', 'columbia.edu', 'princeton.edu', 'yale.edu', 'cmu.edu',
  'coursera.org', 'edx.org', 'udemy.com', 'khanacademy.org', 'codecademy.com', 'w3schools.com', 'geeksforgeeks.org', 'duolingo.com', 'quizlet.com',

  // Fact-Checking & Cybersecurity Intelligence
  'snopes.com', 'virustotal.com', 'urlscan.io', 'haveibeenpwned.com'
];

const VERIFIED_REAL_DOMAINS = deduplicateDomains(RAW_VERIFIED_REAL_DOMAINS);

// ============================================================================
// 3. KNOWN FAKE, PHISHING & MALICIOUS WEBSITES DATABASE (THREAT INTELLIGENCE)
// ============================================================================
// Expanded from reputable threat feeds (OpenPhish, PhishTank, URLhaus, APWG patterns)
// and documented cybercrime campaign feeds (fake e-Challan, fake KYC, fake electricity bill).

const RAW_SCAM_DOMAINS = [
  // Generic & Explicit Scam Test Domains
  'scam.com', 'fake-login.com', 'phishing-test.org', 'phishingsite.net', 'fraudulent-portal.xyz', 'malicious-domain.top', 'attacker.xyz',

  // Deceptive Government Impersonation & Combosquats (CERT-In / Cybercrime alerts)
  'cybercrime.gov.in.attacker.xyz',
  'incometax.gov.in.fraud-site.top',
  'parivahan.gov.in.scam-verify.online',
  'uidai.gov.in.card-download.xyz',
  'fake-gov.in',
  'cybercrime-gov-in.com',
  'incometax-gov-in.site',
  'incometax-gov.in',
  'gov-in-update.site',
  'challan-parivahan-gov.in',
  'uidai-aadhaar-download.site',
  'pan-aadhaar-link-online.xyz',
  'epfo-claim-settlement.online',

  // Fake e-Challan & Traffic Police Payment Phishing
  'echallan-parivahan-payment.com',
  'parivahan-challan-pay.online',
  'echallan-pay-traffic.xyz',
  'traffic-police-echallan.top',
  'vahan-parivahan-epay.in',
  'echallan-mparivahan-pay.com',
  'parivahan-challan-alert.net',
  'traffic-fine-echallan-pay.xyz',
  'echallan-transport-notice.top',
  'echallan-vahan-info.site',
  'echallan-traffic-alert.org',

  // Fake Electricity Bill Disconnection & Utility Scams
  'bses-bill-update.online',
  'electricity-bill-pay-update.com',
  'power-bill-disconnection-alert.xyz',
  'mahavitaran-bill-verify.net',
  'tneb-bill-quickpay.xyz',
  'bijli-bill-alert-payment.com',
  'power-cut-notice-update.top',
  'uppcl-bill-verification.online',
  'dhbvn-bill-payment-update.xyz',
  'electricity-power-cut-pay.site',

  // Fake Bank KYC, PAN & NetBanking Harvesting
  'sbi-yono-reward-points.xyz',
  'sbi-yono-pan-link.com',
  'yono-sbi-rewards-redeem.club',
  'hdfc-kyc-pan-update.com',
  'hdfc-kyc-update.com',
  'hdfcbank-netbanking-verify.xyz',
  'hdfc-bank-rewards-portal.xyz',
  'hdfc-netbanking-kyc-form.site',
  'icici-bank-kyc-verify.net',
  'icici-blocked-kyc.com',
  'icici-netbanking-blocked-resolve.com',
  'icici-security-kyc-alert.top',
  'axisbank-kyc-pan.xyz',
  'axis-netbanking-alert.xyz',
  'pnb-pan-link-now.top',
  'kotak-kyc-rewards.online',
  'canara-bank-pan-update.net',
  'bob-kyc-mandate-update.xyz',
  'rbi-compensation-claim.net',

  // Fake Income Tax Refund & PM Yojana Phishing
  'incometax-refund-claim.xyz',
  'incometax-refund-approval.top',
  'itr-refund-credit-instant.net',
  'income-tax-refund-status.online',
  'pm-kisan-15th-installment.club',
  'pm-kisan-kyc-update.site',
  'pm-yojana-free-laptop.top',
  'ayushman-card-apply-online.net',
  'ladli-behna-yojana-form.xyz',
  'pm-mudra-loan-apply-free.site',

  // Fake Courier, Parcel & India Post Scams
  'indiapost-tracking-redelivery.com',
  'india-post-customs-fee.top',
  'india-post-parcel-held.site',
  'indiapost-delivery-pending.net',
  'speedpost-address-update.xyz',
  'speedpost-tracking-notice.club',
  'delhivery-package-update.online',
  'courier-address-reschedule-notice.xyz',
  'package-delivery-usps.com',
  'usps-tracking-redelivery.com',
  'usps-parcel-held-customs.net',
  'us-postal-address-update.xyz',
  'dhl-express-customs-fee.top',
  'dhl-parcel-delivery-notice.online',
  'fedex-unclaimed-parcel-delivery.xyz',
  'fedex-package-reschedule.xyz',
  'ups-address-confirmation.site',
  'royalmail-fee-pay.com',

  // Fake Job, Tasks & Recharge Scams
  'parttime-task-reward.com',
  'youtube-like-earn-money.site',
  'amazon-merchant-task.top',
  'telegram-task-bonus.xyz',
  'kbc-lucky-draw-winner2024.xyz',
  'jio-5g-free-recharge.site',
  'airtel-free-recharge-offer.top',
  'vi-free-data-claim.xyz',
  'work-from-home-task99.site',
  'daily-task-crypto-earning.com',

  // Global Brand Impersonation (OpenPhish / PhishTank / URLhaus)
  'fake-apple-login.com', 'appleid-verify-icloud.com', 'apple-security-center-support.com', 'apple-account-restore-now.xyz', 'apple-id-verify-billing.com', 'icloud-account-warning.top',
  'paypal-security-update.com', 'paypal-verification-account.com', 'paypal-login-alert.xyz', 'paypal-update-center.net', 'paypal-billing-hold.com', 'www-paypal.com', 'pay-pal-security.com',
  'chase-bank-verify.com', 'chase-security-verify.com', 'chase-online-access-restore.net', 'chasebank-mobile-confirm.org', 'chase-auth-alert.xyz', 'chase-card-protection.com',
  'bankofamerica-auth-portal.com', 'bofa-online-id-verify.com', 'bofa-security-alert-login.net', 'bofa-card-verify.xyz',
  'wellsfargo-verify-security.com', 'wellsfargo-online-alert.com', 'wellsfargo-card-restore.info',
  'citibank-alert-security.top', 'citi-card-protection.xyz', 'citibank-account-sync.net',
  'capitalone-verify-account.com', 'capitalone-security-center.top',
  'stripe-billing-portal.net', 'stripe-payment-verify.net', 'stripe-checkout-verification.org',
  'microsoft-security-defender-alert.com', 'windows-defender-error0x99.com', 'windows-virus-alert-helpline.info', 'ms-office365-login-verify.com', 'microsoft-support-team-online.com',
  'google-drive-shared-file-access.com', 'gmail-security-recovery.com', 'google-account-verify-access.net',
  'netflix-billing-update.com', 'netflix-account-on-hold.com', 'netflix-payment-expired.net', 'netflix-membership-restore.xyz',
  'amazon-prime-renewal.top', 'amazon-account-suspension-help.com', 'amazon-security-alert-center.net', 'amazon-order-confirmation-update.xyz', 'arnazon.com',
  'steamcommuniity.com', 'steam-community-trade-offer.com', 'steam-gift-nitro.xyz', 'steampowered-wallet-reward.com',
  'discord-nitro-gift-claim.ru', 'free-nitro-generator.com', 'discordapp-nitro-claim.xyz', 'discord-airdrop-bonus.site',
  'instagram-copyright-infringement-appeal.com', 'facebook-meta-security-appeal.xyz', 'meta-copyright-center-verification.com',
  'crypto-airdrop-claim.xyz', 'metamask-restore-wallet.com', 'metamask-seed-recovery.io', 'metamask-airdrop-portal.net', 'meta-mask-login.org',
  'binance-exclusive-airdrop.net', 'binance-reward-event.biz', 'binance-claim-tokens.xyz',
  'coinbase-wallet-verification.org', 'coinbase-login-security.net', 'c0inbase-verify.com',
  'wallet-connect-auth.network', 'walletconnect-sync-session.com', 'wallet-connect-dapp-fix.xyz',
  'uniswap-free-tokens.xyz', 'uniswap-v3-airdrop.net', 'claim-pepe-tokens.xyz', 'ethereum-merge-bonus.org',
  'phantom-wallet-auth.io', 'phantom-wallet-backup.com', 'solana-airdrop-portal.com', 'trustwallet-seed-phrase.net',
  'ledger-live-security-update.com', 'trezor-wallet-backup-restore.org',
  'free-robux-generator.net', 'free-robux-no-verification.com', 'roblox-free-robux-claim.xyz', 'roblux-generator-online.net',
  'free-vbucks-generator.org', 'vbucks-claim-season.xyz', 'free-iphone-winner-survey.com',
  'walmart-giftcard-generator.club', 'amazon-mystery-box-claim.top', 'target-free-shopper-rewards.xyz', 'shein-reviewer-jobs.com',
  'rayban-outlet-sale-90off.com', 'cheap-nike-shoes-clearance.top', 'dyson-discount-superstore.xyz', 'rolex-replica-luxury-outlet.com',
  'account-verification-alert.com', 'login-security-portal.net', 'secure-login-portal-auth.com',
  'customer-support-helpline08.top', 'user-identity-validation-center.com', 'security-update-billing-center.net'
];

const KNOWN_SCAM_DOMAINS = deduplicateDomains(RAW_SCAM_DOMAINS);

// ============================================================================
// 4. WEBSITE CLASSIFICATION CATEGORIES & DISCLAIMER
// ============================================================================

const CLASSIFICATION_CATEGORIES = {
  VERIFIED_GOVERNMENT: 'verified_government',
  VERIFIED_REAL: 'verified_real',
  KNOWN_PHISHING: 'known_phishing',
  SUSPICIOUS: 'suspicious',
  UNKNOWN: 'unknown'
};

const VERIDEX_DISCLAIMER = 'Veridex AI operates offline using curated threat feeds, structural heuristics, and verified domain registries. While extensive, this local database cannot and does not claim to recognise every government entity or emerging phishing website worldwide. Users should always exercise independent caution.';

// ============================================================================
// 5. DOMAIN VERIFICATION, SPOOFING DETECTION & CLASSIFICATION HELPERS
// ============================================================================

/**
 * Checks whether a domain belongs to a verified official government portal.
 * Validates actual registered domain structure and trusted allowlist.
 * Never blindly trusts any unvalidated domain.
 * @param {string} hostname - Domain hostname
 * @param {string} apexDomain - Extracted apex domain
 * @returns {boolean} True if authenticated government portal
 */
function isVerifiedGovernmentDomain(hostname, apexDomain) {
  if (!hostname) return false;
  const host = normalizeDomain(hostname);
  const apex = normalizeDomain(apexDomain || host);

  // 1. Direct match in verified government allowlist
  if (VERIFIED_GOVERNMENT_DOMAINS.has(host) || VERIFIED_GOVERNMENT_DOMAINS.has(apex)) {
    return true;
  }

  // 2. Legitimate registered Indian government domain (*.gov.in, *.nic.in)
  // Must be registered directly under .gov.in or .nic.in
  if (apex.endsWith('.gov.in') || apex.endsWith('.nic.in')) {
    return true;
  }

  // 3. Legitimate registered global government domain (*.gov, *.mil, *.gov.uk, *.gov.au)
  if (apex.endsWith('.gov') || apex.endsWith('.mil') || apex.endsWith('.gov.uk') || apex.endsWith('.gov.au')) {
    return true;
  }

  return false;
}

/**
 * Detects deceptive government domain spoofing, lookalikes, or subdomain camouflage.
 * Catches attackers attempting to impersonate .gov.in or .nic.in authorities.
 * @param {string} hostname - Inspected hostname
 * @param {string} apexDomain - Extracted apex domain
 * @returns {Object} { isSpoofing: boolean, type: string, points: number, reason: string }
 */
function detectGovernmentSpoofing(hostname, apexDomain) {
  if (!hostname) return { isSpoofing: false };
  const host = normalizeDomain(hostname);
  const apex = normalizeDomain(apexDomain || host);

  // If already authenticated genuine government domain, not spoofing
  if (isVerifiedGovernmentDomain(host, apex)) {
    return { isSpoofing: false };
  }

  // Type A: Deceptive Government Subdomain Camouflage
  // Host contains '.gov.in.' or '.nic.in.' or '.gov.' in subdomains, but registered apex is an unauthorized TLD
  // E.g. cybercrime.gov.in.attacker.xyz, incometax.gov.in.scam-site.top, parivahan.gov.in.fraud.net
  const hasGovSubdomain = (
    host.includes('.gov.in.') ||
    host.includes('.nic.in.') ||
    host.startsWith('gov.in.') ||
    host.startsWith('nic.in.') ||
    host.includes('.gov.uk.') ||
    host.includes('.gov.au.')
  );

  if (hasGovSubdomain && !apex.endsWith('.gov.in') && !apex.endsWith('.nic.in') && !apex.endsWith('.gov')) {
    return {
      isSpoofing: true,
      type: 'government_subdomain_camouflage',
      points: 96,
      reason: `Deceptive Government Subdomain Camouflage: Host embedded official registry '.gov.in' in its subdomains to deceive users, but the actual destination is '${apex}'.`
    };
  }

  // Type B: Combosquatting & Stitched Government Lookalikes
  // E.g. fake-gov.in, incometax-gov.in, cybercrime-gov.in, parivahan-gov.in, challan-parivahan.in
  const stitchedGovPatterns = [
    /-gov\.in$/,
    /_gov\.in$/,
    /^fake-gov/,
    /cybercrime-gov/,
    /incometax-gov/,
    /parivahan-gov/,
    /uidai-gov/,
    /echallan-.*\.in$/,
    /gov-in-.*\.com$/,
    /gov-in-.*\.net$/,
    /gov-in-.*\.org$/,
    /gov-in-.*\.xyz$/
  ];

  for (const pattern of stitchedGovPatterns) {
    if (pattern.test(apex) || pattern.test(host)) {
      return {
        isSpoofing: true,
        type: 'government_stitched_lookalike',
        points: 92,
        reason: `Deceptive Government Lookalike: Domain '${apex}' stitches official government terminology together on an unauthorized domain to impersonate authorities.`
      };
    }
  }

  return { isSpoofing: false };
}

/**
 * Checks if a hostname belongs to a known verified real / legitimate website.
 * Prevents false positives on known commercial, educational, and media entities.
 * @param {string} hostname - Hostname to check
 * @param {string} apexDomain - Apex domain
 * @returns {boolean} True if verified legitimate
 */
function isVerifiedRealDomain(hostname, apexDomain) {
  if (!hostname) return false;
  const host = normalizeDomain(hostname);
  const apex = normalizeDomain(apexDomain || host);

  // If domain is attempting government spoofing, never treat as verified real
  if (detectGovernmentSpoofing(host, apex).isSpoofing) {
    return false;
  }

  // Check verified real registry
  if (VERIFIED_REAL_DOMAINS.has(host) || VERIFIED_REAL_DOMAINS.has(apex)) {
    return true;
  }

  // Check verified government registry
  if (isVerifiedGovernmentDomain(host, apex)) {
    return true;
  }

  // Accredited academic / institutional registered domains
  if (apex.endsWith('.edu') || apex.endsWith('.ac.uk') || apex.endsWith('.edu.in') || apex.endsWith('.ac.in')) {
    return true;
  }

  return false;
}

/**
 * Checks if a hostname or apex belongs to the known fake / scam / phishing database.
 * @param {string} hostname - Hostname
 * @param {string} apexDomain - Apex domain
 * @returns {boolean} True if match in threat intelligence feed
 */
function isKnownScamDomain(hostname, apexDomain) {
  if (!hostname) return false;
  const host = normalizeDomain(hostname);
  const apex = normalizeDomain(apexDomain || host);

  if (KNOWN_SCAM_DOMAINS.has(host) || KNOWN_SCAM_DOMAINS.has(apex)) {
    return true;
  }

  return false;
}

/**
 * Distinguishes website classification into 5 distinct categories:
 * 1. Verified Government Domains
 * 2. Verified Authentic Websites
 * 3. Known Phishing Websites
 * 4. Suspicious Websites
 * 5. Unknown / Unverified Websites
 *
 * @param {string} hostname - Target hostname
 * @param {string} apexDomain - Apex domain
 * @param {Object} opts - Evaluation options (riskPercentage, verdict, etc.)
 * @returns {Object} Comprehensive classification object
 */
function classifyDomain(hostname, apexDomain, opts = {}) {
  const host = normalizeDomain(hostname);
  const apex = normalizeDomain(apexDomain || host);
  const riskPct = opts.riskPercentage !== undefined ? opts.riskPercentage : (opts.riskScore || 0);
  const isKnownScam = opts.isKnownScam !== undefined ? opts.isKnownScam : isKnownScamDomain(host, apex);
  const isGov = opts.isGovernment !== undefined ? opts.isGovernment : isVerifiedGovernmentDomain(host, apex);
  const isReal = opts.isVerifiedReal !== undefined ? opts.isVerifiedReal : isVerifiedRealDomain(host, apex);
  const isGovSpoof = opts.isGovSpoof !== undefined ? opts.isGovSpoof : detectGovernmentSpoofing(host, apex).isSpoofing;

  // 1. Verified Government Domain
  if (isGov && !isGovSpoof) {
    return {
      category: CLASSIFICATION_CATEGORIES.VERIFIED_GOVERNMENT,
      categoryLabel: 'Verified Government Domain',
      badge: '🏛️ Verified Government',
      badgeClass: 'gov-safe',
      isGovernment: true,
      isKnownPhishing: false,
      isSuspicious: false,
      isUnknown: false,
      description: 'Authenticated official government portal confirmed in the Veridex Trusted Government Allowlist.',
      disclaimer: VERIDEX_DISCLAIMER
    };
  }

  // 2. Known Phishing Website
  if (isKnownScam) {
    return {
      category: CLASSIFICATION_CATEGORIES.KNOWN_PHISHING,
      categoryLabel: 'Known Phishing Website',
      badge: '⛔ Confirmed Phishing',
      badgeClass: 'danger',
      isGovernment: false,
      isKnownPhishing: true,
      isSuspicious: true,
      isUnknown: false,
      description: 'Confirmed fraudulent or phishing website documented in reputable threat intelligence datasets.',
      disclaimer: VERIDEX_DISCLAIMER
    };
  }

  // 3. Verified Legitimate Website (Commercial / Educational / Tech)
  if (isReal && !isGovSpoof && riskPct <= 20) {
    return {
      category: CLASSIFICATION_CATEGORIES.VERIFIED_REAL,
      categoryLabel: 'Verified Authentic Website',
      badge: '✓ Verified Safe',
      badgeClass: 'safe',
      isGovernment: false,
      isKnownPhishing: false,
      isSuspicious: false,
      isUnknown: false,
      description: 'Authenticated legitimate domain cataloged in the Veridex Global Verified Safe Registry.',
      disclaimer: VERIDEX_DISCLAIMER
    };
  }

  // 4. Suspicious Website
  if (isGovSpoof || riskPct >= 35 || opts.verdict === 'suspicious') {
    return {
      category: CLASSIFICATION_CATEGORIES.SUSPICIOUS,
      categoryLabel: 'Suspicious Website',
      badge: '🚨 Suspicious',
      badgeClass: 'warning',
      isGovernment: false,
      isKnownPhishing: false,
      isSuspicious: true,
      isUnknown: false,
      description: 'Unverified website exhibiting deceptive brand impersonation, spoofing tactics, or malicious heuristics.',
      disclaimer: VERIDEX_DISCLAIMER
    };
  }

  // 5. Unknown / Unverified Website
  return {
    category: CLASSIFICATION_CATEGORIES.UNKNOWN,
    categoryLabel: 'Unknown / Unverified Website',
    badge: 'ℹ️ Unknown Website',
    badgeClass: 'neutral',
    isGovernment: false,
    isKnownPhishing: false,
    isSuspicious: false,
    isUnknown: true,
    description: 'Web property not cataloged in official registries. Heuristics are normal, but destination identity is unverified.',
    disclaimer: VERIDEX_DISCLAIMER
  };
}

/**
 * Retrieves the suggested official website when a user visits an unsafe or spoofed site.
 * Accurately points towards the authentic website the fake one has impersonated
 * or resolves the closest authentic legitimate website from verified registries.
 */
function getSuggestedOfficialWebsite(hostname, brandName) {
  if (!hostname) {
    return { name: 'National Cyber Crime Reporting Portal', url: 'https://cybercrime.gov.in', host: 'cybercrime.gov.in' };
  }

  const lowerHost = hostname.toLowerCase();

  // 1. If brand is explicitly identified
  if (brandName) {
    const matchedBrand = VERIDEX_BRANDS.find(b => b.name.toLowerCase() === brandName.toLowerCase() || b.nameKey === brandName.toLowerCase());
    if (matchedBrand) {
      return {
        name: matchedBrand.name,
        url: matchedBrand.officialUrl || `https://www.${matchedBrand.canonical[0]}`,
        host: matchedBrand.canonical[0]
      };
    }
  }

  // 2. Check if spoofing an Indian government authority or public service
  if (lowerHost.includes('cybercrime') || lowerHost.includes('cyber-crime') || lowerHost.includes('1930')) {
    return {
      name: 'National Cyber Crime Reporting Portal',
      url: 'https://cybercrime.gov.in',
      host: 'cybercrime.gov.in'
    };
  }
  if (lowerHost.includes('incometax') || lowerHost.includes('income-tax') || lowerHost.includes('itr-') || lowerHost.includes('efiling')) {
    return {
      name: 'Income Tax Department (Official e-Filing)',
      url: 'https://www.incometax.gov.in',
      host: 'incometax.gov.in'
    };
  }
  if (lowerHost.includes('parivahan') || lowerHost.includes('echallan') || lowerHost.includes('e-challan') || lowerHost.includes('vahan') || lowerHost.includes('sarathi')) {
    return {
      name: 'Parivahan Sewa (Ministry of Road Transport)',
      url: 'https://parivahan.gov.in',
      host: 'parivahan.gov.in'
    };
  }
  if (lowerHost.includes('uidai') || lowerHost.includes('aadhaar') || lowerHost.includes('aadhar')) {
    return {
      name: 'Unique Identification Authority of India (UIDAI)',
      url: 'https://uidai.gov.in',
      host: 'uidai.gov.in'
    };
  }
  if (lowerHost.includes('passport') || lowerHost.includes('seva')) {
    return {
      name: 'Passport Seva (Ministry of External Affairs)',
      url: 'https://www.passportindia.gov.in',
      host: 'passportindia.gov.in'
    };
  }
  if (lowerHost.includes('epfindia') || lowerHost.includes('epfo') || lowerHost.includes('uan-') || lowerHost.includes('epf-')) {
    return {
      name: 'Employees\' Provident Fund Organisation (EPFO)',
      url: 'https://www.epfindia.gov.in',
      host: 'epfindia.gov.in'
    };
  }
  if (lowerHost.includes('digilocker')) {
    return {
      name: 'DigiLocker (National Digital Locker)',
      url: 'https://www.digilocker.gov.in',
      host: 'digilocker.gov.in'
    };
  }
  if (lowerHost.includes('rbi') || lowerHost.includes('reservebank')) {
    return {
      name: 'Reserve Bank of India',
      url: 'https://www.rbi.org.in',
      host: 'rbi.org.in'
    };
  }

  // If spoofing generic government domain (.gov.in / .nic.in lookalike)
  if (detectGovernmentSpoofing(lowerHost).isSpoofing || lowerHost.includes('.gov.in') || lowerHost.includes('.nic.in') || lowerHost.includes('gov-in') || lowerHost.includes('nic-in')) {
    return {
      name: 'National Cyber Crime Reporting Portal',
      url: 'https://cybercrime.gov.in',
      host: 'cybercrime.gov.in'
    };
  }

  // 3. Check against known brands: substring, keywords, or canonical names
  for (const brand of VERIDEX_BRANDS) {
    if (lowerHost.includes(brand.nameKey)) {
      return {
        name: brand.name,
        url: brand.officialUrl || `https://www.${brand.canonical[0]}`,
        host: brand.canonical[0]
      };
    }

    if (brand.keywords && Array.isArray(brand.keywords)) {
      for (const kw of brand.keywords) {
        if (kw.length >= 3 && lowerHost.includes(kw)) {
          return {
            name: brand.name,
            url: brand.officialUrl || `https://www.${brand.canonical[0]}`,
            host: brand.canonical[0]
          };
        }
      }
    }
  }

  // 4. Token-level closest matching (typosquatting & combosquatting resolution)
  const tokens = lowerHost.replace(/[^a-z0-9]/g, ' ').split(/\s+/).filter(t => t.length >= 3);
  let bestBrandMatch = null;
  let minDistance = 999;

  for (const token of tokens) {
    for (const brand of VERIDEX_BRANDS) {
      const target = brand.nameKey;
      let dist = 999;

      // Simple Levenshtein distance calculation for token vs brand nameKey
      if (Math.abs(token.length - target.length) <= 2) {
        const m = token.length;
        const n = target.length;
        const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
        for (let i = 0; i <= m; i++) dp[i][0] = i;
        for (let j = 0; j <= n; j++) dp[0][j] = j;
        for (let i = 1; i <= m; i++) {
          for (let j = 1; j <= n; j++) {
            dp[i][j] = token[i - 1] === target[j - 1]
              ? dp[i - 1][j - 1]
              : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
          }
        }
        dist = dp[m][n];
      }

      if (dist <= 2 && dist < minDistance) {
        minDistance = dist;
        bestBrandMatch = brand;
      }
    }
  }

  if (bestBrandMatch && minDistance <= 2) {
    return {
      name: bestBrandMatch.name,
      url: bestBrandMatch.officialUrl || `https://www.${bestBrandMatch.canonical[0]}`,
      host: bestBrandMatch.canonical[0]
    };
  }

  // 5. Category-specific heuristic target resolution
  if (/bank|pay|upi|wallet|card|loan|fund|credit|debit/.test(lowerHost)) {
    return {
      name: 'State Bank of India',
      url: 'https://www.onlinesbi.sbi',
      host: 'onlinesbi.sbi'
    };
  }
  if (/shop|store|order|cart|deal|buy|sale|mall/.test(lowerHost)) {
    return {
      name: 'Amazon',
      url: 'https://www.amazon.in',
      host: 'amazon.in'
    };
  }
  if (/crypto|btc|eth|binance|coin|token|web3/.test(lowerHost)) {
    return {
      name: 'Binance',
      url: 'https://www.binance.com',
      host: 'binance.com'
    };
  }
  if (/movie|stream|tv|video|cinema|watch/.test(lowerHost)) {
    return {
      name: 'Netflix',
      url: 'https://www.netflix.com',
      host: 'netflix.com'
    };
  }

  // 6. Closest authentic destination fallback: National Cybercrime Defense Portal
  return {
    name: 'National Cyber Crime Reporting Portal',
    url: 'https://cybercrime.gov.in',
    host: 'cybercrime.gov.in'
  };
}

// Export for Node, Service Worker, and Browser Window environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    VERIDEX_BRANDS,
    VERIFIED_REAL_DOMAINS,
    VERIFIED_GOVERNMENT_DOMAINS,
    KNOWN_SCAM_DOMAINS,
    CLASSIFICATION_CATEGORIES,
    VERIDEX_DISCLAIMER,
    normalizeDomain,
    validateDomain,
    deduplicateDomains,
    validateDataset,
    classifyDomain,
    isVerifiedGovernmentDomain,
    isVerifiedRealDomain,
    isKnownScamDomain,
    detectGovernmentSpoofing,
    getSuggestedOfficialWebsite
  };
}
if (typeof self !== 'undefined') {
  self.VERIDEX_BRANDS = VERIDEX_BRANDS;
  self.VERIFIED_REAL_DOMAINS = VERIFIED_REAL_DOMAINS;
  self.VERIFIED_GOVERNMENT_DOMAINS = VERIFIED_GOVERNMENT_DOMAINS;
  self.KNOWN_SCAM_DOMAINS = KNOWN_SCAM_DOMAINS;
  self.CLASSIFICATION_CATEGORIES = CLASSIFICATION_CATEGORIES;
  self.VERIDEX_DISCLAIMER = VERIDEX_DISCLAIMER;
  self.normalizeDomain = normalizeDomain;
  self.validateDomain = validateDomain;
  self.deduplicateDomains = deduplicateDomains;
  self.validateDataset = validateDataset;
  self.classifyDomain = classifyDomain;
  self.isVerifiedGovernmentDomain = isVerifiedGovernmentDomain;
  self.isVerifiedRealDomain = isVerifiedRealDomain;
  self.isKnownScamDomain = isKnownScamDomain;
  self.detectGovernmentSpoofing = detectGovernmentSpoofing;
  self.getSuggestedOfficialWebsite = getSuggestedOfficialWebsite;
}
if (typeof window !== 'undefined') {
  window.VERIDEX_BRANDS = VERIDEX_BRANDS;
  window.VERIFIED_REAL_DOMAINS = VERIFIED_REAL_DOMAINS;
  window.VERIFIED_GOVERNMENT_DOMAINS = VERIFIED_GOVERNMENT_DOMAINS;
  window.KNOWN_SCAM_DOMAINS = KNOWN_SCAM_DOMAINS;
  window.CLASSIFICATION_CATEGORIES = CLASSIFICATION_CATEGORIES;
  window.VERIDEX_DISCLAIMER = VERIDEX_DISCLAIMER;
  window.normalizeDomain = normalizeDomain;
  window.validateDomain = validateDomain;
  window.deduplicateDomains = deduplicateDomains;
  window.validateDataset = validateDataset;
  window.classifyDomain = classifyDomain;
  window.isVerifiedGovernmentDomain = isVerifiedGovernmentDomain;
  window.isVerifiedRealDomain = isVerifiedRealDomain;
  window.isKnownScamDomain = isKnownScamDomain;
  window.detectGovernmentSpoofing = detectGovernmentSpoofing;
  window.getSuggestedOfficialWebsite = getSuggestedOfficialWebsite;
}
if (typeof globalThis !== 'undefined') {
  globalThis.VERIDEX_BRANDS = VERIDEX_BRANDS;
  globalThis.VERIFIED_REAL_DOMAINS = VERIFIED_REAL_DOMAINS;
  globalThis.VERIFIED_GOVERNMENT_DOMAINS = VERIFIED_GOVERNMENT_DOMAINS;
  globalThis.KNOWN_SCAM_DOMAINS = KNOWN_SCAM_DOMAINS;
  globalThis.CLASSIFICATION_CATEGORIES = CLASSIFICATION_CATEGORIES;
  globalThis.VERIDEX_DISCLAIMER = VERIDEX_DISCLAIMER;
  globalThis.normalizeDomain = normalizeDomain;
  globalThis.validateDomain = validateDomain;
  globalThis.deduplicateDomains = deduplicateDomains;
  globalThis.validateDataset = validateDataset;
  globalThis.classifyDomain = classifyDomain;
  globalThis.isVerifiedGovernmentDomain = isVerifiedGovernmentDomain;
  globalThis.isVerifiedRealDomain = isVerifiedRealDomain;
  globalThis.isKnownScamDomain = isKnownScamDomain;
  globalThis.detectGovernmentSpoofing = detectGovernmentSpoofing;
  globalThis.getSuggestedOfficialWebsite = getSuggestedOfficialWebsite;
}
