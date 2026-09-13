'use strict';

/**
 * Heuristic engine for the URL Safety Checker.
 *
 * Pure module: no I/O, no DOM, no dependencies.
 * analyzeUrl(raw) returns a structured risk assessment.
 */

/* ------------------------------ weights ------------------------------ */

const WEIGHTS = {
  // Protocol
  NO_HTTPS: 18,

  // Domain shape
  RAW_IP: 30,
  MANY_SUBDOMAINS: 14,
  SUSPICIOUS_TLD: 16,
  PUNYCODE: 20,

  // Impersonation
  BRAND_OUTSIDE_DOMAIN: 32,

  // Keywords
  PHISHING_KEYWORD: 10,
  PHISHING_KEYWORD_IN_PATH: 16,

  // Obfuscation / shape
  USERINFO_AT: 22,
  ENCODED_CHARS: 12,
  EMBEDDED_URL: 26,
  VERY_LONG_URL: 12,
  MANY_HYPHENS: 8,
  EXECUTABLE_EXT: 25,
};

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'buzz', 'click', 'loan',
  'work', 'bar', 'rest', 'surf', 'monster', 'quest', 'cyou', 'sbs',
  'zip', 'mov', 'cam', 'fit', 'icu', 'cfd', 'srl',
]);

const PHISHING_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'secure', 'account', 'update', 'confirm', 'unlock', 'suspended',
  'limited', 'restore', 'recovery', 'billing', 'invoice', 'payment',
  'prize', 'winner', 'reward', 'claim', 'bonus', 'free', 'gift',
  'urgent', 'alert', 'warning', 'support', 'recover',
];

const WELL_KNOWN_BRANDS = [
  'paypal', 'apple', 'icloud', 'amazon', 'netflix', 'google', 'microsoft',
  'office365', 'outlook', 'facebook', 'instagram', 'whatsapp', 'linkedin',
  'twitter', 'x', 'github', 'dropbox', 'adobe', 'dhl', 'fedex', 'ups',
  'usps', 'irs', 'chase', 'wellsfargo', 'bankofamerica', 'hsbc', 'barclays',
  'sbi', 'hdfcbank', 'icicibank', 'axisbank', 'paytm', 'phonepe', 'amazonpay',
  'steam', 'roblox', 'coinbase', 'binance', 'metamask',
];

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'rebrand.ly', 's.id',
  'shorte.st', 'adf.ly', 'bit.do', 'urls.im', 'v.gd',
]);

const SUSPICIOUS_REDIRECT_PARAMS = new Set([
  'url', 'next', 'redirect', 'redirect_uri', 'redirect_url', 'goto',
  'return', 'returnurl', 'return_to', 'continue', 'dest', 'destination',
  'target', 'link', 'r', 'u', 'out',
]);

const EXECUTABLE_EXTS = new Set([
  'exe', 'msi', 'bat', 'cmd', 'scr', 'apk', 'dmg', 'jar', 'vbs', 'ps1',
  'com', 'pif', 'hta', 'iso', 'img',
]);

const MAX_URL_LENGTH = 100;

/* ------------------------------ helpers ------------------------------ */

function isIpv4Host(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function registrableDomain(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const twoLevelTlds = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'co.in', 'co.jp']);
  const lastTwo = parts.slice(-2).join('.');
  if (twoLevelTlds.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

function decodeSafely(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/* ------------------------------- engine ------------------------------ */

/**
 * Analyze a URL string and return a structured risk assessment.
 * @param {string} raw
 * @returns {{ ok: false, error: string } | {
 *   ok: true,
 *   input: string,
 *   normalizedUrl: string,
 *   verdict: 'safe' | 'suspicious' | 'high-risk',
 *   binaryVerdict: 'safe' | 'suspicious',
 *   score: number,
 *   flags: Array<{ code: string, weight: number, detail: string }>,
 *   urlParts: { protocol: string, hostname: string, domain: string, tld: string, path: string }
 * }}
 */
function analyzeUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { ok: false, error: 'URL is required.' };
  }

  let input = raw.trim();
  // Tolerate pasted values like "url = http://x" or wrapped in quotes/angle brackets
  input = input.replace(/^[<'"\s]+/, '').replace(/[>'"\s]+$/, '');
  if (/^url\s*=/i.test(input)) input = input.replace(/^url\s*=\s*/i, '');

  // Reject explicit non-web schemes before the http:// auto-prefix can mask them
  const explicitScheme = /^[a-z][a-z0-9+.-]*:/i.exec(input);
  if (explicitScheme && !/^https?:/i.test(explicitScheme[0])) {
    return { ok: false, error: 'Only http and https URLs are supported.' };
  }

  if (!/^https?:\/\//i.test(input)) input = 'http://' + input;

  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    return { ok: false, error: 'This does not look like a valid URL.' };
  }

  if (!/^https?:$/.test(parsed.protocol)) {
    return { ok: false, error: 'Only http and https URLs are supported.' };
  }

  const hostname = parsed.hostname.toLowerCase();
  const domain = registrableDomain(hostname);
  const path = parsed.pathname || '/';
  const search = parsed.search || '';
  const hash = parsed.hash || '';
  const fullLower = (hostname + path + search + hash).toLowerCase();

  const flags = [];
  const addFlag = (code, detail) => {
    const weight = WEIGHTS[code];
    if (!weight) throw new Error('Unknown flag code: ' + code);
    flags.push({ code, weight, detail });
  };

  /* -------- protocol -------- */
  const isHttps = parsed.protocol === 'https:';
  if (!isHttps) {
    addFlag('NO_HTTPS', 'Connection is not encrypted (no HTTPS).');
  }

  /* -------- shorteners -------- */
  const isShortener = URL_SHORTENERS.has(domain);

  /* -------- domain shape -------- */
  const isIpHost = isIpv4Host(hostname);
  if (isIpHost) {
    addFlag('RAW_IP', 'Uses a raw IP address instead of a domain name.');
  }

  const labels = hostname.split('.').filter(Boolean);
  if (!isIpHost && labels.length >= 4) {
    addFlag('MANY_SUBDOMAINS', `Long subdomain chain (${labels.length} labels).`);
  }

  const tld = labels[labels.length - 1] || '';
  if (!isShortener && SUSPICIOUS_TLDS.has(tld)) {
    addFlag('SUSPICIOUS_TLD', `".${tld}" is commonly used in phishing campaigns.`);
  }

  if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
    addFlag('PUNYCODE', 'Punycode domain can imitate real characters (homograph attack).');
  }

  /* -------- brand impersonation -------- */
  if (!isShortener) {
    const outside = hostname.replace(domain, ' ');
    for (const brand of WELL_KNOWN_BRANDS) {
      // word-boundary-ish match so "xbox" does not match brand "x"
      const re = new RegExp('(^|[^a-z0-9])' + brand + '($|[^a-z0-9])');
      if (re.test(outside) && domain !== brand && !domain.startsWith(brand + '.') && !domain.includes('.' + brand + '.')) {
        addFlag('BRAND_OUTSIDE_DOMAIN', `Mentions "${brand}" outside the real ${domain} domain.`);
        break;
      }
    }
  }

  /* -------- keywords -------- */
  const wordsInPath = path.toLowerCase() + search.toLowerCase();
  const pathWords = wordsInPath.split(/[^a-z0-9]+/).filter(Boolean);
  const foundKeywords = PHISHING_KEYWORDS.filter((kw) => pathWords.includes(kw));

  if (foundKeywords.length > 0) {
    addFlag(
      'PHISHING_KEYWORD_IN_PATH',
      `Phishing-style wording in the path: ${foundKeywords.slice(0, 3).join(', ')}.`
    );
  } else {
    const hostWords = hostname.split(/[^a-z0-9]+/).filter(Boolean);
    const hostKeyword = PHISHING_KEYWORDS.find((kw) => hostWords.includes(kw));
    if (hostKeyword) {
      addFlag('PHISHING_KEYWORD', `Phishing-style wording in the domain: "${hostKeyword}".`);
    }
  }

  /* -------- obfuscation -------- */
  if (parsed.username || parsed.password || input.includes('@')) {
    addFlag('USERINFO_AT', 'Contains "@" before the host — a classic disguise trick.');
  }

  const rawAfterScheme = input.replace(/^https?:\/\//i, '');
  const pct = (rawAfterScheme.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (pct >= 3) {
    addFlag('ENCODED_CHARS', `${pct} percent-encoded characters can hide the real destination.`);
  }

  if (!isShortener) {
    for (const [k, v] of parsed.searchParams) {
      if (SUSPICIOUS_REDIRECT_PARAMS.has(k.toLowerCase()) && /^https?(%3a|:)/i.test(v)) {
        addFlag('EMBEDDED_URL', 'Query parameter contains another URL (possible open redirect).');
        break;
      }
      const decodedV = decodeSafely(v);
      if (SUSPICIOUS_REDIRECT_PARAMS.has(k.toLowerCase()) && /^https?:\/\//i.test(decodedV)) {
        addFlag('EMBEDDED_URL', 'Query parameter contains another URL (possible open redirect).');
        break;
      }
    }
  }

  /* -------- shape -------- */
  if (rawAfterScheme.length > MAX_URL_LENGTH) {
    addFlag('VERY_LONG_URL', `URL is ${rawAfterScheme.length} characters long.`);
  }

  const pathHyphens = (path.match(/-/g) || []).length;
  if (pathHyphens >= 5) {
    addFlag('MANY_HYPHENS', `${pathHyphens} hyphens in the path.`);
  }

  const lastSeg = path.split('/').filter(Boolean).pop() || '';
  const m = lastSeg.toLowerCase().match(/\.([a-z0-9]+)(\.[a-z0-9]+)?$/);
  if (m) {
    const exts = [m[1], m[2] && m[2].slice(1)].filter(Boolean);
    if (exts.some((e) => EXECUTABLE_EXTS.has(e))) {
      addFlag('EXECUTABLE_EXT', 'Links directly to an executable or disk-image file.');
    }
  }

  /* -------- score + verdict -------- */
  const score = flags.reduce((sum, f) => sum + f.weight, 0);
  const verdict = score >= 61 ? 'high-risk' : score >= 26 ? 'suspicious' : 'safe';

  return {
    ok: true,
    input: raw.trim(),
    normalizedUrl: parsed.href,
    verdict,
    binaryVerdict: score >= 26 ? 'suspicious' : 'safe',
    score,
    maxPossibleScore: Object.values(WEIGHTS).reduce((a, b) => a + b, 0),
    flags,
    urlParts: {
      protocol: parsed.protocol.replace(':', ''),
      hostname,
      domain: isIpHost ? hostname : domain,
      tld: isIpHost ? '' : tld,
      path,
      isShortener,
    },
  };
}

module.exports = { analyzeUrl, WEIGHTS };
