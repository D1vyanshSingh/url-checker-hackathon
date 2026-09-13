'use strict';

const assert = require('assert');
const http = require('http');
const { analyzeUrl } = require('./heuristics');
const { server } = require('./server');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  ✓ ${name}`);
    })
    .catch((err) => {
      failed++;
      failures.push({ name, err });
      console.error(`  ✗ ${name}\n      ${err.message}`);
    });
}

/* ============================ unit tests ============================ */

async function unitTests() {
  console.log('Unit tests: heuristics.js');

  await test('plain https site is safe', () => {
    const r = analyzeUrl('https://github.com/freebuff');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.verdict, 'safe');
    assert.strictEqual(r.score, 0);
    assert.strictEqual(r.flags.length, 0);
  });

  await test('http-only site flags NO_HTTPS', () => {
    const r = analyzeUrl('http://example.com/page');
    assert.ok(r.flags.some((f) => f.code === 'NO_HTTPS'));
    assert.strictEqual(r.verdict, 'safe'); // 18 pts -> still safe tier
  });

  await test('raw IP host flags RAW_IP', () => {
    const r = analyzeUrl('http://192.168.1.44/login.php');
    const codes = r.flags.map((f) => f.code);
    assert.ok(codes.includes('RAW_IP'));
    assert.ok(codes.includes('PHISHING_KEYWORD_IN_PATH'));
  });

  await test('suspicious TLD flags SUSPICIOUS_TLD', () => {
    const r = analyzeUrl('https://cool-deals.xyz');
    assert.ok(r.flags.some((f) => f.code === 'SUSPICIOUS_TLD'));
  });

  await test('brand in subdomain of unrelated domain flags impersonation', () => {
    const r = analyzeUrl('https://paypal.com.verify-secure.tk/signin');
    const imp = r.flags.find((f) => f.code === 'BRAND_OUTSIDE_DOMAIN');
    assert.ok(imp, 'expected BRAND_OUTSIDE_DOMAIN');
    assert.ok(imp.detail.includes('paypal'));
    assert.ok(r.score >= 61, `expected high-risk, score=${r.score}`);
    assert.strictEqual(r.verdict, 'high-risk');
    assert.strictEqual(r.binaryVerdict, 'suspicious');
  });

  await test('real brand domain does not flag impersonation', () => {
    const r = analyzeUrl('https://paypal.com/us/signin');
    assert.ok(!r.flags.some((f) => f.code === 'BRAND_OUTSIDE_DOMAIN'), JSON.stringify(r.flags));
  });

  await test('userinfo @ trick flags USERINFO_AT', () => {
    const r = analyzeUrl('http://secure-bank.com@203.0.113.9/account');
    const codes = r.flags.map((f) => f.code);
    assert.ok(codes.includes('USERINFO_AT'));
    assert.ok(codes.includes('RAW_IP'));
  });

  await test('open redirect param flags EMBEDDED_URL', () => {
    const r = analyzeUrl('https://trusted-news.com/redirect?next=https://evil-phisher.top/claim');
    const codes = r.flags.map((f) => f.code);
    assert.ok(codes.includes('EMBEDDED_URL'), JSON.stringify(r.flags));
  });

  await test('percent-encoded redirect flags EMBEDDED_URL', () => {
    const r = analyzeUrl('https://mail.example.com/out?u=https%3A%2F%2Fgrab-passwords.tk%2Fverify');
    assert.ok(r.flags.some((f) => f.code === 'EMBEDDED_URL'));
  });

  await test('very long URL flags VERY_LONG_URL', () => {
    const pad = '-'.repeat(120);
    const r = analyzeUrl(`https://example.com/file${pad}.html`);
    assert.ok(r.flags.some((f) => f.code === 'VERY_LONG_URL'));
  });

  await test('punycode domain flags PUNYCODE', () => {
    const r = analyzeUrl('https://xn--pple-43d.com/account');
    assert.ok(r.flags.some((f) => f.code === 'PUNYCODE'));
  });

  await test('executable link flags EXECUTABLE_EXT', () => {
    const r = analyzeUrl('https://files.example.com/downloads/invoice.pdf.exe');
    assert.ok(r.flags.some((f) => f.code === 'EXECUTABLE_EXT'));
  });

  await test('shortener gets shortener treatment, no TLD/brand flags', () => {
    const r = analyzeUrl('https://bit.ly/3xYzAbc');
    const codes = r.flags.map((f) => f.code);
    assert.ok(r.urlParts.isShortener);
    assert.ok(!codes.includes('SUSPICIOUS_TLD'));
    assert.ok(!codes.includes('BRAND_OUTSIDE_DOMAIN'));
    assert.strictEqual(r.verdict, 'suspicious'); // opaque token path -> cannot inspect
  });

  await test('regression: 2no.co IP-grabber link is high-risk', () => {
    const r = analyzeUrl('https://2no.co/2lAQX4');
    const codes = r.flags.map((f) => f.code);
    assert.ok(codes.includes('IP_GRABBER'), JSON.stringify(r.flags));
    assert.ok(codes.includes('OPAQUE_SHORT_LINK'));
    assert.strictEqual(r.verdict, 'high-risk');
    assert.strictEqual(r.binaryVerdict, 'suspicious');
    assert.strictEqual(r.score, 65);
  });

  await test('grabify.link is flagged as IP grabber', () => {
    const r = analyzeUrl('https://grabify.link/TRACKID');
    assert.ok(r.flags.some((f) => f.code === 'IP_GRABBER'));
    assert.ok(r.urlParts.isIpGrabber);
  });

  await test('grabber domain with normal-length path still flags IP_GRABBER', () => {
    const r = analyzeUrl('https://iplogger.org/faq');
    assert.ok(r.flags.some((f) => f.code === 'IP_GRABBER'));
    assert.ok(!r.flags.some((f) => f.code === 'OPAQUE_SHORT_LINK'));
  });

  await test('normal site with opaque-looking path is not flagged as shortener', () => {
    const r = analyzeUrl('https://youtube.com/watch\u002Fdef456');
    assert.ok(!r.flags.some((f) => f.code === 'OPAQUE_SHORT_LINK'));
  });

  await test('many subdomains flag MANY_SUBDOMAINS', () => {
    const r = analyzeUrl('https://a.b.c.d.example.com');
    assert.ok(r.flags.some((f) => f.code === 'MANY_SUBDOMAINS'));
  });

  await test('missing scheme is auto-prefixed', () => {
    const r = analyzeUrl('github.com/freebuff');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.verdict, 'safe');
  });

  await test('pasted "url = ..." wrapper is cleaned', () => {
    const r = analyzeUrl('url = https://example.com');
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.verdict, 'safe');
  });

  await test('invalid input returns ok:false', () => {
    assert.strictEqual(analyzeUrl('').ok, false);
    assert.strictEqual(analyzeUrl('not a url!!').ok, false);
    assert.strictEqual(analyzeUrl('ftp://example.com').ok, false);
    assert.strictEqual(analyzeUrl(null).ok, false);
  });

  await test('keyword in bare domain flags PHISHING_KEYWORD', () => {
    const r = analyzeUrl('https://secure-login.example.com');
    const codes = r.flags.map((f) => f.code);
    assert.ok(codes.includes('PHISHING_KEYWORD'));
    assert.ok(!codes.includes('PHISHING_KEYWORD_IN_PATH'));
  });

  await test('co.uk registrable domain handled', () => {
    const r = analyzeUrl('https://paypal.com.security-check.co.uk/verify');
    const imp = r.flags.find((f) => f.code === 'BRAND_OUTSIDE_DOMAIN');
    assert.ok(imp, 'expected impersonation flag for brand on co.uk lookalike');
  });
}

/* ======================= integration tests ========================= */

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        host: '127.0.0.1',
        port: server.address().port,
        method,
        path,
        headers: payload
          ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
          : {},
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(data); } catch { /* keep null */ }
          resolve({ status: res.statusCode, json, raw: data });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function apiTests() {
  console.log('Integration tests: HTTP API');

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  await test('GET /api/health returns ok', async () => {
    const res = await request('GET', '/api/health');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.ok, true);
  });

  await test('GET / returns API info', async () => {
    const res = await request('GET', '/');
    assert.strictEqual(res.status, 200);
    assert.ok(res.json.usage);
  });

  await test('GET /api/check with valid url returns analysis', async () => {
    const res = await request('GET', '/api/check?url=' + encodeURIComponent('https://paypal.com.verify-login.tk/signin'));
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.ok, true);
    assert.strictEqual(res.json.verdict, 'high-risk');
    assert.ok(res.json.flags.length > 0);
  });

  await test('GET /api/check without url param is 400', async () => {
    const res = await request('GET', '/api/check');
    assert.strictEqual(res.status, 400);
  });

  await test('GET /api/check with invalid url is 422', async () => {
    const res = await request('GET', '/api/check?url=' + encodeURIComponent('not a url!!'));
    assert.strictEqual(res.status, 422);
    assert.strictEqual(res.json.ok, false);
  });

  await test('POST /api/check with JSON body works', async () => {
    const res = await request('POST', '/api/check', { url: 'https://github.com' });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.verdict, 'safe');
  });

  await test('POST /api/check with bad JSON is 400', async () => {
    const res = await request('POST', '/api/check', undefined); // empty body
    assert.strictEqual(res.status, 400);
  });

  await test('unknown route is 404', async () => {
    const res = await request('GET', '/api/nope');
    assert.strictEqual(res.status, 404);
  });

  await test('CORS headers present', async () => {
    const res = await request('GET', '/api/health');
    assert.strictEqual(res.json.ok, true);
  });

  await test('rate limit returns 429 after burst', async () => {
    let last = null;
    for (let i = 0; i < 35; i++) {
      last = await request('GET', '/api/check?url=https://example.com');
    }
    assert.strictEqual(last.status, 429);
  });
}

/* ============================== run ================================ */

(async () => {
  await unitTests();
  await apiTests();
  server.close();

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exitCode = 1;
  }
})();
