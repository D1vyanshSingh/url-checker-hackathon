'use strict';

/**
 * URL Safety Checker — HTTP API (zero dependencies, Node >= 18).
 *
 * Endpoints:
 *   GET  /api/health        -> { status: 'ok' }
 *   GET  /api/check?url=... -> analysis result
 *   POST /api/check  { "url": "..." } -> analysis result
 *   GET  /                  -> API info
 */

const http = require('http');
const { analyzeUrl } = require('./heuristics');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

/* ------------------------- rate limiting ------------------------- */

const RATE_LIMIT = 30;            // requests per window per IP
const RATE_WINDOW_MS = 60_000;    // 1 minute
const hits = new Map();           // ip -> [timestamps]

function rateLimit(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5_000) hits.clear(); // crude memory guard
  return list.length <= RATE_LIMIT;
}

/* --------------------------- helpers ----------------------------- */

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readJsonBody(req, limitBytes = 10_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limitBytes) {
        reject(Object.assign(new Error('Request body too large.'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return reject(Object.assign(new Error('Request body is required.'), { status: 400 }));
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('Invalid JSON body.'), { status: 400 }));
      }
    });
    req.on('error', () => reject(Object.assign(new Error('Could not read request body.'), { status: 400 })));
  });
}

function clientIp(req) {
  return req.socket.remoteAddress || 'unknown';
}

/* --------------------------- routing ----------------------------- */

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const route = `${req.method} ${url.pathname}`;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    });
    res.end();
    return;
  }

  if (!rateLimit(clientIp(req))) {
    sendJson(res, 429, { ok: false, error: 'Too many requests. Try again in a minute.' });
    return;
  }

  if (route === 'GET /api/health') {
    sendJson(res, 200, { ok: true, status: 'ok', uptimeSec: Math.round(process.uptime()) });
    return;
  }

  if (route === 'GET /' || route === 'GET /api') {
    sendJson(res, 200, {
      ok: true,
      name: 'URL Safety Checker API',
      usage: {
        checkGet: 'GET /api/check?url=<encoded-url>',
        checkPost: 'POST /api/check  body: {"url": "..."}',
        health: 'GET /api/health',
      },
      verdicts: ['safe', 'suspicious', 'high-risk'],
    });
    return;
  }

  if (url.pathname === '/api/check') {
    let rawUrl;
    if (req.method === 'GET') {
      rawUrl = url.searchParams.get('url');
      if (rawUrl === null) {
        sendJson(res, 400, { ok: false, error: 'Missing "url" query parameter.' });
        return;
      }
    } else if (req.method === 'POST') {
      let body;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        sendJson(res, err.status || 400, { ok: false, error: err.message });
        return;
      }
      rawUrl = body && body.url;
      if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
        sendJson(res, 400, { ok: false, error: 'Body must be JSON like {"url": "https://example.com"}.' });
        return;
      }
    } else {
      sendJson(res, 405, { ok: false, error: 'Use GET or POST.' });
      return;
    }

    const result = analyzeUrl(rawUrl);
    if (!result.ok) {
      sendJson(res, 422, result); // unprocessable: valid request, invalid URL
      return;
    }
    sendJson(res, 200, result);
    return;
  }

  sendJson(res, 404, { ok: false, error: 'Not found. See GET / for usage.' });
}

/* ---------------------------- server ----------------------------- */

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    sendJson(res, err.status || 500, { ok: false, error: err.status ? err.message : 'Internal server error.' });
  });
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`URL Safety Checker API listening on http://localhost:${PORT}`);
    console.log(`Try: curl "http://localhost:${PORT}/api/check?url=http://paypal.com.verify-login.tk/signin"`);
  });
}

module.exports = { server, analyzeUrl };
