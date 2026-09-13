# URL Safety Checker

A lightweight tool that checks whether a URL looks like a phishing attempt. Paste in a link and get back a risk score, a verdict, and a plain-English breakdown of exactly what triggered it — no black box, just the rules that fired.

## Features

- Instant risk score (0–100) for any URL
- Clear verdict: **Safe** / **Suspicious** / **High-Risk**
- Transparent flags array explaining exactly why a URL was scored the way it was
- 15+ weighted heuristic rules, including:
  - Missing HTTPS
  - Raw IP hosts
  - Suspicious TLDs
  - Punycode / homograph tricks
  - `@` userinfo tricks
  - Open-redirect parameters
  - URL shorteners
  - Hyphen spam
  - Executable file extensions
  - Brand impersonation (PayPal, banks, DHL, Netflix, and 30+ others), matched outside the real domain
- Zero external dependencies on the backend
- 29 automated tests (unit + integration)

## Tech Stack

- **Backend:** Node.js, rule-based heuristic engine, no external dependencies
- **Frontend:** HTML, CSS, JavaScript

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/check?url=<url>` | GET | Risk assessment for a URL |
| `/api/check` | POST | Same, with JSON body `{"url": "..."}` |
| `/api/health` | GET | Liveness check |
| `/` | GET | Usage docs |

**Example response:**
```json
{
  "binaryVerdict": "suspicious",
  "score": 96,
  "flags": [
    "Mentions 'paypal' outside the real verify-login.tk domain",
    "No HTTPS",
    "Suspicious TLD"
  ]
}
```

## Getting Started

1. Start the backend:
   ```
   node server/server.js
   ```
2. Open `index.html` in your browser.

## Testing

```
cd server
npm test
```
29 tests covering rule logic and API integration.

## Notes

This is a heuristic-based tool, not a production-grade security product. Real-world phishing detection usually also leans on live threat-intel feeds and ML models — this project is focused on fast, explainable, dependency-free checks.

## Author

Divyansh Singh
