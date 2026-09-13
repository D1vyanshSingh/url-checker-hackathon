URL Safety Checker

A lightweight phishing/URL risk checker — paste a URL, get an instant risk assessment with a transparent breakdown of why it was flagged.

Problem

Phishing attacks disguise malicious links as legitimate websites (banking, login pages, prize claims, etc.) to steal credentials. Most users have no quick way to check a URL before clicking, and rely on gut feeling alone.

Solution

Paste a URL and instantly get:

A verdict — Safe / Suspicious / High-Risk
A numeric risk score (0–100)
A human-readable list of exactly which red flags triggered the score
Features
15 phishing heuristic rules with weighted scoring
Brand impersonation detection (PayPal, banks, DHL, Netflix, and 30+ others) matched outside the real domain
Detects: missing HTTPS, raw IP hosts, suspicious TLDs, punycode, @ userinfo tricks, open-redirect params, URL shorteners, hyphen spam, executable file extensions, and more
Zero external dependencies on the backend
29 automated tests (unit + integration)
Tech Stack
Backend: Node.js, rule-based heuristic engine, no external dependencies
Frontend: HTML, CSS, JavaScript
API
Endpoint	Method	Description
/api/check?url=<url>	GET	Risk assessment for a URL
/api/check	POST	Same, with JSON body {"url": "..."}
/api/health	GET	Liveness check
/	GET	Usage docs

Example response:

json
{
  "binaryVerdict": "suspicious",
  "score": 96,
  "flags": [
    "Mentions 'paypal' outside the real verify-login.tk domain",
    "No HTTPS",
    "Suspicious TLD"
  ]
}
How to Run
Start the backend:
   node server/server.js
Open index.html in your browser.
Testing
cd server
npm test

29 tests covering rule logic and API integration.

Notes

This is a heuristic-based MVP, not a production-grade security tool. Real-world phishing detection typically also uses live threat-intel feeds and ML models — this project focuses on fast, explainable, dependency-free checks.

Author

Divyansh Singh
