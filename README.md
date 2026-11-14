# headerguard

[![CI](https://github.com/ruslan-mustafaev/headerguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ruslan-mustafaev/headerguard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**Audit the HTTP security headers, cookies and CORS policy of any website — and fail your CI
build when it gets worse.**

`headerguard` sends one request, follows the redirect chain and grades the response from
**A+ to F**, with a concrete fix for every problem. It runs anywhere Python runs, has zero
dependencies and needs no account or API key.

## What it checks

| Area | Checks |
|---|---|
| **Transport** | HTTPS, HTTP → HTTPS redirect, HSTS presence, `max-age` ≥ 180 days, `includeSubDomains` |
| **CSP** | presence, Report-Only mode, `'unsafe-inline'` without nonce/hash, `'unsafe-eval'`, wildcard / `https:` script sources (respecting `'strict-dynamic'`), `object-src`, `base-uri` |
| **Clickjacking** | CSP `frame-ancestors` or `X-Frame-Options: DENY / SAMEORIGIN` |
| **CORS** | **active probe** with a random `Origin` — detects origin reflection (with and without credentials), `*` + credentials, `null` origin |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie` |
| **Hardening** | `X-Content-Type-Options`, `Referrer-Policy` (last value wins, like browsers), `Permissions-Policy` |
| **Info leaks** | version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version` |

## Install

```bash
pip install git+https://github.com/ruslan-mustafaev/headerguard.git
```

## Usage

```bash
headerguard example.com
headerguard https://app.example.com https://api.example.com -v      # also show passed checks
headerguard staging.example.com -H "Cookie: session=..."             # audit an authenticated page
headerguard example.com --json | jq '.[0].grade'
```

Example output for a deliberately misconfigured test server:

```text
http://localhost:8000  ->  grade F (5/100)
  [HIGH  ] Site is not served over HTTPS  (-30)
           fix: Serve the site over HTTPS and redirect all HTTP traffic to it.
  [HIGH  ] CORS reflects any Origin with credentials  (-25)
           Access-Control-Allow-Origin: https://headerguard-probe.invalid; Allow-Credentials: true
           fix: Allow only a fixed list of trusted origins.
  [MEDIUM] CSP allows 'unsafe-inline' scripts  (-10)
           'self' 'unsafe-inline'
           fix: Replace 'unsafe-inline' with nonces or hashes.
  [MEDIUM] Page can be framed (clickjacking)  (-10)
           fix: Add CSP frame-ancestors 'self' (and X-Frame-Options: SAMEORIGIN for old browsers).
  [LOW   ] Cookie 'session' is missing flags  (-5)
           no HttpOnly, no SameSite
  [LOW   ] X-Powered-By discloses technology  (-3)
           X-Powered-By: Express
  ...
```

### Options

| Option | Description |
|---|---|
| `--fail-under GRADE` | exit with code `1` if any URL scores worse than `GRADE` (`A+`, `A`, `B`, `C`, `D`, `F`) |
| `--json` | machine-readable report (score, grade, every finding with fix) |
| `-H "Name: value"` | extra request header (repeatable) |
| `-v` | list passed checks too |
| `-k` / `--insecure` | skip TLS verification (self-signed staging certs) |
| `--no-redirects` | audit the first response only |
| `--timeout SEC` | request timeout, default 10 |

Exit codes: `0` OK · `1` grade below `--fail-under` · `2` network error.

## Use it in CI

```yaml
# .github/workflows/security-headers.yml
name: Security headers
on:
  schedule: [{ cron: "0 6 * * 1" }]
  workflow_dispatch:
jobs:
  headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/ruslan-mustafaev/headerguard.git
      - run: headerguard https://your-site.com --fail-under B
```

Works the same for Netlify / Vercel preview deployments — point it at the preview URL.

## As a library

```python
from headerguard import audit

report = audit("https://example.com")
print(report.grade, report.score)
for finding in report.problems:
    print(finding.severity, finding.title, "->", finding.fix)
```

## Scoring

Every site starts at 100. Each failed check subtracts its penalty (shown in the output);
cookie penalties are capped at 15 so a site with many cookies is not dominated by them.
`A+` ≥ 95 · `A` ≥ 85 · `B` ≥ 70 · `C` ≥ 55 · `D` ≥ 40 · `F` below.

## Responsible use

`headerguard` sends a single ordinary `GET` request per URL (plus redirects). Only audit sites
you own or are authorised to test.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests run against a local HTTP server, so no internet access is needed.

## License

[MIT](LICENSE) © Ruslan Mustafaev
