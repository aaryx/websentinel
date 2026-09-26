# WebSentinel

Authorized-use, low-impact CLI web security scanner (V1). WebSentinel performs
**passive and safe** security analysis: HTTP/HTTPS posture, security headers,
cookies, TLS/certificates, information disclosure, CORS, controlled same-origin
crawling, and passive HTML/input analysis — with evidence-based findings,
severity/confidence levels, OWASP/CWE mappings, correlation, and terminal /
JSON / HTML reports.

> **LEGAL NOTICE:** Only scan websites and applications you **own** or have
> **explicit written authorization** to assess. WebSentinel implements no
> exploitation, brute force, DoS, evasion, or persistence. Misuse is your
> responsibility.

## Features

- Async HTTP engine (httpx): pooling, bounded concurrency, timeouts, rate
  limiting, redirect-chain cap, response size cap, graceful network errors
- Security header analysis (CSP, HSTS, XFO, XCTO, Referrer-Policy,
  Permissions-Policy, COOP/CORP/COEP) with context-aware severity
- Cookie attribute analysis (Secure/HttpOnly/SameSite/Domain/Path)
- TLS inspection via stdlib `ssl`: validity, expiry, not-yet-valid, negotiated
  version — always non-intrusive
- OPTIONS-based method advertisement (clearly distinguished from confirmed)
- Information disclosure headers; passive technology fingerprinting
  (data-driven, extensible signatures)
- robots.txt / sitemap.xml / security.txt handling (informational)
- Controlled same-origin crawler (depth/page caps, dedup, robots awareness)
- Passive HTML analysis: insecure forms, mixed content, third-party resources
  (never submits forms, never injects payloads)
- CORS analysis with calibrated confidence
- Finding correlation (never auto-escalates to CRITICAL)
- Reports: Rich terminal, machine-readable JSON, standalone escaped HTML
- Structured logging (`--verbose` / `--quiet`), meaningful exit codes

## Installation

```bash
cd websentinel
python -m venv .venv && .venv\Scripts\activate   # or source .venv/bin/activate
pip install -r requirements.txt
pip install -e .          # provides the `websentinel` command
# dev: pip install -r requirements-dev.txt
```

## Usage

```bash
websentinel scan -u https://example.com
websentinel scan -u https://example.com --verbose
websentinel scan -u https://example.com --format json
websentinel scan -u https://example.com -o report.html --format html
websentinel scan -u https://example.com --crawl --depth 2 --max-pages 50
websentinel scan -u https://example.com --concurrency 10 --timeout 10 --rate-limit 5
websentinel scan -u https://example.com --headers        # headers only
websentinel scan -u https://example.com --tls            # TLS only
websentinel scan -u https://example.com --cookies        # cookies only
websentinel scan -u http://127.0.0.1:8080 --allow-private   # lab targets
websentinel checks
websentinel version
```

Full option list: `websentinel scan --help`.

## Example output

```
╭────────────────────────────────────╮
│        WebSentinel v1.0.0          │
│      Web Security Scanner          │
│      Authorized use only           │
╰────────────────────────────────────╯
Target    https://example.com
Host      example.com:443 (https)
Duration  1.84s   Requests 6   Pages 1

                        Findings
 Severity  ID                Title                       Conf
 HIGH      HTML-INSECURE-FORM Password form over HTTP    HIGH
 MEDIUM    HDR-CSP-MISSING    Missing content-security.. HIGH
 LOW       HDR-XFO-MISSING    Missing x-frame-options    HIGH
 ...

 Summary:  Critical 0 · High 1 · Medium 3 · Low 2 · Info 4
```

## Configuration (`websentinel.yaml`)

Auto-loaded from CWD or via `--config`. See `websentinel.yaml` in this repo
for all keys and safe defaults (timeout, concurrency, rate_limit, max_pages,
max_depth, user_agent, follow_redirects, verify_tls, output_format).

## Finding model

Each finding: `id, title, category, severity, confidence, url, parameter,
description, impact, evidence, remediation, cwe, owasp, references,
timestamp`. Severity ∈ INFO/LOW/MEDIUM/HIGH/CRITICAL; confidence ∈
LOW/MEDIUM/HIGH. A **missing control is not a confirmed vulnerability** —
confidence and descriptions reflect that.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | scan completed, no HIGH/CRITICAL findings |
| 1 | scan completed with findings |
| 2 | invalid arguments / invalid target |
| 3 | target/network error or interrupted |
| 4 | internal error |

## Architecture

```
websentinel/
  cli.py scanning entry   scanner.py orchestration
  http/client.py async engine      analyzers/*.py one module per check
  crawler/crawler.py same-origin crawler
  engine/correlation.py contextual priority
  reporting/{terminal,json_report,html_report}.py
  utils/{urls,logging,timing}.py
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests -q        # 32 tests, fully offline (mocked responses)
```

## Limitations (honest)

- Passive only: no active injection/exploitation — by design. URL parameters
  are *observed*, never attacked.
- TLS analysis uses the certificate a default handshake negotiates; full
  cipher-suite enumeration is out of scope (use testssl.sh for that).
- Host header / SNI-based vhost edge cases may show certificate errors.
- JavaScript-rendered content is not executed (no headless browser).

## Roadmap

Pluggable check registry, report diffing, HAR import, optional headless
rendering, SRI checks, certificate chain visualization.

## License

MIT (see LICENSE).
