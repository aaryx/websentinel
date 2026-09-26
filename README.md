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

## What a scan does

WebSentinel makes bounded HTTP requests to the target and analyzes the responses
it receives. By default it analyzes the starting page; `--crawl` optionally
follows links on the same origin, subject to the configured depth and page
limits. It does not execute JavaScript, submit forms, guess credentials, or
send injection payloads.

The built-in checks cover:

| Check | What it inspects |
| --- | --- |
| Headers | Browser security controls such as CSP, HSTS, clickjacking protections, MIME sniffing, referrer policy, and cross-origin isolation headers |
| Cookies | Whether response cookies set Secure, HttpOnly, and SameSite attributes, with context-sensitive interpretation |
| TLS | Certificate validity dates and negotiated TLS version for HTTPS targets |
| Methods | Methods advertised by the server through an OPTIONS response; advertisement is not treated as proof that a method is usable |
| CORS | Cross-origin response headers and their apparent scope |
| Information | Potentially revealing server and framework response headers |
| Technology | Passive technology hints matched from response data |
| HTML | Insecure form actions, mixed-content references, and third-party resources in returned HTML |
| Robots and well-known files | Informational review of `robots.txt`, `sitemap.xml`, and `security.txt` |
| URL inputs | Query parameter names are recorded as possible input surfaces; no values are attacked |

Checks are evidence-based. A missing header or advertised method is not
automatically a confirmed vulnerability. Findings include severity and
confidence, and related findings are correlated without automatically raising
anything to CRITICAL.

## How it works

1. The CLI validates and normalizes the target URL. Private and loopback
   addresses are blocked unless `--allow-private` is supplied for a lab target.
2. The async HTTP engine fetches the page and supporting endpoints with bounded
   timeouts, redirect handling, response sizes, and configurable concurrency.
3. Optional crawling stays on the target origin and respects discovered
   `robots.txt` disallow rules and page/depth caps.
4. Independent analyzers inspect responses and produce structured findings.
5. Correlation combines related evidence, then a renderer emits terminal, JSON,
   or standalone HTML output.

## Configuration

WebSentinel reads `websentinel.yaml` or `websentinel.yml` from the current
directory by default. Pass `--config path/to/file.yaml` to select another file.
Command-line options override file values when provided. The example config in
this repository documents every supported setting:

```yaml
timeout: 10                 # seconds per request
concurrency: 10             # maximum concurrent HTTP requests
rate_limit: 0               # requests per second; 0 means unlimited
max_pages: 50               # maximum pages for a crawl
max_depth: 1                # maximum link depth for a crawl
user_agent: "WebSentinel/1.0 (+authorized security assessment)"
follow_redirects: true
max_redirects: 5
max_body_bytes: 1048576      # response body cap
verify_tls: true
output_format: terminal     # terminal, json, or html
```

Keep TLS verification enabled for normal assessments. `--no-verify-tls` is
intended only for controlled lab situations with known certificate issues.
`--proxy` can route requests through an authorized proxy.

## Reports

Terminal output summarizes the target, request count, pages, duration, and
findings. JSON is suitable for automation and includes structured scan and
finding data. HTML is a self-contained report that can be opened locally.
Choose a format with `--format`, or use `-o` with a `.json` or `.html` filename
to save a report:

```bash
websentinel scan -u https://example.com --format json
websentinel scan -u https://example.com -o reports/example.html
websentinel scan -u https://example.com --format json -o reports/example.json
```

The repository includes `sample_report.json` and `sample_report.html` as report
examples. Treat reports as assessment data: review them before sharing, since
they can contain hostnames, URLs, response evidence, and technology details.

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
  cli.py                      command-line interface and exit codes
  scanner.py                  scan orchestration
  config.py                   YAML configuration and defaults
  models.py                   targets, responses, findings, and scan results
  http/client.py               bounded asynchronous HTTP engine
  analyzers/                   focused response analysis modules
  crawler/crawler.py           capped same-origin crawler
  engine/correlation.py        finding correlation and context
  reporting/                   terminal, JSON, and HTML renderers
  utils/                       URL validation, logging, and timing helpers
```

The command is available as `websentinel` after installation, and can also be
run as a Python module with `python -m websentinel`.

## Development

WebSentinel supports Python 3.11 and newer. To set up a local development
environment and run the offline test suite:

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux:        source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
pytest -q
```

Tests use mocked responses and do not require scanning a live website. To see
the available analyzer names and descriptions, run `websentinel checks`.

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
