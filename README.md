# WebSentinel

WebSentinel is an authorized-use, low-impact command-line scanner for passive web security assessment. It checks HTTP and HTTPS posture, security headers, cookies, TLS certificates, CORS, information disclosure, HTML, and JavaScript. Optional same-origin crawling and a harmless reflection canary are available.

WebSentinel is intended for websites and applications that you own or are explicitly authorized to assess. It does not exploit vulnerabilities, brute-force credentials, evade detection, or attempt denial of service.

## Features

- Async HTTP client with connection pooling, bounded concurrency, timeouts, redirect limits, response size limits, retries, and a hard request budget.
- Analysis for security headers, cookie attributes, TLS certificates, CORS, advertised HTTP methods, information disclosure, HTML forms and mixed content, robots.txt, sitemaps, and security.txt.
- Passive technology fingerprinting and bounded static JavaScript analysis for API-like endpoint strings, source map references, and high-precision secret patterns. Secret evidence is redacted.
- Optional same-origin crawler with page and depth limits, deduplication, robots awareness, and configurable scope.
- Optional reflection canary enabled only when explicitly selected. It uses harmless unique markers and is capped at ten probes.
- Findings include severity, confidence, evidence, remediation guidance, and applicable CWE/OWASP mappings; related findings are correlated and duplicate findings are grouped.
- Terminal, JSON, HTML, CSV, and SARIF 2.1.0 reports.
- Profiles (`quick`, `standard`, `deep`, `headers`, `tls`, `crawl`, and `api`), check selection, and severity/confidence filters.
- Extra request headers for authorized authenticated assessments. Authorization values are redacted from logs and reports.

## Requirements

- Python 3.11 or newer
- Windows, macOS, or Linux

## Install

Run these commands from the project root (the directory containing `pyproject.toml`).

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

If PowerShell blocks activation, invoke the environment's Python directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Editable installation provides the `websentinel` command. You can also invoke the module with `python -m websentinel`.

## Quick start

Scan only a target you own or have written permission to assess:

```bash
websentinel scan -u https://example.com
```

Save a report in a supported format:

```bash
websentinel scan -u https://example.com --format json -o report.json
websentinel scan -u https://example.com --format html -o report.html
websentinel scan -u https://example.com --format csv -o report.csv
websentinel scan -u https://example.com --format sarif -o report.sarif
```

Some additional examples:

```bash
websentinel scan -u https://example.com --profile quick
websentinel scan -u https://example.com --headers
websentinel scan -u https://example.com --tls
websentinel scan -u https://example.com --crawl --depth 2 --max-pages 50
websentinel scan -u https://example.com --checks headers,cors
websentinel scan -u https://example.com --severity HIGH --confidence HIGH
websentinel scan -u https://example.com --concurrency 5 --timeout 10 --rate-limit 2
websentinel scan -u https://example.com --header "Authorization: Bearer $TOKEN"
websentinel checks
websentinel version
websentinel scan --help
```

Private, loopback, or lab targets are refused by default. To scan a local lab target you are authorized to assess, explicitly allow it:

```bash
websentinel scan -u http://127.0.0.1:8080 --allow-private
```

The complete option list is available with `websentinel scan --help`.

## Configuration

WebSentinel reads configuration from `.websentinel.yml`, `websentinel.yaml`, or `websentinel.yml` in the current directory, in that order. Pass `--config PATH` to select a specific file. The repository includes [`websentinel.yaml`](websentinel.yaml) with the default timeout, concurrency, rate limit, crawl limits, user agent, redirect behavior, response size limit, TLS verification, and output format.

Command-line options override corresponding configuration values. Review configuration before scanning, especially when changing crawl limits or request rate.

## Scan profiles and checks

Profiles provide presets for check selection and crawl limits:

| Profile | Behavior |
| --- | --- |
| `quick` | Small header, cookie, information, and CORS check set; no crawl |
| `standard` | Default check set; no crawl |
| `deep` | Default check set with controlled crawling and larger page/depth limits |
| `headers` | Security header checks only |
| `tls` | TLS checks only |
| `crawl` | Selected page and discovery checks with controlled crawling |
| `api` | Information, CORS, method, and discovery checks |

Use `--checks` to select checks directly. The available IDs are listed by `websentinel checks`. The injection check is off by default and runs only when selected explicitly.

## Reports and exit codes

Reports include findings, target and scan metadata, evidence, and remediation guidance. Use `--severity`, `--confidence`, and `--check-id` to filter findings in the report.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed without HIGH or CRITICAL findings |
| `1` | Scan completed with HIGH or CRITICAL findings |
| `2` | Invalid arguments, invalid target, or configuration error |
| `3` | Target/network error or interruption |
| `4` | Internal error |

## Development

Install development dependencies and run the test suite from the project root:

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

The integration tests use a local fixture server; they do not scan public websites.

## Project layout

```text
websentinel/
  cli.py                 Command-line interface
  scanner.py             Scan orchestration
  checks.py              Check registry and profile definitions
  config.py              Configuration loading and defaults
  http/client.py         Async HTTP engine
  analyzers/             Individual security analyzers
  crawler/               Controlled same-origin crawler
  core/                  Target scope controls
  engine/                Finding correlation and deduplication
  reporting/             Terminal, JSON, HTML, CSV, and SARIF output
  utils/                 URL, logging, and timing helpers
tests/                    Unit and local-fixture integration tests
```

## Scope and limitations

- Most analysis is passive. URL parameters are observed, not attacked. The optional reflection canary uses a harmless marker and does not attempt exploitation.
- Crawl scope defaults to the same origin. Subdomain scope must be requested explicitly; private addresses require `--allow-private`.
- TLS inspection examines the certificate and protocol negotiated by a normal handshake; it does not enumerate cipher suites.
- JavaScript is analyzed as text and is not executed in a browser. Client-rendered content may not be visible.
- Findings are indicators for authorized review, not proof that a site is exploitable. Missing controls and advertised methods are reported with calibrated confidence.

## License

MIT. See [LICENSE](LICENSE).
