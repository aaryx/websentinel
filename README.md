# WebSentinel

[![Quality gates](https://github.com/aaryx/websentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/aaryx/websentinel/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A bounded, evidence-oriented CLI for authorized web security assessment.**

WebSentinel inspects HTTP responses, security headers, cookies, TLS certificates,
CORS policies, HTML, and JavaScript. It produces actionable findings with severity,
confidence, evidence, remediation, and applicable CWE/OWASP mappings.

Use it only against websites you own or are explicitly authorized to assess.
Most checks are passive. Optional crawling and a harmless reflection canary are
bounded; the tool does not exploit vulnerabilities or submit forms.

## Capabilities

See the [changelog](CHANGELOG.md) for the latest changes and implementation commits.

| Area | Coverage |
| --- | --- |
| Transport | HTTP/HTTPS posture, certificate validation and expiry, negotiated TLS version |
| Browser controls | Missing or ineffective security headers, CSP indicators, framing controls |
| Cookies | Secure, HttpOnly, SameSite, cookie-prefix constraints, domain scope |
| Application exposure | CORS, advertised HTTP methods, technology/version disclosure |
| HTML and JavaScript | Form transport, mixed content, directory listings, script endpoint strings, source-map references, credential-shaped values |
| Discovery | robots.txt, sitemap.xml, security.txt, optional scope-controlled crawling |
| Reporting | Terminal, JSON, HTML, CSV, and SARIF 2.1.0; deduplication and evidence-based correlation |

### Operational controls

- Connection pooling, bounded concurrency, total fetch deadlines, retries, redirect
  limits, response-body caps, and a shared HTTP request budget.
- Scope checks before requests; direct connections pin validated DNS addresses
  while retaining the original Host header and TLS hostname verification.
- Consistent Unicode hostname normalization and cross-origin credential handling.
- Per-check execution states and reasons; `--fail-on-incomplete` for CI gating.
- Shared output redaction and atomic report replacement.
- Structured output on stdout, progress/status on stderr, and stable exit codes.

## Installation

Requires **Python 3.11 or newer**. From the repository root:

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m websentinel --version
```

You can activate the environment with `.\.venv\Scripts\Activate.ps1` to use the
`websentinel` command directly.

### macOS and Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
websentinel --version
```

Use `python -m websentinel` as an alternative to the installed entry point.

## Quick start

```bash
# Assess an authorized target
websentinel scan -u https://example.com

# Select a profile or individual checks
websentinel scan -u https://example.com --profile quick
websentinel scan -u https://example.com --checks headers,cookies,cors

# Enable bounded crawling
websentinel scan -u https://example.com --crawl --depth 2 --max-pages 30 --max-requests 100

# Save reports
websentinel scan -u https://example.com --format json -o report.json
websentinel scan -u https://example.com --format html -o report.html
websentinel scan -u https://example.com --format sarif -o report.sarif

# Require complete execution of the selected checks
websentinel scan -u https://example.com --checks headers,cookies --fail-on-incomplete --format json

# Inspect available options
websentinel checks
websentinel scan --help
```

Private/loopback targets require an explicit opt-in:

```bash
websentinel scan -u http://127.0.0.1:8080 --allow-private
```

For authenticated assessments, pass repeatable `--header "Name: value"` options.
For example, in a POSIX shell: `--header "Authorization: Bearer $TOKEN"`;
in PowerShell: `--header "Authorization: Bearer $env:TOKEN"`.

## Configuration and profiles

Configuration discovery order is `.websentinel.yml`, `websentinel.yaml`, then
`websentinel.yml` in the current directory. Use `--config PATH` to select a file.
The included [websentinel.yaml](websentinel.yaml) documents basic defaults.
Profiles supply presets; explicit CLI values take precedence.

| Profile | Behavior |
| --- | --- |
| `quick` | Headers, cookies, information disclosure, and CORS; no crawl |
| `standard` | Default check set; no crawl |
| `deep` | Default check set with increased crawl depth/page limits |
| `headers` | Security-header checks |
| `tls` | TLS/certificate checks |
| `crawl` | Page and discovery checks with controlled crawling |
| `api` | Information, CORS, method, and discovery checks |

The reflection canary is off by default. Select `--checks injection` explicitly;
it uses unique alphanumeric markers and is capped at ten probes.

## Reports and CI integration

JSON exposes `scan.completion` (`complete`, `partial`, or `failed`) and `scan.checks`
with execution states and reasons. Terminal/HTML display execution status; SARIF
includes it in invocation properties. CSV includes completion on finding rows;
use JSON/SARIF when full metadata is needed, including scans with zero findings.

`complete` describes execution within configured scope/check limits. It is not a
claim that the target is vulnerability-free or that every page was assessed.

| Exit code | Meaning |
| --- | --- |
| `0` | No HIGH/CRITICAL findings and no fatal scan error; use `--fail-on-incomplete` to also reject partial coverage |
| `1` | HIGH or CRITICAL findings detected |
| `2` | Invalid arguments, target, configuration, or report output error |
| `3` | Target/network failure, interruption, or incomplete coverage with `--fail-on-incomplete` |
| `4` | Internal error |

`--severity`, `--confidence`, and `--check-id` filter report contents, not the
underlying findings exit status. Explicit `--format` overrides filename inference.
`--quiet` suppresses progress/status while preserving requested structured stdout.
Diagnostic reports can still be produced when a scan fails.

## Validation

Recorded local validation on **2026-09-28**:

| Check | Result |
| --- | --- |
| Strict offline suite | 267 tests passed on Windows/Python 3.14 |
| Coverage | 94.15% statements; 87.50% branches; 92.19% combined |
| Compatibility | Python 3.11 with declared minimum direct dependencies tested |
| Detection conformance | 35 internal labelled cases and 13 adapted MDN Observatory cases |
| Five-minute endurance run | 15,070 fetches; zero unexpected results; zero connections left open |
| Artifact checks | Wheel build, checksum manifest, isolated installed-CLI smoke test |

These are point-in-time results, not universal accuracy or certification claims.
The CI badge above reflects hosted workflow status. See [TESTING.md](TESTING.md)
for reproduction commands and [evidence/endurance.json](evidence/endurance.json)
for recorded endurance measurements.

## Development

```bash
python -m pip install -e .
python -m pip install -r requirements-dev.txt
python -m pytest -q -m "not online" --cov=websentinel --cov-branch --cov-fail-under=90
python -m ruff check websentinel tests scripts
python -m pip check
```

The offline suite uses mocks and local servers. The optional `online` test fetches
the published SARIF schema; dependency audits also require network access.

| Documentation | Purpose |
| --- | --- |
| [TESTING.md](TESTING.md) | Test commands, compatibility, coverage, and endurance evidence |
| [BENCHMARK.md](BENCHMARK.md) | Internal labelled detection corpus and methodology |
| [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md) | External fixture attribution and mapping limits |
| [SECURITY.md](SECURITY.md) | Trust boundaries and vulnerability reporting |
| [RELEASING.md](RELEASING.md) | Maintainer-controlled, attested release candidates |

## Scope and limitations

- Findings are review indicators, not proof of exploitability. JavaScript is
  inspected as text; client-rendered pages are not executed in a browser.
- TLS inspection examines a normal handshake, not a full cipher/protocol matrix.
  Its standalone handshake is additional to the HTTP request budget.
- HTTPS CONNECT proxies control tunnel DNS/routing and must be trusted. Environment
  proxies are ignored; standalone TLS inspection is skipped with an explicit proxy.
- Direct DNS pinning uses the first validated address without automatic address
  failover. A timed-out worker wait cannot cancel the operating system resolver.
- Body decoding supports identity, gzip, and zlib-wrapped deflate. Unsupported
  encodings are rejected. The total fetch timeout includes rate-limit waits.
- Crawling uses the standard-library robots parser with limited wildcard semantics.
  The requested root page and discovery documents are fetched explicitly.
- Redaction covers supported credential patterns and supplied secrets, not every
  unknown secret format. Raw in-memory responses remain sensitive.

## License

Application code is [MIT licensed](LICENSE). The adapted external test file
`tests/test_external_observatory_cases.py` is MPL-2.0; see
[EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md) for attribution.
