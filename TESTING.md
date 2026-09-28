# Testing and validation

## Local quality gates

From an activated project environment:

```console
python -m pip install -e .
python -m pip install -r requirements-dev.txt
python -m pytest -q -m "not online" --cov=websentinel --cov-branch --cov-fail-under=90 --cov-report=term-missing --cov-report=xml --junitxml=test-results.xml
python -m ruff check websentinel tests scripts
python -m pip check
python -m pip_audit --local --skip-editable --progress-spinner off
python -m pytest -q -m online
```

Warnings are test failures. Ordinary tests use mocks/local servers and disable
public DNS. The separate `online` check validates SARIF against its published
schema. Dependency audits query an advisory service; their results are time-dependent.
The editable project is excluded from the advisory lookup, not independently audited.
Ruff checks correctness-oriented rules rather than imposing a formatting standard.

## Recorded results

Validation date: **2026-09-28**. Local platform: Windows AMD64.

| Gate | Evidence |
| --- | --- |
| Python 3.14.3 offline suite | 267 tests passed |
| Python 3.11.16 minimum-dependency compatibility | 265-test suite and the two subsequent workflow/manifest tests passed |
| Statement coverage | 1,804 / 1,916 — 94.15% |
| Branch coverage | 700 / 800 — 87.50% |
| Combined coverage | 92.19%; enforced threshold 90% |
| SARIF 2.1.0 published schema | Passed |
| Correctness lint / dependency consistency | Passed |
| Development-environment advisory audit | No known vulnerabilities reported |
| Wheel / checksum manifest / isolated CLI smoke | Passed |

Minimum direct dependencies are recorded in `constraints-minimum.txt`: HTTPX
0.27.0, Beautiful Soup 4.12.0, Rich 13.0.0, and PyYAML 6.0. Test them in a separate
Python 3.11 environment:

```console
python -m pip install -r requirements-dev.txt -c constraints-minimum.txt
python -m pytest -q -m "not online"
```

Minimum-version compatibility is not a recommendation to deploy older packages
without an up-to-date advisory audit.

## Test coverage

- Real TLS: trusted CA, untrusted CA, hostname mismatch, expiry warning, SNI,
  explicit unverified mode, and certificate inspection errors.
- Real HTTP/HTTPS CONNECT proxies and malformed HTTP wire responses.
- Scope/IDNA consistency, private-address encodings, credential forwarding boundaries,
  JSON/URL redaction, and XML entity rejection.
- Slow-drip deadlines, retries, cancellation cleanup, gzip members/corruption,
  body truncation, concurrency, and request-budget enforcement.
- All five report formats, CLI precedence/exit codes, incomplete-coverage gating,
  and failure-safe atomic report replacement.
- Generated hostile URL/header/cookie/HTML/XML inputs. Generated examples belong
  to their property tests; they are not counted as separate pytest test cases.
- A 35-case internal labelled corpus and 13 adapted MDN Observatory cases. See
  [BENCHMARK.md](BENCHMARK.md) and [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md).

Coverage measures exercised code, not real-world detection accuracy. External
fixtures are conformance inputs; they do not constitute independent review.

## Endurance and resource checks

```console
python scripts/endurance.py --seconds 300 --concurrency 10 --output evidence/endurance.json
```

The harness accepts no external target: it creates a loopback server and mixes
successful responses, redirects, compressed bodies, delays, and disconnects.

Recorded [endurance results](evidence/endurance.json):

- 300.16 seconds, 15,070 fetches, 18,084 wire requests, 302 client cycles.
- Zero unexpected results, server errors, or active connections after close.
- 56,263 bytes of post-warm-up traced allocation growth, below the 10 MB gate.

These are Python traced allocations, not RSS. The harness retains latency samples
and performs garbage collection at sampling points. Loopback results are not a
production-throughput benchmark or a substitute for days-long endurance testing.
The ordinary suite also verifies a 32 MB expanded gzip response against a 4 KiB
body cap and a 2 MB traced-allocation ceiling.

## Continuous integration and artifacts

`.github/workflows/tests.yml` defines Python 3.11–3.14 on Windows, Linux, and macOS,
plus minimum-dependency, advisory/schema, and wheel jobs. Endurance is available on
manual dispatch. JUnit/Cobertura reports and built wheels are workflow artifacts.
Check actual [workflow runs](https://github.com/aaryx/websentinel/actions/workflows/tests.yml)
for hosted-platform status; local measurements do not imply every matrix job passed.

Release candidates use a separate manual workflow. See [RELEASING.md](RELEASING.md)
for tag/version checks, checksums, provenance attestations, and required maintainer
environment settings. A workflow definition alone is not proof of a signed release.

## Remaining validation limits

Independent security review, representative held-out detection benchmarks, longer
production-like endurance runs, broad IPv6/address-failover coverage, and complete
browser-policy semantics remain outside the recorded evidence. Runtime dependencies
use version ranges, not a reproducible release lock. See [SECURITY.md](SECURITY.md)
and the README for operational boundaries.
