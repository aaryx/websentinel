# Security model and vulnerability reporting

## Intended use

WebSentinel performs authorized passive HTTP assessments, bounded crawling, and
an explicitly selected harmless reflection canary. It is not an exploitation
framework. Findings are observations with severity/confidence, not proof of an
exploitable condition or a complete security assessment.

## Trust boundaries

- Target URLs, redirects, HTML, headers, scripts, and XML are untrusted input.
- Unicode hosts use the same IDNA conversion as the HTTP client. Sitemap XML
  containing DTD/entity declarations is rejected rather than expanded.
- Direct TCP destinations are validated and DNS-pinned. HTTPS preserves hostname
  verification. `--allow-private` explicitly authorizes the target's private host.
- An explicitly configured HTTPS proxy controls CONNECT DNS/routing and is a
  trusted component. Environment proxy settings are ignored.
- All five renderers sanitize detached report snapshots. Sensitive query values,
  supplied header secrets, response cookie values, URL passwords, and supported
  credential signatures are redacted. Arbitrary unknown secrets cannot be
  recognized universally. Raw in-memory responses remain sensitive.
- Reports use temporary files in the destination directory, flush/fsync, and
  atomic replacement. Existing reports survive write/replace failures. This does
  not guarantee filesystem durability against every OS/power-loss scenario.
- Limits bound requests, concurrency, crawl pages, body decoding, retries, and
  fetch duration. Timing out a DNS wait cannot terminate OS resolver work.

## Reporting a vulnerability

Use the repository's GitHub **Security → Report a vulnerability** facility if
enabled, or contact the repository maintainer privately through their published
GitHub contact details. Do not put live credentials or private target data in a
public issue. Include the affected version, a minimal local reproduction, expected
behavior, actual behavior, and impact. No response-time guarantee is currently
published.

## Security maintenance

Current development is tested on Python 3.11+; the latest maintained release is
the supported line. CI runs dependency advisory checks, minimum direct-dependency
compatibility, hostile-input tests, TLS/proxy fixtures, and coverage gates. Review
actual CI results for each release. No claim of OWASP, ISO, SOC 2, or NIST
certification is made by this repository.

The manual candidate workflow produces signed build-provenance attestations only
when executed with GitHub permissions. Environment reviewer/tag protection must
be configured by maintainers. See `RELEASING.md`; local files are not evidence of
an executed signing process.
