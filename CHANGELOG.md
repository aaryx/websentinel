# Changelog

## Unreleased

### Implementation commits

- [`4499966`](https://github.com/aaryx/websentinel/commit/4499966) — Harden scanning boundaries and report integrity; add detection and adversarial regression coverage.
- [`46ff3e1`](https://github.com/aaryx/websentinel/commit/46ff3e1) — Add quality gates, minimum-dependency checks, endurance tooling, and attested release candidates.

### Security and reliability

- Enforce request scope and validated DNS destinations; align Unicode hostname
  handling with the HTTP client and retain TLS hostname verification.
- Bound total fetch duration, redirects, retries, decompression, and crawl queues.
- Prevent cross-origin forwarding of supplied credentials; redact supported secrets
  consistently across logs and reports.
- Write reports atomically and expose per-check completion with CI failure gating.

### Detection correctness

- Correct cookie attribute/prefix, CORS case-sensitivity, CSP, and HSTS evaluation.
- Respect document base URLs, preserve encoded/repeated-slash routes, and use final
  HTTPS origins for page analysis and crawling.
- Reject sitemap DTD/entities, distinguish security.txt absence from request failure,
  preserve TLS diagnostics, and retain strongest deduplicated evidence.

### Validation and automation

- Add strict adversarial, TLS/proxy, property-based, CLI, and resource-limit tests.
- Add internal and externally attributed detection conformance cases.
- Add a reproducible endurance harness, isolated-wheel smoke checks, and checksums.
- Configure pinned cross-platform CI and manual attested release candidates.

### Documentation

- Refresh installation, CLI/CI examples, validation evidence, security boundaries,
  benchmark attribution, and maintainer release procedures.
