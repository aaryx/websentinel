"""Finding deduplication: merge identical issues across URLs into one
finding with an affected_urls list."""
from __future__ import annotations

import re

from websentinel.models import Finding, Severity, Confidence


def _key(f: Finding) -> tuple:
    # Same check + same parameter = one finding; per-URL differences are
    # merged into affected_urls.
    return (f.id, f.parameter, f.method)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple, Finding] = {}
    for f in findings:
        k = _key(f)
        if k not in by_key:
            f.affected_urls = list(dict.fromkeys(f.affected_urls + ([f.url] if f.url else [])))
            by_key[k] = f
            continue
        g = by_key[k]
        urls = list(dict.fromkeys(g.affected_urls + f.affected_urls + ([f.url] if f.url else [])))
        if (list(Severity).index(f.severity), list(Confidence).index(f.confidence)) > (
            list(Severity).index(g.severity), list(Confidence).index(g.confidence)
        ):
            by_key[k] = g = f
        g.affected_urls = urls

    for g in by_key.values():
        if len(g.affected_urls) > 1:
            suffix = f" Affects {len(g.affected_urls)} URLs (see affected_urls)."
            g.description = re.sub(r" Affects \d+ URLs \(see affected_urls\)\.", "", g.description) + suffix
    return list(by_key.values())
