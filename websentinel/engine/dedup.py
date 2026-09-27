"""Finding deduplication: merge identical issues across URLs into one
finding with an affected_urls list."""
from __future__ import annotations

from websentinel.models import Finding


def _key(f: Finding) -> tuple:
    # Same check + same parameter = one finding; per-URL differences are
    # merged into affected_urls.
    return (f.id, f.parameter)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple, Finding] = {}
    for f in findings:
        k = _key(f)
        if k not in by_key:
            f.affected_urls = [f.url] if f.url else []
            by_key[k] = f
            continue
        g = by_key[k]
        if f.url and f.url not in g.affected_urls:
            g.affected_urls.append(f.url)

    for g in by_key.values():
        if len(g.affected_urls) > 1:
            suffix = f" Affects {len(g.affected_urls)} URLs (see affected_urls)."
            if "Affects " not in g.description:
                g.description += suffix
            g.url = g.affected_urls[0]
    return list(by_key.values())
