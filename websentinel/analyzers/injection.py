"""Safe reflection canary: appends a harmless unique marker to URL parameters
and checks whether it reflects in the response HTML. Never injects payloads
with metacharacters. Strictly budgeted.

ponytail: only reflection (XSS pre-indicator) is implemented — SQLi/LFI/etc.
detection without destructive testing is too speculative to report honestly.
Upgrade path: error-pattern matching against canary responses.
"""
from __future__ import annotations

import random
import string
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from websentinel.models import Finding, Severity, Confidence

_MARKER = "ws" + "".join(random.choices(string.ascii_lowercase, k=8))


def build_probe(url: str, params: list[str]) -> str:
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    q = [(k, _MARKER) if k in params else (k, v) for k, v in q]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def evaluate_probe(original_url: str, probed_url: str, body: str
                   ) -> Finding | None:
    if _MARKER in body:
        return Finding(
            id="INJ-REFLECTION",
            title="Reflected input detected (harmless canary)",
            category="Injection", severity=Severity.LOW,
            confidence=Confidence.MEDIUM, url=original_url,
            description=f"A harmless marker was reflected in the response. "
                        "This is a pre-indicator for XSS only if the "
                        "reflection is unencoded — manual verification "
                        "required. No payload was used.",
            impact="Potential input reflection point.",
            evidence=f"marker={_MARKER!r} reflected in {probed_url}",
            remediation="Verify output encoding of reflected parameters.",
            tags=["safe-canary"])
    return None
