"""Safe reflection canary: appends a harmless unique marker to URL parameters
and checks whether it reflects in the response HTML. Never injects payloads
with metacharacters. Strictly budgeted.
"""
from __future__ import annotations

import random
import string
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from websentinel.models import Confidence, Finding, Severity

_DEFAULT_MARKER = "ws" + "".join(random.choices(string.ascii_lowercase, k=8))


def generate_marker() -> str:
    """Generate a unique harmless alphanumeric marker for canary reflection testing."""
    return "ws" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


def build_probe(url: str, params: list[str], marker: str | None = None) -> str:
    m = marker or _DEFAULT_MARKER
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    q = [(k, m) if k in params else (k, v) for k, v in q]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def evaluate_probe(
    original_url: str,
    probed_url: str,
    body: str,
    marker: str | None = None,
    param: str | None = None,
) -> Finding | None:
    target_marker = marker or _DEFAULT_MARKER
    if not marker:
        # Try extracting marker from probed_url query string
        p = urlsplit(probed_url)
        for _, v in parse_qsl(p.query, keep_blank_values=True):
            if v and v.startswith("ws") and v in body:
                target_marker = v
                break

    if target_marker in body:
        return Finding(
            id="INJ-REFLECTION",
            title="Reflected input detected (harmless canary)",
            category="Injection",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            url=original_url,
            parameter=param,
            description=(
                "A harmless marker was reflected in the response. This is a "
                "pre-indicator for XSS only if the reflection is unencoded — manual "
                "verification required. No payload was used."
            ),
            impact="Potential input reflection point.",
            evidence=f"marker={target_marker!r} reflected in {probed_url}",
            remediation="Verify output encoding of reflected parameters.",
            tags=["safe-canary"],
        )
    return None
