"""Static analysis of same-origin JavaScript assets: endpoint strings,
sourcemap references, secret-like tokens (pattern-based, redacted)."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from websentinel.models import Finding, Severity, Confidence, Response

# ponytail: only high-precision token formats are flagged — entropy-only
# detection produces noise, contrary to spec. Add formats by appending here.
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."
                       r"[A-Za-z0-9_\-]{5,}\b")),
]
_URL_RE = re.compile(
    r"""["'`](/(?:api|v\d|graphql|rest)[A-Za-z0-9\-_/:.]{0,80})["'`]""")
_SOURCEMAP_RE = re.compile(r"sourceMappingURL=(\S+)")


def _redact(s: str) -> str:
    return s[:6] + "…[REDACTED]" if len(s) > 6 else "[REDACTED]"


def script_urls(resp: Response, scope) -> list[str]:
    if resp.error or "html" not in resp.content_type.lower():
        return []
    soup = BeautifulSoup(resp.body, "html.parser")
    out = []
    for t in soup.find_all("script", src=True):
        full = urljoin(resp.final_url, t["src"])
        if scope.allows(full):
            out.append(full)
    return out


def analyze_javascript(url: str, body: str) -> list[Finding]:
    findings: list[Finding] = []
    hit_kinds: dict[str, list[str]] = {}
    for kind, pat in _SECRET_PATTERNS:
        for m in pat.finditer(body):
            hit_kinds.setdefault(kind, set()).add(_redact(m.group(0)))
    for kind, samples in hit_kinds.items():
        conf = (Confidence.HIGH if kind in
                ("AWS access key", "GitHub token", "Slack token",
                 "Private key", "Google API key") else Confidence.MEDIUM)
        findings.append(Finding(
            id="JS-SECRET", title=f"Possible {kind} in JavaScript",
            category="Information Disclosure", severity=Severity.HIGH,
            confidence=conf, url=url,
            description=f"A {kind}-shaped value appears in a public script. "
                        "If live, it grants account access; verify validity "
                        "manually (not tested).",
            impact="Potential credential compromise.",
            evidence="; ".join(sorted(samples)[:3]),
            remediation="Revoke the credential; move secrets server-side.",
            cwe="CWE-798", owasp="A07:2021 Identification and Authentication "
                                 "Failures"))
    m = _SOURCEMAP_RE.search(body[-2000:])
    if m:
        findings.append(Finding(
            id="JS-SOURCEMAP", title="JavaScript source map reference",
            category="Information Disclosure", severity=Severity.LOW,
            confidence=Confidence.MEDIUM, url=url,
            description="Script references a source map; if accessible it "
                        "exposes original source.",
            impact="Aids reverse engineering and secret discovery.",
            evidence=f"sourceMappingURL={m.group(1)}",
            remediation="Do not publish .map files in production.",
            cwe="CWE-540", owasp="A05:2021 Security Misconfiguration"))
    return findings


def extract_js_endpoints(body: str) -> list[str]:
    return sorted(set(m.group(1) for m in _URL_RE.finditer(body)))[:50]
