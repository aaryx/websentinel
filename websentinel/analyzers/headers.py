"""Security header analysis with context-aware severity."""
from __future__ import annotations

from websentinel.models import Finding, Severity, Confidence, Response

# name -> (finding_id, default severity, remediation, cwe, owasp)
_EXPECTED: dict[str, tuple[str, Severity, str, str | None, str | None]] = {
    "content-security-policy": (
        "HDR-CSP-MISSING", Severity.MEDIUM,
        "Define a Content-Security-Policy to mitigate XSS and data injection.",
        "CWE-693", "A05:2021 Security Misconfiguration"),
    "strict-transport-security": (
        "HDR-HSTS-MISSING", Severity.MEDIUM,
        "Serve Strict-Transport-Security (max-age >= 15552000) on HTTPS.",
        "CWE-319", "A02:2021 Cryptographic Failures"),
    "x-frame-options": (
        "HDR-XFO-MISSING", Severity.LOW,
        "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.",
        "CWE-1021", "A05:2021 Security Misconfiguration"),
    "x-content-type-options": (
        "HDR-XCTO-MISSING", Severity.LOW,
        "Set X-Content-Type-Options: nosniff.",
        "CWE-693", "A05:2021 Security Misconfiguration"),
    "referrer-policy": (
        "HDR-RP-MISSING", Severity.LOW,
        "Set Referrer-Policy (e.g. strict-origin-when-cross-origin).",
        None, None),
    "permissions-policy": (
        "HDR-PP-MISSING", Severity.INFO,
        "Consider a Permissions-Policy to restrict browser features.",
        None, None),
    "cross-origin-opener-policy": (
        "HDR-COOP-MISSING", Severity.INFO,
        "Consider Cross-Origin-Opener-Policy: same-origin.",
        None, None),
    "cross-origin-resource-policy": (
        "HDR-CORP-MISSING", Severity.INFO,
        "Consider Cross-Origin-Resource-Policy where appropriate.",
        None, None),
    "cross-origin-embedder-policy": (
        "HDR-COEP-MISSING", Severity.INFO,
        "Consider Cross-Origin-Embedder-Policy where appropriate.",
        None, None),
}

_HTMLISH = ("text/html", "application/xhtml")


def analyze_headers(resp: Response, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    h = resp.headers
    htmlish = any(t in resp.content_type.lower() for t in _HTMLISH)

    for name, (fid, sev, remediation, cwe, owasp) in _EXPECTED.items():
        if name in h:
            continue
        s = sev
        # Context rules: missing headers on non-HTML (API/assets) matter less
        if not htmlish and name in ("content-security-policy",
                                    "x-frame-options",
                                    "x-content-type-options"):
            s = Severity.INFO
        if name == "strict-transport-security" and not is_https:
            continue  # HSTS is meaningless over plain HTTP; flagged by HTTPS check
        findings.append(Finding(
            id=fid, title=f"Missing {name} header",
            category="Security Headers", severity=s,
            confidence=Confidence.HIGH,
            url=resp.final_url,
            description=f"The {name} header is not set on this response. "
                        "This is a missing defense-in-depth control, not a "
                        "confirmed vulnerability.",
            impact="Reduced client-side protection.",
            evidence=f"GET {resp.final_url} -> {resp.status} (no {name})",
            remediation=remediation, cwe=cwe, owasp=owasp))

    # Weak CSP observation (present but permissive)
    csp = h.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp or "* " in csp
                or csp.strip().endswith("*")):
        findings.append(Finding(
            id="HDR-CSP-WEAK", title="Permissive Content-Security-Policy",
            category="Security Headers", severity=Severity.LOW,
            confidence=Confidence.MEDIUM, url=resp.final_url,
            description="CSP contains permissive directives "
                        "(unsafe-inline/unsafe-eval/wildcard).",
            impact="Weakened XSS mitigation.",
            evidence=csp[:300],
            remediation="Remove unsafe-inline/unsafe-eval; avoid wildcards.",
            cwe="CWE-693", owasp="A05:2021 Security Misconfiguration"))
    return findings
