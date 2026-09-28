"""Security header analysis with context-aware severity."""
from __future__ import annotations

import re

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
    csp = h.get("content-security-policy", "")
    directives = {}
    for part in csp.split(";"):
        bits = part.split()
        if bits:
            directives.setdefault(bits[0].lower(), [b.lower() for b in bits[1:]])
    frame_sources = directives.get("frame-ancestors", [])
    protected_frames = bool(frame_sources) and "*" not in frame_sources

    for name, (fid, sev, remediation, cwe, owasp) in _EXPECTED.items():
        if h.get(name, "").strip():
            continue
        if name == "x-frame-options" and protected_frames:
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

    # CSP value analysis (present but weak / incomplete)
    if csp:
        issues: list[str] = []
        script_src = directives.get("script-src",
                                    directives.get("default-src", []))
        nonce_or_hash = any(re.fullmatch(r"'(?:nonce-|sha(?:256|384|512)-)[a-z0-9+/_-]+=*'", v)
                            for v in script_src)
        bad = [v for v in ("'unsafe-inline'", "'unsafe-eval'", "*")
               if v in script_src and not (v == "'unsafe-inline'" and nonce_or_hash)
               and not (v == "*" and nonce_or_hash and "'strict-dynamic'" in script_src)]
        if bad:
            issues.append(f"permissive script-src ({' '.join(bad)})")
        if not directives.get("default-src"):
            issues.append("missing default-src directive")
        if "*" in directives.get("object-src", ["'none'"]) and \
                "object-src" in directives:
            issues.append("object-src allows any origin")
        for name in ("script-src-elem", "script-src-attr"):
            sources = directives.get(name, [])
            if "*" in sources or "'unsafe-inline'" in sources:
                issues.append(f"permissive {name}")
        if "frame-ancestors" not in directives and "x-frame-options" not in h:
            issues.append("no frame-ancestors (and no X-Frame-Options) — "
                          "clickjacking protection relies on neither")
        if issues:
            sev = Severity.LOW
            if "'unsafe-eval'" in str(script_src) or "*" in script_src:
                sev = Severity.MEDIUM
            findings.append(Finding(
                id="HDR-CSP-WEAK", title="Weak or incomplete "
                "Content-Security-Policy",
                category="Security Headers", severity=sev,
                confidence=Confidence.MEDIUM, url=resp.final_url,
                description="; ".join(issues).capitalize() + ".",
                impact="Reduced XSS / clickjacking mitigation strength.",
                evidence=csp[:300],
                remediation="Set default-src 'self'; use nonces/hashes instead "
                            "of unsafe-inline; add frame-ancestors.",
                cwe="CWE-693", owasp="A05:2021 Security Misconfiguration"))
    invalid = []
    if h.get("x-content-type-options") and h["x-content-type-options"].strip().lower() != "nosniff":
        invalid.append(("XCTO", "x-content-type-options", "Use X-Content-Type-Options: nosniff."))
    if h.get("x-frame-options") and not protected_frames and h["x-frame-options"].strip().upper() not in ("DENY", "SAMEORIGIN"):
        invalid.append(("XFO", "x-frame-options", "Use DENY, SAMEORIGIN, or CSP frame-ancestors."))
    if is_https and h.get("strict-transport-security"):
        ages = re.findall(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?=;|$)', h["strict-transport-security"], re.I)
        if "," in h["strict-transport-security"] or len(ages) != 1 or not ages[0].strip("0"):
            invalid.append(("HSTS", "strict-transport-security", "Set one positive max-age (at least 15552000 recommended)."))
        elif len(ages[0].lstrip("0")) <= 8 and int(ages[0].lstrip("0")) < 15_552_000:
            findings.append(Finding(
                id="HDR-HSTS-SHORT", title="HSTS max-age is less than six months",
                category="Security Headers", severity=Severity.LOW, confidence=Confidence.HIGH,
                url=resp.final_url, description="The HSTS policy expires sooner than the recommended six-month minimum.",
                evidence=h["strict-transport-security"][:300], remediation="Use max-age >= 15552000 after validating HTTPS deployment.",
                cwe="CWE-319"))
    for suffix, name, remediation in invalid:
        findings.append(Finding(
            id=f"HDR-{suffix}-INVALID", title=f"Ineffective {name} header",
            category="Security Headers", severity=Severity.LOW,
            confidence=Confidence.HIGH, url=resp.final_url,
            description=f"The {name} header is present but does not enable the expected protection.",
            evidence=h[name][:300], remediation=remediation, cwe="CWE-693"))
    return findings
