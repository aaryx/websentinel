"""Finding correlation: raise priority only with combined evidence.
Never auto-escalates to CRITICAL."""
from __future__ import annotations

from websentinel.models import Finding, Severity, Confidence

_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
          Severity.CRITICAL]


def bump(sev: Severity, steps: int = 1, cap: Severity = Severity.HIGH
         ) -> Severity:
    i = min(_ORDER.index(sev) + steps, _ORDER.index(cap))
    return _ORDER[i]


def correlate(findings: list[Finding], is_https: bool) -> list[Finding]:
    ids = {f.id for f in findings}
    notes: list[str] = []

    if is_https and "HTML-INSECURE-FORM" in ids:
        cookie_ids = {"CK-NO-SECURE", "CK-NO-HTTPONLY"}
        insecure_urls = {f.url for f in findings if f.id == "HTML-INSECURE-FORM"}
        raised = False
        for f in findings:
            if f.id in cookie_ids and f.url in insecure_urls:
                f.severity = bump(f.severity)
                raised = True
        if raised:
            notes.append(
                "Login-form weaknesses combined with cookie attribute gaps raised "
                "affected cookie findings by one severity level (capped at HIGH).")

    if not is_https and "CK-NO-HTTPONLY" in ids:
        for f in findings:
            if f.id == "CK-NO-HTTPONLY":
                f.description += (" Correlated: target serves content over "
                                  "plain HTTP, increasing cookie exposure risk.")
        notes.append("Plain HTTP target increases impact of cookie findings.")

    if notes:
        findings.append(Finding(
            id="CORR-SUMMARY", title="Correlation notes",
            category="Correlation", severity=Severity.INFO,
            confidence=Confidence.HIGH, url="",
            description=" ".join(notes)))
    return findings
