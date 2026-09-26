"""HTTP method analysis via OPTIONS — advertised only, not exploited."""
from __future__ import annotations

from websentinel.models import Finding, Severity, Confidence, Response

_DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def analyze_methods(url: str, allow_header: str | None) -> list[Finding]:
    if not allow_header:
        return []
    advertised = {m.strip().upper()
                  for m in allow_header.split(",") if m.strip()}
    risky = advertised & _DANGEROUS
    if not risky:
        return []
    return [Finding(
        id="MTH-ADVERTISED",
        title=f"Potentially risky methods advertised: {sorted(risky)}",
        category="HTTP Methods", severity=Severity.LOW,
        confidence=Confidence.LOW, url=url,
        description=f"OPTIONS advertises Allow: {allow_header}. This only "
                    "means the methods are advertised — it is NOT confirmed "
                    "that they are usable. Manual authorized verification "
                    "would be required.",
        impact="If actually enabled, methods like PUT/DELETE/TRACE can be abused.",
        evidence=f"Allow: {allow_header}",
        remediation="Disable unused HTTP methods on the server.",
        cwe="CWE-650", owasp="A05:2021 Security Misconfiguration")]
