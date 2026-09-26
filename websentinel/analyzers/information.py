"""Information disclosure via version/framework headers."""
from __future__ import annotations

import re

from websentinel.models import Finding, Severity, Confidence, Response

_VERSION_RE = re.compile(r"\d+(\.\d+)+")
_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
            "x-generator", "x-drupal-cache", "x-backend-server", "via",
            "x-debug-token", "x-debug-token-link")


def analyze_information(resp: Response) -> list[Finding]:
    findings: list[Finding] = []
    for name in _HEADERS:
        val = resp.headers.get(name)
        if not val:
            continue
        has_version = bool(_VERSION_RE.search(val))
        debugish = "debug" in name
        sev = Severity.LOW if (has_version or debugish) else Severity.INFO
        findings.append(Finding(
            id=f"INFO-{name.upper().replace('-', '_')}",
            title=f"Information disclosure: {name}",
            category="Information Disclosure", severity=sev,
            confidence=Confidence.HIGH if has_version else Confidence.MEDIUM,
            url=resp.final_url,
            description=f"Header '{name}: {val}' reveals technology"
                        + (" and exact version." if has_version else " details.")
                        + " Disclosure alone is not a vulnerability.",
            impact="Aids attacker fingerprinting; versioned info enables "
                   "targeted CVE lookups.",
            evidence=f"{name}: {val}",
            remediation="Remove or genericize version-revealing headers.",
            cwe="CWE-200" if has_version else None,
            owasp="A05:2021 Security Misconfiguration"))
    return findings
