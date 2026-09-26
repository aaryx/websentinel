"""CORS header analysis."""
from __future__ import annotations

from websentinel.models import Finding, Severity, Confidence, Response


def analyze_cors(resp: Response) -> list[Finding]:
    h = resp.headers
    acao = h.get("access-control-allow-origin")
    if not acao:
        return []
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    findings = []
    if acao.strip() == "*":
        findings.append(Finding(
            id="CORS-WILDCARD", title="CORS allows any origin (*)",
            category="CORS", severity=Severity.MEDIUM if not acac else Severity.INFO,
            confidence=Confidence.MEDIUM, url=resp.final_url,
            description="Access-Control-Allow-Origin: * permits cross-origin reads "
                        "of this response. Browsers ignore credentials with '*', so "
                        "exploitability depends on whether the response contains "
                        "non-public data.",
            impact="Any website can read this response cross-origin.",
            evidence=f"Access-Control-Allow-Origin: {acao}; credentials={acac}",
            remediation="Restrict allowed origins to an allowlist.",
            cwe="CWE-942", owasp="A05:2021 Security Misconfiguration"))
    elif acac:
        findings.append(Finding(
            id="CORS-REFLECT-CREDS",
            title="CORS origin reflection with credentials",
            category="CORS", severity=Severity.MEDIUM,
            confidence=Confidence.LOW, url=resp.final_url,
            description="Server echoes an origin in ACAO while allowing credentials. "
                        "If the echo reflects arbitrary request origins this is "
                        "exploitable; verify manually.",
            impact="Potential cross-origin data theft with user credentials.",
            evidence=f"ACAO: {acao}, ACAC: true",
            remediation="Strictly validate origins against an allowlist.",
            cwe="CWE-942", owasp="A05:2021 Security Misconfiguration"))
    return findings
