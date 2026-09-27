"""CORS header analysis: evaluates cross-origin resource sharing policies."""
from __future__ import annotations

from websentinel.models import Confidence, Finding, Response, Severity


def analyze_cors(resp: Response) -> list[Finding]:
    h = resp.headers
    acao = h.get("access-control-allow-origin")
    if not acao:
        return []
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    findings = []
    trimmed_acao = acao.strip()

    if trimmed_acao == "*":
        findings.append(
            Finding(
                id="CORS-WILDCARD",
                title="CORS allows any origin (*)",
                category="CORS",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                url=resp.final_url,
                description=(
                    "Access-Control-Allow-Origin: * permits cross-origin reads "
                    "of this response. Browsers ignore credentials with '*', so "
                    "exploitability depends on whether the response contains "
                    "non-public data."
                    + (
                        " Server also sent Access-Control-Allow-Credentials: true; "
                        "modern browsers reject this invalid combination."
                        if acac
                        else ""
                    )
                ),
                impact="Any website can read this response cross-origin.",
                evidence=f"Access-Control-Allow-Origin: {acao}; credentials={acac}",
                remediation="Restrict allowed origins to an explicit allowlist.",
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
            )
        )
    elif trimmed_acao.lower() == "null":
        findings.append(
            Finding(
                id="CORS-NULL-ORIGIN",
                title="CORS allows 'null' origin",
                category="CORS",
                severity=Severity.HIGH if acac else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=resp.final_url,
                description=(
                    "Access-Control-Allow-Origin is set to 'null'. Sandboxed iframes "
                    "or local files send Origin: null, allowing potential cross-origin access."
                ),
                impact="Untrusted sandboxed contexts can read response data.",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                remediation="Never allow 'null' in Access-Control-Allow-Origin.",
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
            )
        )
    elif acac:
        findings.append(
            Finding(
                id="CORS-REFLECT-CREDS",
                title="CORS origin configuration with credentials",
                category="CORS",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                url=resp.final_url,
                description=(
                    f"Server allows credentials with origin '{acao}'. In passive "
                    "assessment without sending varying Origin headers, this indicates "
                    "a credentialed CORS policy. Verify manually whether arbitrary "
                    "request origins are dynamically reflected."
                ),
                impact="Potential cross-origin data theft if origin validation is permissive.",
                evidence=f"ACAO: {acao}, ACAC: true",
                remediation="Strictly validate origins against a server-side allowlist.",
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
            )
        )
    return findings
