"""Set-Cookie security attribute analysis."""
from __future__ import annotations

from http.cookies import SimpleCookie

from websentinel.models import Confidence, Finding, Response, Severity


def sessionish_cookie(name: str) -> bool:
    return any(k in name.lower() for k in ("sess", "auth", "token", "jwt", "login", "sid"))


def _mk(
    fid: str,
    title: str,
    sev: Severity,
    conf: Confidence,
    url: str,
    cookie: str,
    desc: str,
    impact: str,
    remediation: str,
    evidence: str,
    cwe: str | None = None,
    owasp: str | None = None,
) -> Finding:
    return Finding(
        id=fid,
        title=title,
        category="Cookies",
        severity=sev,
        confidence=conf,
        url=url,
        parameter=cookie,
        description=desc,
        impact=impact,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        owasp=owasp,
    )


def analyze_cookies(resp: Response, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    for raw in resp.set_cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for morsel in cookie.values():
            name = morsel.key
            kv = {k.lower() for k in morsel.keys() if morsel[k]}
            lower = raw.lower()
            has = lambda a: a in kv or a in lower

            # Sanitized attribute summary without leaking raw secret value
            attrs = [f"{k}={morsel[k]}" for k in morsel.keys() if morsel[k]]
            safe_evidence = f"Set-Cookie: {name}=[REDACTED]" + (f"; {'; '.join(attrs)}" if attrs else "")

            sessionish = sessionish_cookie(name)
            if is_https and not has("secure"):
                findings.append(
                    _mk(
                        "CK-NO-SECURE",
                        f"Cookie '{name}' missing Secure",
                        Severity.MEDIUM if sessionish else Severity.LOW,
                        Confidence.HIGH,
                        resp.final_url,
                        name,
                        (
                            f"{'Session/auth cookie' if sessionish else 'Cookie'} set over HTTPS "
                            "without the Secure attribute can be sent over plain HTTP."
                        ),
                        "Cookie may be exposed to network eavesdropping.",
                        "Add the Secure attribute.",
                        safe_evidence,
                        "CWE-614",
                        "A05:2021 Security Misconfiguration",
                    )
                )

            if sessionish and not has("httponly"):
                findings.append(
                    _mk(
                        "CK-NO-HTTPONLY",
                        f"Cookie '{name}' missing HttpOnly",
                        Severity.LOW,
                        Confidence.MEDIUM,
                        resp.final_url,
                        name,
                        (
                            f"Cookie '{name}' appears session-related but lacks HttpOnly. "
                            "This is only exploitable if XSS exists."
                        ),
                        "Readable by JavaScript via document.cookie.",
                        "Add HttpOnly unless client-side JS intentionally requires access.",
                        safe_evidence,
                        "CWE-1004",
                        "A05:2021 Security Misconfiguration",
                    )
                )

            samesite_none = "samesite=none" in lower.replace(" ", "")
            if samesite_none and not has("secure"):
                findings.append(
                    _mk(
                        "CK-SAMESITE-NONE-INSECURE",
                        f"Cookie '{name}': SameSite=None without Secure",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        resp.final_url,
                        name,
                        (
                            "SameSite=None without Secure is rejected by modern browsers "
                            "and indicates misconfiguration."
                        ),
                        "Cookie will be silently rejected or exposed cross-site insecurely.",
                        "Add Secure when using SameSite=None.",
                        safe_evidence,
                        "CWE-614",
                        "A05:2021 Security Misconfiguration",
                    )
                )
            elif not has("samesite"):
                findings.append(
                    _mk(
                        "CK-NO-SAMESITE",
                        f"Cookie '{name}' missing SameSite",
                        Severity.LOW,
                        Confidence.MEDIUM,
                        resp.final_url,
                        name,
                        "No SameSite attribute; default browser behavior applies.",
                        "Increased CSRF exposure depending on browser defaults.",
                        "Set SameSite=Lax or Strict (or None + Secure if cross-site use is required).",
                        safe_evidence,
                        "CWE-1275",
                        "A01:2021 Broken Access Control",
                    )
                )

            domain = morsel["domain"]
            if domain:
                target_host = resp.final_url.split("/")[2].split(":")[0].lower()
                clean_domain = domain.lstrip(".").lower()
                if domain.startswith(".") or (
                    domain.count(".") <= 1 and not target_host.endswith(clean_domain)
                ):
                    findings.append(
                        _mk(
                            "CK-BROAD-DOMAIN",
                            f"Cookie '{name}' has broad Domain",
                            Severity.LOW,
                            Confidence.LOW,
                            resp.final_url,
                            name,
                            f"Domain={domain} may expose the cookie to subdomains.",
                            "Wider attack surface across subdomains.",
                            "Scope cookies to the most specific host needed.",
                            safe_evidence,
                        )
                    )
    return findings
