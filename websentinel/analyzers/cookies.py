"""Set-Cookie security attribute analysis."""
from __future__ import annotations

from http.cookies import SimpleCookie
import re
from urllib.parse import urlsplit

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
            has = lambda a: a in kv

            # Sanitized attribute summary without leaking raw secret value
            attrs = [f"{k}={morsel[k]}" for k in morsel.keys() if morsel[k]]
            safe_evidence = f"Set-Cookie: {name}=[REDACTED]" + (f"; {'; '.join(attrs)}" if attrs else "")

            invalid = []
            if re.search(r";\s*samesite\s*=", raw, re.I) and morsel["samesite"].lower() not in ("lax", "strict", "none"):
                invalid.append("unrecognized SameSite value")
            if name.startswith(("__Secure-", "__Host-", "__Http-")) and (not is_https or not has("secure")):
                invalid.append("cookie prefix requires HTTPS and Secure")
            if name.startswith("__Host-") and (morsel["domain"] or morsel["path"] != "/"):
                invalid.append("__Host- prefix requires Path=/ and no Domain")
            if name.startswith(("__Http-", "__Host-Http-")) and not has("httponly"):
                invalid.append("HTTP cookie prefix requires HttpOnly")
            if invalid:
                findings.append(_mk("CK-INVALID-ATTR", f"Cookie '{name}' has invalid attributes",
                    Severity.LOW, Confidence.HIGH, resp.final_url, name, "; ".join(invalid),
                    "Browsers may reject the cookie or apply unintended defaults.",
                    "Use valid SameSite and cookie-prefix attributes.", safe_evidence, "CWE-614"))

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

            samesite_none = morsel["samesite"].lower() == "none"
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
                target_host = (urlsplit(resp.final_url).hostname or "").lower()
                clean_domain = domain.lstrip(".").lower()
                if target_host.endswith("." + clean_domain):
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
