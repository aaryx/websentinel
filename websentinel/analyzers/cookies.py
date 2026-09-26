"""Set-Cookie security attribute analysis."""
from __future__ import annotations

from http.cookies import SimpleCookie

from websentinel.models import Finding, Severity, Confidence, Response


def _mk(fid, title, sev, conf, url, cookie, desc, impact, remediation,
        cwe=None, owasp=None):
    return Finding(id=fid, title=title, category="Cookies", severity=sev,
                   confidence=conf, url=url, parameter=cookie,
                   description=desc, impact=impact, evidence=f"Set-Cookie: {cookie}",
                   remediation=remediation, cwe=cwe, owasp=owasp)


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

            if is_https and not has("secure"):
                findings.append(_mk(
                    "CK-NO-SECURE", f"Cookie '{name}' missing Secure",
                    Severity.MEDIUM, Confidence.HIGH, resp.final_url, name,
                    "Session/auth cookie set over HTTPS without the Secure "
                    "attribute can be sent over plain HTTP.",
                    "Cookie may be exposed to network eavesdropping.",
                    "Add the Secure attribute.",
                    "CWE-614", "A05:2021 Security Misconfiguration"))
            sessionish = any(k in name.lower() for k in
                             ("sess", "auth", "token", "jwt", "login", "sid"))
            if sessionish and not has("httponly"):
                findings.append(_mk(
                    "CK-NO-HTTPONLY",                     f"Cookie '{name}' missing HttpOnly",
                    Severity.LOW, Confidence.MEDIUM, resp.final_url, name,
                    "Cookie appears session-related but lacks HttpOnly. "
                    "This is only exploitable if XSS exists.",
                    "Readable by JavaScript via document.cookie.",
                    "Add HttpOnly unless client-side JS needs the cookie.",
                    "CWE-1004", "A05:2021 Security Misconfiguration"))
            if not has("samesite"):
                findings.append(_mk(
                    "CK-NO-SAMESITE", f"Cookie '{name}' missing SameSite",
                    Severity.LOW, Confidence.MEDIUM, resp.final_url, name,
                    "No SameSite attribute; default browser behavior applies.",
                    "Increased CSRF exposure depending on browser defaults.",
                    "Set SameSite=Lax or Strict (or None + Secure if cross-site "
                    "use is required).",
                    "CWE-1275", "A01:2021 Broken Access Control"))
            domain = morsel["domain"]
            if domain.startswith(".") or (
                    domain and domain.count(".") <= 1 and
                    not resp.final_url.split("/")[2].endswith(domain)):
                findings.append(_mk(
                    "CK-BROAD-DOMAIN", f"Cookie '{name}' has broad Domain",
                    Severity.LOW, Confidence.LOW, resp.final_url, name,
                    f"Domain={domain} may expose the cookie to many subdomains.",
                    "Wider attack surface across subdomains.",
                    "Scope cookies to the most specific host needed."))
    return findings
