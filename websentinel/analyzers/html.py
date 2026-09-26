"""Passive HTML analysis: forms, mixed content, external resources.
Never submits forms or injects payloads."""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from websentinel.models import Finding, Severity, Confidence, Response


def analyze_html(resp: Response, page_is_https: bool) -> list[Finding]:
    if resp.error or "html" not in resp.content_type.lower():
        return []
    soup = BeautifulSoup(resp.body, "html.parser")
    url = resp.final_url
    findings: list[Finding] = []

    # --- forms ---
    for form in soup.find_all("form"):
        action = form.get("action") or url
        action = urljoin(url, action)
        method = (form.get("method") or "get").lower()
        has_password = any(i.get("type") == "password"
                           for i in form.find_all("input"))
        scheme = urlsplit(action).scheme
        if has_password and scheme == "http":
            findings.append(Finding(
                id="HTML-INSECURE-FORM",
                title="Password form submits over plain HTTP",
                category="HTML", severity=Severity.HIGH,
                confidence=Confidence.HIGH, url=url,
                description=f"A form containing a password field posts to "
                            f"'{action}' over unencrypted HTTP.",
                impact="Credentials can be intercepted in transit.",
                evidence=f"<form method={method} action={action}> "
                         "with input[type=password]",
                remediation="Serve and post the login form over HTTPS.",
                cwe="CWE-319", owasp="A02:2021 Cryptographic Failures"))
        elif method == "post" and action.startswith("http://") and page_is_https:
            findings.append(Finding(
                id="HTML-HTTPS-TO-HTTP-FORM",
                title="HTTPS page posts form to HTTP endpoint",
                category="HTML", severity=Severity.MEDIUM,
                confidence=Confidence.HIGH, url=url,
                description="A POST form on an HTTPS page submits to plain HTTP.",
                impact="Form data sent unencrypted.",
                evidence=f"form action={action}",
                remediation="Post to an HTTPS endpoint.",
                cwe="CWE-319", owasp="A02:2021 Cryptographic Failures"))

    # --- mixed content (HTTPS page loading HTTP subresources) ---
    if page_is_https:
        mixed = []
        for tag, attr in (("script", "src"), ("img", "src"),
                          ("link", "href"), ("iframe", "src")):
            for t in soup.find_all(tag):
                v = t.get(attr, "")
                if v.startswith("http://"):
                    mixed.append(urljoin(url, v))
        if mixed:
            findings.append(Finding(
                id="HTML-MIXED-CONTENT",
                title=f"Mixed content: {len(mixed)} HTTP resources on HTTPS page",
                category="HTML", severity=Severity.MEDIUM,
                confidence=Confidence.HIGH, url=url,
                description="HTTPS page loads subresources over plain HTTP.",
                impact="Subresources can be tampered with by network attackers.",
                evidence="; ".join(mixed[:10]),
                remediation="Load all subresources over HTTPS.",
                cwe="CWE-319", owasp="A02:2021 Cryptographic Failures"))

    # --- external scripts/iframes (observation) ---
    externals = set()
    host = urlsplit(url).hostname or ""
    for tag, attr in (("script", "src"), ("iframe", "src")):
        for t in soup.find_all(tag):
            v = t.get(attr, "")
            if not v:
                continue
            full = urljoin(url, v)
            th = urlsplit(full).hostname or ""
            if th and th != host and not th.endswith("." + host):
                externals.add(th)
    if externals:
        findings.append(Finding(
            id="HTML-EXTERNAL-RES",
            title=f"Third-party resources from {len(externals)} external hosts",
            category="HTML", severity=Severity.INFO,
            confidence=Confidence.HIGH, url=url,
            description="Page loads scripts/iframes from third-party hosts. "
                        "Observation only.",
            impact="Supply-chain exposure; third parties can run script in the "
                   "page's origin.",
            evidence="; ".join(sorted(externals)[:15]),
            remediation="Audit third-party resources; consider SRI for scripts."))
    return findings


def extract_links(resp: Response) -> list[str]:
    if resp.error or "html" not in resp.content_type.lower():
        return []
    soup = BeautifulSoup(resp.body, "html.parser")
    links = [urljoin(resp.final_url, a["href"])
             for a in soup.find_all("a", href=True)]
    return links


def is_directory_listing(resp: Response) -> bool:
    b = resp.body[:50_000].lower()
    return ("index of /" in b or "directory listing for" in b) and \
        "html" in resp.content_type.lower()
