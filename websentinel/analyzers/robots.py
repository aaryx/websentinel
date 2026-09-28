"""robots.txt and sitemap.xml analysis (informational)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
import re

from websentinel.models import Finding, Severity, Confidence, Response


def parse_robots(body: str) -> dict[str, list[str]]:
    rules: dict[str, list[str]] = {"disallow": [], "allow": [], "sitemap": []}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        k = k.lower()
        if k in rules and v:
            rules[k].append(v)
    return rules


def analyze_robots(resp: Response) -> list[Finding]:
    if resp.error or resp.status != 200 or not resp.body.strip():
        return []
    rules = parse_robots(resp.body)
    findings: list[Finding] = []
    interesting = [p for p in rules["disallow"] if p not in ("/", "")]
    if interesting:
        findings.append(Finding(
            id="RBTS-DISALLOW",
            title=f"robots.txt discloses {len(interesting)} disallowed paths",
            category="Information Disclosure", severity=Severity.INFO,
            confidence=Confidence.HIGH, url=resp.final_url,
            description="robots.txt lists paths hidden from crawlers. These are "
                        "publicly visible and not vulnerabilities by themselves.",
            impact="May point to admin or internal areas.",
            evidence="Disallow: " + "; Disallow: ".join(interesting[:20]),
            remediation="Do not rely on robots.txt for access control."))
    return findings


def robots_rules(body: str) -> dict[str, list[str]]:
    return parse_robots(body)


def analyze_security_txt(resp: Response) -> list[Finding]:
    if not resp.error and resp.status in (404, 410):
        return [Finding(
            id="SEC-TXT-MISSING", title="security.txt not found",
            category="Information Disclosure", severity=Severity.INFO,
            confidence=Confidence.MEDIUM, url=resp.final_url,
            description="/.well-known/security.txt was not found.",
            impact="Researchers lack a standard disclosure contact.",
            evidence=f"HTTP {resp.status}",
            remediation="Publish a security.txt per RFC 9116.",
            references=["https://www.rfc-editor.org/rfc/rfc9116"])]
    return []


def parse_sitemap_urls(body: str, limit: int = 100) -> list[str]:
    urls: list[str] = []
    if limit <= 0 or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", body, re.I):
        return urls
    try:
        root = ET.fromstring(body[:1_000_000])
    except ET.ParseError:
        return urls
    for loc in root.iter():
        if loc.tag.rsplit("}", 1)[-1] == "loc" and loc.text:
            urls.append(loc.text.strip())
        if len(urls) >= limit:
            break
    return urls
