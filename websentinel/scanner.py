"""Scan orchestration: ties HTTP engine, analyzers, crawler together."""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urljoin

from websentinel.config import Config
from websentinel.crawler.crawler import Crawler
from websentinel.engine.correlation import correlate
from websentinel.http.client import HttpEngine
from websentinel.models import Finding, Severity, Confidence, ScanResult, Target
from websentinel.analyzers import cookies as cookies_mod
from websentinel.analyzers import headers as headers_mod
from websentinel.analyzers import html as html_mod
from websentinel.analyzers import information as info_mod
from websentinel.analyzers import cors as cors_mod
from websentinel.analyzers import methods as methods_mod
from websentinel.analyzers import robots as robots_mod
from websentinel.analyzers import technology as tech_mod
from websentinel.analyzers import tls as tls_mod

log = logging.getLogger("websentinel.scan")

CHECKS = [
    ("headers",  "Security header analysis"),
    ("cookies",  "Cookie attribute analysis"),
    ("tls",      "TLS & certificate inspection (HTTPS only)"),
    ("methods",  "HTTP method advertisement (OPTIONS)"),
    ("cors",     "CORS configuration analysis"),
    ("info",     "Information disclosure headers"),
    ("tech",     "Passive technology fingerprinting"),
    ("html",     "Passive HTML/form/mixed-content analysis"),
    ("robots",   "robots.txt / sitemap.xml / security.txt"),
    ("crawl",    "Controlled same-origin crawling (with --crawl)"),
]


async def scan(target: Target, cfg: Config, modules: set[str] | None = None,
               crawl: bool = False) -> ScanResult:
    """Run the scan. `modules` limits analysis to the given check names."""
    result = ScanResult(target=target)
    start = time.monotonic()
    all_modules = {c for c, _ in CHECKS}
    modules = modules or all_modules

    async with HttpEngine(cfg) as engine:
        async def fetch(path: str):
            return await engine.fetch(urljoin(target.url, path))

        root, robots_r, sectxt_r, options_r = await asyncio.gather(
            engine.fetch(target.url), fetch("robots.txt"),
            fetch(".well-known/security.txt"),
            engine.fetch(target.url, method="OPTIONS"))
        result.responses.append(root)

        if root.error:
            result.errors.append(f"Failed to fetch target: {root.error}")
            result.duration_s = time.monotonic() - start
            return result

        # HTTPS posture
        if target.scheme == "http":
            https_probe = await engine.fetch(
                target.url.replace("http://", "https://", 1))
            sev = Severity.MEDIUM
            desc = "Target is served over plain HTTP."
            if not https_probe.error:
                desc += " An HTTPS endpoint responded — redirect to it."
            result.findings.append(Finding(
                id="HTTP-PLAINTEXT", title="Site served over plain HTTP",
                category="Transport", severity=sev, confidence=Confidence.HIGH,
                url=target.url, description=desc,
                impact="Traffic is unencrypted and modifiable in transit.",
                evidence=f"scheme=http; https probe status={https_probe.status}",
                remediation="Serve the site over HTTPS and redirect HTTP->HTTPS.",
                cwe="CWE-319", owasp="A02:2021 Cryptographic Failures"))

        # Crawl (optional) or analyze root page only
        robots_paths: list[str] = []
        if not robots_r.error and robots_r.status == 200:
            robots_paths = robots_mod.robots_rules(robots_r.body)["disallow"]
        if crawl:
            crawler = Crawler(engine, target.url, cfg.max_depth,
                              cfg.max_pages, robots_paths)
            crawled = await crawler.crawl(target.url)
            result.responses.extend(r for r in crawled
                                    if r.final_url != root.final_url)
            result.pages = [r.final_url for r in result.responses]
        else:
            result.pages = [root.final_url]

        # Sitemap (same-origin, capped)
        if "robots" in modules:
            sm = await fetch("sitemap.xml")
            if not sm.error and sm.status == 200:
                urls = robots_mod.parse_sitemap_urls(sm.body)
                from websentinel.utils.urls import same_origin
                urls = [u for u in urls if same_origin(u, target.url)]
                if urls:
                    result.findings.append(Finding(
                        id="RBTS-SITEMAP",
                        title=f"sitemap.xml exposes {len(urls)} URLs",
                        category="Information Disclosure", severity=Severity.INFO,
                        confidence=Confidence.HIGH, url=sm.final_url,
                        description="Sitemap is publicly accessible (normal, "
                                    "informational only).",
                        impact="Reveals site structure.",
                        evidence="; ".join(urls[:10]),
                        remediation="None required; review if sensitive paths "
                                    "appear."))
                    result.pages.extend(u for u in urls if u not in result.pages)

        # TLS (blocking stdlib ssl -> thread)
        if "tls" in modules and target.scheme == "https":
            tls_findings, tls_info = await asyncio.to_thread(
                tls_mod.inspect_tls, target)
            result.findings.extend(tls_findings)
            if tls_info.get("error") and not tls_findings:
                result.warnings.append(f"TLS: {tls_info['error']}")

        # Per-response analyzers
        is_https = target.scheme == "https"
        for resp in result.responses:
            if resp.error:
                continue
            if "headers" in modules:
                result.findings.extend(headers_mod.analyze_headers(resp, is_https))
            if "cookies" in modules:
                result.findings.extend(cookies_mod.analyze_cookies(resp, is_https))
            if "info" in modules:
                result.findings.extend(info_mod.analyze_information(resp))
            if "cors" in modules:
                result.findings.extend(cors_mod.analyze_cors(resp))
            if "html" in modules:
                result.findings.extend(html_mod.analyze_html(resp, is_https))
                if html_mod.is_directory_listing(resp):
                    result.findings.append(Finding(
                        id="DIR-LISTING", title="Directory listing enabled",
                        category="Misconfiguration", severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM, url=resp.final_url,
                        description="Page appears to be a server directory index.",
                        impact="File enumeration and accidental exposure.",
                        evidence="Body matches directory-listing signature",
                        remediation="Disable autoindex / Options Indexes.",
                        cwe="CWE-548",
                        owasp="A05:2021 Security Misconfiguration"))

        # One-shot analyzers
        if "methods" in modules:
            result.findings.extend(methods_mod.analyze_methods(
                target.url, options_r.headers.get("allow")))
        if "robots" in modules:
            result.findings.extend(robots_mod.analyze_robots(robots_r))
            result.findings.extend(robots_mod.analyze_security_txt(sectxt_r))
        if "tech" in modules:
            result.technologies = tech_mod.detect_technologies(result.responses)

        # Passive input observation (no payloads)
        from websentinel.utils.urls import extract_params
        for page in result.pages:
            for param in extract_params(page):
                result.findings.append(Finding(
                    id="INPUT-PARAM",
                    title=f"URL parameter observed: {param}",
                    category="Passive Input Analysis", severity=Severity.INFO,
                    confidence=Confidence.HIGH, url=page, parameter=param,
                    description="Parameter observed in URL; no active testing "
                                "performed (out of scope for safe passive scan).",
                    impact="Potential input surface for manual authorized testing.",
                    evidence=page,
                    remediation="Ensure server-side validation of all inputs."))

        result.requests_made = engine.requests_made

    result.findings = correlate(result.findings,
                                is_https=target.scheme == "https")
    result.duration_s = time.monotonic() - start
    return result
