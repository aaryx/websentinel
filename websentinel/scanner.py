"""Scan orchestration: ties HTTP engine, analyzers, crawler together."""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urljoin

from websentinel.analyzers import cookies as cookies_mod
from websentinel.analyzers import cors as cors_mod
from websentinel.analyzers import headers as headers_mod
from websentinel.analyzers import html as html_mod
from websentinel.analyzers import information as info_mod
from websentinel.analyzers import injection as inj_mod
from websentinel.analyzers import javascript as js_mod
from websentinel.analyzers import methods as methods_mod
from websentinel.analyzers import robots as robots_mod
from websentinel.analyzers import technology as tech_mod
from websentinel.analyzers import tls as tls_mod
from websentinel.checks import CHECKS as _REGISTRY
from websentinel.config import Config
from websentinel.core.scope import Scope
from websentinel.crawler.crawler import Crawler
from websentinel.engine.correlation import correlate
from websentinel.engine.dedup import deduplicate
from websentinel.http.client import HttpEngine
from websentinel.models import Confidence, Finding, ScanResult, Severity, Target
from websentinel.utils.urls import extract_params

log = logging.getLogger("websentinel.scan")

CHECKS = [(c["id"], c["name"]) for c in _REGISTRY]


async def scan(
    target: Target,
    cfg: Config,
    modules: set[str] | None = None,
    crawl: bool = False,
) -> ScanResult:
    """Run the scan. `modules` limits analysis to the given check names."""
    result = ScanResult(target=target)
    start = time.monotonic()
    all_modules = {c for c, _ in CHECKS} - {"injection", "crawl"}
    modules = modules or all_modules

    scope = Scope(target, cfg.scope, allow_private=target.allow_private)

    async with HttpEngine(cfg, scope=scope, allow_private=target.allow_private) as engine:
        async def fetch(path: str):
            return await engine.fetch(urljoin(target.url, path))

        # Root fetch first
        root = await engine.fetch(target.url)
        result.responses.append(root)

        if root.error:
            result.errors.append(f"Failed to fetch target: {root.error}")
            result.requests_made = engine.requests_made
            result.duration_s = time.monotonic() - start
            return result

        # Optional initial discovery/method probes only if selected modules need them
        robots_r = None
        sectxt_r = None
        options_r = None
        tasks = []
        task_names = []

        if "robots" in modules or crawl:
            tasks.append(fetch("robots.txt"))
            task_names.append("robots")
        if "robots" in modules:
            tasks.append(fetch(".well-known/security.txt"))
            task_names.append("sectxt")
        if "methods" in modules:
            tasks.append(engine.fetch(target.url, method="OPTIONS"))
            task_names.append("options")

        if tasks:
            gathered = await asyncio.gather(*tasks)
            for name, r in zip(task_names, gathered):
                if name == "robots":
                    robots_r = r
                elif name == "sectxt":
                    sectxt_r = r
                elif name == "options":
                    options_r = r

        # HTTPS posture
        if target.scheme == "http":
            https_probe = await engine.fetch(
                target.url.replace("http://", "https://", 1)
            )
            sev = Severity.MEDIUM
            desc = "Target is served over plain HTTP."
            if not https_probe.error:
                desc += " An HTTPS endpoint responded — redirect to it."
            result.findings.append(
                Finding(
                    id="HTTP-PLAINTEXT",
                    title="Site served over plain HTTP",
                    category="Transport",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    url=target.url,
                    description=desc,
                    impact="Traffic is unencrypted and modifiable in transit.",
                    evidence=f"scheme=http; https probe status={https_probe.status}",
                    remediation="Serve the site over HTTPS and redirect HTTP->HTTPS.",
                    cwe="CWE-319",
                    owasp="A02:2021 Cryptographic Failures",
                )
            )

        # Crawl (optional) or analyze root page only
        robots_paths: list[str] = []
        if robots_r and not robots_r.error and robots_r.status == 200:
            robots_paths = robots_mod.robots_rules(robots_r.body)["disallow"]

        if crawl:
            crawler = Crawler(
                engine,
                target.url,
                cfg.max_depth,
                cfg.max_pages,
                robots_paths,
                scope=scope,
            )
            crawled = await crawler.crawl(target.url, initial_response=root)
            result.responses = crawled
            result.pages = [r.final_url for r in result.responses]
        else:
            result.pages = [root.final_url]

        # Sitemap (scope-checked, capped)
        if "robots" in modules:
            sm = await fetch("sitemap.xml")
            if not sm.error and sm.status == 200:
                urls = robots_mod.parse_sitemap_urls(sm.body)
                urls = [u for u in urls if scope.allows(u)]
                if urls:
                    result.findings.append(
                        Finding(
                            id="RBTS-SITEMAP",
                            title=f"sitemap.xml exposes {len(urls)} URLs",
                            category="Information Disclosure",
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            url=sm.final_url,
                            description=(
                                "Sitemap is publicly accessible (normal, informational only)."
                            ),
                            impact="Reveals site structure.",
                            evidence="; ".join(urls[:10]),
                            remediation="None required; review if sensitive paths appear.",
                        )
                    )
                    result.pages.extend(u for u in urls if u not in result.pages)

        # TLS (blocking stdlib ssl -> thread)
        if "tls" in modules and target.scheme == "https":
            tls_findings, tls_info = await asyncio.to_thread(
                tls_mod.inspect_tls,
                target,
                timeout=cfg.timeout,
                verify_tls=cfg.verify_tls,
            )
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
                    result.findings.append(
                        Finding(
                            id="DIR-LISTING",
                            title="Directory listing enabled",
                            category="Misconfiguration",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            url=resp.final_url,
                            description="Page appears to be a server directory index.",
                            impact="File enumeration and accidental exposure.",
                            evidence="Body matches directory-listing signature",
                            remediation="Disable autoindex / Options Indexes.",
                            cwe="CWE-548",
                            owasp="A05:2021 Security Misconfiguration",
                        )
                    )

        # One-shot analyzers
        if "methods" in modules and options_r and not options_r.error:
            result.findings.extend(
                methods_mod.analyze_methods(
                    target.url, options_r.headers.get("allow")
                )
            )
        if "robots" in modules and robots_r:
            result.findings.extend(robots_mod.analyze_robots(robots_r))
        if "robots" in modules and sectxt_r:
            result.findings.extend(robots_mod.analyze_security_txt(sectxt_r))
        if "tech" in modules:
            result.technologies = tech_mod.detect_technologies(result.responses)

        # Static JavaScript analysis (bounded, same-scope scripts only)
        if "js" in modules:
            js_urls: list[str] = []
            for resp in result.responses:
                js_urls.extend(js_mod.script_urls(resp, scope))
            for jurl in sorted(set(js_urls))[:10]:
                jsr = await engine.fetch(jurl)
                if jsr.error or len(jsr.body) > cfg.max_body_bytes:
                    continue
                result.findings.extend(
                    js_mod.analyze_javascript(jsr.final_url, jsr.body)
                )
                eps = js_mod.extract_js_endpoints(jsr.body)
                if eps:
                    result.findings.append(
                        Finding(
                            id="JS-ENDPOINTS",
                            title=f"JavaScript references {len(eps)} API-like paths",
                            category="API Discovery",
                            severity=Severity.INFO,
                            confidence=Confidence.MEDIUM,
                            url=jsr.final_url,
                            description=(
                                "Endpoint strings found in JavaScript. Discovered endpoints are NOT tested."
                            ),
                            impact="Reveals API surface.",
                            evidence="; ".join(eps[:10]),
                            remediation="Review exposure of undocumented endpoints.",
                        )
                    )

        # Reflection canary (strictly budgeted; only when explicitly enabled)
        if "injection" in modules:
            probes = 0
            for page in result.pages:
                params = extract_params(page)
                if not params or probes >= 10:
                    continue
                for param in params:
                    if probes >= 10:
                        break
                    marker = inj_mod.generate_marker()
                    probed_url = inj_mod.build_probe(page, [param], marker=marker)
                    pr = await engine.fetch(probed_url)
                    probes += 1
                    if not pr.error:
                        f = inj_mod.evaluate_probe(
                            page, pr.final_url, pr.body, marker=marker, param=param
                        )
                        if f:
                            result.findings.append(f)

        # Passive input observation (no payloads)
        for page in result.pages:
            for param in extract_params(page):
                result.findings.append(
                    Finding(
                        id="INPUT-PARAM",
                        title=f"URL parameter observed: {param}",
                        category="Passive Input Analysis",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        url=page,
                        parameter=param,
                        description=(
                            "Parameter observed in URL; no active testing performed (out of scope for safe passive scan)."
                        ),
                        impact="Potential input surface for manual authorized testing.",
                        evidence=page,
                        remediation="Ensure server-side validation of all inputs.",
                    )
                )

        result.requests_made = engine.requests_made

    result.findings = correlate(
        result.findings, is_https=target.scheme == "https"
    )
    result.findings = deduplicate(result.findings)
    result.duration_s = time.monotonic() - start
    return result
