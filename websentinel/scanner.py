"""Scan orchestration: ties HTTP engine, analyzers, crawler together."""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

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
from websentinel.utils.urls import extract_params, normalize_target
from websentinel.utils.redaction import query_secrets, sensitive_values

log = logging.getLogger("websentinel.scan")

CHECKS = [(c["id"], c["name"]) for c in _REGISTRY]


async def scan(
    target: Target,
    cfg: Config,
    modules: set[str] | None = None,
    crawl: bool = False,
) -> ScanResult:
    """Run the scan. `modules` limits analysis to the given check names."""
    cfg.validate()
    result = ScanResult(target=target)
    result.redaction_values = list(cfg.extra_headers.values()) + query_secrets(target.url) + sensitive_values(target.original)
    if cfg.proxy:
        result.warnings.append("HTTPS proxy tunnels delegate destination DNS/routing to the configured proxy; use a trusted proxy.")
    start = time.monotonic()
    all_modules = {c for c, _ in CHECKS} - {"injection", "crawl"}
    modules = all_modules if modules is None else modules
    unknown = modules - {c for c, _ in CHECKS}
    if unknown:
        raise ValueError(f"unknown checks: {sorted(unknown)}")
    crawl = crawl or "crawl" in modules
    selected = modules | ({"crawl"} if crawl else set())
    result.check_status = {name: {"status": "pending", "reasons": []} for name in sorted(selected)}

    def mark(names, status, reason=""):
        for name in names & selected:
            state = result.check_status[name]
            if status == "not_applicable" and state["status"] != "pending":
                continue
            state["status"] = status
            if reason and reason not in state["reasons"]:
                state["reasons"].append(reason)

    def observe(resp, names, *, missing_ok=False):
        reason = resp.error
        if not reason and resp.truncated:
            reason = "response body truncated"
        if not reason and resp.status >= 300 and not (missing_ok and resp.status in (404, 410)):
            reason = f"HTTP {resp.status}"
        if reason:
            reason = f"{resp.final_url}: {reason}"
            mark(names, "partial", reason)
            if reason not in result.warnings:
                result.warnings.append(reason)

    scope = Scope(target, cfg.scope, allow_private=target.allow_private)

    async with HttpEngine(cfg, scope=scope, allow_private=target.allow_private) as engine:
        async def fetch(path: str):
            return await engine.fetch(urljoin(root.final_url, "/" + path.lstrip("/")))

        async def inspect_tls(tls_target):
            if cfg.proxy:
                result.warnings.append("TLS certificate inspection skipped: direct inspection does not support proxies.")
                mark({"tls"}, "skipped", "standalone TLS inspection does not support proxies")
                return
            tls_findings, tls_info = await asyncio.to_thread(
                tls_mod.inspect_tls, tls_target, timeout=cfg.timeout, verify_tls=cfg.verify_tls
            )
            result.findings.extend(tls_findings)
            for finding in tls_findings:
                finding.scanner_check = "tls"
            mark({"tls"}, "complete")
            if tls_info.get("error") and not tls_findings:
                result.warnings.append(f"TLS: {tls_info['error']}")
                mark({"tls"}, "failed", str(tls_info["error"]))
            elif not cfg.verify_tls:
                mark({"tls"}, "partial", "certificate verification disabled; certificate details unavailable")

        # Root fetch first
        root = await engine.fetch(target.url)
        result.responses.append(root)

        if root.error:
            mark(selected, "skipped", "target fetch failed")
            if "tls" in modules and target.scheme == "https":
                await inspect_tls(target)
            result.errors.append(f"Failed to fetch target: {root.error}")
            result.requests_made = engine.requests_made
            result.duration_s = time.monotonic() - start
            return result

        observe(root, selected - {"tls"})

        effective_target = normalize_target(root.final_url, allow_private=target.allow_private, resolve_dns=False)
        if target.scheme == "http" and effective_target.scheme == "https":
            scope = Scope(effective_target, cfg.scope, allow_private=target.allow_private)
            engine.scope = scope
        if "tls" in modules and effective_target.scheme != "https":
            mark({"tls"}, "not_applicable", "final target is not HTTPS")

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
            tasks.append(engine.fetch(root.final_url, method="OPTIONS"))
            task_names.append("options")

        if tasks:
            gathered = await asyncio.gather(*tasks)
            for name, r in zip(task_names, gathered):
                observe(r, {"methods"} if name == "options" else {"robots", "crawl"} if name == "robots" else {"robots"}, missing_ok=name != "options")
                if name == "robots":
                    robots_r = r
                elif name == "sectxt":
                    sectxt_r = r
                elif name == "options":
                    options_r = r

        # HTTPS posture
        if effective_target.scheme == "http" and modules & {"headers", "tls"}:
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
        robots = None
        if robots_r and not robots_r.error and robots_r.status == 200:
            robots = RobotFileParser()
            robots.parse(robots_r.body.splitlines())
        elif robots_r and robots_r.status in (401, 403):
            robots = RobotFileParser()
            robots.disallow_all = True
        elif robots_r and (robots_r.error or robots_r.status >= 500):
            robots = RobotFileParser()
            robots.disallow_all = True
            mark({"crawl"}, "partial", "crawl paused because robots.txt could not be retrieved")

        if crawl:
            crawler = Crawler(
                engine,
                root.final_url,
                cfg.max_depth,
                cfg.max_pages,
                scope=scope,
                robots=robots,
            )
            crawled = await crawler.crawl(target.url, initial_response=root)
            result.responses = crawled
            result.pages = [r.final_url for r in result.responses]
            if len(crawled) >= cfg.max_pages:
                mark({"crawl"}, "partial", "configured page cap reached")
        else:
            result.pages = [root.final_url]

        # Sitemap (scope-checked, capped)
        if "robots" in modules:
            sm = await fetch("sitemap.xml")
            observe(sm, {"robots"}, missing_ok=True)
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
        if "tls" in modules and effective_target.scheme == "https":
            await inspect_tls(effective_target)

        # Per-response analyzers
        for resp in result.responses:
            observe(resp, selected - {"tls", "robots", "methods"})
            if resp.error:
                continue
            is_https = urlsplit(resp.final_url).scheme == "https"
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
                observe(jsr, {"js"})
                if jsr.error or jsr.status >= 400:
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

            if len(set(js_urls)) > 10:
                mark({"js"}, "partial", "script limit of 10 reached")

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
                    observe(pr, {"injection"})
                    probes += 1
                    if not pr.error:
                        f = inj_mod.evaluate_probe(
                            page, pr.final_url, pr.body, marker=marker, param=param
                        )
                        if f:
                            result.findings.append(f)
            if probes == 0:
                mark({"injection"}, "not_applicable", "no URL parameters available to probe")
            elif sum(len(extract_params(page)) for page in result.pages) > 10:
                mark({"injection"}, "partial", "probe limit of 10 reached")

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
        for resp in result.responses:
            if resp.error:
                result.warnings.append(f"Page not analyzed: {resp.final_url}: {resp.error}")
            elif resp.truncated:
                result.warnings.append(f"Response body limit reached: {resp.final_url}; analysis may be incomplete.")
        if engine.requests_made >= cfg.max_requests:
            result.warnings.append("Request budget reached; scan coverage may be incomplete.")

    result.findings = correlate(
        result.findings, is_https=effective_target.scheme == "https"
    )
    result.findings = deduplicate(result.findings)
    prefixes = {"HDR": "headers", "CK": "cookies", "TLS": "tls", "MTH": "methods",
                "CORS": "cors", "INFO": "info", "HTML": "html", "DIR": "html",
                "RBTS": "robots", "SEC": "robots", "JS": "js", "INJ": "injection"}
    for finding in result.findings:
        finding.scanner_check = prefixes.get(finding.id.split("-", 1)[0], finding.scanner_check)
    result.duration_s = time.monotonic() - start
    for state in result.check_status.values():
        if state["status"] == "pending":
            state["status"] = "complete"
    return result
