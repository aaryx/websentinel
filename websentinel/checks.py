"""Check registry: single source of truth for available checks and profiles.

ponytail: a full plugin ABC (run()/context objects) was spec'd but the
existing analyzer-function dispatch in scanner.py already works; this is the
metadata layer `websentinel checks` and profiles need. Upgrade path: convert
analyzers to SecurityCheck classes if third-party checks ever arrive.
"""
from __future__ import annotations

CHECKS: list[dict] = [
    {"id": "headers", "name": "Security header analysis",
     "category": "Security Headers", "requests": 0},
    {"id": "cookies", "name": "Cookie attribute analysis",
     "category": "Cookies", "requests": 0},
    {"id": "tls", "name": "TLS & certificate inspection",
     "category": "TLS", "requests": 1},
    {"id": "methods", "name": "HTTP method advertisement (OPTIONS)",
     "category": "HTTP Methods", "requests": 1},
    {"id": "cors", "name": "CORS configuration analysis",
     "category": "CORS", "requests": 0},
    {"id": "info", "name": "Information disclosure headers",
     "category": "Information Disclosure", "requests": 0},
    {"id": "tech", "name": "Passive technology fingerprinting",
     "category": "Fingerprint", "requests": 0},
    {"id": "html", "name": "HTML/form/mixed-content/CSRF analysis",
     "category": "HTML", "requests": 0},
    {"id": "robots", "name": "robots.txt / sitemap.xml / security.txt",
     "category": "Discovery", "requests": 3},
    {"id": "js", "name": "Static JavaScript analysis (endpoints, secrets)",
     "category": "JavaScript", "requests": "per-script"},
    {"id": "injection", "name": "Reflection canary (safe, off by default)",
     "category": "Injection", "requests": "budgeted"},
    {"id": "crawl", "name": "Controlled same-origin crawling (--crawl)",
     "category": "Crawler", "requests": "per-page"},
]

PROFILES: dict[str, dict] = {
    "quick":    {"checks": {"headers", "cookies", "info", "cors"},
                 "crawl": False, "max_depth": 0, "max_pages": 1},
    "standard": {"checks": None, "crawl": False, "max_depth": 1,
                 "max_pages": 50},
    "deep":     {"checks": None, "crawl": True, "max_depth": 3,
                 "max_pages": 100},
    "headers":  {"checks": {"headers"}, "crawl": False,
                 "max_depth": 0, "max_pages": 1},
    "tls":      {"checks": {"tls"}, "crawl": False,
                 "max_depth": 0, "max_pages": 1},
    "crawl":    {"checks": {"headers", "cookies", "html", "tech", "robots"},
                 "crawl": True, "max_depth": 3, "max_pages": 100},
    "api":      {"checks": {"info", "cors", "methods", "robots"},
                 "crawl": False, "max_depth": 0, "max_pages": 1},
}
