"""Passive technology fingerprinting from headers/html/cookies.

Signatures are plain data — extend by adding entries to SIGNATURES.
"""
from __future__ import annotations

from websentinel.models import Response

# (name, {header-name: substring|None(=exists), body: substring, cookie: prefix})
SIGNATURES: list[tuple[str, dict]] = [
    ("Nginx",        {"headers": {"server": "nginx"}}),
    ("Apache",       {"headers": {"server": "apache"}}),
    ("Cloudflare",   {"headers": {"server": "cloudflare", "cf-ray": None}}),
    ("IIS",          {"headers": {"server": "microsoft-iis"}}),
    ("PHP",          {"headers": {"x-powered-by": "php"}, "cookies": ["phpsessid"]}),
    ("Express/Node", {"headers": {"x-powered-by": "express"}}),
    ("ASP.NET",      {"headers": {"x-aspnet-version": None,
                                  "x-powered-by": "asp.net"},
                      "cookies": ["asp.net_sessionid", ".aspxauth"]}),
    ("Django",       {"cookies": ["csrftoken", "django"]}),
    ("Laravel",      {"cookies": ["laravel_session", "xsrf-token"]}),
    ("WordPress",    {"body": ["wp-content/", "wp-includes/"],
                      "cookies": ["wordpress_"]}),
    ("React",        {"body": ["data-reactroot", "__react", "react-dom"]}),
    ("Next.js",      {"body": ["__next_data__", "/_next/static"]}),
    ("Vue",          {"body": ["data-v-", "__vue__", "vue.js", "vue.min.js"]}),
    ("Angular",      {"body": ["ng-app", "ng-version", "_ngcontent"]}),
    ("jQuery",       {"body": ["jquery"]}),
]


def detect_technologies(responses: list[Response]) -> list[str]:
    found: set[str] = set()
    for r in responses:
        body = r.body[:200_000].lower()
        cookies = " ".join(r.set_cookies).lower()
        for name, sig in SIGNATURES:
            ok = False
            for hname, sub in sig.get("headers", {}).items():
                val = r.headers.get(hname)
                if val is not None and (sub is None or sub in val.lower()):
                    ok = True
            if any(b.lower() in body for b in sig.get("body", [])):
                ok = True
            if any(c in cookies for c in sig.get("cookies", [])):
                ok = True
            if ok:
                found.add(name)
    return sorted(found)
