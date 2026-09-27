import json
import logging

from websentinel.analyzers.injection import build_probe, evaluate_probe
from websentinel.analyzers.javascript import (analyze_javascript,
                                              extract_js_endpoints)
from websentinel.checks import CHECKS as REGISTRY, PROFILES
from websentinel.core.scope import Scope
from websentinel.engine.dedup import deduplicate
from websentinel.models import (Finding, ScanResult, Severity, Confidence,
                                Target)
from websentinel.reporting.csv_report import render_csv
from websentinel.reporting.sarif import render_sarif
from websentinel.utils.logging import RedactFilter
from websentinel.utils.urls import normalize_target


def _f(fid, url="https://x/", param=None, evidence="e"):
    return Finding(id=fid, title="t", category="c", severity=Severity.LOW,
                   confidence=Confidence.MEDIUM, url=url, parameter=param,
                   description="d", evidence=evidence)


# --- dedup ---
def test_dedup_groups_same_issue():
    out = deduplicate([_f("HDR-CSP-MISSING", "https://x/a"),
                       _f("HDR-CSP-MISSING", "https://x/b"),
                       _f("HDR-CSP-MISSING", "https://x/c")])
    assert len(out) == 1
    assert len(out[0].affected_urls) == 3
    assert "3 URLs" in out[0].description


def test_dedup_keeps_distinct():
    out = deduplicate([_f("A", "https://x/a"), _f("B", "https://x/a")])
    assert len(out) == 2


# --- scope ---
def _scope(mode="same-origin"):
    return Scope(normalize_target("https://app.example.com:8443/",
                                  allow_private=False), mode)


def test_scope_same_origin():
    s = _scope()
    assert s.allows("https://app.example.com:8443/x")
    assert not s.allows("https://app.example.com/x")      # different port
    assert not s.allows("https://sub.app.example.com:8443/")
    assert not s.allows("ftp://app.example.com:8443/")


def test_scope_subdomains():
    s = _scope("subdomains")
    assert s.allows("https://sub.app.example.com/")
    assert not s.allows("https://evilapp.example.com/")


# --- javascript analysis ---
def test_js_secret_detected_and_redacted():
    body = 'var k = "AKIAIOSFODNN7EXAMPLE";'
    f = analyze_javascript("https://x/app.js", body)
    assert f and f[0].id == "JS-SECRET" and f[0].severity == Severity.HIGH
    assert "AKIAIOSFODNN7EXAMPLE" not in f[0].evidence  # redacted


def test_js_random_string_not_flagged():
    body = 'var a = "aiusdhiasudhaiushd28198asd";'
    assert not any(x.id == "JS-SECRET" for x in analyze_javascript("u", body))


def test_js_endpoints_and_sourcemap():
    body = 'fetch("/api/v1/users"); fetch("/graphql");'
    eps = extract_js_endpoints(body)
    assert "/api/v1/users" in eps and "/graphql" in eps
    f = analyze_javascript("https://x/a.js",
                           "x=1;\n//# sourceMappingURL=a.js.map")
    assert any(x.id == "JS-SOURCEMAP" for x in f)


# --- injection canary ---
def test_probe_and_evaluation():
    url = "https://x/search?q=hello&p=2"
    probed = build_probe(url, ["q"])
    assert "q=" in probed and "hello" not in probed
    assert evaluate_probe(url, probed, f"no results for {probed.split('q=')[1]}")
    assert evaluate_probe(url, probed, "nothing here") is None


# --- registry / profiles ---
def test_registry_unique_and_profiles_valid():
    ids = [c["id"] for c in REGISTRY]
    assert len(ids) == len(set(ids))
    for name, p in PROFILES.items():
        assert p["checks"] is None or p["checks"] <= set(ids)


# --- reporters ---
def _result():
    t = Target(original="https://x/", url="https://x/", scheme="https",
               host="x", port=443)
    r = ScanResult(target=t)
    r.findings.append(_f("CORS-WILDCARD"))
    return r


def test_csv_report():
    out = render_csv(_result())
    lines = out.strip().splitlines()
    assert lines[0].startswith("id,title")
    assert "CORS-WILDCARD" in lines[1]


def test_sarif_report_valid():
    doc = json.loads(render_sarif(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "CORS-WILDCARD"
    assert run["results"][0]["level"] in ("error", "warning", "note")


# --- log redaction ---
def test_log_redaction():
    rec = logging.LogRecord("t", 20, __file__, 1,
                            "header Authorization: Bearer sekret sent", (), None)
    RedactFilter().filter(rec)
    assert "sekret" not in rec.msg and "REDACTED" in rec.msg
