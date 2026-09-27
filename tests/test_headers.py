from websentinel.analyzers.headers import analyze_headers
from websentinel.models import Severity
from conftest import make_response


def test_missing_headers_flagged():
    f = analyze_headers(make_response(headers={}), is_https=True)
    ids = {x.id for x in f}
    assert "HDR-CSP-MISSING" in ids and "HDR-HSTS-MISSING" in ids


def test_hsts_not_flagged_on_http():
    f = analyze_headers(make_response(url="http://x/", headers={}),
                        is_https=False)
    assert "HDR-HSTS-MISSING" not in {x.id for x in f}


def test_json_response_context_lowers_severity():
    f = analyze_headers(make_response(headers={}, ctype="application/json"),
                        is_https=True)
    csp = next(x for x in f if x.id == "HDR-CSP-MISSING")
    assert csp.severity == Severity.INFO


def test_weak_csp_detected():
    f = analyze_headers(make_response(
        headers={"Content-Security-Policy": "default-src * 'unsafe-inline'"}),
        is_https=True)
    assert "HDR-CSP-WEAK" in {x.id for x in f}


def test_strong_csp_not_flagged():
    f = analyze_headers(make_response(headers={
        "Content-Security-Policy":
            "default-src 'self'; frame-ancestors 'none'"}),
        is_https=True)
    assert "HDR-CSP-WEAK" not in {x.id for x in f}


def test_all_present_no_missing_findings():
    hdrs = {n: "x" for n in (
        "strict-transport-security", "x-frame-options",
        "x-content-type-options", "referrer-policy",
        "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-resource-policy", "cross-origin-embedder-policy")}
    hdrs["content-security-policy"] = "default-src 'self'"
    f = analyze_headers(make_response(headers=hdrs), is_https=True)
    assert not f
