from websentinel.analyzers.cors import analyze_cors
from websentinel.analyzers.html import analyze_html
from websentinel.analyzers.information import analyze_information
from websentinel.analyzers.methods import analyze_methods
from websentinel.analyzers.robots import (analyze_robots, parse_robots,
                                          parse_sitemap_urls)
from websentinel.analyzers.technology import detect_technologies
from websentinel.models import Severity
from conftest import make_response


def test_cors_wildcard():
    f = analyze_cors(make_response(
        headers={"Access-Control-Allow-Origin": "*"}))
    assert f and f[0].id == "CORS-WILDCARD" and f[0].severity == Severity.MEDIUM


def test_cors_none_when_no_header():
    assert analyze_cors(make_response(headers={})) == []


def test_info_disclosure_with_version():
    f = analyze_information(make_response(headers={"Server": "Apache/2.4.1"}))
    assert f[0].severity == Severity.LOW and f[0].cwe == "CWE-200"


def test_info_disclosure_no_version_is_info():
    f = analyze_information(make_response(headers={"Server": "cloudflare"}))
    assert f[0].severity == Severity.INFO


def test_methods_advertised_not_confirmed():
    f = analyze_methods("https://x/", "GET, POST, PUT, DELETE")
    assert f[0].id == "MTH-ADVERTISED"
    assert "NOT confirmed" in f[0].description or "advertised" in f[0].description


def test_html_insecure_password_form():
    f = analyze_html(make_response(
        url="https://x/login",
        body='<form method="post" action="http://x/login">'
             '<input type="password" name="p"></form>'), page_is_https=True)
    assert any(x.id == "HTML-INSECURE-FORM" and x.severity == Severity.HIGH
               for x in f)


def test_html_mixed_content():
    f = analyze_html(make_response(
        body='<img src="http://x/a.png">'), page_is_https=True)
    assert any(x.id == "HTML-MIXED-CONTENT" for x in f)


def test_robots_disallow_info_finding():
    r = make_response(url="https://x/robots.txt",
                      body="User-agent: *\nDisallow: /admin\nDisallow: /bak")
    f = analyze_robots(r)
    assert f and f[0].severity == Severity.INFO


def test_parse_robots_and_sitemap():
    rules = parse_robots("User-agent: *\nDisallow: /a\nAllow: /a/x\n"
                         "Sitemap: https://x/s.xml")
    assert rules["disallow"] == ["/a"] and rules["allow"] == ["/a/x"]
    urls = parse_sitemap_urls(
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '<url><loc>https://x/1</loc></url></urlset>')
    assert urls == ["https://x/1"]


def test_technology_detection():
    r = make_response(headers={"Server": "nginx", "X-Powered-By": "PHP"},
                      cookies=["PHPSESSID=1; Path=/"],
                      body="<html>wp-content/themes</html>")
    techs = detect_technologies([r])
    assert {"Nginx", "PHP", "WordPress"} <= set(techs)


def test_correlation_bumps_cookie_with_insecure_form():
    from websentinel.engine.correlation import correlate
    from websentinel.models import Finding, Confidence
    cookie_f = Finding(id="CK-NO-HTTPONLY", title="t", category="Cookies",
                       severity=Severity.LOW, confidence=Confidence.MEDIUM,
                       url="u", description="d")
    form_f = Finding(id="HTML-INSECURE-FORM", title="t", category="HTML",
                     severity=Severity.HIGH, confidence=Confidence.HIGH,
                     url="u", description="d")
    out = correlate([cookie_f, form_f], is_https=True)
    assert cookie_f.severity == Severity.MEDIUM
    assert any(f.id == "CORR-SUMMARY" for f in out)
