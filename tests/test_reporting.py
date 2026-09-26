import json

from websentinel.models import Finding, ScanResult, Severity, Confidence, Target
from websentinel.reporting.html_report import render_html
from websentinel.reporting.json_report import render_json


def _result():
    t = normalize = Target(original="https://x/", url="https://x/",
                           scheme="https", host="x", port=443)
    r = ScanResult(target=t)
    r.findings.append(Finding(
        id="X-1", title='<script>alert(1)</script>', category="Test",
        severity=Severity.LOW, confidence=Confidence.HIGH, url="https://x/",
        description="d", evidence="<img onerror=x>", remediation="r"))
    r.technologies = ["Nginx"]
    r.pages = ["https://x/"]
    return r


def test_json_report_structure():
    data = json.loads(render_json(_result()))
    assert data["tool"]["name"] == "WebSentinel"
    assert set(data) >= {"tool", "target", "scan", "summary", "findings",
                         "technologies", "crawl"}
    assert data["summary"]["LOW"] == 1
    assert data["findings"][0]["severity"] == "LOW"


def test_html_escapes_untrusted_content():
    out = render_html(_result())
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "<img onerror=x>" not in out
