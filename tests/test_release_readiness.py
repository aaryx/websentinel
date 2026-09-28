"""Release acceptance: secret boundaries, truthful coverage, durable outputs."""
import io
import json
import logging
from urllib.parse import quote

import httpx
import pytest
from rich.console import Console

from conftest import make_response
from websentinel import cli
from websentinel.config import Config
from websentinel.http.client import HttpEngine
from websentinel.models import Confidence, Finding, ScanResult, Severity, Target
from websentinel.reporting.csv_report import render_csv
from websentinel.reporting.files import write_report
from websentinel.reporting.html_report import render_html
from websentinel.reporting.json_report import render_json
from websentinel.reporting.sarif import render_sarif
from websentinel.reporting.terminal import render_console
from websentinel.scanner import scan
from websentinel.utils.logging import RedactFilter
from websentinel.utils.urls import normalize_target


@pytest.mark.parametrize("render", [render_json, render_html, render_csv, render_sarif, None])
def test_every_report_redacts_credentials_without_mutating_scan(render):
    secret = "opaque-auth-value-987"
    query = "query secret/123"
    cookie = "cookie-value-456"
    url = "https://example.com/?access_token=" + quote(query) + "&page=2"
    result = ScanResult(Target(url, url, "https", "example.com", 443), pages=[url], redaction_values=[secret])
    result.findings = [Finding("TEST", secret, "test", Severity.HIGH, Confidence.HIGH, url,
                               f"echo {secret} {query} {cookie}", evidence="ghp_" + "z" * 30)]
    result.responses = [make_response(url=url, cookies=[f"session={cookie}; Secure"], body=secret)]
    result.warnings = [f"{url} echoed {secret}"]
    if render:
        output = render(result)
    else:
        stream = io.StringIO()
        render_console(result, Console(file=stream, width=160))
        output = stream.getvalue()
    for value in (secret, query, quote(query), cookie, "ghp_" + "z" * 30):
        assert value not in output
    assert "page=2" in output and "REDACTED" in output
    assert result.target.url == url and result.responses[0].body == secret
    assert result.findings[0].title == secret


def test_log_redaction_catches_encoded_query_and_custom_header_value():
    record = logging.LogRecord("test", 20, __file__, 1, "%s %s", (
        "https://example.com/?%61ccess_token=hiddenvalue&ok=1", "customvalue"), None)
    RedactFilter(["customvalue"]).filter(record)
    assert "hiddenvalue" not in record.getMessage() and "customvalue" not in record.getMessage()
    assert "ok=1" in record.getMessage()


def test_bearer_secret_is_redacted_when_echoed_without_scheme():
    record = logging.LogRecord("test", 20, __file__, 1, "echoed opaque-token", (), None)
    RedactFilter(["Bearer opaque-token"]).filter(record)
    assert "opaque-token" not in record.getMessage()


def test_redaction_preserves_machine_status_and_rule_ids():
    result = ScanResult(Target("https://x/", "https://x/", "https", "x", 443),
                        check_status={"js": {"status": "partial", "reasons": ["secret partial"]}},
                        redaction_values=["partial", "JS"])
    result.findings = [Finding("JS-SECRET", "JS sample", "JS", Severity.HIGH, Confidence.HIGH, "https://x/", "d")]
    doc = json.loads(render_json(result))
    assert doc["scan"]["completion"] == "partial"
    assert doc["scan"]["checks"]["js"]["status"] == "partial"
    assert doc["findings"][0]["id"] == "JS-SECRET"
    assert doc["findings"][0]["title"].startswith("[REDACTED]")


def test_cli_argument_validation_does_not_resolve_dns(monkeypatch, capsys):
    def unexpected(*args, **kwargs):
        raise AssertionError("argument validation must not block on DNS")
    monkeypatch.setattr("socket.getaddrinfo", unexpected)
    assert cli.main(["scan", "-u", "https://example.com/", "--checks", "nonexistent"]) == cli.EXIT_ARGS


@pytest.mark.asyncio
async def test_probe_not_applicable_does_not_hide_root_failure(monkeypatch):
    async def fetch(self, url, **kwargs):
        return make_response(url=url, status=403)
    monkeypatch.setattr(HttpEngine, "fetch", fetch)
    result = await scan(normalize_target("http://localhost/", True), Config(), modules={"injection"})
    assert result.completion == "partial"


@pytest.mark.asyncio
async def test_redaction_does_not_rewrite_live_request_queries():
    requested = []
    engine = HttpEngine(Config(), allow_private=True)
    await engine.close()
    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(200, text="ok")
    engine._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    url = "http://localhost/?access_token=live-secret"
    async with engine:
        response = await engine.fetch(url)
    assert requested == [url] and response.final_url == url


def test_atomic_write_preserves_old_report_on_replace_failure(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text("previous", encoding="utf-8")
    def fail(*args):
        raise PermissionError("replace denied")
    monkeypatch.setattr("websentinel.reporting.files.os.replace", fail)
    with pytest.raises(PermissionError):
        write_report(path, "new")
    assert path.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [path]


def test_atomic_write_preserves_old_report_on_sync_failure(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text("previous", encoding="utf-8")
    def fail(*args):
        raise OSError("disk full")
    monkeypatch.setattr("websentinel.reporting.files.os.fsync", fail)
    with pytest.raises(OSError):
        write_report(path, "new")
    assert path.read_text() == "previous"
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.asyncio
@pytest.mark.parametrize("status,truncated,error", [(200, False, None), (200, True, None), (403, False, None), (0, False, "timeout")])
async def test_check_status_cannot_misrepresent_target_coverage(monkeypatch, status, truncated, error):
    async def fetch(self, url, **kwargs):
        response = make_response(url=url, status=status)
        response.truncated, response.error = truncated, error
        return response
    monkeypatch.setattr(HttpEngine, "fetch", fetch)
    result = await scan(normalize_target("http://localhost/", True), Config(), modules={"cookies"})
    expected = "failed" if error else "partial" if truncated or status >= 300 else "complete"
    assert result.completion == expected
    doc = json.loads(render_json(result))
    assert doc["scan"]["completion"] == expected
    assert doc["scan"]["checks"]["cookies"]["status"] != "pending"
    assert json.loads(render_sarif(result))["runs"][0]["invocations"][0]["executionSuccessful"] is (expected == "complete")


@pytest.mark.asyncio
async def test_discovery_js_and_robots_failures_are_reported(monkeypatch):
    seen = []
    async def fetch(self, url, **kwargs):
        seen.append(url)
        if url.endswith("/"):
            return make_response(url=url, body='<a href="/page">p</a><script src="/app.js"></script>')
        return make_response(url=url, status=503)
    monkeypatch.setattr(HttpEngine, "fetch", fetch)
    result = await scan(normalize_target("http://localhost/", True), Config(), modules={"robots", "js", "crawl"})
    assert result.completion == "partial"
    assert all(s["status"] == "partial" for s in result.check_status.values())
    assert "http://localhost/page" not in seen
    assert not any(f.id == "JS-SECRET" for f in result.findings)


def test_ci_can_fail_partial_scans_without_high_findings(monkeypatch, capsys):
    async def partial(target, cfg, **kwargs):
        return ScanResult(target, check_status={"js": {"status": "partial", "reasons": ["timeout"]}})
    monkeypatch.setattr(cli, "scan", partial)
    code = cli.main(["scan", "-u", "http://localhost/", "--allow-private", "--format", "json", "--fail-on-incomplete"])
    assert code == cli.EXIT_NETWORK
    assert json.loads(capsys.readouterr().out)["scan"]["completion"] == "partial"


@pytest.mark.asyncio
async def test_no_probe_parameters_is_not_applicable(monkeypatch):
    async def fetch(self, url, **kwargs):
        return make_response(url=url)
    monkeypatch.setattr(HttpEngine, "fetch", fetch)
    result = await scan(normalize_target("http://localhost/", True), Config(), modules={"injection"})
    assert result.check_status["injection"]["status"] == "not_applicable"
    assert result.completion == "complete"
