"""Offline regression checks for scanner safety, coverage, and CLI contracts."""
import gzip
import io
import json
import logging
from unittest.mock import AsyncMock
from urllib.robotparser import RobotFileParser

import httpx
import pytest
from rich.console import Console

from conftest import make_response
from websentinel import cli
from websentinel.analyzers.cookies import analyze_cookies
from websentinel.analyzers.html import analyze_html, extract_links
from websentinel.analyzers.headers import analyze_headers
from websentinel.config import Config
from websentinel.core.scope import Scope
from websentinel.crawler.crawler import Crawler
from websentinel.engine.correlation import correlate
from websentinel.engine.dedup import deduplicate
from websentinel.http.client import HttpEngine
from websentinel.http.client import _PinnedTransport
from websentinel.models import Confidence, Finding, ScanResult, Severity, Target
from websentinel.reporting.json_report import render_json
from websentinel.reporting.terminal import render_console
from websentinel.scanner import scan
from websentinel.utils.logging import RedactFilter
from websentinel.utils.urls import URLValidationError, extract_params, normalize_target, normalize_url
from websentinel.utils.urls import resolve_connection_address


@pytest.mark.parametrize("values", [
    {"timeout": float("nan")}, {"rate_limit": float("inf")}, {"concurrency": True},
    {"verify_tls": "false"}, {"follow_redirects": 1}, {"user_agent": 123},
    {"extra_headers": {"X-Test": "a\r\nb"}}, {"extra_headers": {"Bad Name": "x"}},
    {"extra_headers": {"X-Test": 5}}, {"proxy": "http://x:bad"},
])
def test_config_rejects_invalid_types(values):
    with pytest.raises(ValueError):
        Config(**values).validate()


@pytest.mark.parametrize("yaml", ["false", "[]", "scan: 4", "scan: null", "1: x"])
def test_config_rejects_malformed_sections(tmp_path, yaml):
    path = tmp_path / "config.yml"
    path.write_text(yaml, encoding="utf-8")
    with pytest.raises(ValueError):
        Config.load(str(path))


def test_nested_config_keeps_top_level_values(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text("timeout: 7\nscan:\n  max_pages: 3\n", encoding="utf-8")
    cfg = Config.load(str(path))
    assert (cfg.timeout, cfg.max_pages) == (7, 3)


@pytest.mark.parametrize("url", ["http://[broken", "http://localhost:0/", "http://localhost:bad/", "http://local\nhost/"])
def test_invalid_target_is_argument_error(url):
    with pytest.raises(URLValidationError):
        normalize_target(url, allow_private=True)
    assert cli.main(["scan", "-u", url, "--allow-private"]) == cli.EXIT_ARGS


def test_scope_rejects_malformed_urls_and_credentials():
    scope = Scope(normalize_target("http://localhost/", allow_private=True), allow_private=True)
    for url in ("http://[bad", "http://localhost:bad/", "http://localhost:0/", "http://u:p@localhost/"):
        assert not scope.allows(url)
        assert not scope.allows_redirect(url)


def test_paths_and_parameter_names_preserve_semantics():
    assert normalize_url("https://x/a%2Fb") != normalize_url("https://x/a/b")
    assert extract_params("https://x/?a%20b=1&a%20b=2&empty") == ["a b", "empty"]


def test_log_interpolation_and_report_password_redaction():
    record = logging.LogRecord("t", 20, __file__, 1, "fetch %s: %s", ("https://u:secret@x/", "failed"), None)
    RedactFilter().filter(record)
    assert "secret" not in record.getMessage()
    assert "failed" in record.getMessage() and "%s" not in record.getMessage()
    target = normalize_target("http://u:secret@localhost/", allow_private=True)
    assert "secret" not in render_json(ScanResult(target))


def test_cookie_values_cannot_impersonate_attributes():
    resp = make_response(cookies=["session=secure-httponly-samesite; Path=/"])
    assert {f.id for f in analyze_cookies(resp, True)} >= {"CK-NO-SECURE", "CK-NO-HTTPONLY", "CK-NO-SAMESITE"}


def test_dedup_keeps_strongest_evidence_and_all_urls():
    low = Finding("X", "weak", "test", Severity.INFO, Confidence.HIGH, "https://x/asset", "d")
    high = Finding("X", "strong", "test", Severity.HIGH, Confidence.HIGH, "https://x/page", "d", evidence="strong")
    result = deduplicate([low, high])
    assert result[0].severity == Severity.HIGH
    assert result[0].url == high.url and result[0].evidence == "strong"
    assert deduplicate(result)[0].affected_urls == [low.url, high.url]


def test_correlation_does_not_escalate_unrelated_pages():
    cookie = Finding("CK-NO-HTTPONLY", "t", "Cookies", Severity.LOW, Confidence.MEDIUM, "https://x/a", "d")
    form = Finding("HTML-INSECURE-FORM", "t", "HTML", Severity.HIGH, Confidence.HIGH, "https://x/b", "d")
    correlate([cookie, form], True)
    assert cookie.severity == Severity.LOW


def test_html_base_and_malformed_links():
    resp = make_response(body='<base href="http://example.com/assets/"><a href="http://[bad">bad</a>'
                        '<a href="page">ok</a><form action="login"><input type="PASSWORD"></form>')
    assert extract_links(resp) == ["http://example.com/assets/page"]
    assert any(f.id == "HTML-INSECURE-FORM" for f in analyze_html(resp, True))


def test_terminal_treats_findings_as_literal_text():
    result = ScanResult(Target("https://x/", "https://x/", "https", "x", 443))
    result.findings = [Finding("X", "[/broken]", "Test", Severity.LOW, Confidence.HIGH, "https://x/", "d")]
    stream = io.StringIO()
    render_console(result, Console(file=stream, width=100))
    assert "[/broken]" in stream.getvalue()


@pytest.mark.asyncio
async def test_robots_root_disallow_and_user_agent_groups():
    engine = AsyncMock()
    engine.config = Config()
    root = make_response(url="https://x/", body='<a href="/page">p</a>')
    crawler = Crawler(engine, root.url, robots_disallow=["/"])
    assert await crawler.crawl(root.url, initial_response=root) == [root]
    engine.fetch.assert_not_called()
    robots = RobotFileParser()
    robots.parse("User-agent: OtherBot\nDisallow: /\n\nUser-agent: *\nDisallow: /private".splitlines())
    crawler = Crawler(engine, root.url, robots=robots)
    assert not crawler._blocked_by_robots("https://x/page")
    assert crawler._blocked_by_robots("https://x/private/data")


async def mock_engine(handler, **kwargs):
    engine = HttpEngine(Config(retries=1), **kwargs)
    await engine.close()
    engine._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), headers=engine.config.extra_headers)
    return engine


@pytest.mark.asyncio
async def test_every_request_including_redirect_and_retry_is_rate_limited():
    calls = 0
    def handler(req):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("transient")
        if req.url.path == "/":
            return httpx.Response(302, headers={"location": "/done"})
        return httpx.Response(200, text="ok")
    engine = await mock_engine(handler, allow_private=True)
    engine._rl.wait = AsyncMock()
    async with engine:
        assert (await engine.fetch("http://localhost/")).status == 200
    assert calls == engine.requests_made == engine._rl.wait.await_count == 3


@pytest.mark.asyncio
async def test_initial_out_of_scope_request_never_sent():
    target = normalize_target("http://localhost/", allow_private=True)
    handler = AsyncMock(return_value=httpx.Response(200))
    engine = await mock_engine(handler, scope=Scope(target, allow_private=True), allow_private=True)
    async with engine:
        assert (await engine.fetch("http://169.254.169.254/")).error
    handler.assert_not_called()
    assert engine.requests_made == 0


@pytest.mark.asyncio
async def test_dns_private_alias_refused_before_send(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))])
    target = Target("https://example.com/", "https://example.com/", "https", "example.com", 443)
    handler = AsyncMock(return_value=httpx.Response(200))
    engine = await mock_engine(handler, scope=Scope(target, mode="subdomains"))
    async with engine:
        assert (await engine.fetch("https://api.example.com/")).error
    handler.assert_not_called()


@pytest.mark.asyncio
async def test_redirect_does_not_forward_custom_credentials():
    received = []
    def handler(req):
        received.append(req)
        return httpx.Response(302, headers={"location": "https://localhost/final"}) if req.url.scheme == "http" else httpx.Response(200)
    engine = await mock_engine(handler, allow_private=True)
    async with engine:
        await engine.fetch("http://localhost/", headers={"Authorization": "Bearer secret", "X-Custom-Token": "secret", "Cookie": "a=secret"})
    assert received[0].headers["authorization"] == "Bearer secret"
    assert all(name not in received[1].headers for name in ("authorization", "x-custom-token", "cookie"))


@pytest.mark.asyncio
async def test_real_stream_decompression_is_bounded_and_closed():
    class Stream(httpx.AsyncByteStream):
        closed = False
        async def __aiter__(self):
            yield gzip.compress(b"A" * 5_000_000)
            raise AssertionError("must stop reading once the cap is reached")
        async def aclose(self):
            self.closed = True
    stream = Stream()
    engine = await mock_engine(lambda req: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream), allow_private=True)
    engine.config.max_body_bytes = 2048
    async with engine:
        response = await engine.fetch("http://localhost/")
    assert response.body == "A" * 2048
    assert stream.closed


@pytest.mark.asyncio
async def test_scanner_uses_https_final_origin_for_crawl_and_discovery(monkeypatch):
    seen = []
    async def fetch(self, url, **kwargs):
        seen.append(url)
        self.requests_made += 1
        if url == "http://localhost/app/":
            return make_response(url="https://localhost/app/", body='<a href="child">child</a>')
        return make_response(url=url, body="")
    monkeypatch.setattr(HttpEngine, "fetch", fetch)
    result = await scan(normalize_target("http://localhost/app/", allow_private=True), Config(), modules={"headers", "robots", "crawl"})
    assert "https://localhost/robots.txt" in seen
    assert "https://localhost/.well-known/security.txt" in seen
    assert "https://localhost/sitemap.xml" in seen
    assert "https://localhost/app/child" in seen
    assert any(f.id == "HDR-HSTS-MISSING" for f in result.findings)
    assert not any(f.id == "HTTP-PLAINTEXT" for f in result.findings)


def test_cli_failure_returns_network_code_and_json(monkeypatch, capsys):
    async def failed(target, cfg, **kwargs):
        response = make_response(url=target.url, status=0)
        response.error = "unreachable"
        return ScanResult(target, responses=[response], errors=["unreachable"])
    monkeypatch.setattr(cli, "scan", failed)
    code = cli.main(["scan", "-u", "http://localhost/", "--allow-private", "--format", "json"])
    captured = capsys.readouterr()
    assert code == cli.EXIT_NETWORK
    assert json.loads(captured.out)["scan"]["errors"] == ["unreachable"]


def test_report_filter_cannot_hide_failing_exit_code(monkeypatch, capsys):
    async def found(target, cfg, **kwargs):
        return ScanResult(target, findings=[Finding("X", "t", "Test", Severity.HIGH, Confidence.LOW, target.url, "d")])
    monkeypatch.setattr(cli, "scan", found)
    code = cli.main(["scan", "-u", "http://localhost/", "--allow-private", "--format", "json", "--confidence", "HIGH"])
    assert code == cli.EXIT_FINDINGS
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_empty_check_list_rejected():
    assert cli.main(["scan", "-u", "http://localhost/", "--allow-private", "--checks", ",,"]) == cli.EXIT_ARGS


def test_dns_rebinding_between_validation_and_resolution_is_rejected(monkeypatch):
    replies = iter(["93.184.216.34", "127.0.0.1"])
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (next(replies), 80))])
    with pytest.raises(URLValidationError):
        resolve_connection_address("example.com")


@pytest.mark.asyncio
async def test_pinned_transport_preserves_host_and_sni(monkeypatch):
    monkeypatch.setattr("websentinel.http.client.resolve_connection_address", lambda *a: "93.184.216.34")
    requests = []
    async def send(self, request):
        requests.append(request)
        return httpx.Response(200, content=b"ok")
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", send)
    transport = _PinnedTransport(Config(), None, False, httpx.Limits())
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("https://example.com/path")
        await client.get("https://other.example.com/path")
    assert str(response.url) == "https://example.com/path"
    assert requests[0].url.host == "93.184.216.34"
    assert requests[0].headers["host"] == "example.com"
    assert requests[0].extensions["sni_hostname"] == "example.com"
    assert len(transport.transports) == 2


def test_effective_frame_ancestors_and_invalid_header_values():
    resp = make_response(headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
    assert not any(f.id == "HDR-XFO-MISSING" for f in analyze_headers(resp, True))
    resp = make_response(headers={"Strict-Transport-Security": "max-age=0", "X-Frame-Options": "ALLOWALL", "X-Content-Type-Options": "off"})
    assert {f.id for f in analyze_headers(resp, True)} >= {"HDR-HSTS-INVALID", "HDR-XFO-INVALID", "HDR-XCTO-INVALID"}


@pytest.mark.asyncio
async def test_tls_findings_survive_failed_root_request(monkeypatch):
    async def fetch(self, url, **kwargs):
        response = make_response(url=url, status=0)
        response.error = "certificate verify failed"
        return response
    finding = Finding("TLS-CERT-INVALID", "t", "TLS", Severity.HIGH, Confidence.HIGH, "https://localhost/", "d")
    monkeypatch.setattr(HttpEngine, "fetch", fetch)
    monkeypatch.setattr("websentinel.scanner.tls_mod.inspect_tls", lambda *a, **k: ([finding], {}))
    result = await scan(normalize_target("https://localhost/", allow_private=True), Config(), modules={"tls"})
    assert result.errors and finding in result.findings


@pytest.mark.asyncio
async def test_crawler_frontier_is_bounded():
    engine = AsyncMock()
    engine.config = Config()
    engine.fetch.side_effect = lambda url: make_response(url=url)
    root = make_response(url="https://x/", body="".join(f'<a href="/{i}">p</a>' for i in range(500)))
    crawler = Crawler(engine, root.url, max_pages=3)
    assert len(await crawler.crawl(root.url, initial_response=root)) == 3
    assert len(crawler.seen) == 3
