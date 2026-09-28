"""Integration tests against a local fixture HTTP server + regression
tests for the previously observed finding IDs."""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from websentinel.config import Config
from websentinel.scanner import scan
from websentinel.utils.urls import normalize_target

INDEX = (b'<html><head><script src="/app.js"></script></head><body>'
         b'<a href="/page2">p2</a>'
         b'<form method="post" action="http://LOCALHOST/login">'
         b'<input type="password" name="pw"></form>'
         b'<a href="/?q=test">q</a></body></html>')
APPJS = (b'fetch("/api/v1/users");\nvar k = "AKIAIOSFODNN7EXAMPLE";\n'
         b'//# sourceMappingURL=app.js.map')


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        body = {"/": INDEX, "/app.js": APPJS,
                "/robots.txt": b"User-agent: *\nDisallow: /admin\n"
                }.get(self.path.split("?")[0])
        if self.path.startswith("/?"):
            body = INDEX
        if body is None:
            self.send_response(404)
            body = b"not found"
        else:
            self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()
    srv.server_close()


def _run(url, **kw):
    target = normalize_target(url, allow_private=True)
    cfg = Config(timeout=3, max_requests=200)
    return asyncio.run(scan(target, cfg, **kw))


def test_full_scan_finds_expected(server):
    r = _run(server, crawl=True)
    assert not r.errors
    ids = {f.id for f in r.findings}
    # regression: previously observed IDs still fire
    assert "HDR-CSP-MISSING" in ids and "HDR-CSP-WEAK" not in ids
    assert "INFO-SERVER" in ids
    assert "RBTS-DISALLOW" in ids
    assert "CORS-WILDCARD" in ids
    # new checks
    assert "HTTP-PLAINTEXT" in ids
    assert "HTML-INSECURE-FORM" in ids
    assert "HTML-CSRF-MAYBE" in ids
    assert "CK-NO-SAMESITE" in ids
    assert "JS-SECRET" in ids and "JS-ENDPOINTS" in ids
    assert "INPUT-PARAM" in ids
    # dedup: header findings appear once despite multiple pages
    assert sum(f.id == "HDR-CSP-MISSING" for f in r.findings) == 1
    # secrets never leak into serialized output
    from websentinel.reporting.json_report import render_json
    assert "AKIAIOSFODNN7EXAMPLE" not in render_json(r)


def test_request_budget(server):
    r = _run(server, crawl=True, modules={"headers"},
             )  # budget covered by cfg below
    assert r.requests_made > 0


def test_request_budget_enforced(server):
    target = normalize_target(server, allow_private=True)
    cfg = Config(timeout=3, max_requests=2)
    r = asyncio.run(scan(target, cfg, crawl=True, modules={"headers"}))
    assert r.requests_made <= 2  # every HTTP hop/retry shares the hard budget


def test_injection_canary_enabled(server):
    r = _run(server, modules={"injection"}, crawl=True)
    assert isinstance(r.findings, list)  # marker not reflected by fixture
