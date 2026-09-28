"""Real loopback TLS handshakes and HTTP/CONNECT proxy routing."""
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import select
import socket
import ssl
import threading
from urllib.parse import urlsplit

import pytest
import trustme

from websentinel.analyzers.tls import inspect_tls
from websentinel.config import Config
from websentinel.http.client import HttpEngine
from websentinel.models import Target


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.requests.append((self.path, dict(self.headers)))
        body = b"tls-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def local_server(handler=Handler, context=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.requests = []
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def tls_setup(monkeypatch, *, trust=True, identity="localhost", expires=None):
    ca = trustme.CA()
    cert = ca.issue_cert(identity, not_after=expires)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(context)
    seen_sni = []
    context.set_servername_callback(lambda sock, name, ctx: seen_sni.append(name))
    original = ssl.create_default_context
    if trust:
        def trusted(*args, **kwargs):
            ctx = original(*args, **kwargs)
            ca.configure_trust(ctx)
            return ctx
        monkeypatch.setattr(ssl, "create_default_context", trusted)
        # HTTPX 0.27 builds SSLContext directly; configure trust at the common
        # CA-loading boundary as well so both supported versions use this CA.
        original_load = ssl.SSLContext.load_verify_locations
        def load_with_test_ca(ctx, *args, **kwargs):
            original_load(ctx, *args, **kwargs)
            original_load(ctx, cadata=ca.cert_pem.bytes().decode("ascii"))
        monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", load_with_test_ca)
    # Only resolution is substituted; TCP, TLS, SNI, certificates, and HTTP are real.
    monkeypatch.setattr("websentinel.http.client.resolve_connection_address", lambda *a: "127.0.0.1")
    monkeypatch.setattr("websentinel.utils.urls.resolve_connection_address", lambda *a, **k: "127.0.0.1")
    return context, seen_sni


@pytest.mark.asyncio
async def test_trusted_tls_uses_original_hostname_and_certificate(monkeypatch):
    context, sni = tls_setup(monkeypatch)
    with local_server(context=context) as server:
        url = f"https://localhost:{server.server_port}/"
        async with HttpEngine(Config(retries=0), allow_private=True) as engine:
            response = await engine.fetch(url)
        assert response.status == 200 and response.body == "tls-ok"
        target = Target(url, url, "https", "localhost", server.server_port, True)
        findings, info = await asyncio.to_thread(inspect_tls, target)
    assert not findings
    assert info["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert "localhost" in info["san"]
    assert sni == ["localhost", "localhost"]
    assert server.requests[0][1]["Host"] == f"localhost:{server.server_port}"


@pytest.mark.asyncio
@pytest.mark.parametrize("trust,identity", [(False, "localhost"), (True, "wrong.example")])
async def test_untrusted_and_hostname_mismatch_are_rejected(monkeypatch, trust, identity):
    context, _ = tls_setup(monkeypatch, trust=trust, identity=identity)
    with local_server(context=context) as server:
        url = f"https://localhost:{server.server_port}/"
        async with HttpEngine(Config(retries=0), allow_private=True) as engine:
            response = await engine.fetch(url)
        assert response.error
        target = Target(url, url, "https", "localhost", server.server_port, True)
        findings, _ = await asyncio.to_thread(inspect_tls, target)
        assert any(f.id == "TLS-CERT-INVALID" for f in findings)
    assert not server.requests


@pytest.mark.asyncio
async def test_expiring_certificate_finding(monkeypatch):
    context, _ = tls_setup(monkeypatch, expires=datetime.now(timezone.utc) + timedelta(days=5))
    with local_server(context=context) as server:
        url = f"https://localhost:{server.server_port}/"
        target = Target(url, url, "https", "localhost", server.server_port, True)
        findings, info = await asyncio.to_thread(inspect_tls, target)
    assert any(f.id == "TLS-CERT-EXPIRING" for f in findings)
    assert 3 <= info["days_remaining"] <= 5


@pytest.mark.asyncio
async def test_explicit_unverified_tls_still_sends_sni(monkeypatch):
    context, sni = tls_setup(monkeypatch, trust=False)
    with local_server(context=context) as server:
        async with HttpEngine(Config(verify_tls=False, retries=0), allow_private=True) as engine:
            response = await engine.fetch(f"https://localhost:{server.server_port}/")
    assert response.status == 200
    assert sni == ["localhost"]


class Proxy(Handler):
    def do_CONNECT(self):
        self.server.requests.append((self.path, dict(self.headers)))
        host, port = self.path.rsplit(":", 1)
        # Fixture only forwards to the local origin explicitly assigned by the test.
        if host != "localhost" or int(port) != self.server.origin_port:
            self.send_error(403)
            return
        with socket.create_connection(("127.0.0.1", int(port)), timeout=2) as upstream:
            self.send_response(200, "Connection Established")
            self.end_headers()
            for _ in range(100):
                readable, _, _ = select.select([self.connection, upstream], [], [], 2)
                if not readable:
                    return
                for source in readable:
                    try:
                        data = source.recv(65536)
                    except ConnectionResetError:
                        return  # The client may reset a completed CONNECT tunnel.
                    if not data:
                        return
                    (upstream if source is self.connection else self.connection).sendall(data)


@pytest.mark.asyncio
async def test_http_proxy_receives_pinned_absolute_url(monkeypatch):
    monkeypatch.setattr("websentinel.http.client.resolve_connection_address", lambda *a: "127.0.0.1")
    with local_server(Proxy) as proxy:
        cfg = Config(proxy=f"http://127.0.0.1:{proxy.server_port}", retries=0)
        async with HttpEngine(cfg, allow_private=True) as engine:
            response = await engine.fetch("http://localhost:12345/proxy-path")
    assert response.status == 200
    assert proxy.requests[0][0] == "http://127.0.0.1:12345/proxy-path"
    assert proxy.requests[0][1]["Host"] == "localhost:12345"


@pytest.mark.asyncio
async def test_https_connect_proxy_preserves_tls_hostname(monkeypatch):
    context, sni = tls_setup(monkeypatch)
    with local_server(context=context) as origin, local_server(Proxy) as proxy:
        proxy.origin_port = origin.server_port
        cfg = Config(proxy=f"http://127.0.0.1:{proxy.server_port}", retries=0)
        async with HttpEngine(cfg, allow_private=True) as engine:
            response = await engine.fetch(f"https://localhost:{origin.server_port}/through-proxy")
    assert response.status == 200 and response.body == "tls-ok"
    assert proxy.requests[0][0] == f"localhost:{origin.server_port}"
    assert origin.requests[0][0] == "/through-proxy"
    assert sni == ["localhost"]


def test_tls_network_failure_and_non_tls_target(monkeypatch):
    target = Target("http://localhost/", "http://localhost/", "http", "localhost", 80, True)
    assert inspect_tls(target) == ([], {})
    target.scheme = "https"
    monkeypatch.setattr("websentinel.utils.urls.resolve_connection_address", lambda *a, **k: "127.0.0.1")
    def refused(*args, **kwargs):
        raise ConnectionRefusedError("fixture refused")
    monkeypatch.setattr(socket, "create_connection", refused)
    findings, info = inspect_tls(target)
    assert not findings and "fixture refused" in info["error"]


@pytest.mark.asyncio
async def test_unverified_tls_inspection_preserves_protocol_info(monkeypatch):
    context, sni = tls_setup(monkeypatch, trust=False)
    with local_server(context=context) as server:
        url = f"https://localhost:{server.server_port}/"
        target = Target(url, url, "https", "localhost", server.server_port, True)
        findings, info = await asyncio.to_thread(inspect_tls, target, verify_tls=False)
    assert not findings and info["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert sni == ["localhost"]
