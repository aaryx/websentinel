"""Focused tests for URL validation, IP encodings, SSRF safety, and scope controls."""
import pytest
import httpx

from websentinel.core.scope import Scope
from websentinel.http.client import HttpEngine
from websentinel.config import Config
from websentinel.utils.urls import (
    URLValidationError,
    normalize_target,
    parse_ip_literal,
    is_safe_ip,
    validate_host_safety,
)


def test_encoded_ip_parsing():
    # Decimal integer IP for 127.0.0.1
    ip_dec = parse_ip_literal("2130706433")
    assert str(ip_dec) == "127.0.0.1"
    assert not is_safe_ip(ip_dec)

    # Hex IP for 127.0.0.1
    ip_hex = parse_ip_literal("0x7f000001")
    assert str(ip_hex) == "127.0.0.1"
    assert not is_safe_ip(ip_hex)

    # Octal dotted IP for 127.0.0.1
    ip_oct = parse_ip_literal("0177.0.0.1")
    assert str(ip_oct) == "127.0.0.1"
    assert not is_safe_ip(ip_oct)

    # IPv4-mapped IPv6
    ip_mapped = parse_ip_literal("::ffff:127.0.0.1")
    assert not is_safe_ip(ip_mapped)


def test_reject_unusual_ip_encodings_without_allow_private():
    with pytest.raises(URLValidationError):
        normalize_target("http://2130706433/")

    with pytest.raises(URLValidationError):
        normalize_target("http://0x7f000001/")

    with pytest.raises(URLValidationError):
        normalize_target("http://0177.0.0.1/")

    with pytest.raises(URLValidationError):
        normalize_target("http://[::ffff:127.0.0.1]/")


def test_reserved_private_domains_rejected():
    with pytest.raises(URLValidationError):
        normalize_target("http://localhost/")

    with pytest.raises(URLValidationError):
        normalize_target("http://service.internal/")

    with pytest.raises(URLValidationError):
        normalize_target("http://printer.local/")

    with pytest.raises(URLValidationError):
        normalize_target("http://router.home.arpa/")


def test_ipv6_port_preserved():
    target = normalize_target("http://[::1]:8080/path", allow_private=True)
    assert target.port == 8080
    assert "[::1]:8080" in target.url


def test_credentials_in_url_stripped_from_target():
    target = normalize_target("https://admin:supersecret@example.com/dashboard")
    assert "supersecret" not in target.url
    assert "admin" not in target.url
    assert target.url == "https://example.com/dashboard"


def test_subdomains_scope_restrictions():
    # Domain target
    target = normalize_target("https://example.com:8443/", allow_private=False)
    s = Scope(target, mode="subdomains")

    # Allowed subdomains on matching or standard web ports
    assert s.allows("https://api.example.com:8443/v1")
    assert s.allows("https://api.example.com/v1")  # standard port 443

    # Forbidden: dangerous/arbitrary ports
    assert not s.allows("https://api.example.com:22/")
    assert not s.allows("https://api.example.com:6379/")
    assert not s.allows("https://api.example.com:3306/")

    # Forbidden: unrelated domains
    assert not s.allows("https://notexample.com/")
    assert not s.allows("https://example.com.attacker.com/")


def test_subdomains_scope_on_ip_target():
    # IP targets do not have subdomains
    target = normalize_target("http://127.0.0.1:8080/", allow_private=True)
    s = Scope(target, mode="subdomains", allow_private=True)

    assert s.allows("http://127.0.0.1:8080/path")
    # Subdomain matching must not match arbitrary strings ending with the IP
    assert not s.allows("http://attacker127.0.0.1:8080/")
    assert not s.allows("http://foo.127.0.0.1:8080/")


def test_private_target_permission_does_not_carry_over():
    # An internal target is authorized (e.g. 127.0.0.1)
    target = normalize_target("http://127.0.0.1:8080/", allow_private=True)
    s = Scope(target, mode="subdomains", allow_private=True)

    # Target itself is allowed
    assert s.allows("http://127.0.0.1:8080/admin")

    # AWS/GCP cloud metadata service (169.254.169.254) MUST be blocked
    assert not s.allows("http://169.254.169.254/latest/meta-data/")
    assert not s.allows_redirect("http://169.254.169.254/latest/meta-data/")

    # Other private network hosts (e.g. 10.0.0.1) MUST be blocked
    assert not s.allows("http://10.0.0.1/")
    assert not s.allows_redirect("http://10.0.0.1/")


@pytest.mark.asyncio
async def test_redirect_to_ssrf_destination_stopped():
    # Mock server that redirects to cloud metadata
    def handler(request: httpx.Request):
        if request.url.path == "/redirect-to-metadata":
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(200, text="metadata reached")

    transport = httpx.MockTransport(handler)
    cfg = Config(timeout=2, max_redirects=3)
    target = normalize_target("http://127.0.0.1:8080/", allow_private=True)
    scope = Scope(target, mode="same-origin", allow_private=True)

    engine = HttpEngine(cfg, scope=scope, allow_private=True)
    engine._client = httpx.AsyncClient(transport=transport, follow_redirects=False)

    resp = await engine.fetch("http://127.0.0.1:8080/redirect-to-metadata")
    await engine.close()

    # The redirect must be stopped at the 302 response and NOT follow to 169.254.169.254
    assert resp.status == 302
    assert "169.254.169.254" not in resp.final_url
    assert resp.body != "metadata reached"


def test_canonical_http_to_https_redirect_allowed():
    target = normalize_target("http://example.com/", allow_private=False)
    scope = Scope(target, mode="same-origin", allow_private=False)

    # Directly in allows: strictly same-origin
    assert scope.allows("http://example.com/page")
    assert not scope.allows("https://example.com/page")

    # In allows_redirect: canonical scheme upgrade on same host is allowed
    assert scope.allows_redirect("https://example.com/page")
    assert not scope.allows_redirect("https://different.com/page")
