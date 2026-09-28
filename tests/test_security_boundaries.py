"""Adversarial cases crossing URL-parser, logging, and body-parser boundaries."""
import json

import httpx
import pytest

from conftest import make_response
from websentinel.analyzers.robots import analyze_security_txt, parse_sitemap_urls
from websentinel.core.scope import Scope
from websentinel.utils.redaction import Redactor
from websentinel.utils.urls import normalize_target


@pytest.mark.parametrize("url", ["https://faß.de/", "https://bücher.example/", "https://例え.example/"])
def test_target_host_matches_http_client_idna(url):
    target = normalize_target(url, allow_private=True, resolve_dns=False)
    assert target.host == httpx.URL(url).raw_host.decode("ascii")
    assert httpx.URL(target.url).raw_host == httpx.URL(url).raw_host
    assert Scope(target, allow_private=True).allows(url)


@pytest.mark.parametrize("key", ["password", "access_token", "api_key", "client_secret"])
def test_json_evidence_redacts_quoted_secret_keys(key):
    value = "sensitive-value-123"
    result = Redactor().text(json.dumps({key: value}))
    assert value not in result
    assert "REDACTED" in result


def test_short_secret_replacement_does_not_rewrite_its_own_marker():
    result = Redactor(["x", "R"]).text("x R")
    assert result == "[REDACTED] [REDACTED]"


def test_security_txt_network_failure_is_not_proof_of_absence():
    response = make_response(status=0)
    response.error = "timeout"
    assert analyze_security_txt(response) == []


def test_sitemap_rejects_internal_entity_expansion():
    body = '<!DOCTYPE urlset [<!ENTITY secret "https://example.com/private">]><urlset><url><loc>&secret;</loc></url></urlset>'
    assert parse_sitemap_urls(body) == []


@pytest.mark.parametrize("url", ["http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://169.254.169.254/", "http://2130706433/"])
def test_ssrf_address_encodings_still_rejected(url):
    from websentinel.utils.urls import URLValidationError
    with pytest.raises(URLValidationError):
        normalize_target(url, resolve_dns=False)
