import pytest

from websentinel.utils.urls import (URLValidationError, normalize_target,
                                    normalize_url, same_origin,
                                    extract_params)


def test_defaults_to_https():
    t = normalize_target("example.com")
    assert t.scheme == "https" and t.host == "example.com" and t.port == 443


def test_explicit_http_port():
    t = normalize_target("http://example.com:8080/path?q=1#frag")
    assert t.scheme == "http" and t.port == 8080
    assert "#" not in t.url


def test_rejects_bad_scheme():
    with pytest.raises(URLValidationError):
        normalize_target("ftp://example.com")


def test_rejects_private_ip_without_flag():
    with pytest.raises(URLValidationError):
        normalize_target("http://127.0.0.1/")
    t = normalize_target("http://127.0.0.1/", allow_private=True)
    assert t.host == "127.0.0.1"


def test_ipv6():
    t = normalize_target("http://[2001:4860:4860::8888]/", allow_private=True)
    assert ":" in t.host


def test_normalize_url_dedup():
    a = normalize_url("HTTP://Example.COM:80/a/../b#x")
    b = normalize_url("http://example.com/b")
    assert a == b


def test_same_origin():
    assert same_origin("https://a.com/x", "https://a.com:443/y")
    assert not same_origin("http://a.com/", "https://a.com/")
    assert not same_origin("https://a.com/", "https://b.a.com/")


def test_extract_params():
    assert set(extract_params("https://x/?a=1&b=2")) == {"a", "b"}
    assert extract_params("https://x/") == []
