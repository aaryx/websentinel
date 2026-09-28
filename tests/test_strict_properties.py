"""Generated hostile inputs exercise contracts rather than chosen happy paths."""
import json

from hypothesis import given, settings, strategies as st
import pytest

from conftest import make_response
from websentinel.analyzers.cookies import analyze_cookies
from websentinel.analyzers.headers import analyze_headers
from websentinel.analyzers.html import analyze_html, extract_links
from websentinel.analyzers.robots import parse_sitemap_urls
from websentinel.core.scope import Scope
from websentinel.models import Target
from websentinel.utils.urls import normalize_url, resolve_url


@settings(max_examples=300, deadline=None, derandomize=True)
@given(st.text(max_size=300))
def test_untrusted_references_never_crash_or_escape_scope(reference):
    scope = Scope(Target("https://example.com/", "https://example.com/", "https", "example.com", 443))
    full = resolve_url("https://example.com/", reference)
    assert isinstance(scope.allows(full), bool)
    assert isinstance(scope.allows_redirect(full), bool)
    if full:
        assert normalize_url(normalize_url(full)) == normalize_url(full)


@settings(max_examples=200, deadline=None, derandomize=True)
@given(st.text(max_size=1000))
def test_hostile_cookie_and_header_values_do_not_crash(value):
    response = make_response(cookies=["session=" + value], headers={"Content-Security-Policy": value, "Strict-Transport-Security": value})
    for finding in analyze_cookies(response, True) + analyze_headers(response, True):
        json.dumps(finding.to_dict())


@settings(max_examples=200, deadline=None, derandomize=True)
@given(st.text(alphabet="<>/='\" abcdef012&;:\n", max_size=1000))
def test_hostile_html_and_xml_remain_parseable_or_rejected(body):
    response = make_response(body=body)
    assert isinstance(extract_links(response), list)
    assert isinstance(analyze_html(response, True), list)
    assert isinstance(parse_sitemap_urls(body), list)


@pytest.mark.parametrize("path", ["/a//b", "/a///b", "//a//b"])
def test_normalization_does_not_change_repeated_slash_routes(path):
    assert normalize_url("https://example.com" + path) == "https://example.com" + path
