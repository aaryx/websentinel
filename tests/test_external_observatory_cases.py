# SPDX-License-Identifier: MPL-2.0
# Adapted behavioral fixtures: MDN HTTP Observatory contributors.
"""Behavioral cases adapted from MDN HTTP Observatory, with explicit mappings.

Source revision: 2dda68a02859ce3514281b584e8ecf02a5c33151.
See EXTERNAL_VALIDATION.md for attribution, scope, and deliberate differences.
"""
import pytest

from conftest import make_response
from websentinel.analyzers.cookies import analyze_cookies
from websentinel.analyzers.headers import analyze_headers


@pytest.mark.parametrize("value,expected", [
    (None, "HDR-HSTS-MISSING"),
    ("includeSubDomains; preload", "HDR-HSTS-INVALID"),
    ("max-age=15768000; includeSubDomains, max-age=15768000; includeSubDomains", "HDR-HSTS-INVALID"),
    ("max-age=86400", "HDR-HSTS-SHORT"),
    ("max-age=15768000; includeSubDomains; preload", None),
])
def test_observatory_hsts_cases(value, expected):
    headers = {"Strict-Transport-Security": value} if value is not None else {}
    findings = [f.id for f in analyze_headers(make_response(headers=headers), True) if f.id.startswith("HDR-HSTS")]
    assert findings == ([expected] if expected else [])


@pytest.mark.parametrize("attributes,expected", [
    ("Secure; HttpOnly; SameSite=Strict", None),
    ("Secure; HttpOnly; SameSite=Lax", None),
    ("Secure; HttpOnly; SameSite=None", None),
    ("Secure; HttpOnly; SameSite=", "CK-INVALID-ATTR"),
    ("Secure; HttpOnly; SameSite=True", "CK-INVALID-ATTR"),
    ("Secure; HttpOnly; SameSite=Invalid", "CK-INVALID-ATTR"),
    ("Secure", "CK-NO-HTTPONLY"),
    ("HttpOnly", "CK-NO-SECURE"),
])
def test_observatory_cookie_cases(attributes, expected):
    response = make_response(url="https://mozilla.org/", cookies=[f"SESSIONID=bar; Domain=mozilla.org; Path=/; {attributes}"])
    findings = [f.id for f in analyze_cookies(response, True)]
    if expected:
        assert expected in findings
    else:
        assert not findings
