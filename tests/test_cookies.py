from websentinel.analyzers.cookies import analyze_cookies
from websentinel.models import Severity
from conftest import make_response


def test_missing_secure_on_https():
    f = analyze_cookies(make_response(cookies=["session=abc; Path=/"]),
                        is_https=True)
    ids = {x.id for x in f}
    assert "CK-NO-SECURE" in ids and "CK-NO-SAMESITE" in ids
    no_secure = next(x for x in f if x.id == "CK-NO-SECURE")
    assert no_secure.severity == Severity.MEDIUM


def test_httponly_only_for_sessionish():
    f = analyze_cookies(make_response(
        cookies=["pref=dark; Secure"]), is_https=True)
    assert "CK-NO-HTTPONLY" not in {x.id for x in f}


def test_fully_secure_cookie_no_findings():
    f = analyze_cookies(make_response(cookies=[
        "session=abc; Secure; HttpOnly; SameSite=Lax; Path=/"]),
        is_https=True)
    assert not f


def test_broad_domain():
    f = analyze_cookies(make_response(
        url="https://sub.example.com/",
        cookies=['session=abc; Secure; HttpOnly; SameSite=Lax; '
                 'Domain=.example.com']), is_https=True)
    assert "CK-BROAD-DOMAIN" in {x.id for x in f}
