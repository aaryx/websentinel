"""Tests for analyzer correctness, finding evidence sanitization, and output safety."""
from conftest import make_response
from websentinel.analyzers.cookies import analyze_cookies
from websentinel.analyzers.cors import analyze_cors
from websentinel.analyzers.javascript import analyze_javascript
from websentinel.engine.dedup import deduplicate
from websentinel.models import Finding, ScanResult, Severity, Confidence, Target
from websentinel.reporting.csv_report import render_csv


def test_cors_null_origin():
    resp = make_response(headers={"Access-Control-Allow-Origin": "null"})
    findings = analyze_cors(resp)
    assert any(f.id == "CORS-NULL-ORIGIN" for f in findings)


def test_cookie_evidence_redaction():
    resp = make_response(
        url="https://example.com/",
        cookies=["auth_token=super_secret_jwt_token_12345; Secure; HttpOnly; SameSite=Strict; Path=/"],
    )
    findings = analyze_cookies(resp, is_https=True)
    # Fully secure cookie has no findings
    assert not findings

    # If missing HttpOnly, evidence must not contain the sensitive value
    resp_vuln = make_response(
        url="https://example.com/",
        cookies=["auth_token=super_secret_jwt_token_12345; Secure; Path=/"],
    )
    findings_vuln = analyze_cookies(resp_vuln, is_https=True)
    assert any(f.id == "CK-NO-HTTPONLY" for f in findings_vuln)
    for f in findings_vuln:
        assert "super_secret_jwt_token_12345" not in f.evidence
        assert "[REDACTED]" in f.evidence


def test_cookie_session_vs_nonsession_severity():
    resp = make_response(
        url="https://example.com/",
        cookies=["pref=dark; Path=/", "sessionid=xyz; Path=/"],
    )
    findings = analyze_cookies(resp, is_https=True)
    pref_sec = next(f for f in findings if f.id == "CK-NO-SECURE" and f.parameter == "pref")
    sess_sec = next(f for f in findings if f.id == "CK-NO-SECURE" and f.parameter == "sessionid")
    # Non-session cookie has lower severity than session cookie
    assert pref_sec.severity == Severity.LOW
    assert sess_sec.severity == Severity.MEDIUM


def test_js_secret_distinct_types_not_merged_by_dedup():
    body = (
        'var aws = "AKIAIOSFODNN7EXAMPLE";\n'
        'var gh = "ghp_123456789012345678901234567890123456";\n'
    )
    findings = analyze_javascript("https://example.com/app.js", body)
    assert len(findings) == 2
    # Before dedup
    assert {f.parameter for f in findings} == {"AWS access key", "GitHub token"}

    # After dedup, both distinct kinds MUST be preserved
    deduped = deduplicate(findings)
    assert len(deduped) == 2
    kinds = {f.parameter for f in deduped}
    assert "AWS access key" in kinds and "GitHub token" in kinds


def test_dedup_idempotent_description_suffix():
    f1 = Finding(
        id="HDR-CSP-MISSING",
        title="t",
        category="c",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        url="https://x/1",
        description="Missing CSP.",
    )
    f2 = Finding(
        id="HDR-CSP-MISSING",
        title="t",
        category="c",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        url="https://x/2",
        description="Missing CSP.",
    )

    out1 = deduplicate([f1, f2])
    desc1 = out1[0].description
    assert "Affects 2 URLs" in desc1

    # Running deduplicate again must not duplicate the suffix
    out2 = deduplicate(out1)
    desc2 = out2[0].description
    assert desc2.count("Affects 2 URLs") == 1


def test_csv_formula_injection_sanitized():
    t = Target(original="https://x/", url="https://x/", scheme="https", host="x", port=443)
    r = ScanResult(target=t)
    r.findings.append(
        Finding(
            id="FORMULA-1",
            title="=cmd|' /C calc'!A0",
            category="Test",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            url="https://x/",
            description="+2+5+cmd",
            evidence="-evidence",
            remediation="@lookup(param)",
        )
    )

    csv_text = render_csv(r)
    # Malicious leading formula characters should be prefixed with single quote
    assert "'=cmd|" in csv_text
    assert "'+2+5+cmd" in csv_text
    assert "'-evidence" in csv_text
    assert "'@lookup(param)" in csv_text
