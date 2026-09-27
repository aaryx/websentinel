"""TLS/certificate inspection using stdlib ssl — non-intrusive."""
from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from websentinel.models import Finding, Severity, Confidence, Target

log = logging.getLogger("websentinel.tls")

_DAYS_WARN = 30


def _parse_cert_time(s: str) -> datetime:
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc)


def inspect_tls(
    target: Target,
    days_warn: int = _DAYS_WARN,
    timeout: float = 10.0,
    verify_tls: bool = True,
) -> tuple[list[Finding], dict]:
    """Connect once, read negotiated TLS version and peer certificate."""
    findings: list[Finding] = []
    info: dict = {}
    if target.scheme != "https":
        return findings, info

    from websentinel.utils.urls import URLValidationError, validate_host_safety

    try:
        validate_host_safety(target.host, allow_private=target.allow_private)
    except URLValidationError as e:
        info["error"] = str(e)
        return findings, info

    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=target.host if verify_tls else None) as ssock:
            info["tls_version"] = ssock.version()
            cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            id="TLS-CERT-INVALID", title="Certificate validation failed",
            category="TLS", severity=Severity.HIGH, confidence=Confidence.HIGH,
            url=target.url,
            description="The server's certificate could not be validated "
                        "(expired, mismatched hostname, or untrusted chain).",
            impact="Users are exposed to man-in-the-middle attacks.",
            evidence=str(e),
            remediation="Install a valid certificate from a trusted CA.",
            cwe="CWE-295", owasp="A02:2021 Cryptographic Failures",
            references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]))
        info["error"] = str(e)
        return findings, info
    except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as e:
        log.warning("TLS inspection failed: %s", e)
        info["error"] = str(e)
        return findings, info

    if not cert:
        return findings, info

    # Certificate details
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
    info.update(subject=subject.get("commonName", ""),
                issuer=issuer.get("organizationName",
                                  issuer.get("commonName", "")),
                san=sans,
                not_before=cert.get("notBefore"),
                not_after=cert.get("notAfter"))

    now = datetime.now(timezone.utc)
    try:
        not_after = _parse_cert_time(cert["notAfter"])
        not_before = _parse_cert_time(cert["notBefore"])
        info["days_remaining"] = (not_after - now).days
        base = dict(category="TLS", url=target.url, cwe="CWE-295",
                    owasp="A02:2021 Cryptographic Failures")
        if now > not_after:
            findings.append(Finding(
                id="TLS-CERT-EXPIRED", title="Certificate expired",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                description=f"Certificate expired on {cert['notAfter']}.",
                impact="Browsers will warn; MITM risk.",
                evidence=f"notAfter={cert['notAfter']}",
                remediation="Renew and reinstall the certificate.", **base))
        elif now < not_before:
            findings.append(Finding(
                id="TLS-CERT-NOTYET", title="Certificate not yet valid",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                description=f"Certificate is not valid until {cert['notBefore']}.",
                impact="Clients will reject the certificate.",
                evidence=f"notBefore={cert['notBefore']}",
                remediation="Check server clock and certificate validity window.",
                **base))
        elif (not_after - now).days <= days_warn:
            findings.append(Finding(
                id="TLS-CERT-EXPIRING", title="Certificate expiring soon",
                severity=Severity.LOW, confidence=Confidence.HIGH,
                description=f"Certificate expires in {(not_after - now).days} days.",
                impact="Upcoming outage if not renewed.",
                evidence=f"notAfter={cert['notAfter']}",
                remediation="Renew the certificate before expiry.", **base))
    except (KeyError, ValueError) as e:
        log.debug("could not parse cert times: %s", e)

    ver = info.get("tls_version", "")
    if ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(Finding(
            id="TLS-WEAK-VERSION", title=f"Outdated TLS version negotiated ({ver})",
            category="TLS", severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            url=target.url,
            description=f"The server negotiated {ver}, which is deprecated.",
            impact="Weak protocol versions have known cryptographic weaknesses.",
            evidence=f"negotiated={ver}",
            remediation="Disable TLS < 1.2 on the server.",
            cwe="CWE-326", owasp="A02:2021 Cryptographic Failures",
            references=["https://datatracker.ietf.org/doc/rfc8996/"]))

    # Hostname match is enforced by wrap_socket with check_hostname; reaching
    # here means it matched.
    return findings, info
