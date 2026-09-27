"""URL validation and normalization (SSRF-aware)."""
from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
from urllib.parse import urlsplit, urlunsplit, quote, unquote

from websentinel.models import Target


class URLValidationError(ValueError):
    pass


RESERVED_PRIVATE_DOMAINS = (
    "localhost",
    "local",
    "internal",
    "lan",
    "corp",
    "home.arpa",
    "localdomain",
    "invalid",
    "test",
    "example",
)


def parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse standard, integer, hex, octal, or IPv4-mapped IP addresses."""
    clean = host.strip("[]").strip()
    if not clean:
        return None

    # Standard IPv4 or IPv6
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass

    # Decimal integer IPv4 (e.g. 2130706433)
    if clean.isdigit():
        val = int(clean)
        if 0 <= val <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(val)

    # Hex integer IPv4 (e.g. 0x7f000001)
    if clean.lower().startswith("0x"):
        try:
            val = int(clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Dotted IPv4 with mixed decimal/octal/hex components (e.g. 0177.0.0.1 or 0x7f.0.0.1)
    parts = clean.split(".")
    if len(parts) == 4:
        try:
            nums = []
            for p in parts:
                p = p.strip()
                if p.lower().startswith("0x"):
                    nums.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1:
                    nums.append(int(p, 8))
                else:
                    nums.append(int(p, 10))
            if all(0 <= n <= 255 for n in nums):
                return ipaddress.IPv4Address(bytes(nums))
        except ValueError:
            pass

    return None


def is_safe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP is globally routable and not private/loopback/reserved/link-local."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def validate_host_safety(host: str, allow_private: bool = False) -> None:
    """Ensure host does not point to private, loopback, or non-public addresses."""
    if allow_private:
        return

    clean_host = host.lower().strip().strip("[]").rstrip(".")
    if not clean_host:
        raise URLValidationError("Empty host")

    ip = parse_ip_literal(clean_host)
    if ip is not None:
        if not is_safe_ip(ip):
            raise URLValidationError(
                f"Refusing non-public address {host!r}; use --allow-private "
                "to scan lab/internal targets"
            )
        return

    # Check known local/internal/private domain suffixes (RFC 6761, 6762, 8375)
    # Note: .test and .example are RFC 2606 reserved and shouldn't route on the public Internet.
    is_reserved_domain = clean_host == "localhost" or any(
        clean_host.endswith("." + d) or clean_host == d
        for d in ("localhost", "local", "internal", "lan", "corp", "home.arpa", "localdomain")
    )
    if is_reserved_domain:
        raise URLValidationError(
            f"Refusing non-public address {host!r}; use --allow-private "
            "to scan lab/internal targets"
        )

    # Attempt DNS resolution to detect rebinding/aliases to private IPs
    try:
        results = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for r in results:
            sockaddr = r[4]
            resolved_ip_str = sockaddr[0]
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            if not is_safe_ip(resolved_ip):
                raise URLValidationError(
                    f"Refusing address {host!r} which resolves to non-public IP {resolved_ip}; "
                    "use --allow-private to scan lab/internal targets"
                )
    except socket.gaierror:
        # If DNS lookup fails (e.g. offline tests or non-existent domains), do not block here;
        # connection failure will be handled gracefully during HTTP fetch.
        pass


def sanitize_url_for_logging(url: str) -> str:
    """Mask credentials in URL for safe logging and reporting."""
    parts = urlsplit(url)
    if parts.username or parts.password:
        user = parts.username or ""
        netloc = f"{user}:[REDACTED]@{parts.hostname}" if parts.hostname else "[REDACTED]"
        if parts.port:
            netloc += f":{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return url


def normalize_target(raw: str, allow_private: bool = False) -> Target:
    """Validate and normalize a user-supplied target URL."""
    raw = raw.strip()
    if not raw:
        raise URLValidationError("Empty target URL")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise URLValidationError(f"Unsupported scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise URLValidationError("Missing host")

    host = parts.hostname
    # IDNA for internationalized domains
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise URLValidationError(f"Invalid host: {e}") from e

    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as e:
        raise URLValidationError("Invalid port") from e
    if not (1 <= port <= 65535):
        raise URLValidationError(f"Invalid port: {port}")

    validate_host_safety(host, allow_private=allow_private)

    path = parts.path or "/"
    # Never preserve credentials in normalized target URL
    netloc = (
        f"[{host}]:{port}"
        if ":" in host and parts.port
        else f"[{host}]"
        if ":" in host
        else f"{host}:{port}"
        if parts.port
        else host
    )
    url = urlunsplit((parts.scheme, netloc, path, parts.query, ""))  # fragments dropped
    return Target(
        original=raw,
        url=url,
        scheme=parts.scheme,
        host=host,
        port=port,
        allow_private=allow_private,
    )


def normalize_url(url: str) -> str:
    """Canonicalize a URL for dedup: lowercase host, drop fragment,
    normalize path dot-segments, strip default ports, strip credentials."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    default = 443 if scheme == "https" else 80
    netloc = f"[{host}]" if ":" in host else host
    if port and port != default:
        netloc = f"{netloc}:{port}"
    path = quote(unquote(parts.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    path = posixpath.normpath(path)
    if parts.path.endswith("/") and not path.endswith("/"):
        path += "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    da = pa.port or (443 if pa.scheme == "https" else 80)
    db = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme, (pa.hostname or "").lower(), da) == (
        pb.scheme,
        (pb.hostname or "").lower(),
        db,
    )


_PARAM_RE = re.compile(r"[?&]([^=&]+)=")


def extract_params(url: str) -> list[str]:
    return _PARAM_RE.findall(urlsplit(url).query and "?" + urlsplit(url).query or "")
