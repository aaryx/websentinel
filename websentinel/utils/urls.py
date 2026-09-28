"""URL validation and normalization (SSRF-aware)."""
from __future__ import annotations

import ipaddress
import re
import socket
import httpx
from urllib.parse import urlsplit, urlunsplit, urljoin, quote, parse_qsl, unquote_plus

from websentinel.models import Target


class URLValidationError(ValueError):
    pass


def canonical_host(host: str) -> str:
    """Use the HTTP client's IDNA implementation at every scope boundary."""
    try:
        authority = f"[{host}]" if ":" in host else host
        return httpx.URL(f"https://{authority}/").raw_host.decode("ascii").lower()
    except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
        raise URLValidationError("Invalid host") from exc


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


def validate_host_safety(host: str, allow_private: bool = False, *, resolve_dns: bool = True) -> None:
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

    if not resolve_dns:
        return
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


def sanitize_url_for_logging(url: str, *, redact_query: bool = True) -> str:
    """Mask credentials in URL for safe logging and reporting."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "[INVALID URL]"
    if redact_query:
        from websentinel.utils.redaction import _SENSITIVE
        query = "&".join(part.partition("=")[0] + "=[REDACTED]"
                         if _SENSITIVE.search(unquote_plus(part.partition("=")[0])) else part
                         for part in parts.query.split("&"))
        parts = parts._replace(query=query)
    if parts.username or parts.password:
        user = parts.username or ""
        host = parts.hostname or ""
        host = f"[{host}]" if ":" in host else host
        netloc = f"{user}:[REDACTED]@{host}"
        if port is not None:
            netloc += f":{port}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return urlunsplit(parts)


def resolve_connection_address(host: str, allow_private: bool = False) -> str:
    """Resolve once and validate the exact address used for the connection."""
    validate_host_safety(host, allow_private=allow_private)
    addresses = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not addresses:
        raise URLValidationError("Host has no addresses")
    if not allow_private and any(not is_safe_ip(ipaddress.ip_address(a[4][0])) for a in addresses):
        raise URLValidationError("DNS resolved to a non-public address")
    return addresses[0][4][0]


def normalize_target(raw: str, allow_private: bool = False, *, resolve_dns: bool = True) -> Target:
    """Validate and normalize a user-supplied target URL."""
    raw = raw.strip()
    if not raw:
        raise URLValidationError("Empty target URL")
    if "://" not in raw:
        raw = "https://" + raw
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise URLValidationError("Control characters are not allowed in target URLs")
    try:
        parts = urlsplit(raw)
    except ValueError as e:
        raise URLValidationError("Malformed target URL") from e
    if parts.scheme not in ("http", "https"):
        raise URLValidationError(f"Unsupported scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise URLValidationError("Missing host")

    host = parts.hostname
    host = canonical_host(host)

    try:
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    except ValueError as e:
        raise URLValidationError("Invalid port") from e
    if not (1 <= port <= 65535):
        raise URLValidationError(f"Invalid port: {port}")

    validate_host_safety(host, allow_private=allow_private, resolve_dns=resolve_dns)

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
        original=sanitize_url_for_logging(raw),
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
    host = canonical_host(parts.hostname) if parts.hostname else ""
    try:
        port = parts.port
    except ValueError as e:
        raise URLValidationError("Invalid port") from e
    default = 443 if scheme == "https" else 80
    netloc = f"[{host}]" if ":" in host else host
    if port and port != default:
        netloc = f"{netloc}:{port}"
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    segments = []
    for segment in path.split("/"):
        if segment == "..":
            if len(segments) > 1:
                segments.pop()
        elif segment != ".":
            segments.append(segment)
    path = "/".join(segments)
    if parts.path.endswith(("/", "/.", "/..")) and not path.endswith("/"):
        path += "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def resolve_url(base: str, reference: str) -> str:
    """Resolve untrusted HTML references; ignore malformed/non-web URLs."""
    try:
        full = urljoin(base, reference.strip())
        p = urlsplit(full)
        if (p.scheme not in ("http", "https") or not p.hostname
                or p.username is not None or p.password is not None
                or p.port == 0):
            return ""
        return full
    except (ValueError, AttributeError, TypeError):
        return ""


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    da = pa.port or (443 if pa.scheme == "https" else 80)
    db = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme, canonical_host(pa.hostname) if pa.hostname else "", da) == (
        pb.scheme,
        canonical_host(pb.hostname) if pb.hostname else "",
        db,
    )


def extract_params(url: str) -> list[str]:
    return list(dict.fromkeys(k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)))
