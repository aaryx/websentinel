"""URL validation and normalization (SSRF-aware)."""
from __future__ import annotations

import ipaddress
import posixpath
import re
from urllib.parse import urlsplit, urlunsplit, quote, unquote

from websentinel.models import Target


class URLValidationError(ValueError):
    pass


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

    if not allow_private:
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if not ip.is_global:
                raise URLValidationError(
                    f"Refusing non-public address {host!r}; use --allow-private "
                    "to scan lab/internal targets")
        except ValueError as e:
            if "Refusing" in str(e):
                raise

    path = parts.path or "/"
    url = urlunsplit((parts.scheme,
                      f"[{host}]" if ":" in host else
                      (f"{host}:{port}" if parts.port else host),
                      path, parts.query, ""))  # fragments dropped
    return Target(original=raw, url=url, scheme=parts.scheme, host=host,
                  port=port)


def normalize_url(url: str) -> str:
    """Canonicalize a URL for dedup: lowercase host, drop fragment,
    normalize path dot-segments, strip default ports."""
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
    return (pa.scheme, (pa.hostname or "").lower(), da) == \
           (pb.scheme, (pb.hostname or "").lower(), db)


_PARAM_RE = re.compile(r"[?&]([^=&]+)=")


def extract_params(url: str) -> list[str]:
    return _PARAM_RE.findall(urlsplit(url).query and "?" + urlsplit(url).query
                             or "")
