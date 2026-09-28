"""Scope control: restrict crawling/discovery to authorized scope."""
from __future__ import annotations

from urllib.parse import urlsplit

from websentinel.models import Target
from websentinel.utils.urls import is_safe_ip, parse_ip_literal, canonical_host


class Scope:
    """Enforces target boundary and prevents SSRF and scope escapes."""

    def __init__(
        self,
        target: Target,
        mode: str = "same-origin",
        allow_private: bool = False,
    ) -> None:
        if mode not in ("same-origin", "subdomains"):
            raise ValueError(f"unsafe scope mode: {mode!r}")
        self.target = target
        self.mode = mode
        self.scheme = target.scheme.lower()
        self.host = canonical_host(target.host)
        self.port = target.port
        self.allow_private = allow_private
        self.is_ip_host = parse_ip_literal(self.host) is not None

    def _is_safe_destination(self, host: str) -> bool:
        """Ensure private target permission does not carry over to third-party private hosts."""
        ip = parse_ip_literal(host)
        if ip is not None and not is_safe_ip(ip):
            if not self.allow_private:
                return False
            # Even with allow_private, only the target host itself is authorized
            if host != self.host:
                return False

        clean = host.rstrip(".")
        if clean == "localhost" or any(
            clean.endswith("." + d) or clean == d
            for d in ("localhost", "local", "internal", "lan", "corp", "home.arpa", "localdomain")
        ):
            if not self.allow_private or host != self.host:
                return False

        return True

    def allows(self, url: str) -> bool:
        """Check whether a URL is strictly within the allowed scan scope."""
        try:
            p = urlsplit(url)
            host = canonical_host(p.hostname) if p.hostname else ""
            port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        except ValueError:
            return False
        if p.username is not None or p.password is not None or not 1 <= port <= 65535:
            return False
        if p.scheme not in ("http", "https"):
            return False

        if not host:
            return False

        if not self._is_safe_destination(host):
            return False

        if self.mode == "same-origin":
            return (p.scheme, host, port) == (self.scheme, self.host, self.port)

        # subdomains mode
        if self.is_ip_host:
            # IP addresses do not have subdomains
            if host != self.host:
                return False
        else:
            if not (host == self.host or host.endswith("." + self.host)):
                return False

        # In subdomains mode: prevent arbitrary ports (e.g. SSH 22, Redis 6379, MySQL 3306)
        # Port must either match target port or be standard web ports (80, 443)
        allowed_ports = {self.port, 80, 443}
        if port not in allowed_ports:
            return False

        return True

    def allows_redirect(self, url: str) -> bool:
        """Check whether a redirect hop is permissible.

        Permits in-scope URLs as well as canonical HTTP -> HTTPS upgrade on the same host.
        """
        try:
            p = urlsplit(url)
            host = canonical_host(p.hostname) if p.hostname else ""
            port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        except ValueError:
            return False
        if p.username is not None or p.password is not None or not 1 <= port <= 65535:
            return False
        if p.scheme not in ("http", "https"):
            return False

        if not host:
            return False

        if not self._is_safe_destination(host):
            return False

        # Direct in-scope
        if self.allows(url):
            return True

        # Canonical HTTP -> HTTPS upgrade on same host
        if (
            self.scheme == "http"
            and p.scheme == "https"
            and host == self.host
            and (port == 443 or port == self.port)
        ):
            return True

        return False
