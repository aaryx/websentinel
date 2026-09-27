"""Scope control: restrict crawling/discovery to authorized scope."""
from __future__ import annotations

from urllib.parse import urlsplit

from websentinel.models import Target


class Scope:
    def __init__(self, target: Target, mode: str = "same-origin") -> None:
        if mode not in ("same-origin", "subdomains"):
            raise ValueError(f"unsafe scope mode: {mode!r}")
        self.mode = mode
        self.scheme = target.scheme
        self.host = target.host
        self.port = target.port

    def allows(self, url: str) -> bool:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
        if p.scheme not in ("http", "https"):
            return False
        if self.mode == "same-origin":
            port = p.port or (443 if p.scheme == "https" else 80)
            return (p.scheme, host, port) == (self.scheme, self.host, self.port)
        # subdomains: host must be target host or a subdomain of it
        return host == self.host or host.endswith("." + self.host)
