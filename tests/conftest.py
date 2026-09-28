from websentinel.models import Response
import ipaddress
import socket

import pytest


@pytest.fixture(autouse=True)
def offline_dns(monkeypatch, request):
    """Ordinary tests must not depend on public DNS or network availability."""
    if request.node.get_closest_marker("online"):
        return
    original = socket.getaddrinfo
    def local_only(host, *args, **kwargs):
        text = host.decode() if isinstance(host, bytes) else str(host)
        try:
            loopback = ipaddress.ip_address(text).is_loopback
        except ValueError:
            loopback = text == "localhost"
        if loopback:
            return original(host, *args, **kwargs)
        raise socket.gaierror("public DNS disabled by offline test fixture")
    monkeypatch.setattr(socket, "getaddrinfo", local_only)


def make_response(url="https://example.com/", status=200, headers=None,
                  cookies=(), body="", ctype="text/html"):
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return Response(url=url, final_url=url, status=status, headers=h,
                    set_cookies=list(cookies), body=body,
                    content_type=ctype or h.get("content-type", ""),
                    content_length=len(body), elapsed_ms=1.0,
                    http_version="HTTP/2")
