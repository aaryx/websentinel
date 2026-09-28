"""Async HTTP engine: pooling, bounded concurrency, rate limiting,
response size cap, graceful errors, and scope-safe redirects."""
from __future__ import annotations

import asyncio
import logging
import re
import time
import zlib
from urllib.parse import urlsplit

import httpx

from websentinel.config import Config
from websentinel.core.scope import Scope
from websentinel.models import Response
from websentinel.utils.timing import RateLimiter, elapsed_ms
from websentinel.utils.urls import (
    URLValidationError,
    sanitize_url_for_logging,
    validate_host_safety,
    same_origin,
    resolve_connection_address,
    canonical_host,
)

log = logging.getLogger("websentinel.http")


class _PinnedTransport(httpx.AsyncBaseTransport):
    """Keep original URLs/cookies while connecting only to a validated DNS result."""

    def __init__(self, config, scope, allow_private, limits):
        self.config, self.scope, self.allow_private = config, scope, allow_private
        self.limits = limits
        self.transports = {}

    async def handle_async_request(self, request):
        host = request.url.raw_host.decode("ascii")
        private_allowed = self.allow_private and (self.scope is None or host == self.scope.host)
        address = await asyncio.wait_for(
            asyncio.to_thread(resolve_connection_address, host, private_allowed), self.config.timeout
        )
        # Separate pools prevent TLS sessions being reused across hostnames sharing an IP.
        origin = (request.url.scheme, host, request.url.port)
        if origin not in self.transports:
            self.transports[origin] = httpx.AsyncHTTPTransport(
                verify=self.config.verify_tls, proxy=self.config.proxy,
                limits=self.limits, trust_env=False,
            )
        pinned = httpx.Request(
            # HTTP CONNECT in httpcore does not honor sni_hostname. Keep the
            # hostname for HTTPS proxies; the explicitly configured proxy owns
            # tunnel DNS/routing and must be trusted (as with conventional clients).
            request.method, request.url if self.config.proxy and request.url.scheme == "https"
            else request.url.copy_with(host=address), headers=request.headers,
            stream=request.stream, extensions={**request.extensions, "sni_hostname": host},
        )
        return await self.transports[origin].handle_async_request(pinned)

    async def aclose(self):
        await asyncio.gather(*(t.aclose() for t in self.transports.values()))


class HttpEngine:
    """Bounded, scope-enforcing async HTTP client."""

    def __init__(
        self,
        config: Config,
        scope: Scope | None = None,
        allow_private: bool = False,
    ) -> None:
        config.validate()
        self.config = config
        self.scope = scope
        self._credential_origin = scope.target.url if scope else None
        self.allow_private = allow_private
        self._sem = asyncio.Semaphore(config.concurrency)
        self._rl = RateLimiter(config.rate_limit)
        self._budget_lock = asyncio.Lock()
        limits = httpx.Limits(
            max_connections=config.concurrency,
            max_keepalive_connections=config.concurrency,
        )
        headers = {"User-Agent": config.user_agent, "Accept-Encoding": "identity", **config.extra_headers}
        self._client = httpx.AsyncClient(
            limits=limits,
            timeout=httpx.Timeout(config.timeout),
            verify=config.verify_tls,
            transport=_PinnedTransport(config, scope, allow_private, limits),
            headers=headers,
            follow_redirects=False,  # handled manually to cap chain & enforce scope
            trust_env=False,
        )
        self.requests_made = 0

    @property
    def _over_budget(self) -> bool:
        return self.requests_made >= self.config.max_requests

    async def _reserve_request(self) -> bool:
        async with self._budget_lock:
            if self.requests_made >= self.config.max_requests:
                return False
            self.requests_made += 1
            return True

    def _is_redirect_allowed(self, target_url: str) -> bool:
        if self.scope is not None:
            return self.scope.allows_redirect(target_url)

        try:
            p = urlsplit(target_url)
            port = p.port
        except ValueError:
            return False
        if p.username is not None or p.password is not None or port == 0:
            return False
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        if not host:
            return False
        return True

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpEngine":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Bound total fetch time after admission, including slow-drip bodies."""
        async with self._sem:
            start = time.monotonic()
            try:
                return await asyncio.wait_for(self._fetch(url, method, headers), self.config.timeout)
            except TimeoutError:
                return self._err(url, start, "total request timeout")

    async def _fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Fetch a URL safely; never raises for network errors."""
        # The public fetch method owns admission and the total deadline.
        async with asyncio.timeout(self.config.timeout):
            start = time.monotonic()

            try:
                for attempt in range(self.config.retries + 1):
                    chain: list[str] = []
                    current = url
                    try:
                        for _ in range(self.config.max_redirects + 1):
                            if not self._is_redirect_allowed(current):
                                return self._err(url, start, "destination refused (out of scope or unsafe)")
                            host = canonical_host(urlsplit(current).hostname or "")
                            private_allowed = self.allow_private and (
                                self.scope is None or host.lower() == self.scope.host
                            )
                            await asyncio.wait_for(
                                asyncio.to_thread(validate_host_safety, host, private_allowed), self.config.timeout
                            )
                            if not await self._reserve_request():
                                return self._err(
                                    url,
                                    start,
                                    f"request budget ({self.config.max_requests}) exhausted",
                                )

                            await self._rl.wait()
                            req = self._client.build_request(
                                method, current, headers=headers
                            )
                            credential_origin = self._credential_origin or url
                            if not same_origin(current, credential_origin):
                                for name in {"authorization", "proxy-authorization", "cookie", "host",
                                             *map(str.lower, self.config.extra_headers),
                                             *map(str.lower, headers or {})}:
                                    req.headers.pop(name, None)
                                req.headers["Host"] = httpx.URL(current).netloc.decode("ascii")
                            r = await self._client.send(req, stream=True)

                            if (
                                r.is_redirect
                                and self.config.follow_redirects
                                and "location" in r.headers
                            ):
                                raw_loc = r.headers["location"]
                                try:
                                    next_url = str(r.url.join(raw_loc))
                                except (ValueError, httpx.InvalidURL):
                                    await r.aclose()
                                    return self._err(url, start, "invalid redirect URL")
                                chain.append(str(r.url))

                                if not self._is_redirect_allowed(next_url):
                                    log.info(
                                        "redirect to %s refused (out of scope or unsafe)",
                                        sanitize_url_for_logging(next_url),
                                    )
                                    return await self._to_response(r, start, chain)

                                await r.aclose()
                                current = next_url
                                continue

                            return await self._to_response(r, start, chain)

                        return Response(
                            url=sanitize_url_for_logging(url),
                            final_url=sanitize_url_for_logging(current),
                            status=0,
                            headers={},
                            set_cookies=[],
                            body="",
                            content_type="",
                            content_length=0,
                            elapsed_ms=elapsed_ms(start),
                            http_version="",
                            redirect_chain=[sanitize_url_for_logging(u) for u in chain],
                            error="redirect loop / too many redirects",
                        )
                    except (httpx.ConnectError, httpx.ReadTimeout):
                        if attempt >= self.config.retries:
                            raise
                        await asyncio.sleep(0.25 * (attempt + 1))

                return self._err(url, start, "retry budget exhausted")
            except httpx.TimeoutException:
                return self._err(url, start, "connection/Read timeout")
            except TimeoutError:
                return self._err(url, start, "DNS resolution timeout")
            except httpx.ConnectError as e:
                return self._err(url, start, f"connection error: {e}")
            except httpx.HTTPError as e:
                return self._err(url, start, f"HTTP error: {e}")
            except URLValidationError:
                return self._err(url, start, "destination refused (non-public address)")
            except Exception as e:  # malformed responses, SSL oddities
                return self._err(url, start, f"unexpected error: {e}")

    async def _to_response(
        self, r: httpx.Response, start: float, chain: list[str]
    ) -> Response:
        try:
            max_bytes = self.config.max_body_bytes
            body = bytearray()
            # Bound decompression itself, not just the final stored body.
            encoding = r.headers.get("content-encoding", "identity").lower().strip()
            decoder = None
            if not r.is_stream_consumed:
                if encoding in ("gzip", "deflate"):
                    decoder = zlib.decompressobj(31 if encoding == "gzip" else 15)
                elif encoding not in ("", "identity"):
                    raise ValueError("unsupported response content encoding")
            if r.is_stream_consumed:
                body.extend(r.content[:max_bytes + 1])
            else:
                async for chunk in r.aiter_raw(chunk_size=min(65536, max_bytes)):
                    while chunk and len(body) <= max_bytes:
                        remaining = max_bytes + 1 - len(body)
                        if decoder:
                            if decoder.eof:
                                if encoding != "gzip":
                                    raise ValueError("trailing data after compressed response")
                                decoder = zlib.decompressobj(31)
                            body.extend(decoder.decompress(chunk, remaining))
                            chunk = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
                        else:
                            body.extend(chunk[:remaining])
                            break
                    if len(body) > max_bytes:
                        break
                if decoder and len(body) <= max_bytes and not decoder.eof:
                    raise ValueError("incomplete compressed response")
            truncated = len(body) > max_bytes
            body_bytes = bytes(body[:max_bytes])
        finally:
            await r.aclose()

        headers = {k.lower(): v for k, v in r.headers.items()}
        sc = r.headers.get_list("set-cookie") or [
            v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"
        ]
        try:
            text = body_bytes.decode(r.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            text = body_bytes.decode("utf-8", errors="replace")

        http_version = getattr(r, "http_version", "") or ""
        req_url = sanitize_url_for_logging(str(r.request.url), redact_query=False)
        resp_url = sanitize_url_for_logging(str(r.url), redact_query=False)

        return Response(
            url=req_url,
            final_url=resp_url,
            status=r.status_code,
            headers=headers,
            set_cookies=sc,
            body=text,
            content_type=headers.get("content-type", ""),
            content_length=len(body_bytes),
            elapsed_ms=elapsed_ms(start),
            http_version=http_version,
            redirect_chain=[sanitize_url_for_logging(u, redact_query=False) for u in chain],
            truncated=truncated,
        )

    @staticmethod
    def _err(url: str, start: float, msg: str) -> Response:
        safe_url = sanitize_url_for_logging(url)
        msg = re.sub(r"https?://[^\s'\"<>]+", lambda m: sanitize_url_for_logging(m.group()), msg)
        log.warning("fetch %s failed: %s", safe_url, msg)
        return Response(
            url=safe_url,
            final_url=safe_url,
            status=0,
            headers={},
            set_cookies=[],
            body="",
            content_type="",
            content_length=0,
            elapsed_ms=elapsed_ms(start),
            http_version="",
            error=msg,
        )
