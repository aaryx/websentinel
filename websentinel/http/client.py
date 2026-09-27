"""Async HTTP engine: pooling, bounded concurrency, rate limiting,
response size cap, graceful errors, and scope-safe redirects."""
from __future__ import annotations

import asyncio
import logging
import time
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
)

log = logging.getLogger("websentinel.http")


class HttpEngine:
    """Bounded, scope-enforcing async HTTP client."""

    def __init__(
        self,
        config: Config,
        scope: Scope | None = None,
        allow_private: bool = False,
    ) -> None:
        self.config = config
        self.scope = scope
        self.allow_private = allow_private
        self._sem = asyncio.Semaphore(config.concurrency)
        self._rl = RateLimiter(config.rate_limit)
        self._budget_lock = asyncio.Lock()
        limits = httpx.Limits(
            max_connections=config.concurrency,
            max_keepalive_connections=config.concurrency,
        )
        headers = {"User-Agent": config.user_agent, **config.extra_headers}
        self._client = httpx.AsyncClient(
            limits=limits,
            timeout=httpx.Timeout(config.timeout),
            verify=config.verify_tls,
            proxy=config.proxy,
            headers=headers,
            follow_redirects=False,  # handled manually to cap chain & enforce scope
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

        p = urlsplit(target_url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        if not host:
            return False
        if not self.allow_private:
            try:
                validate_host_safety(host, allow_private=False)
            except URLValidationError:
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
        """Fetch a URL safely; never raises for network errors."""
        async with self._sem:
            await self._rl.wait()
            start = time.monotonic()

            try:
                for attempt in range(self.config.retries + 1):
                    chain: list[str] = []
                    current = url
                    try:
                        for _ in range(self.config.max_redirects + 1):
                            if not await self._reserve_request():
                                return self._err(
                                    url,
                                    start,
                                    f"request budget ({self.config.max_requests}) exhausted",
                                )

                            req = self._client.build_request(
                                method, current, headers=headers
                            )
                            r = await self._client.send(req, stream=True)

                            if (
                                r.is_redirect
                                and self.config.follow_redirects
                                and "location" in r.headers
                            ):
                                raw_loc = r.headers["location"]
                                next_url = str(r.url.join(raw_loc))
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
                            redirect_chain=chain,
                            error="redirect loop / too many redirects",
                        )
                    except (httpx.ConnectError, httpx.ReadTimeout):
                        if attempt >= self.config.retries:
                            raise
                        await asyncio.sleep(0.25 * (attempt + 1))

                return self._err(url, start, "retry budget exhausted")
            except httpx.TimeoutException:
                return self._err(url, start, "connection/Read timeout")
            except httpx.ConnectError as e:
                return self._err(url, start, f"connection error: {e}")
            except httpx.HTTPError as e:
                return self._err(url, start, f"HTTP error: {e}")
            except Exception as e:  # malformed responses, SSL oddities
                return self._err(url, start, f"unexpected error: {e}")

    async def _to_response(
        self, r: httpx.Response, start: float, chain: list[str]
    ) -> Response:
        try:
            chunks: list[bytes] = []
            total_read = 0
            max_bytes = self.config.max_body_bytes

            async for chunk in r.aiter_bytes():
                chunks.append(chunk)
                total_read += len(chunk)
                if total_read >= max_bytes:
                    break

            body_bytes = b"".join(chunks)[:max_bytes]
            if total_read > max_bytes:
                log.debug("response body truncated at %d bytes", max_bytes)
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
        req_url = sanitize_url_for_logging(str(r.request.url))
        resp_url = sanitize_url_for_logging(str(r.url))

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
            redirect_chain=[sanitize_url_for_logging(u) for u in chain],
        )

    @staticmethod
    def _err(url: str, start: float, msg: str) -> Response:
        safe_url = sanitize_url_for_logging(url)
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
