"""Async HTTP engine: pooling, bounded concurrency, rate limiting,
response size cap, graceful errors."""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from websentinel.config import Config
from websentinel.models import Response
from websentinel.utils.timing import RateLimiter, elapsed_ms

log = logging.getLogger("websentinel.http")


class HttpEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._sem = asyncio.Semaphore(config.concurrency)
        self._rl = RateLimiter(config.rate_limit)
        limits = httpx.Limits(max_connections=config.concurrency,
                              max_keepalive_connections=config.concurrency)
        headers = {"User-Agent": config.user_agent, **config.extra_headers}
        self._client = httpx.AsyncClient(
            limits=limits,
            timeout=httpx.Timeout(config.timeout),
            verify=config.verify_tls,
            proxy=config.proxy,
            headers=headers,
            follow_redirects=False,  # handled manually to cap chain
        )
        self.requests_made = 0

    @property
    def _over_budget(self) -> bool:
        return self.requests_made >= self.config.max_requests

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpEngine":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def fetch(self, url: str, method: str = "GET",
                    headers: dict[str, str] | None = None) -> Response:
        """Fetch a URL safely; never raises for network errors."""
        async with self._sem:
            await self._rl.wait()
            if self._over_budget:
                return self._err(url, time.monotonic(),
                                 f"request budget ({self.config.max_requests}) exhausted")
            chain: list[str] = []
            current = url
            start = time.monotonic()
            try:
                for attempt in range(self.config.retries + 2):
                    try:
                        for _ in range(self.config.max_redirects + 1):
                            r = await self._client.request(
                                method, current, headers=headers,
                                follow_redirects=False)
                            self.requests_made += 1
                            if r.is_redirect and self.config.follow_redirects \
                                    and "location" in r.headers:
                                chain.append(str(r.url))
                                current = str(r.url.join(
                                    r.headers["location"]))
                                continue
                            return await self._to_response(r, start, chain)
                        return Response(
                            url=url, final_url=current, status=0, headers={},
                            set_cookies=[], body="", content_type="",
                            content_length=0, elapsed_ms=elapsed_ms(start),
                            http_version="", redirect_chain=chain,
                            error="redirect loop / too many redirects")
                    except (httpx.ConnectError, httpx.ReadTimeout):
                        if attempt > self.config.retries:
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

    async def _to_response(self, r: httpx.Response, start: float,
                           chain: list[str]) -> Response:
        # ponytail: reads up to cap+1 then truncates; streaming would be
        # nicer — switch to r.aiter_bytes if bodies > 1MB become common
        body = await r.aread()
        truncated = body[: self.config.max_body_bytes]
        if len(body) > self.config.max_body_bytes:
            log.debug("response body truncated at %d bytes",
                      self.config.max_body_bytes)
        headers = {k.lower(): v for k, v in r.headers.items()}
        sc = r.headers.get_list("set-cookie") or [
            v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
        try:
            text = truncated.decode(r.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            text = truncated.decode("utf-8", errors="replace")
        http_version = getattr(r, "http_version", "") or ""
        return Response(
            url=str(r.request.url), final_url=str(r.url),
            status=r.status_code, headers=headers, set_cookies=sc,
            body=text, content_type=headers.get("content-type", ""),
            content_length=len(body), elapsed_ms=elapsed_ms(start),
            http_version=http_version, redirect_chain=chain)

    @staticmethod
    def _err(url: str, start: float, msg: str) -> Response:
        log.warning("fetch %s failed: %s", url, msg)
        return Response(url=url, final_url=url, status=0, headers={},
                        set_cookies=[], body="", content_type="",
                        content_length=0, elapsed_ms=elapsed_ms(start),
                        http_version="", error=msg)
