"""Bounded same-origin crawler with dedup, depth, page cap, content-type filter."""
from __future__ import annotations

import asyncio
import logging
from collections import deque

from websentinel.analyzers.html import extract_links
from websentinel.http.client import HttpEngine
from websentinel.models import Response
from websentinel.utils.urls import normalize_url, same_origin

log = logging.getLogger("websentinel.crawler")


class Crawler:
    def __init__(
        self,
        engine: HttpEngine,
        origin: str,
        max_depth: int = 1,
        max_pages: int = 50,
        robots_disallow: list[str] | None = None,
        scope=None,
        robots=None,
    ) -> None:
        self.engine = engine
        self.origin = origin
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.disallow = robots_disallow or []
        self.scope = scope
        self.robots = robots
        self.skipped_out_of_scope = 0
        self.seen: set[str] = set()

    def _blocked_by_robots(self, url: str) -> bool:
        from urllib.parse import urlsplit

        path = urlsplit(url).path
        if self.robots is not None:
            return not self.robots.can_fetch(self.engine.config.user_agent, url)
        return any(path.startswith(d) for d in self.disallow if d)

    def _enqueue_links(self, resp, depth, queue, results_count):
        for link in extract_links(resp):
            if results_count + len(queue) >= self.max_pages:
                break
            try:
                in_scope = self.scope.allows(link) if self.scope else same_origin(link, self.origin)
                n = normalize_url(link)
            except ValueError:
                continue
            if n in self.seen or not in_scope or self._blocked_by_robots(n):
                if n not in self.seen and not in_scope:
                    self.skipped_out_of_scope += 1
                continue
            self.seen.add(n)
            queue.append((n, depth))

    async def crawl(
        self, start_url: str, initial_response: Response | None = None
    ) -> list[Response]:
        queue: deque[tuple[str, int]] = deque()
        self.seen.add(normalize_url(start_url))
        results: list[Response] = []

        if initial_response is not None:
            results.append(initial_response)
            self.seen.add(normalize_url(initial_response.final_url))
            if not initial_response.error and self.max_depth > 0:
                self._enqueue_links(initial_response, 1, queue, len(results))
        else:
            queue.append((start_url, 0))

        while queue and len(results) < self.max_pages:
            batch: list[tuple[str, int]] = []
            while (
                queue
                and len(batch) < self.engine.config.concurrency
                and len(results) + len(batch) < self.max_pages
            ):
                batch.append(queue.popleft())
            if not batch:
                break
            responses = await asyncio.gather(
                *(self.engine.fetch(u) for u, _ in batch)
            )
            results.extend(responses)
            for (u, depth), resp in zip(batch, responses):
                self.seen.add(normalize_url(resp.final_url))
                if resp.error or depth >= self.max_depth:
                    continue
                self._enqueue_links(resp, depth + 1, queue, len(results))
        return results
