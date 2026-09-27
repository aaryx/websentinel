"""Tests for HTTP resilience: streaming limits, budget under concurrency, retries, and redaction."""
import asyncio
import gzip
import httpx
import pytest

from websentinel.config import Config
from websentinel.http.client import HttpEngine
from websentinel.utils.urls import sanitize_url_for_logging


@pytest.mark.asyncio
async def test_response_streaming_size_limit():
    large_payload = b"X" * 100_000

    def handler(request: httpx.Request):
        return httpx.Response(200, content=large_payload)

    transport = httpx.MockTransport(handler)
    cfg = Config(max_body_bytes=1024)
    engine = HttpEngine(cfg)
    engine._client = httpx.AsyncClient(transport=transport)

    resp = await engine.fetch("http://test.local/large")
    await engine.close()

    assert resp.status == 200
    assert len(resp.body) == 1024
    assert resp.content_length == 1024


@pytest.mark.asyncio
async def test_decompression_bomb_size_bounded():
    # 500 KB compressed to a few hundred bytes
    uncompressed = b"A" * 500_000
    compressed = gzip.compress(uncompressed)

    def handler(request: httpx.Request):
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip", "Content-Type": "text/plain"},
            content=compressed,
        )

    transport = httpx.MockTransport(handler)
    cfg = Config(max_body_bytes=2048)
    engine = HttpEngine(cfg)
    engine._client = httpx.AsyncClient(transport=transport)

    resp = await engine.fetch("http://test.local/bomb")
    await engine.close()

    assert resp.status == 200
    # The decompressed content must be strictly capped at max_body_bytes
    assert len(resp.body) == 2048


@pytest.mark.asyncio
async def test_request_budget_strict_under_concurrency():
    count = 0
    lock = asyncio.Lock()

    def handler(request: httpx.Request):
        nonlocal count
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    # Set hard budget of 5 with concurrency of 10
    cfg = Config(max_requests=5, concurrency=10, retries=0)
    engine = HttpEngine(cfg)
    engine._client = httpx.AsyncClient(transport=transport)

    # Launch 20 concurrent requests
    tasks = [engine.fetch(f"http://test.local/item{i}") for i in range(20)]
    responses = await asyncio.gather(*tasks)
    await engine.close()

    # Total requests recorded must not exceed 5
    assert engine.requests_made == 5

    # Successful responses should be exactly 5, and remaining 15 should have budget exhausted error
    successes = [r for r in responses if r.status == 200]
    exhausted = [r for r in responses if "budget" in (r.error or "").lower()]
    assert len(successes) == 5
    assert len(exhausted) == 15


@pytest.mark.asyncio
async def test_bounded_retries_resets_chain():
    attempts = 0

    def handler(request: httpx.Request):
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, text="recovered")

    transport = httpx.MockTransport(handler)
    cfg = Config(retries=2, timeout=2)
    engine = HttpEngine(cfg)
    engine._client = httpx.AsyncClient(transport=transport)

    resp = await engine.fetch("http://test.local/retry")
    await engine.close()

    assert resp.status == 200
    assert resp.body == "recovered"
    assert attempts == 2


def test_sanitize_url_for_logging():
    url_with_creds = "https://admin:mysecretpassword@example.com/api/data?key=123"
    sanitized = sanitize_url_for_logging(url_with_creds)
    assert "mysecretpassword" not in sanitized
    assert "[REDACTED]" in sanitized
    assert "admin:[REDACTED]@example.com" in sanitized
