"""Adversarial streaming, deadlines, cancellation, and load contracts."""
import asyncio
import gzip
import time
import tracemalloc
import zlib

import httpx
import pytest

from websentinel.config import Config
from websentinel.http.client import HttpEngine


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks, delay=0):
        self.chunks, self.delay, self.closed = chunks, delay, False

    async def __aiter__(self):
        for chunk in self.chunks:
            if self.delay:
                await asyncio.sleep(self.delay)
            yield chunk

    async def aclose(self):
        self.closed = True


async def engine_for(handler, **config):
    engine = HttpEngine(Config(retries=0, **config), allow_private=True)
    await engine.close()
    engine._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return engine


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding,payload", [
    ("gzip", gzip.compress(b"first") + gzip.compress(b"second")),
    ("deflate", zlib.compress(b"firstsecond")),
    ("identity", b"firstsecond"),
])
async def test_complete_decoding_across_tiny_chunks(encoding, payload):
    stream = Stream([payload[i:i + 1] for i in range(len(payload))])
    engine = await engine_for(lambda r: httpx.Response(200, headers={"content-encoding": encoding}, stream=stream))
    async with engine:
        response = await engine.fetch("http://localhost/")
    assert response.body == "firstsecond"
    assert not response.truncated and stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [gzip.compress(b"secret")[:-6], gzip.compress(b"secret") + b"corrupt", b"not gzip"])
async def test_corrupt_compression_is_not_silently_successful(payload):
    stream = Stream([payload])
    engine = await engine_for(lambda r: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream))
    async with engine:
        response = await engine.fetch("http://localhost/")
    assert response.error
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("length,expected_truncated", [(1023, False), (1024, False), (1025, True)])
async def test_truncation_flag_is_exact(length, expected_truncated):
    stream = Stream([b"a" * length])
    engine = await engine_for(lambda r: httpx.Response(200, stream=stream), max_body_bytes=1024)
    async with engine:
        response = await engine.fetch("http://localhost/")
    assert response.truncated is expected_truncated
    assert len(response.body) == min(length, 1024)


@pytest.mark.asyncio
async def test_slow_drip_has_total_request_deadline():
    stream = Stream([b"a"] * 100, delay=0.02)
    engine = await engine_for(lambda r: httpx.Response(200, stream=stream), timeout=0.1)
    start = time.monotonic()
    async with engine:
        response = await asyncio.wait_for(engine.fetch("http://localhost/"), timeout=0.8)
    assert response.error and "timeout" in response.error.lower()
    assert time.monotonic() - start < 0.8
    assert stream.closed


@pytest.mark.asyncio
async def test_cancellation_closes_stream_and_releases_slot():
    stream = Stream([b"a"], delay=10)
    entered = asyncio.Event()
    def handler(req):
        entered.set()
        return httpx.Response(200, stream=stream) if req.url.path == "/slow" else httpx.Response(200)
    engine = await engine_for(handler, concurrency=1)
    async with engine:
        task = asyncio.create_task(engine.fetch("http://localhost/slow"))
        await entered.wait()
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (await asyncio.wait_for(engine.fetch("http://localhost/ok"), 1)).status == 200
    assert stream.closed


@pytest.mark.asyncio
async def test_large_compressed_body_has_bounded_allocation():
    payload = gzip.compress(b"a" * 32_000_000)
    stream = Stream([payload])
    engine = await engine_for(lambda r: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream), max_body_bytes=4096)
    tracemalloc.start()
    try:
        async with engine:
            response = await engine.fetch("http://localhost/")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert response.body == "a" * 4096 and response.truncated
    assert peak < 2_000_000, f"decoder allocated {peak} bytes for a 4 KiB cap"


@pytest.mark.asyncio
async def test_concurrency_and_budget_under_200_scheduled_requests():
    active = peak = sent = 0
    async def handler(req):
        nonlocal active, peak, sent
        sent += 1
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.005)
        active -= 1
        return httpx.Response(200)
    engine = await engine_for(handler, concurrency=4, max_requests=17)
    async with engine:
        responses = await asyncio.gather(*(engine.fetch(f"http://localhost/{i}") for i in range(200)))
    assert 1 < peak <= 4
    assert sent == engine.requests_made == 17
    assert sum(r.status == 200 for r in responses) == 17


@pytest.mark.asyncio
async def test_real_rate_spacing_across_redirect_hops():
    sent = []
    def handler(req):
        sent.append(time.monotonic())
        return httpx.Response(302, headers={"location": "/next"}) if len(sent) < 3 else httpx.Response(200)
    engine = await engine_for(handler, rate_limit=20)
    async with engine:
        assert (await engine.fetch("http://localhost/")).status == 200
    assert all(b - a >= 0.045 for a, b in zip(sent, sent[1:]))


@pytest.mark.asyncio
async def test_redirect_loop_closes_every_response_and_obeys_cap():
    streams = []
    def handler(req):
        stream = Stream([])
        streams.append(stream)
        return httpx.Response(302, headers={"location": "/"}, stream=stream)
    engine = await engine_for(handler, max_redirects=2)
    async with engine:
        response = await engine.fetch("http://localhost/")
    assert response.error and "redirect" in response.error
    assert len(streams) == engine.requests_made == 3
    assert all(s.closed for s in streams)
