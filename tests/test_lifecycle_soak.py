"""Bounded real-socket lifecycle soak: repeated clients must close connections."""
import asyncio
import gc

import pytest

from websentinel.config import Config
from websentinel.http.client import HttpEngine


@pytest.mark.asyncio
async def test_repeated_pooled_clients_release_real_sockets():
    active = set()
    errors = []
    completed_requests = 0

    async def handler(reader, writer):
        nonlocal completed_requests
        task = asyncio.current_task()
        active.add(task)
        try:
            while True:
                try:
                    await reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError:
                    break
                completed_requests += 1
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        except Exception as exc:
            errors.append(exc)
        finally:
            writer.close()
            await writer.wait_closed()
            active.discard(task)

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        for _ in range(20):
            async with HttpEngine(Config(concurrency=4, retries=0), allow_private=True) as engine:
                responses = await asyncio.gather(*(engine.fetch(f"http://127.0.0.1:{port}/{n}") for n in range(10)))
                assert all(r.status == 200 and r.body == "ok" for r in responses)
                assert engine.requests_made == 10
            if active:
                await asyncio.wait_for(asyncio.gather(*list(active)), 3)
            assert not active
    gc.collect()
    assert not errors and completed_requests == 200
