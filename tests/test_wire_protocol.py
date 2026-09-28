"""Malformed HTTP wire responses and early disconnects over real sockets."""
import asyncio

import pytest

from websentinel.config import Config
from websentinel.http.client import HttpEngine


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", [
    b"NOT HTTP\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\ninvalid\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na",
])
async def test_bad_wire_returns_error_without_hanging(wire):
    finished = asyncio.Event()
    async def handler(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(wire)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            finished.set()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server, HttpEngine(Config(timeout=1, retries=0), allow_private=True) as engine:
        response = await engine.fetch(f"http://127.0.0.1:{port}/")
        await asyncio.wait_for(finished.wait(), 2)
    assert response.status == 0 and response.error
    assert engine.requests_made == 1
