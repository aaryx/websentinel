"""Sustained loopback HTTP exercise with machine-readable resource evidence.

Run from the installed project: python scripts/endurance.py --seconds 300
No supplied targets: this harness only connects to its own local fixture server.
"""
import argparse
import asyncio
import gc
import gzip
import json
import logging
import platform
import statistics
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

from websentinel.config import Config
from websentinel.http.client import HttpEngine
from websentinel.reporting.files import write_report


async def exercise(seconds, concurrency):
    active = set()
    accepted = received = failures = completed = cycles = 0
    server_errors = []
    timings = []
    samples = []
    compressed = gzip.compress(b"x" * 100_000)

    async def serve(reader, writer):
        nonlocal accepted, received
        accepted += 1
        task = asyncio.current_task()
        active.add(task)
        try:
            while True:
                try:
                    request = await reader.readuntil(b"\r\n\r\n")
                except asyncio.IncompleteReadError:
                    break
                received += 1
                path = request.split(b" ")[1]
                if path == b"/disconnect":
                    break
                if path == b"/slow":
                    await asyncio.sleep(0.02)
                if path == b"/redirect":
                    wire = b"HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\n\r\n"
                elif path == b"/gzip":
                    wire = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + str(len(compressed)).encode() + b"\r\n\r\n" + compressed
                else:
                    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                writer.write(wire)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass  # Expected when the scanner closes a capped gzip body.
        except Exception as exc:
            server_errors.append(type(exc).__name__)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
            active.discard(task)

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    paths = ["/ok", "/gzip", "/redirect", "/slow", "/disconnect"]
    start = time.monotonic()
    started_utc = datetime.now(timezone.utc).isoformat()
    tracemalloc.start()
    try:
        async with server:
            while time.monotonic() - start < seconds:
                async with HttpEngine(Config(concurrency=concurrency, timeout=3, retries=0,
                                              max_body_bytes=4096, max_requests=1000), allow_private=True) as engine:
                    for _ in range(5):
                        responses = await asyncio.gather(*(engine.fetch(f"http://127.0.0.1:{port}{paths[n % 5]}")
                                                           for n in range(concurrency)))
                        for n, response in enumerate(responses):
                            expected = paths[n % 5]
                            valid = bool(response.error) if expected == "/disconnect" else (
                                response.status == 200 and (response.truncated and len(response.body) == 4096
                                                            if expected == "/gzip" else response.body == "ok"))
                            failures += not valid
                            completed += 1
                            timings.append(response.elapsed_ms)
                        if time.monotonic() - start >= seconds:
                            break
                        await asyncio.sleep(0.01)
                if active:
                    await asyncio.wait_for(asyncio.gather(*list(active)), 5)
                assert not active, "fixture connections leaked after engine.close()"
                cycles += 1
                if cycles % 10 == 0:
                    gc.collect()
                    samples.append(tracemalloc.get_traced_memory()[0])
                    # Bound the harness's own latency history; aggregate a moving sample.
                    timings = timings[-1000:]
        gc.collect()
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    duration = time.monotonic() - start
    growth = samples[-1] - samples[1] if len(samples) > 2 else 0
    passed = failures == 0 and not server_errors and not active and growth < 10_000_000
    return {
        "started_utc": started_utc,
        "python": platform.python_version(), "platform": platform.platform(),
        "duration_s": round(duration, 2), "requested_duration_s": seconds,
        "concurrency": concurrency, "client_cycles": cycles, "fetches": completed,
        "wire_requests": received, "connections_accepted": accepted,
        "active_connections_after_close": len(active), "unexpected_results": failures,
        "server_errors": server_errors, "latency_sample_size": len(timings),
        "latency_median_ms": round(statistics.median(timings), 2),
        "traced_current_bytes": current, "traced_peak_bytes": peak,
        "post_warmup_traced_growth_bytes": growth, "memory_samples": samples,
        "memory_growth_limit_bytes": 10_000_000, "passed": passed,
        "limits": "Python traced allocations, not RSS; loopback fixture, not production traffic",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 86400 or not 1 <= args.concurrency <= 100:
        parser.error("seconds must be 1..86400 and concurrency 1..100")
    logging.getLogger("websentinel").setLevel(logging.CRITICAL)
    result = asyncio.run(exercise(args.seconds, args.concurrency))
    text = json.dumps(result, indent=2)
    if args.output:
        write_report(args.output, text)
    print(text)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
