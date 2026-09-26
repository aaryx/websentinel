import pytest

from websentinel.config import Config
from websentinel.crawler.crawler import Crawler
from conftest import make_response


class FakeEngine:
    def __init__(self, pages):
        self.pages = pages
        self.config = Config(concurrency=4, rate_limit=0, timeout=1)
        self.requests_made = 0

    async def fetch(self, url, **kw):
        self.requests_made += 1
        return self.pages.get(url, make_response(url=url, status=404,
                                                 body=""))


@pytest.mark.asyncio
async def test_same_origin_and_depth():
    root = make_response(url="https://x.test/", body='<a href="/a">a</a>'
                         '<a href="https://evil.test/">x</a>'
                         '<a href="/deep">d</a>')
    pa = make_response(url="https://x.test/a", body='<a href="/b">b</a>')
    pd = make_response(url="https://x.test/deep", body="")
    engine = FakeEngine({"https://x.test/": root, "https://x.test/a": pa,
                         "https://x.test/deep": pd})
    c = Crawler(engine, "https://x.test/", max_depth=1, max_pages=10)
    pages = {r.final_url for r in await c.crawl("https://x.test/")}
    assert "https://evil.test/" not in pages          # off-origin excluded
    assert "https://x.test/a" in pages
    assert "https://x.test/b" not in pages            # depth=1


@pytest.mark.asyncio
async def test_max_pages_cap():
    body = "".join(f'<a href="/{i}">{i}</a>' for i in range(100))
    root = make_response(url="https://x.test/", body=body)
    engine = FakeEngine({"https://x.test/": root})
    c = Crawler(engine, "https://x.test/", max_depth=1, max_pages=5)
    res = await c.crawl("https://x.test/")
    assert len(res) <= 5
