"""Configuration loading with safe defaults."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    timeout: float = 10.0
    concurrency: int = 10
    rate_limit: float = 0.0          # requests/second, 0 = unlimited
    max_pages: int = 50
    max_depth: int = 1
    user_agent: str = "WebSentinel/1.0 (+authorized security assessment)"
    follow_redirects: bool = True
    max_redirects: int = 5
    max_body_bytes: int = 1_048_576
    verify_tls: bool = True
    output_format: str = "terminal"
    proxy: str | None = None
    retries: int = 1
    max_requests: int = 500           # hard request budget
    scope: str = "same-origin"        # same-origin | subdomains
    extra_headers: dict = field(default_factory=dict)  # redacted from logs

    @classmethod
    def load(cls, path: str | None) -> "Config":
        cfg = cls()
        candidates = ([Path(path)] if path else
                      [Path(".websentinel.yml"), Path("websentinel.yaml"),
                       Path("websentinel.yml")])
        data = None
        for p in candidates:
            if p.is_file():
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                break
        if data:
            flat = dict(data.get("scan", data))  # support flat or nested
            for k, v in flat.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
            cfg.scope = data.get("scope", {}).get("mode", cfg.scope) \
                if isinstance(data.get("scope"), dict) else flat.get(
                    "scope", cfg.scope)
        return cfg
