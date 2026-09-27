"""Configuration loading with strict validation and safe defaults."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_VALID_KEYS = {
    "timeout",
    "concurrency",
    "rate_limit",
    "max_pages",
    "max_depth",
    "user_agent",
    "follow_redirects",
    "max_redirects",
    "max_body_bytes",
    "verify_tls",
    "output_format",
    "proxy",
    "retries",
    "max_requests",
    "scope",
    "extra_headers",
    "scan",
}


@dataclass
class Config:
    timeout: float = 10.0
    concurrency: int = 10
    rate_limit: float = 0.0  # requests/second, 0 = unlimited
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
    max_requests: int = 500  # hard request budget
    scope: str = "same-origin"  # same-origin | subdomains
    extra_headers: dict = field(default_factory=dict)  # redacted from logs

    def validate(self) -> None:
        """Validate config constraints and types."""
        if not isinstance(self.timeout, (int, float)) or self.timeout <= 0:
            raise ValueError(f"timeout must be positive number, got {self.timeout!r}")
        if not isinstance(self.concurrency, int) or self.concurrency < 1:
            raise ValueError(f"concurrency must be integer >= 1, got {self.concurrency!r}")
        if not isinstance(self.rate_limit, (int, float)) or self.rate_limit < 0:
            raise ValueError(f"rate_limit must be >= 0, got {self.rate_limit!r}")
        if not isinstance(self.max_pages, int) or self.max_pages < 1:
            raise ValueError(f"max_pages must be integer >= 1, got {self.max_pages!r}")
        if not isinstance(self.max_depth, int) or self.max_depth < 0:
            raise ValueError(f"max_depth must be integer >= 0, got {self.max_depth!r}")
        if not isinstance(self.max_redirects, int) or self.max_redirects < 0:
            raise ValueError(f"max_redirects must be integer >= 0, got {self.max_redirects!r}")
        if not isinstance(self.max_body_bytes, int) or self.max_body_bytes < 1:
            raise ValueError(f"max_body_bytes must be integer >= 1, got {self.max_body_bytes!r}")
        if not isinstance(self.retries, int) or self.retries < 0:
            raise ValueError(f"retries must be integer >= 0, got {self.retries!r}")
        if not isinstance(self.max_requests, int) or self.max_requests < 1:
            raise ValueError(f"max_requests must be integer >= 1, got {self.max_requests!r}")
        if self.scope not in ("same-origin", "subdomains"):
            raise ValueError(f"scope must be 'same-origin' or 'subdomains', got {self.scope!r}")
        if self.output_format not in ("terminal", "json", "html", "csv", "sarif"):
            raise ValueError(
                f"output_format must be one of terminal, json, html, csv, sarif; got {self.output_format!r}"
            )
        if not isinstance(self.extra_headers, dict):
            raise ValueError(f"extra_headers must be a dictionary, got {type(self.extra_headers).__name__}")

    @classmethod
    def load(cls, path: str | None) -> "Config":
        cfg = cls()
        if path:
            p = Path(path)
            if not p.is_file():
                raise FileNotFoundError(f"Configuration file not found: {path}")
            candidates = [p]
        else:
            candidates = [
                Path(".websentinel.yml"),
                Path("websentinel.yaml"),
                Path("websentinel.yml"),
            ]

        data = None
        for p in candidates:
            if p.is_file():
                try:
                    loaded = yaml.safe_load(p.read_text(encoding="utf-8"))
                except yaml.YAMLError as e:
                    raise ValueError(f"Invalid YAML in config file {p}: {e}") from e
                data = loaded or {}
                break

        if data is not None:
            if not isinstance(data, dict):
                raise ValueError(f"Configuration must be a YAML mapping, got {type(data).__name__}")

            # Check for unknown keys at top level
            unknown = set(data.keys()) - _VALID_KEYS
            if unknown:
                raise ValueError(f"Unknown configuration key(s): {', '.join(sorted(unknown))}")

            flat = dict(data.get("scan", data))
            if isinstance(data.get("scan"), dict):
                scan_unknown = set(data["scan"].keys()) - (_VALID_KEYS - {"scan"})
                if scan_unknown:
                    raise ValueError(
                        f"Unknown key(s) in 'scan' section: {', '.join(sorted(scan_unknown))}"
                    )

            for k, v in flat.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)

            if isinstance(data.get("scope"), dict):
                cfg.scope = data["scope"].get("mode", cfg.scope)
            elif "scope" in flat:
                cfg.scope = flat["scope"]

        cfg.validate()
        return cfg
