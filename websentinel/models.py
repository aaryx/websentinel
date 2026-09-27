"""Core data models: targets, responses, findings, scan results."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Target:
    original: str
    url: str
    scheme: str
    host: str
    port: int


@dataclass
class Response:
    """Sanitized record of one HTTP response."""
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    set_cookies: list[str]
    body: str
    content_type: str
    content_length: int
    elapsed_ms: float
    http_version: str
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    url: str
    description: str
    impact: str = ""
    evidence: str = ""
    remediation: str = ""
    parameter: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    method: str = "GET"
    scanner_check: str = ""
    tags: list[str] = field(default_factory=list)
    affected_urls: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class ScanResult:
    target: Target
    findings: list[Finding] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    responses: list[Response] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    started: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_s: float = 0.0
    requests_made: int = 0

    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
