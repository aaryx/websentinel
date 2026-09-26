"""Machine-readable JSON report."""
from __future__ import annotations

import json
from dataclasses import asdict

from websentinel import __version__
from websentinel.models import ScanResult


def to_dict(result: ScanResult) -> dict:
    t = result.target
    root = result.responses[0] if result.responses else None
    return {
        "tool": {"name": "WebSentinel", "version": __version__},
        "target": asdict(t),
        "scan": {
            "started": result.started,
            "duration_s": round(result.duration_s, 3),
            "requests_made": result.requests_made,
            "http": ({
                "status": root.status, "final_url": root.final_url,
                "content_type": root.content_type,
                "http_version": root.http_version,
                "redirect_chain": root.redirect_chain,
            } if root and not root.error else None),
            "errors": result.errors,
            "warnings": result.warnings,
        },
        "summary": result.summary(),
        "technologies": result.technologies,
        "crawl": {"pages": result.pages, "count": len(result.pages)},
        "findings": [f.to_dict() for f in result.findings],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, default=str)
