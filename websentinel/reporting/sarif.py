"""SARIF 2.1.0 report for CI/code-scanning integration."""
from __future__ import annotations

import json

from websentinel import __version__
from websentinel.models import ScanResult, Severity
from websentinel.utils.redaction import safe_report

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@safe_report
def render_sarif(result: ScanResult) -> str:
    seen: dict[str, dict] = {}
    for f in result.findings:
        seen.setdefault(
            f.id,
            {
                "id": f.id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description[:400]},
                "help": {"text": f.remediation or "No remediation provided."},
                "properties": {
                    k: v
                    for k, v in (
                        ("cwe", f.cwe),
                        ("owasp", f.owasp),
                        ("confidence", f.confidence.value),
                        ("category", f.category),
                    )
                    if v
                },
            },
        )
    results = [
        {
            "ruleId": f.id,
            "level": _LEVEL[f.severity],
            "message": {"text": f.description[:500]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.url or result.target.url
                        }
                    }
                }
            ],
            "properties": {
                "evidence": f.evidence[:300],
                "affectedUrls": f.affected_urls,
            },
        }
        for f in result.findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WebSentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/aaryx/websentinel",
                        "rules": list(seen.values()),
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": result.completion == "complete",
                    "properties": {"completion": result.completion, "checks": result.check_status},
                    "toolExecutionNotifications": [
                        {"level": level, "message": {"text": message}}
                        for level, messages in (("error", result.errors), ("warning", result.warnings))
                        for message in messages
                    ],
                }],
            }
        ],
    }
    return json.dumps(doc, indent=2)
