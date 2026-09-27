"""CSV report with spreadsheet formula injection mitigation."""
from __future__ import annotations

import csv
import io

from websentinel.models import ScanResult

_FIELDS = [
    "id",
    "title",
    "category",
    "severity",
    "confidence",
    "url",
    "parameter",
    "cwe",
    "owasp",
    "description",
    "evidence",
    "remediation",
    "affected_urls",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_cell(val: object) -> str:
    """Neutralize spreadsheet formula injection risks."""
    if val is None:
        return ""
    text = str(val)
    if text and text.startswith(_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_FIELDS)
    for f in result.findings:
        w.writerow(
            [
                _sanitize_cell(f.id),
                _sanitize_cell(f.title),
                _sanitize_cell(f.category),
                f.severity.value,
                f.confidence.value,
                _sanitize_cell(f.url),
                _sanitize_cell(f.parameter or ""),
                _sanitize_cell(f.cwe or ""),
                _sanitize_cell(f.owasp or ""),
                _sanitize_cell(f.description),
                _sanitize_cell(f.evidence),
                _sanitize_cell(f.remediation),
                _sanitize_cell(";".join(f.affected_urls)),
            ]
        )
    return buf.getvalue()
