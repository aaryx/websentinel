"""CSV report."""
from __future__ import annotations

import csv
import io

from websentinel.models import ScanResult

_FIELDS = ["id", "title", "category", "severity", "confidence", "url",
           "parameter", "cwe", "owasp", "description", "evidence",
           "remediation", "affected_urls"]


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_FIELDS)
    for f in result.findings:
        w.writerow([f.id, f.title, f.category, f.severity.value,
                    f.confidence.value, f.url, f.parameter or "",
                    f.cwe or "", f.owasp or "", f.description,
                    f.evidence, f.remediation, ";".join(f.affected_urls)])
    return buf.getvalue()
