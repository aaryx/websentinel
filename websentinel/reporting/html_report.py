"""Standalone HTML report. ALL untrusted values are HTML-escaped."""
from __future__ import annotations

import html

from websentinel import __version__
from websentinel.models import ScanResult, Severity
from websentinel.utils.redaction import safe_report

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
          Severity.LOW, Severity.INFO]
_COLORS = {"CRITICAL": "#7f1d1d", "HIGH": "#dc2626", "MEDIUM": "#d97706",
           "LOW": "#0891b2", "INFO": "#6b7280"}

_CSS = """
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1000px;color:#1f2937}
h1{border-bottom:3px solid #2563eb;padding-bottom:.3rem}
.sev{display:inline-block;padding:.15rem .5rem;border-radius:4px;color:#fff;
font-size:.8rem;font-weight:600}
.finding{border:1px solid #e5e7eb;border-radius:8px;padding:1rem;margin:.8rem 0}
.finding h3{margin:.1rem 0}
.evidence{background:#f3f4f6;padding:.5rem;border-radius:4px;overflow-wrap:anywhere;
font-family:monospace;font-size:.85rem;white-space:pre-wrap}
table{border-collapse:collapse}td,th{border:1px solid #e5e7eb;padding:.4rem .8rem}
.dim{color:#6b7280;font-size:.85rem}
"""


def _e(s: object) -> str:
    return html.escape(str(s)) if s else ""


@safe_report
def render_html(result: ScanResult) -> str:
    t = result.target
    summary = result.summary()
    parts = [f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WebSentinel Report - {_e(t.host)}</title><style>{_CSS}</style></head><body>
<h1>WebSentinel v{_e(__version__)} — Security Report</h1>
<p class="dim">Authorized-use scan. Observations are not confirmed
vulnerabilities unless stated.</p>
<table>
<tr><th>Target</th><td>{_e(t.url)}</td></tr>
<tr><th>Host</th><td>{_e(t.host)}:{t.port} ({_e(t.scheme)})</td></tr>
<tr><th>Scan started</th><td>{_e(result.started)}</td></tr>
<tr><th>Duration</th><td>{result.duration_s:.2f}s</td></tr>
<tr><th>Requests</th><td>{result.requests_made}</td></tr>
<tr><th>Completion</th><td>{_e(result.completion)}</td></tr>
<tr><th>Pages</th><td>{len(result.pages)}</td></tr>
<tr><th>Technologies</th><td>{_e(", ".join(result.technologies)) or "—"}</td></tr>
</table>
<h2>Summary</h2><table><tr><th>Severity</th><th>Count</th></tr>"""]
    for sev in _ORDER:
        parts.append(
            f'<tr><td><span class="sev" style="background:{_COLORS[sev.value]}">'
            f'{sev.value}</span></td><td>{summary[sev.value]}</td></tr>')
    parts.append("</table><h2>Check execution</h2><ul>")
    parts.extend(f"<li>{_e(name)}: {_e(state['status'])} — {_e('; '.join(state['reasons']))}</li>"
                 for name, state in result.check_status.items())
    parts.append("</ul><h2>Findings</h2>")

    for sev in _ORDER:
        for f in (x for x in result.findings if x.severity == sev):
            parts.append(f"""<div class="finding">
<span class="sev" style="background:{_COLORS[sev.value]}">{sev.value}</span>
<h3>{_e(f.title)} <span class="dim">[{_e(f.id)}]</span></h3>
<p class="dim">Category: {_e(f.category)} · Confidence: {_e(f.confidence.value)}
{f" · CWE: {_e(f.cwe)}" if f.cwe else ""}
{f" · OWASP: {_e(f.owasp)}" if f.owasp else ""}</p>
<p><b>URL:</b> {_e(f.url)}</p>
<p>{_e(f.description)}</p>
{f'<p><b>Impact:</b> {_e(f.impact)}</p>' if f.impact else ""}
{f'<div class="evidence">{_e(f.evidence)}</div>' if f.evidence else ""}
{f'<p><b>Remediation:</b> {_e(f.remediation)}</p>' if f.remediation else ""}
</div>""")

    if result.pages:
        parts.append("<h2>Pages discovered</h2><ul>")
        parts.extend(f"<li>{_e(p)}</li>" for p in result.pages[:200])
        parts.append("</ul>")
    if result.errors:
        parts.append("<h2>Errors</h2><ul>")
        parts.extend(f"<li>{_e(e)}</li>" for e in result.errors)
        parts.append("</ul>")
    if result.warnings:
        parts.append("<h2>Warnings</h2><ul>")
        parts.extend(f"<li>{_e(w)}</li>" for w in result.warnings)
        parts.append("</ul>")
    parts.append("</body></html>")
    return "\n".join(parts)
