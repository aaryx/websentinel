"""Rich terminal report."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from websentinel import __version__
from websentinel.models import ScanResult, Severity

_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
          Severity.LOW, Severity.INFO]


def render_console(result: ScanResult, console: Console | None = None) -> None:
    c = console or Console()
    t = result.target
    c.print(Panel.fit(
        f"[bold]WebSentinel v{__version__}[/bold]\nWeb Security Scanner\n"
        "[dim]Authorized use only[/dim]", border_style="blue"))

    meta = Table.grid(padding=(0, 2))
    meta.add_row("[bold]Target[/bold]", t.url)
    meta.add_row("[bold]Host[/bold]", f"{t.host}:{t.port} ({t.scheme})")
    meta.add_row("[bold]Duration[/bold]", f"{result.duration_s:.2f}s")
    meta.add_row("[bold]Requests[/bold]", str(result.requests_made))
    meta.add_row("[bold]Pages[/bold]", str(len(result.pages)))
    if result.technologies:
        meta.add_row("[bold]Technologies[/bold]", ", ".join(result.technologies))
    c.print(meta)

    for w in result.warnings:
        c.print(f"[yellow]warning:[/yellow] {w}")

    table = Table(title="Findings", show_lines=False)
    table.add_column("Severity", width=10)
    table.add_column("ID", style="dim", width=20)
    table.add_column("Title")
    table.add_column("Conf", width=7)
    for sev in _ORDER:
        for f in (x for x in result.findings if x.severity == sev):
            table.add_row(f"[{_STYLE[sev]}]{sev.value}[/]", f.id, f.title,
                          f.confidence.value)
    c.print(table)

    summary = result.summary()
    s = Table(title="Summary")
    s.add_column("Severity")
    s.add_column("Count", justify="right")
    for sev in _ORDER:
        s.add_row(sev.value, str(summary[sev.value]))
    c.print(s)

    if result.errors:
        c.print("[red]Errors:[/red]")
        for e in result.errors:
            c.print(f"  - {e}")
