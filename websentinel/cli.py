"""WebSentinel CLI (argparse).

Exit codes:
  0  scan completed, no HIGH/CRITICAL findings
  1  scan completed with findings (or HIGH+ present)
  2  invalid arguments / invalid target / configuration error
  3  target/network error
  4  internal error
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from websentinel import __version__
from websentinel.checks import CHECKS as REGISTRY, PROFILES
from websentinel.config import Config
from websentinel.models import Severity
from websentinel.scanner import CHECKS, scan
from websentinel.utils.logging import setup_logging
from websentinel.utils.urls import URLValidationError, normalize_target

EXIT_OK, EXIT_FINDINGS, EXIT_ARGS, EXIT_NETWORK, EXIT_INTERNAL = 0, 1, 2, 3, 4


def _safe_output_path(path: str) -> Path:
    """Validate output path for writing."""
    p = Path(path)
    if p.is_dir():
        raise argparse.ArgumentTypeError(
            f"output path is a directory, expected a file path: {p}"
        )
    return p


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="websentinel",
        description=(
            f"WebSentinel v{__version__} - authorized-use, low-impact web security "
            "scanner. Only scan targets you own or are explicitly authorized to assess."
        ),
    )
    p.add_argument(
        "--version", action="version", version=f"WebSentinel {__version__}"
    )
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser(
        "scan",
        help="Scan a target URL",
        description="Run passive and authorized bounded security checks against a target.",
    )
    s.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    s.add_argument(
        "-o",
        "--output",
        type=_safe_output_path,
        help="Save report to file (.json, .html, .csv, .sarif)",
    )
    s.add_argument(
        "--format",
        choices=["terminal", "json", "html", "csv", "sarif"],
        default=None,
        help="Report format (default: terminal; inferred from -o extension if given)",
    )
    s.add_argument(
        "--profile",
        choices=list(PROFILES),
        default=None,
        help="Scan profile preset (quick, standard, deep, headers, tls, crawl, api)",
    )
    s.add_argument(
        "--checks",
        help="Comma-separated check IDs to run (e.g. headers,cors,cookies,injection)",
    )
    s.add_argument(
        "--severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "info", "low", "medium", "high", "critical"],
        help="Filter report findings >= severity",
    )
    s.add_argument(
        "--confidence",
        choices=["LOW", "MEDIUM", "HIGH", "low", "medium", "high"],
        help="Filter report findings >= confidence",
    )
    s.add_argument(
        "--check-id",
        dest="check_filter",
        help="Report only findings with this check ID",
    )
    s.add_argument(
        "--scope",
        choices=["same-origin", "subdomains"],
        default=None,
        help="Scan scope mode (default: same-origin)",
    )
    s.add_argument(
        "--max-requests",
        type=int,
        default=None,
        help="Hard global request budget across entire scan (default: 500)",
    )
    s.add_argument(
        "--retries",
        type=int,
        default=None,
        help="Retries on transient connection errors (default: 1)",
    )
    s.add_argument(
        "--max-response-size",
        type=int,
        default=None,
        help="Max response bytes kept in memory after decompression (default: 1048576)",
    )
    s.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="Extra request header (repeatable; redacted from logs and reports)",
    )
    s.add_argument(
        "--crawl",
        action="store_true",
        help="Enable bounded crawling",
    )
    s.add_argument(
        "--depth",
        type=int,
        default=None,
        help="Maximum crawl link depth (default: 1)",
    )
    s.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="Maximum pages to fetch during crawling (default: 50)",
    )
    s.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Maximum concurrent HTTP connections (default: 10)",
    )
    s.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Request timeout in seconds (default: 10.0)",
    )
    s.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        help="Requests per second limit, 0 = unlimited (default: 0)",
    )
    s.add_argument("--headers", action="store_true", help="Header checks only")
    s.add_argument("--tls", action="store_true", help="TLS checks only")
    s.add_argument("--cookies", action="store_true", help="Cookie checks only")
    s.add_argument("--config", help="Config file (default: websentinel.yaml)")
    s.add_argument("--user-agent", default=None, help="Custom User-Agent header")
    s.add_argument("--proxy", default=None, help="HTTP/HTTPS proxy URL")
    s.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Disable TLS verification (lab/testing use only)",
    )
    s.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow private/loopback/internal target addresses (lab/testing use only)",
    )
    s.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    s.add_argument("-q", "--quiet", action="store_true", help="Suppress non-error output")

    sub.add_parser("checks", help="List available checks")
    sub.add_parser("version", help="Show version")
    return p


_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_CONF_ORDER = ["LOW", "MEDIUM", "HIGH"]


def _apply_filters(result, a: argparse.Namespace) -> None:
    if a.severity:
        lo = _ORDER.index(a.severity.upper())
        result.findings = [
            f for f in result.findings if _ORDER.index(f.severity.value) >= lo
        ]
    if a.confidence:
        lo = _CONF_ORDER.index(a.confidence.upper())
        result.findings = [
            f for f in result.findings if _CONF_ORDER.index(f.confidence.value) >= lo
        ]
    if a.check_filter:
        result.findings = [
            f
            for f in result.findings
            if f.id == a.check_filter or f.scanner_check == a.check_filter
        ]


def _selected_modules(a: argparse.Namespace) -> set[str] | None:
    if a.checks:
        requested = {c.strip() for c in a.checks.split(",") if c.strip()}
        known = {c for c, _ in CHECKS}
        unknown = requested - known
        if unknown:
            raise ValueError(f"unknown checks: {sorted(unknown)}")
        return requested
    only = {
        name
        for name, flag in (
            ("headers", a.headers),
            ("tls", a.tls),
            ("cookies", a.cookies),
        )
        if flag
    }
    return only or None


def _cmd_scan(a: argparse.Namespace) -> int:
    setup_logging(a.verbose, a.quiet)

    # Validate target early
    try:
        target = normalize_target(a.url, allow_private=a.allow_private)
    except URLValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ARGS

    # Load and validate configuration
    try:
        cfg = Config.load(a.config)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ARGS

    # Apply profile preset if requested
    crawl_enabled = a.crawl
    if a.profile:
        prof = PROFILES[a.profile]
        if prof.get("max_depth") is not None and a.depth is None:
            cfg.max_depth = prof["max_depth"]
        if prof.get("max_pages") is not None and a.max_pages is None:
            cfg.max_pages = prof["max_pages"]
        if prof.get("crawl") and not crawl_enabled:
            crawl_enabled = True
        if prof.get("checks") and not (a.headers or a.tls or a.cookies or a.checks):
            a.checks = ",".join(sorted(prof["checks"]))

    # CLI overrides have highest precedence
    if a.timeout is not None:
        cfg.timeout = a.timeout
    if a.concurrency is not None:
        cfg.concurrency = a.concurrency
    if a.rate_limit is not None:
        cfg.rate_limit = a.rate_limit
    if a.depth is not None:
        cfg.max_depth = a.depth
    if a.max_pages is not None:
        cfg.max_pages = a.max_pages
    if a.user_agent is not None:
        cfg.user_agent = a.user_agent
    if a.no_verify_tls:
        cfg.verify_tls = False
    if a.proxy is not None:
        cfg.proxy = a.proxy
    if a.scope is not None:
        cfg.scope = a.scope
    if a.retries is not None:
        cfg.retries = a.retries
    if a.max_requests is not None:
        cfg.max_requests = a.max_requests
    if a.max_response_size is not None:
        cfg.max_body_bytes = a.max_response_size

    for h in a.header:
        if ":" not in h:
            print(f"error: malformed --header {h!r}; expected 'Name: value'", file=sys.stderr)
            return EXIT_ARGS
        k, v = h.split(":", 1)
        cfg.extra_headers[k.strip()] = v.strip()

    try:
        cfg.validate()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ARGS

    # Resolve output format
    fmt = a.format or cfg.output_format
    if a.output and fmt == "terminal":
        inferred = {
            ".json": "json",
            ".html": "html",
            ".csv": "csv",
            ".sarif": "sarif",
        }.get(a.output.suffix.lower())
        if inferred:
            fmt = inferred

    try:
        mods = _selected_modules(a)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ARGS

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as prog:
            prog.add_task(f"Scanning {target.url} ...", total=None)
            result = asyncio.run(
                scan(target, cfg, modules=mods, crawl=crawl_enabled)
            )
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return EXIT_NETWORK
    except Exception as e:
        print(f"internal error: {e}", file=sys.stderr)
        return EXIT_INTERNAL

    if result.errors and not result.responses:
        print(f"error: {result.errors[0]}", file=sys.stderr)
        return EXIT_NETWORK

    _apply_filters(result, a)

    rendered = None
    if fmt == "json":
        from websentinel.reporting.json_report import render_json

        rendered = render_json(result)
    elif fmt == "html":
        from websentinel.reporting.html_report import render_html

        rendered = render_html(result)
    elif fmt == "csv":
        from websentinel.reporting.csv_report import render_csv

        rendered = render_csv(result)
    elif fmt == "sarif":
        from websentinel.reporting.sarif import render_sarif

        rendered = render_sarif(result)

    if a.output:
        try:
            a.output.parent.mkdir(parents=True, exist_ok=True)
            if rendered is not None:
                a.output.write_text(rendered, encoding="utf-8")
                print(f"Report written to {a.output}")
            else:
                # Terminal format written to file
                c = Console(record=True, width=100)
                from websentinel.reporting.terminal import render_console

                render_console(result, console=c)
                a.output.write_text(c.export_text(), encoding="utf-8")
                print(f"Report written to {a.output}")
        except OSError as e:
            print(f"error writing output file {a.output}: {e}", file=sys.stderr)
            return EXIT_ARGS

        if fmt == "terminal":
            from websentinel.reporting.terminal import render_console

            render_console(result)
    elif rendered is not None:
        print(rendered)
    else:
        from websentinel.reporting.terminal import render_console

        render_console(result)

    summary = result.summary()
    high = summary[Severity.HIGH.value] + summary[Severity.CRITICAL.value]
    if not result.findings or high == 0:
        return EXIT_OK
    return EXIT_FINDINGS


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "checks":
        for name, desc in CHECKS:
            print(f"  {name:10s} {desc}")
        return EXIT_OK
    if args.command == "version":
        print(f"WebSentinel {__version__}")
        return EXIT_OK
    build_parser().print_help()
    return EXIT_ARGS
