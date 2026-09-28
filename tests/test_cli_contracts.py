"""CLI precedence, exit status, file output, and report contract checks."""
import csv
import io
import json

import pytest

from conftest import make_response
from websentinel import cli
from websentinel.models import Confidence, Finding, ScanResult, Severity
from websentinel.reporting.sarif import render_sarif


@pytest.fixture
def scanned(monkeypatch):
    seen = {}
    async def fake(target, cfg, modules, crawl):
        seen.update(config=cfg, modules=modules, crawl=crawl)
        result = ScanResult(target, responses=[make_response(url=target.url)], pages=[target.url], requests_made=1)
        result.findings.append(Finding("HTML-INSECURE-FORM", "Password form", "HTML", Severity.HIGH,
                                       Confidence.HIGH, target.url, "Unsafe form", scanner_check="html"))
        seen["result"] = result
        return result
    monkeypatch.setattr(cli, "scan", fake)
    return seen


BASE = ["scan", "-u", "http://127.0.0.1/", "--allow-private"]


@pytest.mark.parametrize("fmt", ["json", "html", "csv", "sarif", "terminal"])
def test_report_formats_written_with_clean_quiet_stdout(scanned, tmp_path, capsys, fmt):
    path = tmp_path / ("output." + fmt)
    code = cli.main(BASE + ["--format", fmt, "--quiet", "-o", str(path)])
    assert code == cli.EXIT_FINDINGS
    output = capsys.readouterr()
    assert output.out == output.err == ""
    body = path.read_text(encoding="utf-8")
    if fmt in ("json", "sarif"):
        assert isinstance(json.loads(body), dict)
    elif fmt == "csv":
        assert list(csv.DictReader(io.StringIO(body)))[0]["severity"] == "HIGH"
    else:
        assert "Password form" in body


@pytest.mark.parametrize("fmt", ["json", "html", "csv", "sarif"])
def test_machine_stdout_contains_only_report(scanned, capsys, fmt):
    assert cli.main(BASE + ["--format", fmt]) == cli.EXIT_FINDINGS
    output = capsys.readouterr()
    assert "Scanning" not in output.out
    assert output.err == ""
    if fmt in ("json", "sarif"):
        json.loads(output.out)


def test_cli_overrides_config_and_profile(scanned, tmp_path, capsys):
    path = tmp_path / "config.yml"
    path.write_text("timeout: 8\nconcurrency: 7\nmax_depth: 1\n", encoding="utf-8")
    assert cli.main(BASE + ["--quiet", "--config", str(path), "--profile", "deep",
        "--checks", "html", "--timeout", "3", "--concurrency", "2", "--depth", "2",
        "--max-pages", "4", "--max-requests", "8", "--rate-limit", "1", "--retries", "0",
        "--scope", "subdomains", "--max-response-size", "2048", "--no-verify-tls",
        "--user-agent", "Testing/1", "--proxy", "http://127.0.0.1:8080", "--header", "X-Test: value"]) == cli.EXIT_FINDINGS
    cfg = scanned["config"]
    assert (cfg.timeout, cfg.concurrency, cfg.max_depth, cfg.max_pages, cfg.max_requests) == (3, 2, 2, 4, 8)
    assert (cfg.rate_limit, cfg.retries, cfg.max_body_bytes, cfg.verify_tls) == (1, 0, 2048, False)
    assert cfg.extra_headers == {"X-Test": "value"}
    assert cfg.scope == "subdomains" and cfg.user_agent == "Testing/1"
    assert scanned["modules"] == {"html"} and scanned["crawl"] is True


@pytest.mark.parametrize("args", [["--checks", "unknown"], ["--header", "missing-colon"],
    ["--header", ": value"], ["--timeout", "nan"], ["--concurrency", "0"]])
def test_argument_errors_never_start_scan(scanned, args, capsys):
    assert cli.main(BASE + args) == cli.EXIT_ARGS
    assert not scanned
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("exception,code", [(KeyboardInterrupt(), cli.EXIT_NETWORK), (RuntimeError("broken"), cli.EXIT_INTERNAL)])
def test_interrupt_and_internal_failure_exit_codes(monkeypatch, capsys, exception, code):
    async def fail(*args, **kwargs):
        raise exception
    monkeypatch.setattr(cli, "scan", fail)
    assert cli.main(BASE + ["--quiet"]) == code
    assert capsys.readouterr().err


def test_output_error_is_reported(scanned, tmp_path, capsys):
    parent = tmp_path / "not-a-directory"
    parent.write_text("file", encoding="utf-8")
    assert cli.main(BASE + ["--format", "json", "-o", str(parent / "out.json")]) == cli.EXIT_ARGS
    assert "error writing" in capsys.readouterr().err


def test_explicit_terminal_beats_json_filename(scanned, tmp_path, capsys):
    path = tmp_path / "result.json"
    cli.main(BASE + ["--quiet", "--format", "terminal", "-o", str(path)])
    assert "WebSentinel" in path.read_text(encoding="utf-8")
    assert not path.read_text(encoding="utf-8").startswith("{")


def test_extension_inference_and_module_filter(scanned, tmp_path, capsys):
    path = tmp_path / "out.json"
    cli.main(BASE + ["--quiet", "--profile", "headers", "--severity", "HIGH", "--check-id", "html", "-o", str(path)])
    assert json.loads(path.read_text(encoding="utf-8"))["findings"]
    assert scanned["modules"] == {"headers"}


@pytest.mark.parametrize("command", [["checks"], ["version"], []])
def test_informational_commands(command, capsys):
    assert cli.main(command) == (cli.EXIT_OK if command else cli.EXIT_ARGS)
    assert capsys.readouterr().out


def test_terminal_stdout_and_file_status(scanned, tmp_path, capsys):
    assert cli.main(BASE) == cli.EXIT_FINDINGS
    assert "Findings" in capsys.readouterr().out
    path = tmp_path / "out.txt"
    assert cli.main(BASE + ["-o", str(path)]) == cli.EXIT_FINDINGS
    captured = capsys.readouterr()
    assert "Report written" in captured.err and "Findings" in captured.out
    assert path.is_file()


def test_missing_config_error(scanned, tmp_path, capsys):
    assert cli.main(BASE + ["--config", str(tmp_path / "missing.yml")]) == cli.EXIT_ARGS
    assert not scanned and "Configuration file not found" in capsys.readouterr().err


@pytest.mark.online
def test_sarif_against_published_schema(scanned):
    import httpx
    from jsonschema import Draft7Validator
    cli.main(BASE + ["--quiet"])
    result = scanned["result"]
    result.errors = ["example failure"]
    result.warnings = ["coverage limited"]
    response = httpx.get("https://json.schemastore.org/sarif-2.1.0.json", follow_redirects=True, timeout=30)
    response.raise_for_status()
    schema = response.json()
    Draft7Validator.check_schema(schema)
    Draft7Validator(schema).validate(json.loads(render_sarif(result)))
