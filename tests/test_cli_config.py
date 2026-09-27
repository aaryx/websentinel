"""Tests for configuration validation, CLI option precedence, and exit codes."""
import pytest

from websentinel.cli import main, EXIT_OK, EXIT_ARGS, build_parser
from websentinel.config import Config


def test_config_missing_file_raises(tmp_path):
    missing = tmp_path / "nonexistent.yaml"
    with pytest.raises(FileNotFoundError):
        Config.load(str(missing))


def test_config_invalid_yaml_raises(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("timeout: [unclosed list", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        Config.load(str(bad_yaml))


def test_config_unknown_key_raises(tmp_path):
    custom_yaml = tmp_path / "unknown.yaml"
    custom_yaml.write_text("timeout: 5\ninvalid_dangerous_key: 123", encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown configuration key"):
        Config.load(str(custom_yaml))


def test_config_negative_values_rejected():
    cfg = Config(timeout=-1)
    with pytest.raises(ValueError, match="timeout must be positive"):
        cfg.validate()

    cfg2 = Config(concurrency=0)
    with pytest.raises(ValueError, match="concurrency must be integer >= 1"):
        cfg2.validate()

    cfg3 = Config(max_requests=-5)
    with pytest.raises(ValueError, match="max_requests must be integer >= 1"):
        cfg3.validate()


def test_cli_invalid_severity_returns_exit_args():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "-u", "https://example.com", "--severity", "SUPER_CRITICAL"])
    assert exc.value.code == EXIT_ARGS


def test_cli_invalid_confidence_returns_exit_args():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "-u", "https://example.com", "--confidence", "100_PERCENT"])
    assert exc.value.code == EXIT_ARGS


def test_cli_invalid_target_returns_exit_args():
    code = main(["scan", "-u", "ftp://example.com"])
    assert code == EXIT_ARGS


def test_cli_output_directory_rejected(tmp_path):
    # Output path is an existing directory instead of a file
    with pytest.raises(SystemExit) as exc:
        main(["scan", "-u", "https://example.com", "-o", str(tmp_path)])
    assert exc.value.code == EXIT_ARGS


def test_cli_profile_and_override_precedence(tmp_path):
    cfg_file = tmp_path / "test_cfg.yaml"
    cfg_file.write_text("concurrency: 7\ntimeout: 12\nmax_depth: 1\n", encoding="utf-8")

    parser = build_parser()
    # profile 'deep' sets max_depth to 3, but explicit --depth 2 must override both
    args = parser.parse_args([
        "scan", "-u", "https://example.com",
        "--config", str(cfg_file),
        "--profile", "deep",
        "--depth", "2"
    ])

    cfg = Config.load(args.config)
    # config loaded 7 and 12
    assert cfg.concurrency == 7
    assert cfg.timeout == 12

    # CLI depth overrides
    assert args.depth == 2
    assert args.profile == "deep"
