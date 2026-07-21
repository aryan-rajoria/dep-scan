"""Tests for depscan.cli helpers."""

import argparse

import pytest

from depscan import cli
from depscan.cli_options import (
    DEFAULT_SPEC_VERSION,
    build_parser,
    validate_spec_version,
)


def test_validate_spec_version_accepts_supported():
    assert validate_spec_version("1.6") == "1.6"
    assert validate_spec_version("1.7") == "1.7"
    assert validate_spec_version(1.5) == "1.5"
    assert validate_spec_version("2.0") == "2.0"
    assert validate_spec_version(2) == "2.0"


@pytest.mark.parametrize("bad", ["1.10", "1.3", "3.0", "abc", "", None])
def test_validate_spec_version_rejects_unsupported(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        validate_spec_version(bad)


def test_spec_version_defaults_to_1_6(monkeypatch):
    monkeypatch.delenv("CDX_SPEC_VERSION", raising=False)
    parser = build_parser()
    args = parser.parse_args([])
    assert args.spec_version == DEFAULT_SPEC_VERSION == "1.6"


def test_spec_version_cli_override():
    parser = build_parser()
    args = parser.parse_args(["--spec-version", "1.7"])
    assert args.spec_version == "1.7"


def test_spec_version_cli_rejects_bad(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--spec-version", "9.9"])


def test_download_vdb_succeeds_first_attempt(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "download_image", lambda url, d: calls.append(url) or ["ok"])
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    result = cli.download_vdb_with_retries("oras://x", "/tmp/d", attempts=3)
    assert result == ["ok"]
    assert len(calls) == 1


def test_download_vdb_retries_then_succeeds(monkeypatch):
    calls = []

    def flaky(url, d):
        calls.append(url)
        if len(calls) < 3:
            raise ConnectionError("Connection broken: IncompleteRead")
        return ["ok"]

    monkeypatch.setattr(cli, "download_image", flaky)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    result = cli.download_vdb_with_retries("oras://x", "/tmp/d", attempts=3)
    assert result == ["ok"]
    assert len(calls) == 3


def test_download_vdb_reraises_after_exhausting_attempts(monkeypatch):
    calls = []

    def always_fail(url, d):
        calls.append(url)
        raise ConnectionError("Connection broken")

    monkeypatch.setattr(cli, "download_image", always_fail)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    with pytest.raises(ConnectionError):
        cli.download_vdb_with_retries("oras://x", "/tmp/d", attempts=3)
    assert len(calls) == 3


def test_positive_int_env(monkeypatch):
    monkeypatch.setenv("DS_TEST_RETRIES", "7")
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 7
    monkeypatch.setenv("DS_TEST_RETRIES", "0")
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 3
    monkeypatch.setenv("DS_TEST_RETRIES", "notanint")
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 3
    monkeypatch.delenv("DS_TEST_RETRIES", raising=False)
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 3
