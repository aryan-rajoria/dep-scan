"""Tests for depscan.cli helpers."""

import pytest

from depscan import cli


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
