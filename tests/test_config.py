"""Unit tests for usb_sentinel.config and application startup behavior."""

from __future__ import annotations

import inspect
import io
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import usb_sentinel
from usb_sentinel import __main__
from usb_sentinel.config import (
    APP_NAME,
    APP_VERSION,
    AUDIT_LOG_FILENAME,
    DEFAULT_CONFIG,
    DEFAULT_STREAM_CHUNK_SIZE_BYTES,
    DEFAULT_SUSPICIOUS_EXTENSIONS,
    DEFAULT_WATCHDOG_POLICY,
    QUARANTINE_INDEX_FILENAME,
    SentinelConfig,
    get_config,
    get_default_restoration_dir,
    get_default_system_app_dir,
)


def test_default_suspicious_extensions() -> None:
    """Verify that the required high-risk heuristic extensions match the approved plan."""
    expected = {".exe", ".bat", ".vbs", ".ps1", ".scr"}
    assert DEFAULT_SUSPICIOUS_EXTENSIONS == expected
    assert DEFAULT_CONFIG.suspicious_extensions == expected


def test_default_watchdog_policy_is_alert_and_log_only() -> None:
    """Verify that default watchdog behavior is non-destructive ALERT AND LOG ONLY."""
    assert DEFAULT_WATCHDOG_POLICY == "ALERT_AND_LOG_ONLY"
    assert DEFAULT_CONFIG.watchdog_policy == "ALERT_AND_LOG_ONLY"


def test_default_auto_quarantine_is_disabled() -> None:
    """Verify that automatic quarantine is disabled by default."""
    assert DEFAULT_CONFIG.auto_quarantine_enabled is False


def test_required_file_names() -> None:
    """Verify that mandatory ledger and index file names are strictly preserved."""
    assert AUDIT_LOG_FILENAME == "usb_sentinel_audit.csv"
    assert QUARANTINE_INDEX_FILENAME == "quarantine_index.txt"


def test_config_paths_derived_correctly(isolated_config: SentinelConfig, tmp_path: Path) -> None:
    """Verify derived directory and file paths are correctly rooted under base_dir."""
    assert isolated_config.base_dir == tmp_path
    assert isolated_config.vault_dir == tmp_path / "vault"
    assert isolated_config.staging_dir == tmp_path / "staging"
    assert isolated_config.keys_dir == tmp_path / "keys"
    assert isolated_config.logs_dir == tmp_path / "logs"
    assert isolated_config.reports_dir == tmp_path / "reports"
    assert isolated_config.recovery_dir == tmp_path / "vault" / "recovery"
    assert isolated_config.audit_csv_path == tmp_path / "logs" / "usb_sentinel_audit.csv"
    assert (
        isolated_config.quarantine_index_path
        == tmp_path / "logs" / "quarantine_index.txt"
    )


def test_import_and_instantiation_has_no_filesystem_side_effects(tmp_path: Path) -> None:
    """Verify that creating a config instance does NOT automatically create folders on disk."""
    custom_dir = tmp_path / "uncreated_sentinel_data"
    assert not custom_dir.exists()

    cfg = SentinelConfig(base_dir=custom_dir)
    assert not custom_dir.exists()
    assert not cfg.vault_dir.exists()
    assert not cfg.keys_dir.exists()
    assert not cfg.logs_dir.exists()


def test_ensure_runtime_directories_creates_all_subdirs(tmp_path: Path) -> None:
    """Verify that calling ensure_runtime_directories() explicitly creates all folders."""
    custom_dir = tmp_path / "test_app_dir"
    cfg = SentinelConfig(base_dir=custom_dir)
    assert not custom_dir.exists()

    cfg.ensure_runtime_directories()
    assert custom_dir.is_dir()
    assert cfg.vault_dir.is_dir()
    assert cfg.staging_dir.is_dir()
    assert cfg.keys_dir.is_dir()
    assert cfg.logs_dir.is_dir()
    assert cfg.reports_dir.is_dir()
    assert cfg.recovery_dir.is_dir()


def test_no_hardcoded_developer_paths_in_source() -> None:
    """Verify that developer username and specific home directories are never hardcoded."""
    from usb_sentinel import config as cfg_module

    source_code = inspect.getsource(cfg_module)
    # Check that personal developer paths or usernames are not written into source code
    assert "/Users/merajuddin" not in source_code
    assert "C:\\Users\\" not in source_code or "C:\\Users\\<user>" in source_code


def test_windows_app_data_path_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that Windows environment variables (%LOCALAPPDATA%) are respected on Windows."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Custom\AppData\Local")

    resolved = get_default_system_app_dir("USBSentinel")
    assert resolved == Path(r"C:\Custom\AppData\Local") / "USBSentinel"


def test_windows_fallback_app_data_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Windows fallback if %LOCALAPPDATA% is unset."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)

    resolved = get_default_system_app_dir("USBSentinel")
    assert resolved == Path.home() / "AppData" / "Local" / "USBSentinel"


def test_macos_app_data_path_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify macOS resolves to ~/Library/Application Support/<app_name>."""
    monkeypatch.setattr(sys, "platform", "darwin")

    resolved = get_default_system_app_dir("USBSentinel")
    assert resolved == Path.home() / "Library" / "Application Support" / "USBSentinel"


def test_linux_app_data_path_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Linux respects $XDG_DATA_HOME or falls back to ~/.local/share."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", "/custom/xdg/data")

    resolved = get_default_system_app_dir("USBSentinel")
    assert resolved == Path("/custom/xdg/data") / "USBSentinel"


def test_config_validation_rejects_non_positive_chunk_size() -> None:
    """Verify that chunk size <= 0 raises ValueError."""
    with pytest.raises(ValueError, match="stream_chunk_size_bytes must be positive"):
        SentinelConfig(stream_chunk_size_bytes=0)

    with pytest.raises(ValueError, match="stream_chunk_size_bytes must be positive"):
        SentinelConfig(stream_chunk_size_bytes=-1024)


def test_config_validation_rejects_invalid_extension_format() -> None:
    """Verify extensions missing leading dot or in uppercase raise ValueError."""
    with pytest.raises(ValueError, match="must start with a leading dot"):
        SentinelConfig(suspicious_extensions=frozenset({"exe"}))

    with pytest.raises(ValueError, match="must be lowercased"):
        SentinelConfig(suspicious_extensions=frozenset({".EXE"}))


def test_application_entry_point_executes_cleanly() -> None:
    """Verify that usb_sentinel.__main__.main() executes and returns code 0."""
    captured_stdout = io.StringIO()
    with patch("sys.stdout", captured_stdout):
        exit_code = __main__.main()

    output = captured_stdout.getvalue()
    assert exit_code == 0
    assert APP_NAME in output
    assert APP_VERSION in output
    assert "ALERT_AND_LOG_ONLY" in output
    assert "Display Active System Mounts" in output
