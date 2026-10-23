"""Unit tests for usb_sentinel.scanner."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.models import ScanStatus
from usb_sentinel.scanner import (
    VolumeScanner,
    extract_platform_timestamps,
    is_reparse_point_or_symlink,
    normalize_scan_path,
)


def compute_file_sha256(path: Path) -> str:
    """Helper to compute SHA-256 for integrity comparison."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture
def scanner() -> VolumeScanner:
    return VolumeScanner()


# ==============================================================================
# Target Validation Tests
# ==============================================================================


def test_scan_raises_on_nonexistent_target(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify scanning a non-existent path raises FileNotFoundError."""
    missing = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        scanner.scan(missing)


def test_scan_raises_on_file_target(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify scanning a regular file instead of a directory raises NotADirectoryError."""
    target_file = tmp_path / "single_file.txt"
    target_file.write_text("hello", encoding="utf-8")
    with pytest.raises(NotADirectoryError, match="not a directory"):
        scanner.scan(target_file)


# ==============================================================================
# Traversal & Metadata Collection Tests
# ==============================================================================


def test_scan_empty_directory(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify scanning an empty directory completes cleanly with zero files and findings."""
    empty_dir = tmp_path / "empty_folder"
    empty_dir.mkdir()

    report = scanner.scan(empty_dir)
    assert report.result.status == ScanStatus.COMPLETED
    assert report.result.files_inspected == 0
    assert report.result.findings_count == 0
    assert report.result.errors_count == 0
    assert len(report.scanned_files) == 0
    assert len(report.findings) == 0


def test_scan_nested_directories_and_extensions(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify recursive scanning across nested directories accurately counts files and findings."""
    root = tmp_path / "usb_root"
    sub1 = root / "documents"
    sub2 = root / "tools" / "bin"
    sub1.mkdir(parents=True)
    sub2.mkdir(parents=True)

    # Benign files
    (sub1 / "readme.txt").write_text("Documentation", encoding="utf-8")
    (sub1 / "report.pdf").write_bytes(b"%PDF-1.4...")
    (root / "unrelated").write_text("No extension", encoding="utf-8")

    # Flagged suspicious files
    (root / "autorun.bat").write_text("@echo off\nexit", encoding="utf-8")
    (sub2 / "helper.EXE").write_bytes(b"MZ\x90\x00...")  # Uppercase
    (sub2 / "script.Ps1").write_text("Write-Host 'Hi'", encoding="utf-8")  # Mixed-case

    report = scanner.scan(root)
    assert report.result.status == ScanStatus.COMPLETED
    assert report.result.files_inspected == 6
    assert report.result.findings_count == 3
    assert report.result.errors_count == 0

    flagged_names = {f.file_path for f in report.findings}
    assert any("autorun.bat" in p for p in flagged_names)
    assert any("helper.EXE" in p for p in flagged_names)
    assert any("script.Ps1" in p for p in flagged_names)


def test_scan_unusual_filenames_and_spaces(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify scanner handles spaces, unicode, and symbols in filenames."""
    root = tmp_path / "special_names"
    root.mkdir()

    (root / "my setup utility 2026.bat").write_text("echo 1", encoding="utf-8")
    (root / "русский_скрипт.vbs").write_text("' comment", encoding="utf-8")
    (root / "emoji_🚀_script.ps1").write_text("# rocket", encoding="utf-8")
    (root / "test [copy] (1).scr").write_bytes(b"MZ...")

    report = scanner.scan(root)
    assert report.result.status == ScanStatus.COMPLETED
    assert report.result.files_inspected == 4
    assert report.result.findings_count == 4
    assert report.result.errors_count == 0


def test_scan_non_destructive_guarantee(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify that scanning NEVER modifies file content, size, or modification timestamps."""
    root = tmp_path / "integrity_test"
    root.mkdir()

    test_file = root / "payload.exe"
    original_content = b"MZ\x90\x00\x03\x00\x00\x00CriticalBinaryPayloadData"
    test_file.write_bytes(original_content)

    original_hash = compute_file_sha256(test_file)
    original_mtime = test_file.stat().st_mtime

    report = scanner.scan(root)
    assert report.result.findings_count == 1

    # Verify after scan
    after_hash = compute_file_sha256(test_file)
    after_mtime = test_file.stat().st_mtime

    assert original_hash == after_hash, "Scan modified file content!"
    assert original_mtime == after_mtime, "Scan modified file modification timestamp!"


# ==============================================================================
# Symlinks, Junctions & Boundary Containment Tests
# ==============================================================================


def test_scan_skips_file_and_directory_symlinks(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify scanner does not traverse into directory symlinks or inspect file symlinks."""
    scan_root = tmp_path / "scan_target"
    external_dir = tmp_path / "external_private"
    scan_root.mkdir()
    external_dir.mkdir()

    # External file that should NEVER be scanned
    secret_file = external_dir / "secret.exe"
    secret_file.write_text("secret", encoding="utf-8")

    # Regular file inside scan root
    (scan_root / "normal.txt").write_text("regular", encoding="utf-8")

    try:
        # Create directory symlink inside scan_root pointing to external_dir
        symlink_dir = scan_root / "linked_folder"
        symlink_dir.symlink_to(external_dir, target_is_directory=True)

        # Create file symlink pointing to secret_file
        symlink_file = scan_root / "linked_secret.exe"
        symlink_file.symlink_to(secret_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this test environment.")

    report = scanner.scan(scan_root)
    # Only normal.txt should be inspected; linked_folder and linked_secret.exe are skipped
    assert report.result.files_inspected == 1
    assert report.result.findings_count == 0
    assert len(report.skipped_paths) >= 2


def test_reparse_point_detection() -> None:
    """Verify is_reparse_point_or_symlink detects reparse point attributes."""
    dummy_path = Path("/mock/junction")

    # Mock Windows FILE_ATTRIBUTE_REPARSE_POINT (0x400)
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o040777
    mock_stat.st_file_attributes = 0x400

    with patch.object(Path, "is_symlink", return_value=False), \
         patch("os.path.islink", return_value=False), \
         patch.object(Path, "stat", return_value=mock_stat):
        assert is_reparse_point_or_symlink(dummy_path) is True


# ==============================================================================
# Defensive Error Handling & Cancellation Tests
# ==============================================================================


def test_scan_handles_permission_error_gracefully(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify scanner logs PermissionError on locked files and continues scanning."""
    root = tmp_path / "perm_test"
    root.mkdir()

    f1 = root / "accessible.txt"
    f1.write_text("ok", encoding="utf-8")

    f2 = root / "locked.exe"
    f2.write_text("locked", encoding="utf-8")

    orig_stat = Path.stat

    def mock_stat(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self.name == "locked.exe":
            raise PermissionError("Access denied by Windows Defender or file lock.")
        return orig_stat(self, *args, **kwargs)

    with patch.object(Path, "stat", mock_stat):
        report = scanner.scan(root)

    assert report.result.status == ScanStatus.COMPLETED_WITH_ERRORS
    assert report.result.files_inspected == 1
    assert report.result.errors_count == 1
    assert any("Permission denied" in err for err in report.errors)


def test_scan_handles_disappearing_file_gracefully(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify scanner handles FileNotFoundError when a file disappears mid-scan."""
    root = tmp_path / "disappear_test"
    root.mkdir()

    f1 = root / "file1.txt"
    f1.write_text("ok", encoding="utf-8")

    orig_stat = Path.stat

    def mock_stat(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self.name == "file1.txt":
            raise FileNotFoundError("File removed mid-scan.")
        return orig_stat(self, *args, **kwargs)

    with patch.object(Path, "stat", mock_stat):
        report = scanner.scan(root)

    assert report.result.status == ScanStatus.COMPLETED_WITH_ERRORS
    assert report.result.files_inspected == 0
    assert report.result.errors_count == 1
    assert any("disappeared" in err for err in report.errors)


def test_scan_handles_walk_directory_error(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify os.walk onerror callback captures directory access failures."""
    root = tmp_path / "dir_err_test"
    root.mkdir()

    def mock_walk(top, followlinks=False, onerror=None):  # type: ignore[no-untyped-def]
        if onerror:
            err = PermissionError("Locked system directory")
            err.filename = str(top / "System Volume Information")
            err.strerror = "Access denied"
            onerror(err)
        return [(str(top), [], ["valid.txt"])]

    (root / "valid.txt").write_text("content", encoding="utf-8")

    with patch("os.walk", side_effect=mock_walk):
        report = scanner.scan(root)

    assert report.result.status == ScanStatus.COMPLETED_WITH_ERRORS
    assert report.result.errors_count == 1
    assert any("Directory access error" in err for err in report.errors)


def test_scan_cancellation_callback(scanner: VolumeScanner, tmp_path: Path) -> None:
    """Verify providing a cancellation callback aborts scan early with ABORTED_DISCONNECT."""
    root = tmp_path / "cancel_test"
    root.mkdir()

    (root / "f1.txt").write_text("1", encoding="utf-8")
    (root / "f2.txt").write_text("2", encoding="utf-8")

    cancelled_flag = False

    def check_cancel() -> bool:
        nonlocal cancelled_flag
        return cancelled_flag

    # Trigger cancellation after first file
    cancelled_flag = True
    report = scanner.scan(root, is_cancelled=check_cancel)
    assert report.result.status == ScanStatus.ABORTED_DISCONNECT
    assert any("cancelled" in err.lower() for err in report.errors)


# ==============================================================================
# Helper Function Tests
# ==============================================================================


def test_normalize_scan_path_windows_long_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify normalize_scan_path adds \\?\\ only on Windows for >= 240 char absolute drive paths."""
    monkeypatch.setattr(sys, "platform", "win32")
    long_tail = "a" * 240
    long_path = Path(f"C:\\{long_tail}")

    normalized = normalize_scan_path(long_path)
    assert str(normalized).startswith("\\\\?\\C:\\")


def test_normalize_scan_path_posix_does_not_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify normalize_scan_path never prefixes on macOS/Linux even if long."""
    monkeypatch.setattr(sys, "platform", "darwin")
    long_path = Path("/var/tmp/" + "a" * 300)
    normalized = normalize_scan_path(long_path)
    assert not str(normalized).startswith("\\\\?\\")
