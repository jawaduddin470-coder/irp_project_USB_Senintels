"""Unit tests for usb_sentinel.quarantine (crash-safe 5-step quarantine workflow and policy enforcement)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.config import SentinelConfig
from usb_sentinel.models import AuditEventType, AuditStatus, QuarantineStatus
from usb_sentinel.quarantine import (
    QuarantineError,
    QuarantineManager,
    QuarantinePersistenceError,
    QuarantinePolicyViolationError,
    QuarantineVerificationError,
)
from usb_sentinel.vault import VaultError


@pytest.fixture
def quarantine_mgr(tmp_path: Path) -> QuarantineManager:
    """Create a QuarantineManager rooted in an isolated test directory."""
    config = SentinelConfig(base_dir=tmp_path, stream_chunk_size_bytes=4096)
    return QuarantineManager(config=config)


def test_quarantine_default_policy_enforcement(quarantine_mgr: QuarantineManager, tmp_path: Path) -> None:
    """Verify quarantine is rejected under default ALERT_AND_LOG_ONLY unless explicitly confirmed."""
    src = tmp_path / "threat.exe"
    src.write_bytes(b"Suspicious payload")

    # Without explicit_confirm=True
    with pytest.raises(QuarantinePolicyViolationError, match="default policy is ALERT AND LOG ONLY"):
        quarantine_mgr.quarantine_file(src, explicit_confirm=False)

    # Source must remain untouched
    assert src.exists()
    assert quarantine_mgr.index_manager.list_records() == []


def test_quarantine_successful_retain_source(quarantine_mgr: QuarantineManager, tmp_path: Path) -> None:
    """Verify quarantine with remove_source=False retains the original file and commits to vault."""
    src = tmp_path / "script.bat"
    src.write_bytes(b"@echo off\r\ncalc.exe")

    record = quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=False)

    assert record.status == QuarantineStatus.COMMITTED
    assert record.is_restored is False
    assert record.original_path == str(src)
    assert record.file_size_bytes == src.stat().st_size

    # Source file remains untouched
    assert src.exists()

    # Vault object exists
    vault_file = quarantine_mgr.config.vault_dir / record.vault_filename
    assert vault_file.exists()

    # Quarantine index contains record
    idx_record = quarantine_mgr.index_manager.get_record(record.quarantine_id)
    assert idx_record is not None
    assert idx_record.status == QuarantineStatus.COMMITTED

    # Audit ledger has QUARANTINE_COMMITTED
    events = quarantine_mgr.audit_ledger.read_all_events()
    comm_events = [e for e in events if e.event_type == AuditEventType.QUARANTINE_COMMITTED]
    assert len(comm_events) >= 1
    assert comm_events[-1].status == AuditStatus.SUCCESS


def test_quarantine_successful_remove_source(quarantine_mgr: QuarantineManager, tmp_path: Path) -> None:
    """Verify quarantine with remove_source=True deletes the original file and marks status QUARANTINED."""
    src = tmp_path / "malware.exe"
    src.write_bytes(b"Dangerous binary content")

    record = quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=True)

    assert record.status == QuarantineStatus.QUARANTINED
    # Source file was deleted
    assert not src.exists()

    # Vault object exists
    vault_file = quarantine_mgr.config.vault_dir / record.vault_filename
    assert vault_file.exists()

    # Index reflects QUARANTINED
    idx_rec = quarantine_mgr.index_manager.get_record(record.quarantine_id)
    assert idx_rec is not None
    assert idx_rec.status == QuarantineStatus.QUARANTINED


def test_quarantine_source_write_protected(quarantine_mgr: QuarantineManager, tmp_path: Path) -> None:
    """Verify write-protected USB failure records QUARANTINE_SOURCE_LOCKED and retains vault copy."""
    src = tmp_path / "locked_trojan.exe"
    src.write_bytes(b"Trojan content")

    # Simulate PermissionError on src.unlink() (write-protected media)
    with patch.object(Path, "unlink", side_effect=PermissionError("Media is write-protected")):
        record = quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=True)

    # Status must be explicitly QUARANTINE_SOURCE_LOCKED
    assert record.status == QuarantineStatus.QUARANTINE_SOURCE_LOCKED

    # Original file is STILL on disk!
    assert src.exists()

    # Verified vault object is retained!
    vault_file = quarantine_mgr.config.vault_dir / record.vault_filename
    assert vault_file.exists()

    # Audit ledger contains QUARANTINE_SOURCE_LOCKED with WARNING
    events = quarantine_mgr.audit_ledger.read_all_events()
    locked_events = [e for e in events if e.event_type == AuditEventType.QUARANTINE_SOURCE_LOCKED]
    assert len(locked_events) == 1
    assert locked_events[0].status == AuditStatus.WARNING
    assert "write-protected" in (locked_events[0].details or "")


def test_quarantine_rejects_symlink_under_defensive_policy(
    quarantine_mgr: QuarantineManager, tmp_path: Path
) -> None:
    """Verify quarantine rejects symbolic links under strict boundary safety policy."""
    real_file = tmp_path / "real.txt"
    real_file.write_bytes(b"Real file")

    symlink_file = tmp_path / "symlink.exe"
    try:
        symlink_file.symlink_to(real_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in environment")

    with pytest.raises(QuarantineError, match="Refusing to quarantine symbolic link"):
        quarantine_mgr.quarantine_file(symlink_file, explicit_confirm=True)


def test_quarantine_missing_source_raises(quarantine_mgr: QuarantineManager, tmp_path: Path) -> None:
    """Verify quarantine raises FileNotFoundError when source does not exist."""
    missing = tmp_path / "missing.exe"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        quarantine_mgr.quarantine_file(missing, explicit_confirm=True)


def test_quarantine_aborts_deletion_if_source_mutated(
    quarantine_mgr: QuarantineManager, tmp_path: Path
) -> None:
    """Verify pre-deletion revalidation aborts deletion if file was modified during processing."""
    src = tmp_path / "mutating.exe"
    src.write_bytes(b"Initial data")

    orig_stat = Path.stat
    stat_call_count = 0

    def mock_stat(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal stat_call_count
        stat_call_count += 1
        res = orig_stat(self, *args, **kwargs)
        if self == src and stat_call_count >= 3:
            # Simulate modification on post-encryption check
            mocked = MagicMock(wraps=res)
            mocked.st_size = res.st_size + 50
            mocked.st_mtime_ns = res.st_mtime_ns + 1000000
            return mocked
        return res

    with patch.object(Path, "stat", mock_stat):
        record = quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=True)

    # Deletion was aborted: status remains COMMITTED, source file still exists
    assert record.status == QuarantineStatus.COMMITTED
    assert src.exists()


def test_quarantine_step2_verification_failure_aborts_cleanly(
    quarantine_mgr: QuarantineManager, tmp_path: Path
) -> None:
    """Verify failure during Step 2 verification cleans up staging and leaves source untouched."""
    src = tmp_path / "corrupt_on_stage.exe"
    src.write_bytes(b"Payload to test failure")

    with patch.object(
        quarantine_mgr.vault_manager,
        "authenticate_and_verify_stream",
        side_effect=VaultError("Simulated tag corruption"),
    ):
        with pytest.raises(QuarantineVerificationError, match="Step 2 verification failed"):
            quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=True)

    # Source untouched
    assert src.exists()

    # No vault files created
    vault_files = list(quarantine_mgr.config.vault_dir.glob("*.qnt"))
    assert len(vault_files) == 0

    # No staging files lingering
    staging_files = list(quarantine_mgr.config.staging_dir.glob("*.tmp"))
    assert len(staging_files) == 0


def test_quarantine_index_persistence_failure_raises(
    quarantine_mgr: QuarantineManager, tmp_path: Path
) -> None:
    """Verify index persistence failure surfaces QuarantinePersistenceError without silent data loss."""
    src = tmp_path / "persist_fail.exe"
    src.write_bytes(b"Payload")

    with patch.object(
        quarantine_mgr.index_manager,
        "add_record",
        side_effect=OSError("Disk write error to index"),
    ):
        with pytest.raises(QuarantinePersistenceError, match="persistence failed"):
            quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=True)

    # Source file was NOT deleted because index commit failed
    assert src.exists()


def test_quarantine_aborts_deletion_if_source_content_mutated_same_size(
    quarantine_mgr: QuarantineManager, tmp_path: Path
) -> None:
    """Verify pre-deletion SHA-256 check aborts deletion if content changed even when size and mtime are mocked as identical."""
    src = tmp_path / "same_size_mutating.exe"
    src.write_bytes(b"OriginalPayload1234")

    orig_stat = Path.stat

    # Function to mutate file content right after staging/vault creation
    def patched_stat(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        res = orig_stat(self, *args, **kwargs)
        if self == src:
            # Overwrite source content with identical length (19 bytes)
            src.write_bytes(b"MUTATEDPayload_9999")
            # Freeze mtime to original to test that content hash caught it
            mocked = MagicMock(wraps=res)
            mocked.st_size = len(b"OriginalPayload1234")
            mocked.st_mtime_ns = res.st_mtime_ns
            return mocked
        return res

    with patch.object(Path, "stat", patched_stat):
        record = quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=True)

    # Deletion aborted because pre-deletion hash did not match recorded hash
    assert record.status == QuarantineStatus.COMMITTED
    assert src.exists()
    assert src.read_bytes() == b"MUTATEDPayload_9999"


def test_quarantine_audit_append_failure_aborts_source_deletion(
    quarantine_mgr: QuarantineManager, tmp_path: Path
) -> None:
    """Verify that if appending the committed audit event fails, source deletion is aborted and QuarantinePersistenceError is raised."""
    src = tmp_path / "audit_fail.exe"
    src.write_bytes(b"Important Source Data")

    orig_append = quarantine_mgr.audit_ledger.append_event

    def mock_append(event):  # type: ignore[no-untyped-def]
        from usb_sentinel.models import AuditEventType
        if event.event_type == AuditEventType.QUARANTINE_COMMITTED:
            raise OSError("Simulated disk error writing audit ledger")
        return orig_append(event)

    with patch.object(quarantine_mgr.audit_ledger, "append_event", side_effect=mock_append):
        with pytest.raises(QuarantinePersistenceError, match="audit logging failed"):
            quarantine_mgr.quarantine_file(src, explicit_confirm=True, remove_source=True)

    # Source file MUST remain untouched
    assert src.exists()
    assert src.read_bytes() == b"Important Source Data"

