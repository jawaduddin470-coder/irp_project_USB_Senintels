"""Unit tests for usb_sentinel.restoration (safe restoration, conflict policies, and integrity verification)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from usb_sentinel.config import SentinelConfig
from usb_sentinel.models import AuditEventType, AuditStatus, QuarantineStatus
from usb_sentinel.quarantine import QuarantineManager
from usb_sentinel.restoration import (
    RestorationCollisionError,
    RestorationConflictPolicy,
    RestorationError,
    RestorationIntegrityError,
    RestorationManager,
)
from usb_sentinel.vault import DestinationCollisionError


@pytest.fixture
def restoration_env(tmp_path: Path) -> tuple[QuarantineManager, RestorationManager]:
    config = SentinelConfig(base_dir=tmp_path, stream_chunk_size_bytes=4096)
    q_mgr = QuarantineManager(config=config)
    r_mgr = RestorationManager(
        config=config,
        key_manager=q_mgr._key_manager,
        vault_manager=q_mgr._vault_manager,
        index_manager=q_mgr._index_manager,
        audit_ledger=q_mgr._audit_ledger,
    )
    return q_mgr, r_mgr


def test_successful_restoration_to_directory(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify quarantined file is decrypted, verified, and placed at specified directory."""
    q_mgr, r_mgr = restoration_env
    original_data = b"Legitimate administrative tool binary content 12345"
    orig_file = tmp_path / "mock_usb" / "admin_tool.exe"
    orig_file.parent.mkdir(parents=True, exist_ok=True)
    orig_file.write_bytes(original_data)

    record = q_mgr.quarantine_file(orig_file, explicit_confirm=True, remove_source=True)
    assert not orig_file.exists()

    restore_dir = tmp_path / "restored_output"
    restored_path, updated_record = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=restore_dir,
    )

    assert restored_path.exists()
    assert restored_path.name == "admin_tool.exe"
    assert restored_path.read_bytes() == original_data
    assert hashlib.sha256(restored_path.read_bytes()).hexdigest().lower() == record.sha256_hash

    # Index updated
    assert updated_record.is_restored is True
    assert updated_record.status == QuarantineStatus.RESTORED
    assert updated_record.restored_path == str(restored_path)

    # Audit event logged
    events = r_mgr._audit_ledger.read_all_events()
    rest_events = [e for e in events if e.event_type == AuditEventType.FILE_RESTORED]
    assert len(rest_events) == 1
    assert rest_events[0].status == AuditStatus.SUCCESS


def test_restoration_collision_reject_policy(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify restoration raises RestorationCollisionError when target exists under REJECT policy."""
    q_mgr, r_mgr = restoration_env
    orig_file = tmp_path / "tool.bat"
    orig_file.write_bytes(b"content")

    record = q_mgr.quarantine_file(orig_file, explicit_confirm=True, remove_source=True)

    restore_dir = tmp_path / "dest"
    restore_dir.mkdir(parents=True, exist_ok=True)
    collision_file = restore_dir / "tool.bat"
    collision_file.write_bytes(b"Pre-existing different file")

    with pytest.raises(RestorationCollisionError, match="destination file already exists"):
        r_mgr.restore_file(
            quarantine_id=record.quarantine_id,
            destination_dir=restore_dir,
            conflict_policy=RestorationConflictPolicy.REJECT,
        )

    # Pre-existing file remains untouched
    assert collision_file.read_bytes() == b"Pre-existing different file"


def test_restoration_collision_rename_policy(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify restoration with RENAME_NEW policy creates non-colliding timestamped file."""
    q_mgr, r_mgr = restoration_env
    orig_file = tmp_path / "app.exe"
    orig_file.write_bytes(b"Quarantined app content")

    record = q_mgr.quarantine_file(orig_file, explicit_confirm=True, remove_source=True)

    restore_dir = tmp_path / "dest"
    restore_dir.mkdir(parents=True, exist_ok=True)
    existing_file = restore_dir / "app.exe"
    existing_file.write_bytes(b"Existing file content")

    restored_path, _ = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=restore_dir,
        conflict_policy=RestorationConflictPolicy.RENAME_NEW,
    )

    assert restored_path.exists()
    assert restored_path != existing_file
    assert "app_restored_" in restored_path.name
    assert restored_path.suffix == ".exe"
    assert restored_path.read_bytes() == b"Quarantined app content"
    assert existing_file.read_bytes() == b"Existing file content"


def test_restoration_integrity_failure_aborts_without_releasing_plaintext(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify tampered vault file aborts restoration and leaves no unverified plaintext on disk."""
    q_mgr, r_mgr = restoration_env
    orig_file = tmp_path / "tampered.exe"
    orig_file.write_bytes(b"Content before corruption")

    record = q_mgr.quarantine_file(orig_file, explicit_confirm=True, remove_source=True)
    vault_file = q_mgr.config.vault_dir / record.vault_filename

    # Corrupt ciphertext byte
    raw_data = bytearray(vault_file.read_bytes())
    raw_data[200] ^= 0x01
    vault_file.write_bytes(raw_data)

    restore_dir = tmp_path / "dest"
    with pytest.raises((RestorationIntegrityError, RestorationError)):
        r_mgr.restore_file(
            quarantine_id=record.quarantine_id,
            destination_dir=restore_dir,
        )

    # Restored target file must NOT exist
    assert not (restore_dir / "tampered.exe").exists()
    # No temporary files lingering in destination directory
    assert len(list(restore_dir.glob("*.tmp_*"))) == 0


def test_restoration_missing_record_raises(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify attempting to restore an unknown quarantine ID raises RestorationError."""
    _, r_mgr = restoration_env
    with pytest.raises(RestorationError, match="not found in index"):
        r_mgr.restore_file(quarantine_id="NON_EXISTENT_ID", destination_dir=tmp_path)


def test_restoration_explicit_target_path_and_overwrite(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify explicit target path restoration and OVERWRITE policy."""
    q_mgr, r_mgr = restoration_env
    orig_file = tmp_path / "custom.exe"
    orig_file.write_bytes(b"Fresh version 2.0")

    record = q_mgr.quarantine_file(orig_file, explicit_confirm=True, remove_source=True)

    explicit_dest = tmp_path / "custom_location" / "restored_custom.exe"
    explicit_dest.parent.mkdir(parents=True, exist_ok=True)
    explicit_dest.write_bytes(b"Old obsolete version 1.0")

    # With OVERWRITE policy
    restored_path, _ = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        explicit_target_path=explicit_dest,
        conflict_policy=RestorationConflictPolicy.OVERWRITE,
    )

    assert restored_path == explicit_dest
    assert restored_path.read_bytes() == b"Fresh version 2.0"


def test_restoration_missing_destination_when_original_unavailable(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify that when original path is inaccessible and no destination is provided, an informative error is raised."""
    q_mgr, r_mgr = restoration_env
    # Create file on simulated unmounted drive path that won't exist
    phantom_drive_file = tmp_path / "Z_DRIVE" / "phantom.exe"
    phantom_drive_file.parent.mkdir(parents=True, exist_ok=True)
    phantom_drive_file.write_bytes(b"data")

    record = q_mgr.quarantine_file(phantom_drive_file, explicit_confirm=True, remove_source=True)
    # Remove phantom drive directory to simulate USB disconnected
    os.rmdir(phantom_drive_file.parent)

    with pytest.raises(RestorationError, match="Original drive location .* is unavailable"):
        r_mgr.restore_file(quarantine_id=record.quarantine_id)


def test_restoration_collision_leaves_existing_destination_byte_for_byte_unchanged(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify that collision with REJECT policy leaves existing file 100% byte-for-byte identical with no temporary debris."""
    q_mgr, r_mgr = restoration_env
    orig_file = tmp_path / "orig_data.txt"
    orig_file.write_bytes(b"Restorable fresh content")
    record = q_mgr.quarantine_file(orig_file, explicit_confirm=True, remove_source=True)

    dest_dir = tmp_path / "target_dir"
    dest_dir.mkdir(parents=True, exist_ok=True)
    existing_dest = dest_dir / "orig_data.txt"
    critical_data = b"CRITICAL_USER_DATABASE_RECORD_DO_NOT_TOUCH_OR_OVERWRITE"
    existing_dest.write_bytes(critical_data)

    # Attempt restoration with default REJECT policy
    with pytest.raises(RestorationCollisionError) as exc_info:
        r_mgr.restore_file(
            quarantine_id=record.quarantine_id,
            destination_dir=dest_dir,
            conflict_policy=RestorationConflictPolicy.REJECT,
        )

    # Assert exception inherits from DestinationCollisionError
    assert isinstance(exc_info.value, DestinationCollisionError)
    assert isinstance(exc_info.value, RestorationCollisionError)

    # Assert existing file is 100% untouched
    assert existing_dest.exists()
    assert existing_dest.read_bytes() == critical_data

    # Assert no temporary files or orphaned decrypted files remain in target directory
    all_files = list(dest_dir.iterdir())
    assert all_files == [existing_dest]


def test_restoration_strictly_blocks_destination_symlinks(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify that restoration rejects destination symbolic links even under overwrite policy."""
    q_mgr, r_mgr = restoration_env
    orig_file = tmp_path / "sym_src.exe"
    orig_file.write_bytes(b"Fresh payload")
    record = q_mgr.quarantine_file(orig_file, explicit_confirm=True, remove_source=True)

    real_victim = tmp_path / "victim_config.json"
    real_victim.write_bytes(b'{"secret": "sensitive_original_config"}')

    symlink_dest = tmp_path / "restored_symlink.exe"
    try:
        os.symlink(real_victim, symlink_dest)
    except OSError:
        pytest.skip("Symlink creation not supported in current test context")

    # Attempt restoration over symlink with OVERWRITE policy
    with pytest.raises(RestorationCollisionError, match="symbolic link"):
        r_mgr.restore_file(
            quarantine_id=record.quarantine_id,
            explicit_target_path=symlink_dest,
            conflict_policy=RestorationConflictPolicy.OVERWRITE,
            allow_overwrite=True,
        )

    # Verify real victim file was NEVER modified
    assert real_victim.read_bytes() == b'{"secret": "sensitive_original_config"}'


def test_restoration_handles_windows_path_leaf_and_traversal(
    restoration_env: tuple[QuarantineManager, RestorationManager], tmp_path: Path
) -> None:
    """Verify Windows backslash paths extract leaf filenames correctly and traversal is blocked."""
    q_mgr, r_mgr = restoration_env

    # 1. Quarantined file whose original_path had Windows backslashes
    src = tmp_path / "win_payload.bin"
    src.write_bytes(b"Windows payload content")
    record = q_mgr.quarantine_file(src, explicit_confirm=True, remove_source=False)

    import dataclasses

    # Manually update index to simulate Windows path: E:\Infected\Sub\deep_tool.exe
    win_rec = dataclasses.replace(record, original_path=r"E:\Infected\Sub\deep_tool.exe")
    q_mgr.index_manager._records[record.quarantine_id] = win_rec
    q_mgr.index_manager._persist_unlocked(q_mgr.index_manager._records)

    dest_dir = tmp_path / "restore_out"
    dest_dir.mkdir(parents=True, exist_ok=True)

    restored_path, _ = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=dest_dir,
    )

    # Should restore cleanly as deep_tool.exe inside dest_dir
    assert restored_path.exists()
    assert restored_path.name == "deep_tool.exe"
    assert restored_path.parent.resolve() == dest_dir.resolve()
    assert restored_path.read_bytes() == b"Windows payload content"

    # 2. Test directory traversal rejection when original_path leaf contains dot-dot
    dot_rec = dataclasses.replace(record, original_path="..")
    q_mgr.index_manager._records[record.quarantine_id] = dot_rec
    q_mgr.index_manager._persist_unlocked(q_mgr.index_manager._records)
    restored_fallback, _ = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=dest_dir,
    )
    # Replaces '..' with fallback safe filename
    assert restored_fallback.name == f"restored_{record.quarantine_id}.bin"
    assert restored_fallback.parent.resolve() == dest_dir.resolve()



