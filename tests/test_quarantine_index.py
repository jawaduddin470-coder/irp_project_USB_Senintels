"""Unit tests for usb_sentinel.quarantine_index."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from usb_sentinel.models import QuarantineRecord, QuarantineStatus
from usb_sentinel.quarantine_index import (
    CURRENT_SCHEMA_VERSION,
    DuplicateRecordError,
    QuarantineIndexCorruptedError,
    QuarantineIndexError,
    QuarantineIndexManager,
    RecordNotFoundError,
)


@pytest.fixture
def sample_record(sample_utc_time: datetime) -> QuarantineRecord:
    return QuarantineRecord(
        quarantine_id="550e8400-e29b-41d4-a716-446655440000",
        original_path="E:\\tools\\setup.exe",
        vault_filename="550e8400.qnt",
        quarantined_at=sample_utc_time,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=1024,
        status=QuarantineStatus.COMMITTED,
        is_restored=False,
        restored_at=None,
        restored_path=None,
    )


def test_quarantine_index_initial_empty(tmp_path: Path) -> None:
    """Verify loading a non-existent index file results in an empty registry without error."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)

    mgr.load()
    assert mgr.list_records() == []
    assert not index_file.exists()  # Ensure loading does not create file until records are added


def test_add_and_lookup_record(tmp_path: Path, sample_record: QuarantineRecord) -> None:
    """Verify adding a record persists to disk and allows retrieval by ID."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)

    mgr.add_record(sample_record)
    assert index_file.exists()

    retrieved = mgr.get_record(sample_record.quarantine_id)
    assert retrieved is not None
    assert retrieved.quarantine_id == sample_record.quarantine_id
    assert retrieved.original_path == sample_record.original_path
    assert retrieved.status == QuarantineStatus.COMMITTED


def test_data_preservation_across_reloads(tmp_path: Path, sample_record: QuarantineRecord) -> None:
    """Verify data survives process restart by reloading from disk."""
    index_file = tmp_path / "quarantine_index.txt"

    # Session 1: Add record
    mgr1 = QuarantineIndexManager(index_path=index_file)
    mgr1.add_record(sample_record)

    # Session 2: Fresh manager loading file
    mgr2 = QuarantineIndexManager(index_path=index_file)
    mgr2.load()

    records = mgr2.list_records()
    assert len(records) == 1
    assert records[0].quarantine_id == sample_record.quarantine_id
    assert records[0].sha256_hash == sample_record.sha256_hash
    assert records[0].quarantined_at == sample_record.quarantined_at


def test_reject_duplicate_ids(tmp_path: Path, sample_record: QuarantineRecord) -> None:
    """Verify DuplicateRecordError is raised when inserting an existing ID."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)
    mgr.add_record(sample_record)

    with pytest.raises(DuplicateRecordError, match="already exists"):
        mgr.add_record(sample_record)


def test_unicode_and_windows_paths(tmp_path: Path, sample_utc_time: datetime) -> None:
    """Verify index handles Windows paths, backslashes, extended prefixes, and Unicode."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)

    rec = QuarantineRecord(
        quarantine_id="UNI_REC_01",
        original_path="\\\\?\\E:\\папка с файлами\\emoji_🚀_script.bat",
        vault_filename="UNI_REC_01.qnt",
        quarantined_at=sample_utc_time,
        status=QuarantineStatus.COMMITTED,
    )
    mgr.add_record(rec)

    mgr_reload = QuarantineIndexManager(index_path=index_file)
    loaded = mgr_reload.get_record("UNI_REC_01")
    assert loaded is not None
    assert loaded.original_path == "\\\\?\\E:\\папка с файлами\\emoji_🚀_script.bat"


def test_list_and_filter_records(tmp_path: Path, sample_utc_time: datetime) -> None:
    """Verify list_records returns all records or filters by QuarantineStatus."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)

    r1 = QuarantineRecord(
        quarantine_id="ID_1",
        original_path="E:\\f1.exe",
        vault_filename="f1.qnt",
        quarantined_at=sample_utc_time,
        status=QuarantineStatus.COMMITTED,
    )
    r2 = QuarantineRecord(
        quarantine_id="ID_2",
        original_path="E:\\f2.bat",
        vault_filename="f2.qnt",
        quarantined_at=sample_utc_time,
        status=QuarantineStatus.QUARANTINE_SOURCE_LOCKED,
    )
    mgr.add_record(r1)
    mgr.add_record(r2)

    assert len(mgr.list_records()) == 2
    committed_only = mgr.list_records(status_filter=QuarantineStatus.COMMITTED)
    assert len(committed_only) == 1
    assert committed_only[0].quarantine_id == "ID_1"

    locked_only = mgr.list_records(status_filter=QuarantineStatus.QUARANTINE_SOURCE_LOCKED)
    assert len(locked_only) == 1
    assert locked_only[0].quarantine_id == "ID_2"


def test_update_record(tmp_path: Path, sample_record: QuarantineRecord, sample_utc_time: datetime) -> None:
    """Verify updating a record persists changes and maintains integrity."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)
    mgr.add_record(sample_record)

    updated = mgr.update_record(
        quarantine_id=sample_record.quarantine_id,
        status=QuarantineStatus.RESTORED,
        is_restored=True,
        restored_at=sample_utc_time,
        restored_path="C:\\Restored\\setup.exe",
    )
    assert updated.status == QuarantineStatus.RESTORED
    assert updated.is_restored is True
    assert updated.restored_path == "C:\\Restored\\setup.exe"

    # Verify persisted to disk
    mgr_reload = QuarantineIndexManager(index_path=index_file)
    reloaded = mgr_reload.get_record(sample_record.quarantine_id)
    assert reloaded is not None
    assert reloaded.status == QuarantineStatus.RESTORED
    assert reloaded.is_restored is True


def test_update_nonexistent_record_raises(tmp_path: Path) -> None:
    """Verify RecordNotFoundError is raised when updating an unknown ID."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)
    with pytest.raises(RecordNotFoundError, match="not found"):
        mgr.update_record(quarantine_id="UNKNOWN_ID", is_restored=True)


def test_corrupted_index_raises_and_preserves_file(tmp_path: Path) -> None:
    """Verify QuarantineIndexCorruptedError is raised on malformed data and file is NOT destroyed."""
    index_file = tmp_path / "quarantine_index.txt"
    corrupt_content = 'NOT_VALID_JSON_ON_LINE_1\n{"schema_version": 1}\n'
    index_file.write_text(corrupt_content, encoding="utf-8")

    mgr = QuarantineIndexManager(index_path=index_file)
    with pytest.raises(QuarantineIndexCorruptedError, match="Malformed JSON"):
        mgr.load()

    # CRITICAL: Verify corrupted file content is preserved for forensic recovery!
    assert index_file.read_text(encoding="utf-8") == corrupt_content


def test_unsupported_schema_version_raises(tmp_path: Path) -> None:
    """Verify loading a record with future unsupported schema_version raises QuarantineIndexCorruptedError."""
    index_file = tmp_path / "quarantine_index.txt"
    bad_schema_line = json.dumps({
        "schema_version": 999,
        "quarantine_id": "REC_FUTURE",
        "original_path": "E:\\f.exe",
        "vault_filename": "f.qnt",
        "quarantined_at": "2026-10-16T01:00:00Z",
    }) + "\n"
    index_file.write_text(bad_schema_line, encoding="utf-8")

    mgr = QuarantineIndexManager(index_path=index_file)
    with pytest.raises(QuarantineIndexCorruptedError, match="Unsupported schema version"):
        mgr.load()


def test_persistence_failure_rolls_back_in_memory_state(tmp_path: Path, sample_record: QuarantineRecord) -> None:
    """Verify that a disk write failure does not leave in-memory state with an uncommitted record."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)
    mgr.load()
    assert mgr.list_records() == []

    # Mock os.replace to simulate I/O or filesystem failure
    with patch("os.replace", side_effect=OSError("Disk full or permission denied")):
        with pytest.raises(QuarantineIndexError, match="Failed to persist"):
            mgr.add_record(sample_record)

    # In-memory registry must have rolled back to 0 records!
    assert mgr.get_record(sample_record.quarantine_id) is None
    assert len(mgr.list_records()) == 0
    assert not index_file.exists()


def test_temporary_file_uniqueness_and_cleanup(tmp_path: Path, sample_record: QuarantineRecord) -> None:
    """Verify temporary files use unique random suffixes and leave no orphaned files."""
    index_file = tmp_path / "quarantine_index.txt"
    mgr = QuarantineIndexManager(index_path=index_file)

    mgr.add_record(sample_record)
    assert index_file.exists()

    # Verify no lingering .tmp_ files in directory after normal write
    tmp_files = list(tmp_path.glob("*.tmp_*"))
    assert len(tmp_files) == 0

    # Simulate failure during os.replace to test temp file cleanup
    rec2 = QuarantineRecord(
        quarantine_id="SECOND_ID",
        original_path="E:\\doc.bat",
        vault_filename="doc.qnt",
        quarantined_at=datetime(2026, 10, 16, 2, 0, 0, tzinfo=timezone.utc),
    )
    with patch("os.replace", side_effect=OSError("Atomic replace denied")):
        with pytest.raises(QuarantineIndexError):
            mgr.add_record(rec2)

    # Temporary file must have been unlinked
    assert len(list(tmp_path.glob("*.tmp_*"))) == 0
