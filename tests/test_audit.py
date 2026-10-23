"""Unit tests for usb_sentinel.audit (persistent CSV audit ledger and formula sanitization)."""

from __future__ import annotations

import concurrent.futures
import csv
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from usb_sentinel.audit import (
    CSV_HEADER,
    AuditLedger,
    AuditLedgerError,
    desanitize_csv_value,
    format_utc_timestamp,
    parse_utc_timestamp,
    sanitize_csv_value,
)
from usb_sentinel.models import AuditEvent, AuditEventType, AuditStatus


@pytest.fixture
def sample_event(sample_utc_time: datetime) -> AuditEvent:
    return AuditEvent(
        event_id="EVT_001",
        timestamp=sample_utc_time,
        event_type=AuditEventType.DEVICE_INSERTED,
        status=AuditStatus.SUCCESS,
        device_ref="E:",
        target_path="E:\\",
        quarantine_id=None,
        sha256_hash=None,
        details="USB storage volume mounted successfully.",
        error_message=None,
    )


def test_audit_ledger_initialization(tmp_path: Path) -> None:
    """Verify initialize creates parent folder and writes CSV header exactly once."""
    csv_file = tmp_path / "deep" / "logs" / "usb_sentinel_audit.csv"
    ledger = AuditLedger(csv_path=csv_file)
    assert not csv_file.exists()

    ledger.initialize()
    assert csv_file.exists()

    # Verify header line
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == list(CSV_HEADER)
        # Ensure no subsequent lines
        assert next(reader, None) is None


def test_audit_ledger_append_and_read(tmp_path: Path, sample_event: AuditEvent) -> None:
    """Verify appending events and reading them back preserves all fields and datetimes."""
    csv_file = tmp_path / "audit.csv"
    ledger = AuditLedger(csv_path=csv_file)

    ledger.append_event(sample_event)
    events = ledger.read_all_events()

    assert len(events) == 1
    read_event = events[0]
    assert read_event.event_id == sample_event.event_id
    assert read_event.timestamp == sample_event.timestamp
    assert read_event.event_type == sample_event.event_type
    assert read_event.status == sample_event.status
    assert read_event.device_ref == sample_event.device_ref
    assert read_event.details == sample_event.details
    assert read_event.quarantine_id is None
    assert read_event.error_message is None


def test_no_duplicate_headers_across_restarts(tmp_path: Path, sample_event: AuditEvent) -> None:
    """Verify closing and reopening the ledger appends rows without duplicating the header."""
    csv_file = tmp_path / "audit.csv"

    # First session: write 1 event
    ledger1 = AuditLedger(csv_path=csv_file)
    ledger1.append_event(sample_event)

    # Second session: write 2nd event
    event2 = AuditEvent(
        event_id="EVT_002",
        timestamp=datetime(2026, 10, 16, 13, 0, 0, tzinfo=timezone.utc),
        event_type=AuditEventType.FILE_FLAGGED,
        status=AuditStatus.WARNING,
        device_ref="E:",
        target_path="E:\\script.bat",
        details="Suspicious extension flagged.",
    )
    ledger2 = AuditLedger(csv_path=csv_file)
    ledger2.append_event(event2)

    # Read raw lines directly to verify exactly 1 header line
    with open(csv_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    assert len(lines) == 3  # Header + 2 data rows
    assert lines[0].strip().startswith("event_id,timestamp,")
    assert not lines[1].strip().startswith("event_id,timestamp,")
    assert not lines[2].strip().startswith("event_id,timestamp,")

    events = ledger2.read_all_events()
    assert len(events) == 2


def test_canonical_ledger_round_trip_fidelity(tmp_path: Path, sample_utc_time: datetime) -> None:
    """Verify canonical ledger stores raw values verbatim, preserving leading =, +, -, @, and ' without corruption."""
    csv_file = tmp_path / "canonical_audit.csv"
    ledger = AuditLedger(csv_path=csv_file)

    event_with_special_chars = AuditEvent(
        event_id="EVT_SPECIAL",
        timestamp=sample_utc_time,
        event_type=AuditEventType.FILE_FLAGGED,
        status=AuditStatus.WARNING,
        target_path="'+C:\\malicious\\payload.exe",  # starts with apostrophe AND plus
        details="'=already_quoted_formula()",         # starts with apostrophe AND equals
        error_message="-Error Formula Prefix",
    )

    ledger.append_event(event_with_special_chars)

    # Read back from canonical ledger: MUST match 100% identically without stripping apostrophes
    events = ledger.read_all_events()
    assert len(events) == 1
    assert events[0].target_path == "'+C:\\malicious\\payload.exe"
    assert events[0].details == "'=already_quoted_formula()"
    assert events[0].error_message == "-Error Formula Prefix"


def test_csv_formula_injection_sanitization_on_export(tmp_path: Path, sample_utc_time: datetime) -> None:
    """Verify export_to_csv applies formula injection sanitization while canonical ledger stores raw values."""
    canonical_csv = tmp_path / "canonical.csv"
    export_csv = tmp_path / "exported.csv"
    ledger = AuditLedger(csv_path=canonical_csv)

    malicious_event = AuditEvent(
        event_id="=cmd|'/C calc'!A0",
        timestamp=sample_utc_time,
        event_type=AuditEventType.FILE_FLAGGED,
        status=AuditStatus.WARNING,
        target_path="+C:\\malicious\\payload.exe",
        details="@DDE('calc.exe')",
        error_message="\tTabPrefix",
    )

    ledger.append_event(malicious_event)

    # 1. Canonical ledger must contain raw values
    with open(canonical_csv, "r", encoding="utf-8") as f:
        canonical_raw = f.read()
    assert "=cmd|'/C calc'!A0" in canonical_raw
    assert "+C:\\malicious\\payload.exe" in canonical_raw
    assert "@DDE('calc.exe')" in canonical_raw

    # 2. Exported CSV must have protective single quotes prepended for spreadsheets
    count = ledger.export_to_csv(export_csv)
    assert count == 1

    with open(export_csv, "r", encoding="utf-8") as f:
        export_raw = f.read()

    assert "'=cmd|'/C calc'!A0" in export_raw
    assert "'+C:\\malicious\\payload.exe" in export_raw
    assert "'@DDE('calc.exe')" in export_raw
    assert "'\tTabPrefix" in export_raw


def test_sanitize_csv_value_unit() -> None:
    """Unit test sanitize_csv_value and desanitize_csv_value on various inputs."""
    assert sanitize_csv_value(None) == ""
    assert sanitize_csv_value("") == ""
    assert sanitize_csv_value("normal_text") == "normal_text"
    assert sanitize_csv_value("=1+1") == "'=1+1"
    assert sanitize_csv_value("+cmd") == "'+cmd"
    assert sanitize_csv_value("-5") == "'-5"
    assert sanitize_csv_value("@import") == "'@import"
    assert sanitize_csv_value("\tsome_tab") == "'\tsome_tab"
    assert sanitize_csv_value("\rreturn") == "'\rreturn"
    # Starting with apostrophe followed by formula char
    assert sanitize_csv_value("'=dangerous") == "''=dangerous"

    # Desanitization
    assert desanitize_csv_value(None) is None
    assert desanitize_csv_value("") is None
    assert desanitize_csv_value("normal_text") == "normal_text"
    assert desanitize_csv_value("'=1+1") == "=1+1"
    assert desanitize_csv_value("'+cmd") == "+cmd"
    assert desanitize_csv_value("'-5") == "-5"
    assert desanitize_csv_value("'@import") == "@import"
    assert desanitize_csv_value("'\tsome_tab") == "\tsome_tab"


def test_unicode_and_multiline_fields(tmp_path: Path, sample_utc_time: datetime) -> None:
    """Verify CSV properly handles Unicode characters, commas, quotes, and newlines in details."""
    csv_file = tmp_path / "unicode_audit.csv"
    ledger = AuditLedger(csv_path=csv_file)

    complex_event = AuditEvent(
        event_id="EVT_UNICODE",
        timestamp=sample_utc_time,
        event_type=AuditEventType.SYSTEM_WARNING,
        status=AuditStatus.WARNING,
        target_path="E:\\русский_путь\\emoji_🚀_script.bat",
        details='Message with "quotes", commas, and\nmultiple lines of text.',
    )

    ledger.append_event(complex_event)
    events = ledger.read_all_events()

    assert len(events) == 1
    assert events[0].target_path == "E:\\русский_путь\\emoji_🚀_script.bat"
    assert events[0].details == 'Message with "quotes", commas, and\nmultiple lines of text.'


def test_concurrent_multithreaded_appends(tmp_path: Path, sample_utc_time: datetime) -> None:
    """Verify that multiple threads appending to the ledger do not interleave or corrupt lines."""
    csv_file = tmp_path / "concurrent_audit.csv"
    ledger = AuditLedger(csv_path=csv_file)
    ledger.initialize()

    num_threads = 8
    events_per_thread = 20
    total_events = num_threads * events_per_thread

    def worker(worker_id: int) -> None:
        for i in range(events_per_thread):
            event = AuditEvent(
                event_id=f"THREAD_{worker_id}_EVT_{i}",
                timestamp=sample_utc_time,
                event_type=AuditEventType.FILE_FLAGGED,
                status=AuditStatus.SUCCESS,
                details=f"Thread {worker_id} logging event {i}",
            )
            ledger.append_event(event)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, tid) for tid in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    events = ledger.read_all_events()
    assert len(events) == total_events
    event_ids = {e.event_id for e in events}
    assert len(event_ids) == total_events


def test_audit_ledger_io_error_propagation(tmp_path: Path, sample_event: AuditEvent) -> None:
    """Verify that file write failures raise AuditLedgerError and are not swallowed."""
    csv_file = tmp_path / "protected_audit.csv"
    ledger = AuditLedger(csv_path=csv_file)

    with patch("builtins.open", side_effect=PermissionError("Disk write prohibited")):
        with pytest.raises(AuditLedgerError, match="(Failed to write event|Failed to initialize audit ledger)"):
            ledger.append_event(sample_event)


def test_audit_export_to_csv(tmp_path: Path, sample_event: AuditEvent) -> None:
    """Verify export_to_csv exports records cleanly to a user-specified destination."""
    source_csv = tmp_path / "source_audit.csv"
    dest_csv = tmp_path / "exported" / "audit_backup.csv"

    ledger = AuditLedger(csv_path=source_csv)
    ledger.append_event(sample_event)

    count = ledger.export_to_csv(dest_csv)
    assert count == 1
    assert dest_csv.exists()

    exported_ledger = AuditLedger(csv_path=dest_csv)
    events = exported_ledger.read_all_events()
    assert len(events) == 1
    assert events[0].event_id == sample_event.event_id
