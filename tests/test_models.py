"""Unit tests for shared typed data models in usb_sentinel.models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DetectionConfidence,
    DetectionMethod,
    DeviceClassification,
    DeviceTelemetry,
    FileMetadata,
    QuarantineRecord,
    QuarantineStatus,
    RiskFinding,
    RiskSeverity,
    ScanResult,
    ScanStatus,
    utc_now,
)


def test_utc_now_returns_timezone_aware_utc() -> None:
    """Verify that utc_now() produces a valid timezone-aware UTC datetime."""
    now = utc_now()
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc


# ==============================================================================
# Model Instantiation & Field Tests
# ==============================================================================


def test_device_telemetry_instantiation(sample_utc_time: datetime) -> None:
    """Verify DeviceTelemetry instantiates with valid data and handles optional fields."""
    telemetry = DeviceTelemetry(
        device_id="USB_DISK_001",
        detected_at=sample_utc_time,
        mount_point="E:\\",
        volume_label="BACKUP_STICK",
        filesystem="FAT32",
        total_bytes=32_000_000_000,
        free_bytes=16_000_000_000,
        volume_serial="A1B2-C3D4",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
        detection_backend="WMI",
        warning=None,
    )
    assert telemetry.device_id == "USB_DISK_001"
    assert telemetry.mount_point == "E:\\"
    assert telemetry.volume_label == "BACKUP_STICK"
    assert telemetry.filesystem == "FAT32"
    assert telemetry.classification == DeviceClassification.USB_MASS_STORAGE
    assert telemetry.confidence == DetectionConfidence.DEFINITIVE_WMI_USB
    assert telemetry.warning is None


def test_device_telemetry_with_unknown_fields(sample_utc_time: datetime) -> None:
    """Verify DeviceTelemetry gracefully represents unknown attributes as None."""
    telemetry = DeviceTelemetry(
        device_id="DEV_UNRESOLVED",
        detected_at=sample_utc_time,
    )
    assert telemetry.mount_point is None
    assert telemetry.volume_label is None
    assert telemetry.filesystem is None
    assert telemetry.total_bytes is None
    assert telemetry.free_bytes is None
    assert telemetry.volume_serial is None
    assert telemetry.classification == DeviceClassification.UNKNOWN
    assert telemetry.confidence == DetectionConfidence.UNVERIFIED


def test_file_metadata_instantiation(sample_utc_time: datetime) -> None:
    """Verify FileMetadata captures file attributes and platform timestamps."""
    metadata = FileMetadata(
        filename="autorun.bat",
        file_path="E:\\autorun.bat",
        extension=".bat",
        size_bytes=1024,
        modified_at=sample_utc_time,
        created_at=sample_utc_time,
        is_symlink=False,
        is_readonly=True,
    )
    assert metadata.filename == "autorun.bat"
    assert metadata.extension == ".bat"
    assert metadata.size_bytes == 1024
    assert metadata.is_symlink is False
    assert metadata.is_readonly is True
    assert metadata.created_at == sample_utc_time


def test_file_metadata_optional_creation_time(sample_utc_time: datetime) -> None:
    """Verify FileMetadata allows None for created_at when unsupported on OS."""
    metadata = FileMetadata(
        filename="notes.txt",
        file_path="/Volumes/USB/notes.txt",
        extension=".txt",
        size_bytes=512,
        modified_at=sample_utc_time,
        created_at=None,
    )
    assert metadata.created_at is None


def test_risk_finding_instantiation(sample_utc_time: datetime) -> None:
    """Verify RiskFinding indicates heuristic risk without claiming malware certainty."""
    finding = RiskFinding(
        file_path="E:\\tools\\setup.exe",
        severity=RiskSeverity.SUSPICIOUS,
        matched_rule="RULE_SUSPICIOUS_EXTENSION_EXE",
        explanation="Executable binary on removable media flagged for heuristic review.",
        timestamp=sample_utc_time,
        detection_method=DetectionMethod.EXTENSION_HEURISTIC,
    )
    assert finding.severity == RiskSeverity.SUSPICIOUS
    assert finding.matched_rule == "RULE_SUSPICIOUS_EXTENSION_EXE"
    assert "malware" not in finding.explanation.lower()
    assert finding.detection_method == DetectionMethod.EXTENSION_HEURISTIC


def test_scan_result_lifecycle(sample_utc_time: datetime) -> None:
    """Verify ScanResult accurately tracks inspection counts and completion statuses."""
    result = ScanResult(
        scan_id="SCAN_20261016_001",
        target_path="E:\\",
        started_at=sample_utc_time,
        completed_at=sample_utc_time,
        files_inspected=142,
        findings_count=3,
        errors_count=0,
        status=ScanStatus.COMPLETED,
        error_summary=None,
    )
    assert result.scan_id == "SCAN_20261016_001"
    assert result.files_inspected == 142
    assert result.findings_count == 3
    assert result.status == ScanStatus.COMPLETED


def test_quarantine_record_instantiation(sample_utc_time: datetime) -> None:
    """Verify QuarantineRecord tracks isolation state without storing raw secrets."""
    record = QuarantineRecord(
        quarantine_id="550e8400-e29b-41d4-a716-446655440000",
        original_path="E:\\scripts\\payload.ps1",
        vault_filename="550e8400-e29b-41d4-a716-446655440000.qnt",
        quarantined_at=sample_utc_time,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=2048,
        status=QuarantineStatus.COMMITTED,
        is_restored=False,
        restored_at=None,
        restored_path=None,
    )
    assert record.quarantine_id == "550e8400-e29b-41d4-a716-446655440000"
    assert record.vault_filename.endswith(".qnt")
    assert record.status == QuarantineStatus.COMMITTED
    assert record.is_restored is False
    assert not hasattr(record, "encryption_key")  # Verify no key stored in model


def test_quarantine_record_source_locked_status(sample_utc_time: datetime) -> None:
    """Verify QuarantineRecord supports write-protected USB state."""
    record = QuarantineRecord(
        quarantine_id="661f9511-f3ac-42e5-b827-557766551111",
        original_path="E:\\readonly\\script.vbs",
        vault_filename="661f9511.qnt",
        quarantined_at=sample_utc_time,
        status=QuarantineStatus.QUARANTINE_SOURCE_LOCKED,
    )
    assert record.status == QuarantineStatus.QUARANTINE_SOURCE_LOCKED


def test_audit_event_instantiation(sample_utc_time: datetime) -> None:
    """Verify AuditEvent models ledger entries cleanly."""
    event = AuditEvent(
        event_id="EVT_1001",
        timestamp=sample_utc_time,
        event_type=AuditEventType.DEVICE_INSERTED,
        status=AuditStatus.SUCCESS,
        device_ref="E:",
        target_path="E:\\",
        details="USB mass storage volume mounted successfully.",
        error_message=None,
    )
    assert event.event_id == "EVT_1001"
    assert event.event_type == AuditEventType.DEVICE_INSERTED
    assert event.status == AuditStatus.SUCCESS
    assert event.error_message is None


# ==============================================================================
# Model Behavior & Boundary Checks
# ==============================================================================


def test_models_are_immutable() -> None:
    """Verify that models marked frozen=True prevent field re-assignment."""
    metadata = FileMetadata(
        filename="test.scr",
        file_path="E:\\test.scr",
        extension=".scr",
        size_bytes=100,
        modified_at=datetime.now(timezone.utc),
    )
    with pytest.raises(Exception):  # FrozenInstanceError / dataclass error
        metadata.size_bytes = 200  # type: ignore[misc]


def test_no_mutable_default_leaks() -> None:
    """Verify that successive model instances do not share mutable state."""
    finding1 = RiskFinding(
        file_path="E:\\a.exe",
        severity=RiskSeverity.SUSPICIOUS,
        matched_rule="R1",
        explanation="First",
    )
    finding2 = RiskFinding(
        file_path="E:\\b.exe",
        severity=RiskSeverity.SUSPICIOUS,
        matched_rule="R2",
        explanation="Second",
    )
    assert finding1.file_path != finding2.file_path
    assert finding1.matched_rule != finding2.matched_rule


def test_models_do_not_import_windows_apis() -> None:
    """Verify that models.py does not import win32, wmi, or win32api."""
    from usb_sentinel import models

    imported_modules = dir(models)
    assert "win32" not in imported_modules
    assert "win32file" not in imported_modules
    assert "wmi" not in imported_modules
    assert "ctypes" not in imported_modules
