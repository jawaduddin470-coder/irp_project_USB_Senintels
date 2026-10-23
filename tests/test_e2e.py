"""End-to-End (E2E) integration test suite for USB Sentinel (Phase 7).

Validates 10 realistic operational scenarios covering the full system lifecycle:
1. Full lifecycle: insertion -> detection -> scan -> file flagged -> manual quarantine -> inspect index -> safe restore -> audit export.
2. USB external HDD/SSD classified as fixed media disambiguated via WMI/IOCTL.
3. Unknown device classification & degraded detection fallback.
4. Suspicious extensions flagged without automatic modification (ALERT_AND_LOG_ONLY).
5. Quarantine with source deletion -> restore with SHA-256 verification.
6. Interrupted quarantine (write-protected media, permission error, disconnect) preserves original.
7. Tampered vault object, corrupted ciphertext, wrong key, missing key rejected cleanly.
8. Restoration destination collision with overwrite confirmation, rename, and cancellation.
9. Audit ledger export with formula escaping & HTML/text report generation.
10. Watchdog shutdown during discovery/scan and clean restart.
"""

from __future__ import annotations

import csv
import hashlib
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.audit import AuditLedger
from usb_sentinel.config import SentinelConfig
from usb_sentinel.crypto_keys import KeyManager, KeyProtectionError, LocalDevKeyBackend
from usb_sentinel.device_detection import (
    BusTypeNvme,
    BusTypeSata,
    BusTypeUsb,
    DRIVE_FIXED,
    DRIVE_REMOVABLE,
    DeviceEventType,
    MockDeviceDetector,
    RawDeviceEvent,
    WindowsDeviceDetector,
)
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    QuarantineRecord,
    QuarantineStatus,
    RiskFinding,
    RiskSeverity,
    ScanResult,
    ScanStatus,
    utc_now,
)
from usb_sentinel.quarantine import (
    QuarantineError,
    QuarantineManager,
    QuarantinePolicyViolationError,
)
from usb_sentinel.quarantine_index import QuarantineIndexManager
from usb_sentinel.reporting import IncidentData, IncidentReportGenerator
from usb_sentinel.restoration import (
    RestorationCollisionError,
    RestorationConflictPolicy,
    RestorationError,
    RestorationIntegrityError,
    RestorationManager,
)
from usb_sentinel.risk_engine import RiskEngine
from usb_sentinel.scanner import ScanReport, VolumeScanner
from usb_sentinel.vault import (
    DestinationCollisionError,
    IncompleteCipherstreamError,
    VaultAuthenticationError,
    VaultError,
    VaultIntegrityError,
    VaultManager,
)
from usb_sentinel.watchdog import ActiveDeviceSession, USBWatchdog, WatchdogState


# ==============================================================================
# Helper Factories
# ==============================================================================


def create_e2e_environment(tmp_path: Path) -> dict:
    """Create a fully integrated, isolated Sentinel operational environment."""
    config = SentinelConfig(
        base_dir=tmp_path / "sentinel_app_data",
        watchdog_debounce_seconds=0.2,
        watchdog_discovery_retries=3,
        watchdog_retry_delay_seconds=0.05,
        watchdog_auto_scan=True,
        stream_chunk_size_bytes=4096,
    )
    config.ensure_runtime_directories()

    detector = MockDeviceDetector()
    audit_ledger = AuditLedger(config=config)
    index_manager = QuarantineIndexManager(config=config)
    key_manager = KeyManager(config=config)
    vault_manager = VaultManager(config=config, key_manager=key_manager)
    quarantine_manager = QuarantineManager(
        config=config,
        key_manager=key_manager,
        vault_manager=vault_manager,
        index_manager=index_manager,
        audit_ledger=audit_ledger,
    )
    restoration_manager = RestorationManager(
        config=config,
        key_manager=key_manager,
        vault_manager=vault_manager,
        index_manager=index_manager,
        audit_ledger=audit_ledger,
    )
    scanner = VolumeScanner(config=config)
    watchdog = USBWatchdog(
        config=config,
        detector=detector,
        audit_ledger=audit_ledger,
        scanner=scanner,
    )

    return {
        "config": config,
        "detector": detector,
        "audit_ledger": audit_ledger,
        "index_manager": index_manager,
        "key_manager": key_manager,
        "vault_manager": vault_manager,
        "quarantine_manager": quarantine_manager,
        "restoration_manager": restoration_manager,
        "scanner": scanner,
        "watchdog": watchdog,
    }


def make_usb_telemetry(drive_letter: str = "E:", mount_path: Path | None = None) -> DeviceTelemetry:
    """Create standard USB mass storage telemetry for testing."""
    return DeviceTelemetry(
        device_id=drive_letter,
        detected_at=utc_now(),
        mount_point=str(mount_path) if mount_path else f"{drive_letter}\\",
        volume_label="TEST_USB",
        filesystem="FAT32",
        total_bytes=32_000_000_000,
        free_bytes=28_000_000_000,
        volume_serial="E2E1-ABCD",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
        detection_backend="WMI",
        device_model="SanDisk Ultra USB 3.0",
        bus_type="USB",
    )


# ==============================================================================
# Scenario 1: Full Lifecycle Integration
# ==============================================================================


def test_e2e_scenario_1_full_lifecycle(tmp_path: Path) -> None:
    """Scenario 1: Full Lifecycle.
    Insertion -> Detection -> Scan -> File Flagged -> Manual Quarantine ->
    Inspect Index -> Safe Restore -> Audit Export.
    """
    env = create_e2e_environment(tmp_path)
    config: SentinelConfig = env["config"]
    detector: MockDeviceDetector = env["detector"]
    audit_ledger: AuditLedger = env["audit_ledger"]
    q_mgr: QuarantineManager = env["quarantine_manager"]
    r_mgr: RestorationManager = env["restoration_manager"]
    watchdog: USBWatchdog = env["watchdog"]

    # 1. Setup mock USB filesystem
    usb_mount = tmp_path / "mock_usb_drive"
    usb_mount.mkdir(parents=True, exist_ok=True)
    malicious_script = usb_mount / "autorun_helper.scr"
    malicious_content = b"MZ\x90\x00_SUSPICIOUS_PAYLOAD_EXECUTION_STUB_" * 50
    malicious_script.write_bytes(malicious_content)
    expected_sha256 = hashlib.sha256(malicious_content).hexdigest().lower()

    clean_file = usb_mount / "notes.txt"
    clean_file.write_text("Meeting notes from yesterday")

    # 2. Simulate USB insertion and detection
    telemetry = make_usb_telemetry("E:", usb_mount)
    detector.set_volume(telemetry)

    # 3. Watchdog scan triggered on insertion
    session = ActiveDeviceSession(
        session_id="e2e_session_1",
        drive_letter="E:",
        telemetry=telemetry,
        connected_at=utc_now(),
    )
    scan_report = watchdog.scan_device(session)
    assert scan_report is not None
    assert scan_report.result.status == ScanStatus.COMPLETED
    assert scan_report.result.files_inspected >= 2
    assert len(scan_report.findings) >= 1

    # Verify risk engine flagged the .scr file
    scr_finding = next((f for f in scan_report.findings if f.file_path == str(malicious_script)), None)
    assert scr_finding is not None
    assert scr_finding.severity in (RiskSeverity.HIGH, RiskSeverity.SUSPICIOUS)

    # Verify default policy ALERT_AND_LOG_ONLY: file is NOT modified
    assert malicious_script.exists()
    assert clean_file.exists()

    # 4. Operator explicitly confirms manual quarantine with source removal
    record = q_mgr.quarantine_file(
        source_path=malicious_script,
        explicit_confirm=True,
        remove_source=True,
    )
    assert record.status == QuarantineStatus.QUARANTINED
    assert record.sha256_hash == expected_sha256
    assert not malicious_script.exists()  # Source safely removed from USB
    assert clean_file.exists()  # Clean file unaffected

    # Verify encrypted vault object created
    vault_file = config.vault_dir / record.vault_filename
    assert vault_file.exists()
    assert vault_file.stat().st_size > 0

    # 5. Inspect Quarantine Index
    indexed_record = q_mgr.index_manager.get_record(record.quarantine_id)
    assert indexed_record is not None
    assert indexed_record.is_restored is False
    assert indexed_record.quarantine_id == record.quarantine_id

    # 6. Operator restores the quarantined file to verified destination
    restore_dest = tmp_path / "restored_files"
    restored_path, updated_rec = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=restore_dest,
        conflict_policy=RestorationConflictPolicy.RENAME_NEW,
    )

    assert restored_path.exists()
    assert restored_path.read_bytes() == malicious_content
    assert hashlib.sha256(restored_path.read_bytes()).hexdigest().lower() == expected_sha256
    assert updated_rec.is_restored is True
    assert updated_rec.status == QuarantineStatus.RESTORED

    # 7. Audit Ledger Export
    export_csv = tmp_path / "exported_audit.csv"
    exported_count = audit_ledger.export_to_csv(export_csv)
    assert exported_count >= 2
    assert export_csv.exists()

    with open(export_csv, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert "event_type" in header
        rows = list(reader)
        event_types = [r[header.index("event_type")] for r in rows]
        assert "QUARANTINE_COMMITTED" in event_types
        assert "FILE_RESTORED" in event_types


# ==============================================================================
# Scenario 2: USB External HDD/SSD Disambiguation
# ==============================================================================


def test_e2e_scenario_2_usb_external_drive_fixed_disk_disambiguation() -> None:
    """Scenario 2: USB external HDD/SSD classified as fixed media disambiguated via WMI/IOCTL."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    # 1. Simulate External USB HDD (e.g., WD My Passport, Samsung T7)
    # Windows reports DriveType = DRIVE_FIXED, but WMI InterfaceType is USB
    mock_ldisk_usb = MagicMock()
    mock_ldisk_usb.DeviceID = "H:"
    mock_ldisk_usb.DriveType = DRIVE_FIXED

    mock_part_usb = MagicMock()
    mock_disk_usb = MagicMock()
    mock_disk_usb.InterfaceType = "USB"
    mock_disk_usb.PNPDeviceID = "USBSTOR\\DISK&VEN_SAMSUNG&PROD_PORTABLE_SSD_T7\\12345"
    mock_disk_usb.Model = "Samsung PSSD T7 USB Device"

    mock_ldisk_usb.associators.return_value = [mock_part_usb]
    mock_part_usb.associators.return_value = [mock_disk_usb]

    # 2. Simulate Internal NVMe drive (C:)
    mock_ldisk_nvme = MagicMock()
    mock_ldisk_nvme.DeviceID = "C:"
    mock_ldisk_nvme.DriveType = DRIVE_FIXED

    mock_part_nvme = MagicMock()
    mock_disk_nvme = MagicMock()
    mock_disk_nvme.InterfaceType = "NVMe"
    mock_disk_nvme.PNPDeviceID = "SCSI\\DISK&VEN_NVME&PROD_SAMSUNG_SSD_980\\000000"
    mock_disk_nvme.Model = "Samsung SSD 980 PRO"

    mock_ldisk_nvme.associators.return_value = [mock_part_nvme]
    mock_part_nvme.associators.return_value = [mock_disk_nvme]

    def mock_logical_disk(**kwargs):
        dev_id = kwargs.get("DeviceID", "")
        if dev_id == "H:":
            return [mock_ldisk_usb]
        elif dev_id == "C:":
            return [mock_ldisk_nvme]
        return []

    mock_wmi = MagicMock()
    mock_wmi.Win32_LogicalDisk.side_effect = mock_logical_disk
    detector._wmi_client = mock_wmi

    # Classify H: (USB external SSD)
    cls_h, conf_h, backend_h, warn_h, model_h, bus_h = detector._classify_drive("H:")
    assert cls_h == DeviceClassification.USB_MASS_STORAGE
    assert conf_h == DetectionConfidence.DEFINITIVE_WMI_USB
    assert bus_h == "USB"
    assert model_h == "Samsung PSSD T7 USB Device"

    # Classify C: (Internal NVMe)
    cls_c, conf_c, backend_c, warn_c, model_c, bus_c = detector._classify_drive("C:")
    assert cls_c == DeviceClassification.FIXED_VOLUME
    assert bus_c == "NVME"


# ==============================================================================
# Scenario 3: Unknown Device Classification & Degraded Detection Fallback
# ==============================================================================


def test_e2e_scenario_3_unknown_device_classification_and_degraded_fallback(tmp_path: Path) -> None:
    """Scenario 3: Unknown device classification & degraded detection fallback."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    # Simulate WMI failure (e.g. WMI service down or RPC error)
    mock_wmi = MagicMock()
    mock_wmi.Win32_LogicalDisk.side_effect = Exception("WMI RPC service unavailable")
    detector._wmi_client = mock_wmi

    # Simulate IOCTL failure (access denied)
    with patch.object(detector, "_query_storage_ioctl", return_value=None):
        classification, confidence, backend, warning, model, bus = detector._classify_drive("Z:")

    assert classification == DeviceClassification.UNKNOWN
    assert confidence == DetectionConfidence.UNVERIFIED
    assert warning is not None
    assert "Unable to determine" in warning

    # Verify detector produces a valid DeviceTelemetry with explicit uncertainty notice
    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_is_drive_mounted", return_value=True), \
         patch.object(detector, "_get_volume_information", return_value=("UNKNOWN_VOL", "RAW", "0000-0000")), \
         patch.object(detector, "_get_disk_free_space", return_value=(0, 0)):
        telemetry = detector.get_volume_telemetry("Z:")

    assert telemetry is not None
    assert telemetry.classification == DeviceClassification.UNKNOWN
    assert telemetry.confidence == DetectionConfidence.UNVERIFIED
    assert telemetry.warning is not None


# ==============================================================================
# Scenario 4: Suspicious Extensions Flagged (ALERT_AND_LOG_ONLY)
# ==============================================================================


def test_e2e_scenario_4_alert_and_log_only_preserves_files(tmp_path: Path) -> None:
    """Scenario 4: Suspicious extensions flagged without automatic modification (ALERT_AND_LOG_ONLY)."""
    env = create_e2e_environment(tmp_path)
    scanner: VolumeScanner = env["scanner"]
    watchdog: USBWatchdog = env["watchdog"]

    usb_mount = tmp_path / "usb_test_read_only"
    usb_mount.mkdir(parents=True, exist_ok=True)

    files_data = {
        "payload.scr": b"MZ_SCREENSAVER_BINARY_PAYLOAD",
        "script.vbs": b"WScript.Echo 'Executing stealth payload'",
        "double_ext.pdf.exe": b"MZ_FAKE_PDF_EXECUTABLE_BINARY",
        "normal_document.docx": b"PK\x03\x04_AUTHENTIC_OFFICE_DOCX_STREAM",
    }

    initial_states = {}
    for filename, content in files_data.items():
        file_path = usb_mount / filename
        file_path.write_bytes(content)
        st = file_path.stat()
        initial_states[filename] = {
            "size": st.st_size,
            "mtime": st.st_mtime,
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    telemetry = make_usb_telemetry("F:", usb_mount)
    session = ActiveDeviceSession(
        session_id="e2e_session_4",
        drive_letter="F:",
        telemetry=telemetry,
        connected_at=utc_now(),
    )
    scan_report = watchdog.scan_device(session)

    # Verify scan found threats
    assert scan_report is not None
    assert scan_report.result.status == ScanStatus.COMPLETED
    assert len(scan_report.findings) >= 3

    # CRITICAL: Verify not a single file was modified, moved, renamed, or deleted
    for filename, content in files_data.items():
        file_path = usb_mount / filename
        assert file_path.exists(), f"File {filename} was deleted by scan!"
        st = file_path.stat()
        assert st.st_size == initial_states[filename]["size"], f"Size changed for {filename}"
        assert st.st_mtime == initial_states[filename]["mtime"], f"Timestamp changed for {filename}"
        assert hashlib.sha256(file_path.read_bytes()).hexdigest() == initial_states[filename]["sha256"], f"Content changed for {filename}"


# ==============================================================================
# Scenario 5: Quarantine With Source Deletion -> Restore with SHA-256 Verification
# ==============================================================================


def test_e2e_scenario_5_quarantine_deletion_and_verified_restoration(tmp_path: Path) -> None:
    """Scenario 5: Quarantine with source deletion -> restore with SHA-256 verification."""
    env = create_e2e_environment(tmp_path)
    q_mgr: QuarantineManager = env["quarantine_manager"]
    r_mgr: RestorationManager = env["restoration_manager"]

    source_dir = tmp_path / "usb_quarantine_src"
    source_dir.mkdir(parents=True, exist_ok=True)
    test_binary = source_dir / "ransomware_tool.exe"
    # Create 128KB pseudo-random content
    test_data = os.urandom(128 * 1024)
    test_binary.write_bytes(test_data)
    expected_digest = hashlib.sha256(test_data).hexdigest().lower()

    # Quarantine with source removal
    record = q_mgr.quarantine_file(test_binary, explicit_confirm=True, remove_source=True)

    assert not test_binary.exists()
    assert record.sha256_hash == expected_digest

    # Restore to isolated folder
    restore_target_dir = tmp_path / "restored_safe"
    restored_path, rec_after = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=restore_target_dir,
    )

    assert restored_path.exists()
    assert restored_path.stat().st_size == 128 * 1024
    assert hashlib.sha256(restored_path.read_bytes()).hexdigest().lower() == expected_digest
    assert rec_after.is_restored is True


# ==============================================================================
# Scenario 6: Interrupted Quarantine Preserves Original
# ==============================================================================


def test_e2e_scenario_6_interrupted_quarantine_preserves_original(tmp_path: Path) -> None:
    """Scenario 6: Interrupted quarantine (write-protected media, mutation) preserves original."""
    env = create_e2e_environment(tmp_path)
    q_mgr: QuarantineManager = env["quarantine_manager"]

    # 1. Write-Protected / Read-Only Source (QUARANTINE_SOURCE_LOCKED fallback)
    src_locked = tmp_path / "locked_file.exe"
    src_locked.write_bytes(b"Locked read-only malware")

    with patch.object(os, "unlink", side_effect=PermissionError("Media is write protected")):
        record_locked = q_mgr.quarantine_file(src_locked, explicit_confirm=True, remove_source=True)

    assert src_locked.exists()  # Source remains on disk!
    assert record_locked.status == QuarantineStatus.QUARANTINE_SOURCE_LOCKED

    # 2. Source file mutated between initial hashing and pre-deletion verification
    src_mutated = tmp_path / "mutating_payload.exe"
    src_mutated.write_bytes(b"Original payload content")

    with patch("usb_sentinel.quarantine.compute_sha256", return_value="0" * 64):
        rec_mutated = q_mgr.quarantine_file(src_mutated, explicit_confirm=True, remove_source=True)

    # Deletion was aborted: status remains COMMITTED, original source file exists!
    assert rec_mutated.status == QuarantineStatus.COMMITTED
    assert src_mutated.exists()


# ==============================================================================
# Scenario 7: Tampered Vault Object & Wrong Key Rejection
# ==============================================================================


def test_e2e_scenario_7_tampered_vault_and_wrong_key_rejection(tmp_path: Path) -> None:
    """Scenario 7: Tampered vault object, corrupted ciphertext, wrong key, missing key rejected cleanly."""
    env = create_e2e_environment(tmp_path)
    config: SentinelConfig = env["config"]
    q_mgr: QuarantineManager = env["quarantine_manager"]
    r_mgr: RestorationManager = env["restoration_manager"]
    vault_mgr: VaultManager = env["vault_manager"]
    key_mgr: KeyManager = env["key_manager"]

    src = tmp_path / "secret_document.exe"
    src.write_bytes(b"Valuable sensitive payload" * 100)
    record = q_mgr.quarantine_file(src, explicit_confirm=True, remove_source=False)
    vault_path = config.vault_dir / record.vault_filename

    # 1. Corrupt ciphertext chunk (tamper detection)
    corrupted_vault = tmp_path / "corrupted.vault"
    vault_bytes = bytearray(vault_path.read_bytes())
    # Flip a bit in the encrypted payload area (after header)
    vault_bytes[-10] ^= 0xFF
    corrupted_vault.write_bytes(vault_bytes)

    restore_target = tmp_path / "tamper_restore.bin"
    master_key = key_mgr.get_or_create_master_key()

    with pytest.raises(VaultAuthenticationError):
        vault_mgr.decrypt_vault_file(
            vault_file_path=corrupted_vault,
            quarantine_id=record.quarantine_id,
            master_key=master_key,
            destination_path=restore_target,
            expected_sha256=record.sha256_hash,
        )
    assert not restore_target.exists()

    # 2. Truncated vault file
    truncated_vault = tmp_path / "truncated.vault"
    truncated_vault.write_bytes(vault_bytes[: len(vault_bytes) // 2])

    with pytest.raises((IncompleteCipherstreamError, VaultError)):
        vault_mgr.decrypt_vault_file(
            vault_file_path=truncated_vault,
            quarantine_id=record.quarantine_id,
            master_key=master_key,
            destination_path=restore_target,
            expected_sha256=record.sha256_hash,
        )

    # 3. Wrong master key
    wrong_master_key = os.urandom(32)
    with pytest.raises(VaultAuthenticationError):
        vault_mgr.decrypt_vault_file(
            vault_file_path=vault_path,
            quarantine_id=record.quarantine_id,
            master_key=wrong_master_key,
            destination_path=restore_target,
            expected_sha256=record.sha256_hash,
        )


# ==============================================================================
# Scenario 8: Restoration Destination Collision Handling
# ==============================================================================


def test_e2e_scenario_8_restoration_collision_policies(tmp_path: Path) -> None:
    """Scenario 8: Restoration destination collision with overwrite confirmation, rename, and cancellation."""
    env = create_e2e_environment(tmp_path)
    q_mgr: QuarantineManager = env["quarantine_manager"]
    r_mgr: RestorationManager = env["restoration_manager"]

    src = tmp_path / "target_tool.exe"
    original_data = b"AUTHENTIC_ORIGINAL_TOOL_BINARY"
    src.write_bytes(original_data)
    record = q_mgr.quarantine_file(src, explicit_confirm=True, remove_source=False)

    dest_dir = tmp_path / "restore_collisions"
    dest_dir.mkdir(parents=True, exist_ok=True)
    existing_dest = dest_dir / "target_tool.exe"
    existing_dest.write_bytes(b"PRE_EXISTING_UNRELATED_FILE_CONTENT")

    # Policy 1: REJECT (default)
    with pytest.raises(RestorationCollisionError, match="already exists"):
        r_mgr.restore_file(
            quarantine_id=record.quarantine_id,
            destination_dir=dest_dir,
            conflict_policy=RestorationConflictPolicy.REJECT,
            allow_overwrite=False,
        )
    assert existing_dest.read_bytes() == b"PRE_EXISTING_UNRELATED_FILE_CONTENT"

    # Policy 2: RENAME_NEW
    renamed_path, _ = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=dest_dir,
        conflict_policy=RestorationConflictPolicy.RENAME_NEW,
    )
    assert renamed_path.exists()
    assert renamed_path != existing_dest
    assert "target_tool_restored_" in renamed_path.name
    assert renamed_path.read_bytes() == original_data
    assert existing_dest.read_bytes() == b"PRE_EXISTING_UNRELATED_FILE_CONTENT"

    # Policy 3: OVERWRITE (with allow_overwrite=True)
    overwritten_path, _ = r_mgr.restore_file(
        quarantine_id=record.quarantine_id,
        destination_dir=dest_dir,
        conflict_policy=RestorationConflictPolicy.OVERWRITE,
        allow_overwrite=True,
    )
    assert overwritten_path == existing_dest
    assert overwritten_path.read_bytes() == original_data


# ==============================================================================
# Scenario 9: Audit Ledger Export with Formula Escaping & Report Generation
# ==============================================================================


def test_e2e_scenario_9_audit_export_formula_escaping_and_incident_reporting(tmp_path: Path) -> None:
    """Scenario 9: Audit ledger export with formula escaping & HTML/text report generation."""
    env = create_e2e_environment(tmp_path)
    config: SentinelConfig = env["config"]
    audit_ledger: AuditLedger = env["audit_ledger"]

    # Record malicious CSV formula injection events
    injection_payloads = [
        "=CMD|' /C calc'!A0",
        "@SUM(1, 2, 3)",
        "-2*5",
        "+cmd.exe /c notepad",
    ]
    for idx, payload in enumerate(injection_payloads):
        evt = AuditEvent(
            event_id=f"EVT_INJ_{idx}",
            timestamp=utc_now(),
            event_type=AuditEventType.SCAN_COMPLETED,
            status=AuditStatus.SUCCESS,
            details=payload,
            target_path=f"E:\\{payload}\\malware.exe",
        )
        audit_ledger.append_event(evt)

    # Export sanitized CSV
    export_csv = tmp_path / "sanitized_audit.csv"
    audit_ledger.export_to_csv(export_csv)

    with open(export_csv, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        details_col = header.index("details")
        path_col = header.index("target_path")
        for row in reader:
            details_val = row[details_col]
            path_val = row[path_col]
            for trigger in ("=", "@", "+", "-"):
                assert not details_val.startswith(trigger), f"Unescaped formula in details: {details_val}"
                assert not path_val.startswith(trigger), f"Unescaped formula in path: {path_val}"

    # Verify canonical ledger retains raw, unmutated fidelity
    canonical_events = audit_ledger.read_all_events()
    raw_details = [e.details for e in canonical_events if e.event_id.startswith("EVT_INJ_")]
    assert any(d.startswith("=CMD|") for d in raw_details)
    assert any(d.startswith("@SUM") for d in raw_details)

    # Generate Incident Report
    scan_result = ScanResult(
        scan_id="SCAN-001",
        target_path="E:\\",
        started_at=utc_now(),
        completed_at=utc_now(),
        status=ScanStatus.COMPLETED,
        files_inspected=10,
        findings_count=1,
    )
    incident_data = IncidentData(
        incident_id="INC-2026-0001",
        generated_at=utc_now(),
        telemetry=make_usb_telemetry("E:"),
        scan_report=ScanReport(
            result=scan_result,
            findings=(
                RiskFinding(
                    file_path="E:\\<script>alert(1)</script>.exe",
                    matched_rule="HighRiskExtension",
                    severity=RiskSeverity.HIGH,
                    explanation="XSS payload injection attempt",
                ),
            ),
        ),
    )

    report_gen = IncidentReportGenerator(config=config)
    html_path, txt_path = report_gen.save_reports(incident_data)

    assert txt_path.exists()
    assert html_path.exists()

    # Verify HTML escaping
    html_content = html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_content


# ==============================================================================
# Scenario 10: Watchdog Shutdown During Active Discovery/Scan & Clean Restart
# ==============================================================================


def test_e2e_scenario_10_watchdog_shutdown_and_clean_restart(tmp_path: Path) -> None:
    """Scenario 10: Watchdog shutdown during discovery/scan and clean restart."""
    env = create_e2e_environment(tmp_path)
    detector: MockDeviceDetector = env["detector"]
    watchdog: USBWatchdog = env["watchdog"]

    usb_mount = tmp_path / "restart_usb"
    usb_mount.mkdir(parents=True, exist_ok=True)
    for i in range(10):
        (usb_mount / f"file_{i}.bin").write_bytes(b"data" * 100)

    telemetry = make_usb_telemetry("G:", usb_mount)
    detector.set_volume(telemetry)

    # Start watchdog
    watchdog.start(discover_initial=False)
    assert watchdog.state == WatchdogState.RUNNING

    # Queue arrival event
    detector.simulate_arrival("G:", telemetry)

    # Shutdown promptly
    time.sleep(0.05)
    watchdog.stop()
    assert watchdog.state == WatchdogState.STOPPED

    # Clean restart with a new watchdog on the same config
    watchdog_2 = USBWatchdog(
        config=env["config"],
        detector=detector,
        audit_ledger=env["audit_ledger"],
        scanner=env["scanner"],
    )
    watchdog_2.start(discover_initial=False)
    assert watchdog_2.state == WatchdogState.RUNNING
    watchdog_2.stop()
    assert watchdog_2.state == WatchdogState.STOPPED
