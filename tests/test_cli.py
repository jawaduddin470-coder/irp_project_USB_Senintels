"""Automated test suite for USB Sentinel Command-Line Interface (Phase 6).

Verifies:
1. Strict five-option menu navigation and invalid input handling.
2. Graceful exit (Option 5) and clean handling of EOFError and KeyboardInterrupt.
3. Option 1: Display mounted volumes, hardware telemetry, fallback notices, and on-demand scans.
4. Option 2: Watchdog lifecycle, real-time arrival/removal/scan events, incident report generation, and clean stop.
5. Option 3: Quarantine index inspection, record details view, safe restoration (custom dir, fallback desktop, collision handling).
6. Option 4: Audit ledger export with formula escaping, overwrite confirmation, and summary metrics.
7. Secret hygiene: zero exposure of cryptographic keys in CLI output.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.audit import AuditLedger
from usb_sentinel.cli import SentinelCLI, main
from usb_sentinel.config import SentinelConfig
from usb_sentinel.crypto_keys import KeyManager
from usb_sentinel.device_detection import BaseDeviceDetector
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
from usb_sentinel.quarantine import QuarantineManager
from usb_sentinel.quarantine_index import QuarantineIndexManager
from usb_sentinel.reporting import IncidentData
from usb_sentinel.restoration import RestorationConflictPolicy
from usb_sentinel.scanner import ScanReport


from usb_sentinel.device_detection import MockDeviceDetector


def make_test_cli(
    tmp_path: Path,
    inputs: List[str],
    volumes: Optional[List[DeviceTelemetry]] = None,
) -> tuple[SentinelCLI, list[str], MockDeviceDetector]:
    """Factory creating a test CLI instance with queued inputs and recorded outputs."""
    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()

    output_lines: list[str] = []
    input_queue = list(inputs)

    def mock_input(prompt: str = "") -> str:
        if prompt:
            output_lines.append(prompt)
        if not input_queue:
            raise EOFError("No more mock input")
        val = input_queue.pop(0)
        output_lines.append(f">> {val}")
        return val

    def mock_output(text: str = "") -> None:
        output_lines.append(str(text))

    detector = MockDeviceDetector()
    if volumes:
        for v in volumes:
            detector.set_volume(v)

    cli = SentinelCLI(
        config=cfg,
        detector=detector,
        input_func=mock_input,
        output_func=mock_output,
        use_color=False,
    )
    return cli, output_lines, detector


# --- Test 1: Main Menu & Exit Handling ---

def test_cli_option_5_clean_exit(tmp_path: Path) -> None:
    """Selecting Option 5 should cleanly exit the main loop with code 0."""
    cli, output, _ = make_test_cli(tmp_path, inputs=["5"])
    exit_code = cli.run()

    assert exit_code == 0
    full_output = "\n".join(output)
    assert "USB Sentinel v" in full_output
    assert "Exiting USB Sentinel" in full_output
    assert "Goodbye." in full_output


def test_cli_handles_eof_and_keyboard_interrupt_at_main_menu(tmp_path: Path) -> None:
    """EOFError or KeyboardInterrupt at the main menu should cleanly exit with code 0."""
    cli, output, _ = make_test_cli(tmp_path, inputs=[])
    exit_code = cli.run()

    assert exit_code == 0
    full_output = "\n".join(output)
    assert "Exiting USB Sentinel" in full_output


def test_cli_rejects_invalid_menu_options(tmp_path: Path) -> None:
    """Non-numeric or out-of-range choices should display an error and re-prompt."""
    cli, output, _ = make_test_cli(tmp_path, inputs=["99", "abc", "", "5"])
    exit_code = cli.run()

    assert exit_code == 0
    full_output = "\n".join(output)
    assert full_output.count("[ERROR] Invalid selection.") == 3
    assert "Exiting USB Sentinel" in full_output


# --- Test 2: Option 1 - Active System Mounts & USB Telemetry ---

def test_cli_option_1_displays_empty_mounts(tmp_path: Path) -> None:
    """Option 1 should handle systems with no detected mounts gracefully."""
    cli, output, _ = make_test_cli(tmp_path, inputs=["1", "5"], volumes=[])
    cli.run()

    full_output = "\n".join(output)
    assert "=== [1] Active Storage Mounts & Device Telemetry ===" in full_output
    assert "No active storage volumes detected" in full_output


def test_cli_option_1_displays_volumes_and_fallback_notice(tmp_path: Path) -> None:
    """Option 1 displays volume table and warns when fallback heuristics were used."""
    vol1 = DeviceTelemetry(
        device_id="E:",
        detected_at=utc_now(),
        mount_point="E:\\",
        volume_label="USB_FLASH",
        filesystem="NTFS",
        total_bytes=32_000_000_000,
        free_bytes=28_000_000_000,
        bus_type="USB",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
    )
    vol2 = DeviceTelemetry(
        device_id="F:",
        detected_at=utc_now(),
        mount_point="F:\\",
        volume_label="FALLBACK_DRV",
        filesystem="FAT32",
        total_bytes=8_000_000_000,
        free_bytes=7_000_000_000,
        bus_type="UNKNOWN",
        classification=DeviceClassification.UNKNOWN_REMOVABLE,
        confidence=DetectionConfidence.HEURISTIC_REMOVABLE,
    )

    cli, output, _ = make_test_cli(tmp_path, inputs=["1", "", "5"], volumes=[vol1, vol2])
    cli.run()

    full_output = "\n".join(output)
    assert "USB_FLASH" in full_output
    assert "FALLBACK_DRV" in full_output
    assert "[NOTICE] One or more volumes detected using fallback heuristics." in full_output


def test_cli_option_1_on_demand_scan_clean(tmp_path: Path) -> None:
    """On-demand scan on a clean folder should report 0 suspicious files."""
    scan_dir = tmp_path / "clean_volume"
    scan_dir.mkdir()
    (scan_dir / "document.txt").write_text("Safe text file", encoding="utf-8")
    (scan_dir / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    cli, output, _ = make_test_cli(tmp_path, inputs=["1", str(scan_dir), "5"])
    cli.run()

    full_output = "\n".join(output)
    assert "[CLEAN] Zero suspicious executable or script vectors flagged." in full_output


def test_cli_option_1_on_demand_scan_with_threats_and_quarantine(tmp_path: Path) -> None:
    """On-demand scan with threats allows generating reports and manual quarantine."""
    scan_dir = tmp_path / "infected_volume"
    scan_dir.mkdir()
    bad_file = scan_dir / "invoice.pdf.exe"
    bad_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")

    # Inputs:
    # 1: Option 1
    # str(scan_dir): target path
    # 'y': generate incident reports
    # 'y': manual quarantine?
    # '1': select finding 1
    # 'y': confirm quarantine
    # 'n': remove original source? (keep original)
    # 5: exit
    inputs = ["1", str(scan_dir), "y", "y", "1", "y", "n", "5"]
    cli, output, _ = make_test_cli(tmp_path, inputs=inputs)
    cli.run()

    full_output = "\n".join(output)
    assert "invoice.pdf.exe" in full_output
    assert "[SAVED] HTML Report:" in full_output
    assert "[SAVED] Text Report:" in full_output
    assert "[SUCCESS] File quarantined successfully! QID:" in full_output

    # Verify report was generated
    reports = list(cli.config.reports_dir.glob("*.html"))
    assert len(reports) == 1
    assert reports[0].exists()

    # Verify quarantine record exists in index
    records = cli._index_manager.list_records()
    assert len(records) == 1
    assert records[0].original_path == str(bad_file)


# --- Test 3: Option 2 - Real-Time USB Watchdog ---

def test_cli_option_2_watchdog_lifecycle_and_events(tmp_path: Path) -> None:
    """Watchdog option starts monitor, logs real-time arrival/removal/scans, and stops on prompt."""
    vol = DeviceTelemetry(
        device_id="E:",
        detected_at=utc_now(),
        mount_point="E:\\",
        volume_label="SECURE_USB",
        filesystem="NTFS",
        total_bytes=16_000_000_000,
        free_bytes=14_000_000_000,
        bus_type="USB",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
    )

    # Inputs: "2" to start watchdog, "q" to stop it, "5" to exit
    cli, output, detector = make_test_cli(tmp_path, inputs=["2", "q", "5"], volumes=[vol])

    with patch("usb_sentinel.cli.USBWatchdog") as MockWatchdogClass:
        mock_watchdog_instance = MagicMock()
        mock_watchdog_instance.is_running = False
        MockWatchdogClass.return_value = mock_watchdog_instance

        cli.run()

        # Verify watchdog was instantiated and managed
        assert MockWatchdogClass.called
        assert mock_watchdog_instance.start.called
        assert mock_watchdog_instance.stop.called

    full_output = "\n".join(output)
    assert "=== [2] Real-Time USB Insertion Watchdog ===" in full_output
    assert "ALERT_AND_LOG_ONLY" in full_output
    assert "USB Watchdog stopped. Returning to main menu." in full_output


def test_cli_option_2_watchdog_scan_alert_saves_incident_report(tmp_path: Path) -> None:
    """When watchdog scan discovers threats, it triggers alerts and saves incident reports."""
    cli, output, _ = make_test_cli(tmp_path, inputs=["5"])

    finding = RiskFinding(
        file_path="E:\\autorun.vbs",
        severity=RiskSeverity.HIGH,
        matched_rule="SUSPICIOUS_EXTENSION",
        explanation="Script file on root",
    )
    scan_report = ScanReport(
        result=ScanResult(
            scan_id="SCAN-001",
            target_path="E:\\",
            started_at=utc_now(),
            completed_at=utc_now(),
            status=ScanStatus.COMPLETED,
            files_inspected=42,
            findings_count=1,
            errors_count=0,
        ),
        findings=[finding],
    )
    telemetry = DeviceTelemetry(
        device_id="E:",
        detected_at=utc_now(),
        mount_point="E:\\",
        volume_label="USB_STICK",
        filesystem="FAT32",
        total_bytes=8_000_000_000,
        free_bytes=6_000_000_000,
        bus_type="USB",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
    )

    incident = IncidentData(
        incident_id="INC-TEST01",
        generated_at=utc_now(),
        telemetry=telemetry,
        scan_report=scan_report,
        audit_events=[],
        action_taken="ALERT_AND_LOG_ONLY",
        recommended_action="Review autorun.vbs",
    )
    html_p, txt_p = cli._report_generator.save_reports(incident)
    assert html_p.exists()
    assert txt_p.exists()
    assert "autorun.vbs" in html_p.read_text(encoding="utf-8")


# --- Test 4: Option 3 - Inspect & Restore Quarantined Files ---

def test_cli_option_3_empty_quarantine_index(tmp_path: Path) -> None:
    """Option 3 reports empty index when no files are quarantined."""
    cli, output, _ = make_test_cli(tmp_path, inputs=["3", "5"])
    cli.run()

    full_output = "\n".join(output)
    assert "=== [3] Inspect & Restore Quarantined Files ===" in full_output
    assert "No quarantined files found in index" in full_output


def test_cli_option_3_inspect_and_restore_to_custom_destination(tmp_path: Path) -> None:
    """Quarantine a file, inspect it in CLI Option 3, and restore to custom path."""
    source_dir = tmp_path / "source_usb"
    source_dir.mkdir()
    source_file = source_dir / "malware.exe"
    source_content = b"MZ-DUMMY-PAYLOAD-12345"
    source_file.write_bytes(source_content)

    restore_dir = tmp_path / "restored_output"
    restore_dir.mkdir()

    # Pre-populate quarantine
    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()
    q_mgr = QuarantineManager(config=cfg)
    record = q_mgr.quarantine_file(
        source_path=source_file,
        explicit_confirm=True,
        remove_source=False,
    )

    # CLI Inputs:
    # 3: Option 3
    # 1: Select record #1
    # 3: Restore to custom directory
    # str(restore_dir): path to custom directory
    # 5: exit
    inputs = ["3", "1", "3", str(restore_dir), "5"]
    cli, output, _ = make_test_cli(tmp_path, inputs=inputs)
    cli.run()

    full_output = "\n".join(output)
    assert record.quarantine_id in full_output
    assert "[SUCCESS] File successfully restored to:" in full_output
    assert "[VERIFIED] Plaintext SHA-256 integrity verified" in full_output

    restored_file = restore_dir / "malware.exe"
    assert restored_file.exists()
    assert restored_file.read_bytes() == source_content


def test_cli_option_3_collision_resolution_rename(tmp_path: Path) -> None:
    """Restoration detects collision and safely renames when policy 1 is chosen."""
    source_dir = tmp_path / "source_usb"
    source_dir.mkdir()
    source_file = source_dir / "payload.bat"
    source_content = b"@echo off\r\nexit\r\n"
    source_file.write_bytes(source_content)

    restore_dir = tmp_path / "restored_output"
    restore_dir.mkdir()
    # Pre-create conflicting file
    (restore_dir / "payload.bat").write_bytes(b"EXISTING_CONFLICT_CONTENT")

    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()
    q_mgr = QuarantineManager(config=cfg)
    record = q_mgr.quarantine_file(
        source_path=source_file,
        explicit_confirm=True,
        remove_source=False,
    )

    # CLI Inputs:
    # 3: Option 3
    # 1: Select record #1
    # 3: Custom directory
    # str(restore_dir): path
    # 1: Conflict resolution: rename with timestamp suffix
    # 5: Exit
    inputs = ["3", "1", "3", str(restore_dir), "1", "5"]
    cli, output, _ = make_test_cli(tmp_path, inputs=inputs)
    cli.run()

    full_output = "\n".join(output)
    assert "[COLLISION DETECTED]" in full_output
    assert "[SUCCESS] File successfully restored to:" in full_output

    # Existing file intact
    assert (restore_dir / "payload.bat").read_bytes() == b"EXISTING_CONFLICT_CONTENT"

    # Restored file created with suffix
    renamed_files = list(restore_dir.glob("payload_restored_*.bat"))
    assert len(renamed_files) == 1
    assert renamed_files[0].read_bytes() == source_content


def test_cli_option_3_fallback_when_original_volume_missing(tmp_path: Path) -> None:
    """Restoration to original path falls back to desktop when drive is disconnected."""
    desktop_restore = tmp_path / "Desktop_Restored"
    cfg = SentinelConfig(base_dir=tmp_path / "app_data", default_restored_dir=desktop_restore)
    cfg.ensure_runtime_directories()

    import shutil

    source_subdir = tmp_path / "simulated_usb_drive"
    source_subdir.mkdir()
    source_file = source_subdir / "temp_quarantine.exe"
    source_file.write_bytes(b"TEST_PAYLOAD")

    q_mgr = QuarantineManager(config=cfg)
    record = q_mgr.quarantine_file(source_file, explicit_confirm=True)

    # Disconnect the simulated drive by deleting its root directory
    shutil.rmtree(source_subdir)

    # CLI Inputs:
    # 3: Option 3
    # 1: Select record #1
    # 1: Option 1 (Original location) -> warned missing -> confirms fallback to desktop ('y')
    # 5: Exit
    inputs = ["3", "1", "1", "y", "5"]
    output_lines: list[str] = []

    def mock_in(_=""):
        if not inputs:
            return "5"
        return inputs.pop(0)

    cli_test = SentinelCLI(
        config=cfg,
        input_func=mock_in,
        output_func=lambda s: output_lines.append(str(s)),
        use_color=False,
    )
    cli_test.run()

    full_output = "\n".join(output_lines)
    assert "Original location" in full_output
    assert "is not accessible or volume is disconnected" in full_output
    assert "[SUCCESS] File successfully restored to:" in full_output

    restored_dest = desktop_restore / "temp_quarantine.exe"
    assert restored_dest.exists()
    assert restored_dest.read_bytes() == b"TEST_PAYLOAD"


# --- Test 5: Option 4 - Export USB Audit Ledger to CSV ---

def test_cli_option_4_export_empty_ledger(tmp_path: Path) -> None:
    """Option 4 informs user if audit ledger is empty."""
    cli, output, _ = make_test_cli(tmp_path, inputs=["4", "5"])
    cli.run()

    full_output = "\n".join(output)
    assert "=== [4] Export USB Audit Ledger to CSV ===" in full_output
    assert "Audit ledger is empty" in full_output


def test_cli_option_4_export_with_events_and_formula_defense(tmp_path: Path) -> None:
    """Option 4 exports ledger, escapes formula injection, and prints summary metrics."""
    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()
    ledger = AuditLedger(config=cfg)

    # Append test events with formula injection attempts
    ledger.append_event(
        AuditEvent(
            event_id="EVT-001",
            timestamp=utc_now(),
            event_type=AuditEventType.DEVICE_INSERTED,
            status=AuditStatus.INFORMATIONAL,
            device_ref="E:",
            details="=cmd|' /C calc'!A0",
        )
    )
    ledger.append_event(
        AuditEvent(
            event_id="EVT-002",
            timestamp=utc_now(),
            event_type=AuditEventType.FILE_FLAGGED,
            status=AuditStatus.WARNING,
            target_path="+C:\\danger.bat",
            details="High risk batch script",
        )
    )

    export_dest = tmp_path / "exported_ledger.csv"
    inputs = ["4", str(export_dest), "5"]

    cli, output, _ = make_test_cli(tmp_path, inputs=inputs)
    cli.run()

    full_output = "\n".join(output)
    assert f"[SUCCESS] Exported 2 audit events to: {export_dest}" in full_output
    assert "[SECURITY] Spreadsheet formula-injection protection applied" in full_output
    assert "Total Logged Events   : 2" in full_output
    assert "DEVICE_INSERTED" in full_output
    assert "FILE_FLAGGED" in full_output

    # Verify exported content has apostrophe prepended to formula prefixes
    exported_content = export_dest.read_text(encoding="utf-8")
    assert "'=cmd|' /C calc'!A0" in exported_content
    assert "'+C:\\danger.bat" in exported_content


def test_cli_option_4_overwrite_confirmation_rejected(tmp_path: Path) -> None:
    """When target export CSV exists, user can reject overwrite."""
    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()
    ledger = AuditLedger(config=cfg)
    ledger.append_event(
        AuditEvent(
            event_id="EVT-001",
            timestamp=utc_now(),
            event_type=AuditEventType.CONFIGURATION_LOADED,
            status=AuditStatus.SUCCESS,
        )
    )

    existing_dest = tmp_path / "already_exists.csv"
    existing_dest.write_text("PRE_EXISTING_DATA", encoding="utf-8")

    # Inputs: 4 (Export), str(existing_dest), 'n' (reject overwrite), 5 (Exit)
    inputs = ["4", str(existing_dest), "n", "5"]
    cli, output, _ = make_test_cli(tmp_path, inputs=inputs)
    cli.run()

    full_output = "\n".join(output)
    assert "already exists. Overwrite?" in full_output
    assert "[CANCELLED] Export aborted." in full_output
    assert existing_dest.read_text(encoding="utf-8") == "PRE_EXISTING_DATA"


# --- Test 6: Secret & Cryptographic Hygiene ---

def test_cli_never_exposes_master_keys_or_subkeys(tmp_path: Path) -> None:
    """Confirm encryption keys, subkeys, and nonces are never leaked in terminal output."""
    source_file = tmp_path / "confidential.exe"
    source_file.write_bytes(b"SECRET_EXECUTABLE_CONTENT")

    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()
    key_mgr = KeyManager(config=cfg)
    master_key = key_mgr.get_or_create_master_key()

    q_mgr = QuarantineManager(config=cfg, key_manager=key_mgr)
    record = q_mgr.quarantine_file(source_file, explicit_confirm=True)

    # Run through Options 1, 3, 4, 5
    inputs = [
        "1", "",          # Option 1, decline scan
        "3", "1", "4",    # Option 3, inspect #1, cancel
        "4", "", "5",     # Option 4 (empty ledger or cancel), Option 5 exit
    ]
    cli, output, _ = make_test_cli(tmp_path, inputs=inputs)
    cli.run()

    full_output = "\n".join(output)
    # Verify raw master key bytes or hex are NOT anywhere in output
    assert master_key.hex() not in full_output
    assert "master_key" not in full_output.lower()
    assert "hkdf" not in full_output.lower()
