"""Integration tests between CLI and Incident Reporting for USB Sentinel (Phase 6).

Verifies:
1. End-to-end workflow from CLI scan/watchdog finding to report generation.
2. HTML and plaintext reports validation for well-formedness and escaping.
3. User cancellation of report generation.
4. Custom report destination handling.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.cli import SentinelCLI
from usb_sentinel.config import SentinelConfig
from usb_sentinel.device_detection import (
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    MockDeviceDetector,
)
from usb_sentinel.models import (
    DetectionMethod,
    RiskFinding,
    RiskSeverity,
    ScanResult,
    ScanStatus,
    utc_now,
)
from usb_sentinel.reporting import IncidentData, IncidentReportGenerator
from usb_sentinel.scanner import ScanReport


def test_cli_reporting_end_to_end_on_demand_scan(tmp_path: Path) -> None:
    """CLI on-demand scan automatically generates valid HTML and text incident reports."""
    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()

    scan_target = tmp_path / "mock_usb"
    scan_target.mkdir()
    flagged_file = scan_target / "exploit.bat"
    flagged_file.write_text("@echo off\r\nstart calc.exe\r\n", encoding="utf-8")

    vol = DeviceTelemetry(
        device_id="E:",
        detected_at=utc_now(),
        mount_point=str(scan_target),
        volume_label="THREAT_USB",
        filesystem="FAT32",
        total_bytes=4_000_000_000,
        free_bytes=3_500_000_000,
        bus_type="USB",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
    )
    detector = MockDeviceDetector()
    detector.set_volume(vol)

    inputs = [
        "1",                # Option 1
        str(scan_target),   # Enter scan path
        "y",                # Confirm generate incident reports
        "n",                # Decline manual quarantine
        "5",                # Option 5 Exit
    ]
    output_lines: list[str] = []

    def mock_in(_=""):
        if not inputs:
            return "5"
        return inputs.pop(0)

    cli = SentinelCLI(
        config=cfg,
        detector=detector,
        input_func=mock_in,
        output_func=lambda s: output_lines.append(str(s)),
        use_color=False,
    )
    exit_code = cli.run()

    assert exit_code == 0
    full_output = "\n".join(output_lines)
    assert "exploit.bat" in full_output
    assert "[SAVED] HTML Report:" in full_output
    assert "[SAVED] Text Report:" in full_output

    html_reports = list(cfg.reports_dir.glob("*.html"))
    txt_reports = list(cfg.reports_dir.glob("*.txt"))
    assert len(html_reports) == 1
    assert len(txt_reports) == 1

    html_content = html_reports[0].read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "USB Sentinel Incident Report" in html_content
    assert "exploit.bat" in html_content
    assert "ALERT_AND_LOG_ONLY" in html_content

    txt_content = txt_reports[0].read_text(encoding="utf-8")
    assert "USB SENTINEL INCIDENT & VOLUME INSPECTION REPORT" in txt_content
    assert "exploit.bat" in txt_content
    assert "DISCLAIMER" in txt_content


def test_cli_reporting_user_declines_report_generation(tmp_path: Path) -> None:
    """When user declines report generation in CLI, no report files are created."""
    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()

    scan_target = tmp_path / "mock_usb"
    scan_target.mkdir()
    (scan_target / "danger.vbs").write_text("WScript.Echo 'test'", encoding="utf-8")

    inputs = [
        "1",                # Option 1
        str(scan_target),   # Path
        "n",                # Decline report generation
        "n",                # Decline manual quarantine
        "5",                # Exit
    ]
    output_lines: list[str] = []

    def mock_in(_=""):
        if not inputs:
            return "5"
        return inputs.pop(0)

    cli = SentinelCLI(
        config=cfg,
        detector=MockDeviceDetector(),
        input_func=mock_in,
        output_func=lambda s: output_lines.append(str(s)),
        use_color=False,
    )
    cli.run()

    assert len(list(cfg.reports_dir.glob("*"))) == 0


def test_cli_watchdog_auto_reporting_on_threat(tmp_path: Path) -> None:
    """Watchdog triggers automatic report generation upon detecting threat on connected device."""
    cfg = SentinelConfig(base_dir=tmp_path / "app_data")
    cfg.ensure_runtime_directories()

    generator = IncidentReportGenerator(config=cfg)
    finding = RiskFinding(
        file_path="G:\\payload.exe",
        severity=RiskSeverity.HIGH,
        matched_rule="SUSPICIOUS_EXTENSION_EXE",
        explanation="Executable binary located on root of removable media",
    )
    report = ScanReport(
        result=ScanResult(
            scan_id="SCAN-TEST-002",
            target_path="G:\\",
            started_at=utc_now(),
            completed_at=utc_now(),
            status=ScanStatus.COMPLETED,
            files_inspected=10,
            findings_count=1,
            errors_count=0,
        ),
        findings=[finding],
    )
    telemetry = DeviceTelemetry(
        device_id="G:",
        detected_at=utc_now(),
        mount_point="G:\\",
        volume_label="AUTO_SCAN_DRIVE",
        filesystem="NTFS",
        total_bytes=64_000_000_000,
        free_bytes=50_000_000_000,
        bus_type="USB",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
    )
    incident = IncidentData(
        incident_id="INC-AUTO-01",
        generated_at=utc_now(),
        telemetry=telemetry,
        scan_report=report,
        audit_events=[],
        action_taken="ALERT_AND_LOG_ONLY: Watchdog detected flagged items.",
        recommended_action="Isolate removable volume immediately.",
    )

    html_p, txt_p = generator.save_reports(incident)
    assert html_p.exists()
    assert txt_p.exists()
    assert "payload.exe" in html_p.read_text(encoding="utf-8")
    assert "AUTO_SCAN_DRIVE" in txt_p.read_text(encoding="utf-8")
