"""Unit tests for usb_sentinel.reporting (HTML escaping, monospace text, and atomic persistence)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from usb_sentinel.config import SentinelConfig
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    FileMetadata,
    RiskFinding,
    RiskSeverity,
    ScanResult,
    ScanStatus,
    utc_now,
)
from usb_sentinel.reporting import DISCLAIMER_TEXT, IncidentData, IncidentReportGenerator
from usb_sentinel.scanner import ScanReport


@pytest.fixture
def sample_incident_data(tmp_path: Path) -> IncidentData:
    """Fixture providing rich incident data with telemetry, findings, and audit events."""
    telemetry = DeviceTelemetry(
        device_id="E:",
        detected_at=utc_now(),
        mount_point="E:\\",
        volume_label="TEST_SECURE_USB",
        filesystem="FAT32",
        total_bytes=32_000_000_000,
        free_bytes=16_000_000_000,
        volume_serial="1234-ABCD",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
        detection_backend="WMI",
        device_model="SanDisk Ultra USB 3.0",
        bus_type="USB",
    )

    finding1 = RiskFinding(
        file_path="E:\\autorun.bat",
        matched_rule="RULE_SUSPICIOUS_EXTENSION_BAT",
        severity=RiskSeverity.SUSPICIOUS,
        explanation="Windows Command Prompt batch script detected on removable media.",
        timestamp=utc_now(),
    )

    finding2 = RiskFinding(
        file_path="E:\\payload<xss>.exe",
        matched_rule="RULE_SUSPICIOUS_EXTENSION_EXE",
        severity=RiskSeverity.HIGH,
        explanation="Binary executable with HTML tags in filename.",
        timestamp=utc_now(),
    )

    scan_result = ScanResult(
        scan_id="SCAN_TEST_1001",
        target_path="E:\\",
        started_at=utc_now(),
        completed_at=utc_now(),
        files_inspected=42,
        findings_count=2,
        errors_count=0,
        status=ScanStatus.COMPLETED,
    )

    scan_report = ScanReport(
        result=scan_result,
        scanned_files=[],
        findings=[finding1, finding2],
        skipped_paths=[],
    )

    audit_event = AuditEvent(
        event_id="EVT_FLAG_TEST01",
        timestamp=utc_now(),
        event_type=AuditEventType.FILE_FLAGGED,
        status=AuditStatus.WARNING,
        device_ref="E:",
        target_path="E:\\autorun.bat",
        details="Flagged SUSPICIOUS risk: Batch script on removable volume.",
    )

    generator = IncidentReportGenerator(config=SentinelConfig(base_dir=tmp_path))
    return generator.generate_incident_data(
        scan_report=scan_report,
        telemetry=telemetry,
        audit_events=[audit_event],
        incident_id="INC-20261016-TEST01",
    )


def test_text_report_contains_expected_sections_and_disclaimer(
    sample_incident_data: IncidentData, tmp_path: Path
) -> None:
    """Verify monospace text report renders all required sections, telemetry, and disclaimer."""
    generator = IncidentReportGenerator(config=SentinelConfig(base_dir=tmp_path))
    report_text = generator.render_text_report(sample_incident_data)

    assert "USB SENTINEL INCIDENT & VOLUME INSPECTION REPORT" in report_text
    assert "Incident ID : INC-20261016-TEST01" in report_text
    assert "[1] TARGET DEVICE TELEMETRY" in report_text
    assert "SanDisk Ultra USB 3.0" in report_text
    assert "[2] VOLUME SCAN EXECUTION SUMMARY" in report_text
    assert "Files Inspected     : 42" in report_text
    assert "[3] HEURISTIC RISK FINDINGS" in report_text
    assert "E:\\autorun.bat" in report_text
    assert "RULE_SUSPICIOUS_EXTENSION_BAT" in report_text
    assert "[4] ACTIONS TAKEN & RECOMMENDATIONS" in report_text
    assert "ALERT_AND_LOG_ONLY" in report_text
    assert "[5] RELEVANT AUDIT TRAIL ENTRIES" in report_text
    assert "EVT_FLAG_TEST01" in report_text
    assert DISCLAIMER_TEXT in report_text


def test_html_report_strictly_escapes_untrusted_input(
    sample_incident_data: IncidentData, tmp_path: Path
) -> None:
    """CRITICAL SECURITY TEST: Verify HTML report escapes dangerous HTML characters in file paths."""
    generator = IncidentReportGenerator(config=SentinelConfig(base_dir=tmp_path))
    html_report = generator.render_html_report(sample_incident_data)

    # Must be valid HTML5
    assert "<!DOCTYPE html>" in html_report
    assert "<title>USB Sentinel Incident Report - INC-20261016-TEST01</title>" in html_report

    # Path containing '<xss>' MUST be escaped to '&lt;xss&gt;' and NEVER appear raw!
    assert "payload&lt;xss&gt;.exe" in html_report
    assert "payload<xss>.exe" not in html_report

    # Telemetry and findings badges
    assert "TEST_SECURE_USB" in html_report
    assert "badge-high" in html_report
    assert "badge-warn" in html_report
    assert "ALERT_AND_LOG_ONLY" in html_report


def test_reporting_handles_missing_telemetry_gracefully(tmp_path: Path) -> None:
    """Verify report generation handles absent telemetry or scan report without crashing."""
    generator = IncidentReportGenerator(config=SentinelConfig(base_dir=tmp_path))
    empty_data = generator.generate_incident_data(
        scan_report=None,
        telemetry=None,
        audit_events=[],
        incident_id="INC-EMPTY-01",
    )

    text_rep = generator.render_text_report(empty_data)
    assert "Device telemetry was not provided or unavailable" in text_rep
    assert "No scan execution report attached" in text_rep
    assert "No heuristic threat vectors" in text_rep

    html_rep = generator.render_html_report(empty_data)
    assert "N/A" in html_rep
    assert "No suspicious files or execution vectors flagged" in html_rep


def test_reporting_handles_aborted_disconnect_scans(tmp_path: Path) -> None:
    """Verify reports accurately convey scan cancellation upon device disconnection."""
    scan_result = ScanResult(
        scan_id="SCAN_ABORT_01",
        target_path="M:\\",
        started_at=utc_now(),
        completed_at=utc_now(),
        files_inspected=12,
        findings_count=1,
        errors_count=1,
        status=ScanStatus.ABORTED_DISCONNECT,
        error_summary="Scan was cancelled by user or caller request.",
    )
    scan_report = ScanReport(
        result=scan_result,
        scanned_files=[],
        findings=[],
        skipped_paths=[],
    )

    generator = IncidentReportGenerator(config=SentinelConfig(base_dir=tmp_path))
    data = generator.generate_incident_data(
        scan_report=scan_report,
        action_taken="SCAN_ABORTED: Volume M: disconnected while inspection was in progress.",
    )

    text_rep = generator.render_text_report(data)
    assert "ABORTED_DISCONNECT" in text_rep
    assert "Scan was cancelled by user or caller request." in text_rep

    html_rep = generator.render_html_report(data)
    assert "ABORTED_DISCONNECT" in html_rep


def test_save_reports_atomic_persistence(sample_incident_data: IncidentData, tmp_path: Path) -> None:
    """Verify save_reports atomically writes both .html and .txt files to config.reports_dir."""
    config = SentinelConfig(base_dir=tmp_path)
    generator = IncidentReportGenerator(config=config)

    html_path, txt_path = generator.save_reports(sample_incident_data)

    assert html_path.exists()
    assert txt_path.exists()
    assert html_path.parent == config.reports_dir
    assert txt_path.parent == config.reports_dir

    assert html_path.suffix == ".html"
    assert txt_path.suffix == ".txt"

    html_content = html_path.read_text(encoding="utf-8")
    txt_content = txt_path.read_text(encoding="utf-8")

    assert "INC-20261016-TEST01" in html_content
    assert "INC-20261016-TEST01" in txt_content
