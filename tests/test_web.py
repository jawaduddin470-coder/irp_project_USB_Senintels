"""Comprehensive tests for USB Sentinel Web Dashboard.

Validates:
1. Application initialization, routing, and localhost binding enforcement.
2. Template rendering, navigation, and empty states.
3. CSRF protection verification on state-modifying POST requests.
4. Watchdog controls: start, stop, duplicate starts, status reflection.
5. On-demand scanning: directory traversal validation, results rendering, and incident report generation.
6. Quarantine workflow: explicit confirmation requirement, cryptographic vault storage, source removal.
7. Restoration workflow: collision handling (REJECT/OVERWRITE), destination choices, integrity check.
8. Audit ledger viewing and CSV export with spreadsheet formula sanitization.
9. Incident report viewing, downloading, and strict path traversal defense.
10. HTML escaping of malicious filenames (XSS mitigation).
"""

from __future__ import annotations

import io
import re
from pathlib import Path
from typing import Generator

import pytest
from flask import Flask
from flask.testing import FlaskClient

from usb_sentinel.config import SentinelConfig
from usb_sentinel.device_detection import BaseDeviceDetector
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    utc_now,
)
from usb_sentinel.web_app import create_app, run_web


class MockDeviceDetector(BaseDeviceDetector):
    """Predictable mock device detector for web interface testing."""

    def __init__(self, config: SentinelConfig, volumes: list[DeviceTelemetry] | None = None) -> None:
        self._config = config
        self._volumes = volumes or []

    def get_mounted_volumes(self) -> list[DeviceTelemetry]:
        return list(self._volumes)

    def set_volumes(self, volumes: list[DeviceTelemetry]) -> None:
        self._volumes = list(volumes)

    def get_volume_telemetry(self, drive_or_path: str):
        for v in self._volumes:
            if v.device_id.upper() == drive_or_path.upper() or (v.mount_point and v.mount_point.upper() == drive_or_path.upper()):
                return v
        return None

    def start_event_monitoring(self, callback) -> None:
        pass

    def stop_event_monitoring(self) -> None:
        pass

    @property
    def is_monitoring(self) -> bool:
        return False


@pytest.fixture
def mock_detector(isolated_config: SentinelConfig) -> MockDeviceDetector:
    """Provide a mock detector with one simulated USB mass storage volume."""
    usb_vol = DeviceTelemetry(
        device_id="E:",
        detected_at=utc_now(),
        volume_label="SECURE_USB",
        filesystem="FAT32",
        total_bytes=16 * 1024 * 1024 * 1024,
        free_bytes=12 * 1024 * 1024 * 1024,
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
        mount_point="E:",
        bus_type="USB",
    )
    return MockDeviceDetector(isolated_config, volumes=[usb_vol])


@pytest.fixture
def web_app(isolated_config: SentinelConfig, mock_detector: MockDeviceDetector) -> Flask:
    """Create a configured Flask test application."""
    app = create_app(
        config=isolated_config,
        detector=mock_detector,
        test_config={"TESTING": True, "SECRET_KEY": "test-secret-key"},
    )
    return app


@pytest.fixture
def client(web_app: Flask) -> FlaskClient:
    """Provide a Flask test client with session cookies enabled."""
    return web_app.test_client()


def get_csrf_token(client: FlaskClient) -> str:
    """Helper to extract CSRF token by querying any GET page."""
    res = client.get("/dashboard")
    match = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', res.text)
    if match:
        return match.group(1)
    # Alternatively get from session
    with client.session_transaction() as sess:
        return sess.get("csrf_token", "")


# ==============================================================================
# Test Cases
# ==============================================================================


def test_index_redirects_to_dashboard(client: FlaskClient) -> None:
    """Root URL (/) must issue a 302 redirect to /dashboard."""
    res = client.get("/")
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/dashboard")


def test_dashboard_view_renders_correctly(client: FlaskClient) -> None:
    """Dashboard must render overview telemetry, detected USB devices, and policy banner."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "Security Dashboard & Telemetry Overview" in res.text
    assert "ALERT_AND_LOG_ONLY" in res.text
    assert "SECURE_USB" in res.text
    assert "E:" in res.text
    assert "STOPPED" in res.text


def test_devices_view_renders_correctly(client: FlaskClient) -> None:
    """Devices view must display connected volumes and on-demand scanner form."""
    res = client.get("/devices")
    assert res.status_code == 200
    assert "USB Devices & Threat Scanner" in res.text
    assert "Heuristic Analysis Disclaimer" in res.text
    assert "SECURE_USB" in res.text
    assert "On-Demand Path Scanner" in res.text


def test_watchdog_view_and_lifecycle(client: FlaskClient) -> None:
    """Watchdog controls should allow starting and stopping the watchdog engine cleanly."""
    res = client.get("/watchdog")
    assert res.status_code == 200
    assert "STOPPED" in res.text

    csrf = get_csrf_token(client)

    # Start Watchdog
    res_start = client.post("/watchdog/start", data={"csrf_token": csrf}, follow_redirects=True)
    assert res_start.status_code == 200
    assert "Watchdog engine started successfully" in res_start.text
    assert "RUNNING" in res_start.text

    # Duplicate Start should inform cleanly
    res_dup = client.post("/watchdog/start", data={"csrf_token": csrf}, follow_redirects=True)
    assert res_dup.status_code == 200
    assert "Watchdog engine is already running" in res_dup.text

    # Stop Watchdog
    res_stop = client.post("/watchdog/stop", data={"csrf_token": csrf}, follow_redirects=True)
    assert res_stop.status_code == 200
    assert "Watchdog engine stopped cleanly" in res_stop.text
    assert "STOPPED" in res_stop.text


def test_csrf_protection_rejects_unauthorized_post(client: FlaskClient) -> None:
    """POST request lacking valid CSRF token must be rejected with 403 Forbidden."""
    # Attempt start without token
    res_no_token = client.post("/watchdog/start")
    assert res_no_token.status_code == 403

    # Attempt start with invalid token
    res_bad_token = client.post("/watchdog/start", data={"csrf_token": "invalid_forged_token"})
    assert res_bad_token.status_code == 403


def test_on_demand_scan_flow(client: FlaskClient, tmp_path: Path) -> None:
    """On-demand scan must inspect directory, flag heuristic threats, and render findings."""
    scan_dir = tmp_path / "mock_usb"
    scan_dir.mkdir()

    # Create benign and suspicious files
    (scan_dir / "document.txt").write_text("Legitimate text content", encoding="utf-8")
    (scan_dir / "payload.exe").write_text("MZ fake executable header", encoding="utf-8")
    (scan_dir / "trojan.bat").write_text("@echo off\necho attack", encoding="utf-8")

    csrf = get_csrf_token(client)
    res_scan = client.post(
        "/devices/scan",
        data={"csrf_token": csrf, "target_path": str(scan_dir), "sync": "1"},
        follow_redirects=True,
    )
    assert res_scan.status_code == 200
    assert "Scan completed for" in res_scan.text
    assert "Threat Scan Results" in res_scan.text
    assert "payload.exe" in res_scan.text
    assert "trojan.bat" in res_scan.text
    assert "document.txt" not in res_scan.text  # Benign file not in flagged list


def test_on_demand_scan_invalid_paths(client: FlaskClient) -> None:
    """On-demand scan must validate path existence and directory type."""
    csrf = get_csrf_token(client)

    # Empty path
    res_empty = client.post("/devices/scan", data={"csrf_token": csrf, "target_path": ""}, follow_redirects=True)
    assert "Target path cannot be empty" in res_empty.text

    # Non-existent path
    res_missing = client.post(
        "/devices/scan",
        data={"csrf_token": csrf, "target_path": "/path/does/not/exist/12345"},
        follow_redirects=True,
    )
    assert "Specified target path does not exist" in res_missing.text


def test_manual_quarantine_and_inspection(client: FlaskClient, tmp_path: Path) -> None:
    """Manual quarantine encrypts file into vault and updates index."""
    test_file = tmp_path / "malicious.bat"
    test_file.write_text("@echo off\nexit", encoding="utf-8")

    csrf = get_csrf_token(client)

    # Quarantine without confirmation checkbox should fail
    res_unconfirmed = client.post(
        "/quarantine/add",
        data={"csrf_token": csrf, "target_path": str(test_file), "confirmed": "no"},
        follow_redirects=True,
    )
    assert "Quarantine aborted: Explicit user confirmation is required" in res_unconfirmed.text
    assert test_file.exists()  # Source preserved!

    # Quarantine with confirmation
    res_confirmed = client.post(
        "/quarantine/add",
        data={"csrf_token": csrf, "target_path": str(test_file), "confirmed": "yes", "remove_source": "yes"},
        follow_redirects=True,
    )
    assert "Successfully encrypted and quarantined" in res_confirmed.text
    assert not test_file.exists()  # Source safely deleted after vault commit

    # View records in /quarantine
    res_q_page = client.get("/quarantine")
    assert res_q_page.status_code == 200
    assert "malicious.bat" in res_q_page.text

    # Extract quarantine ID and test record inspection
    match = re.search(r'href="/quarantine\?inspect=([a-f0-9\-]+)"', res_q_page.text)
    assert match is not None
    qid = match.group(1)

    res_inspect = client.get(f"/quarantine?inspect={qid}")
    assert res_inspect.status_code == 200
    assert "Quarantine Record Details" in res_inspect.text
    assert qid in res_inspect.text
    assert "AES-256-GCM" in res_inspect.text


def test_safe_restoration_workflow(client: FlaskClient, tmp_path: Path) -> None:
    """Restoration safely decrypts file to target directory with integrity verification."""
    # 1. Prepare and quarantine a file
    src_file = tmp_path / "important_script.bat"
    src_content = "REM Essential script content\ncalc.exe"
    src_file.write_text(src_content, encoding="utf-8")

    csrf = get_csrf_token(client)
    client.post(
        "/quarantine/add",
        data={"csrf_token": csrf, "target_path": str(src_file), "confirmed": "yes", "remove_source": "yes"},
        follow_redirects=True,
    )

    res_q = client.get("/quarantine")
    match = re.search(r'href="/quarantine\?inspect=([a-f0-9\-]+)"', res_q.text)
    assert match is not None
    qid = match.group(1)

    # 2. Restore to a custom destination directory
    restore_dir = tmp_path / "restored_output"
    restore_dir.mkdir()

    # Attempt without confirmation checkbox -> rejected
    res_unconf = client.post(
        "/quarantine/restore",
        data={
            "csrf_token": csrf,
            "quarantine_id": qid,
            "dest_mode": "CUSTOM",
            "custom_path": str(restore_dir),
            "collision_policy": "REJECT",
            "confirmed": "no",
        },
        follow_redirects=True,
    )
    assert "Restoration aborted: Explicit user confirmation checkbox is required" in res_unconf.text

    # Confirmed restore
    res_restore = client.post(
        "/quarantine/restore",
        data={
            "csrf_token": csrf,
            "quarantine_id": qid,
            "dest_mode": "CUSTOM",
            "custom_path": str(restore_dir),
            "collision_policy": "REJECT",
            "confirmed": "yes",
        },
        follow_redirects=True,
    )
    assert "File successfully restored" in res_restore.text

    restored_target = restore_dir / "important_script.bat"
    assert restored_target.exists()
    assert restored_target.read_text(encoding="utf-8") == src_content

    # 3. Test collision policy REJECT
    res_collide = client.post(
        "/quarantine/restore",
        data={
            "csrf_token": csrf,
            "quarantine_id": qid,
            "dest_mode": "CUSTOM",
            "custom_path": str(restore_dir),
            "collision_policy": "REJECT",
            "confirmed": "yes",
        },
        follow_redirects=True,
    )
    assert "Restoration collision" in res_collide.text

    # 4. Test collision policy OVERWRITE
    res_overwrite = client.post(
        "/quarantine/restore",
        data={
            "csrf_token": csrf,
            "quarantine_id": qid,
            "dest_mode": "CUSTOM",
            "custom_path": str(restore_dir),
            "collision_policy": "OVERWRITE",
            "confirmed": "yes",
        },
        follow_redirects=True,
    )
    assert "File successfully restored" in res_overwrite.text


def test_logs_view_and_csv_export(client: FlaskClient, web_app: Flask) -> None:
    """Audit logs view displays events and export provides formula-sanitized CSV."""
    hub = web_app.hub  # type: ignore[attr-defined]

    # Append test audit events (including a potentially dangerous formula injection value)
    evt1 = AuditEvent(
        event_id="EVT_TEST_101",
        timestamp=utc_now(),
        event_type=AuditEventType.FILE_FLAGGED,
        status=AuditStatus.WARNING,
        target_path="=SUM(1+1).bat",
        details="Suspicious formula-style filename",
    )
    hub.audit_ledger.append_event(evt1)

    res_logs = client.get("/logs")
    assert res_logs.status_code == 200
    assert "Canonical Audit Ledger" in res_logs.text
    assert "EVT_TEST_101" in res_logs.text

    # CSV Export
    res_csv = client.get("/logs/export")
    assert res_csv.status_code == 200
    assert res_csv.headers["Content-Type"].startswith("text/csv")
    csv_text = res_csv.text
    assert "event_id,timestamp,event_type,status" in csv_text
    # Verify formula character '=' is sanitized by prepending "'"
    assert "'=SUM(1+1).bat" in csv_text


def test_logs_view_filtering(client: FlaskClient, web_app: Flask) -> None:
    """Audit logs view supports server-side GET filtering by event_type, status, and search."""
    hub = web_app.hub  # type: ignore[attr-defined]

    evt_scan = AuditEvent(
        event_id="EVT_FILTER_SCAN",
        timestamp=utc_now(),
        event_type=AuditEventType.SCAN_COMPLETED,
        status=AuditStatus.SUCCESS,
        target_path="E:\\benign_data",
        details="Scan finished clean",
    )
    evt_quarantine = AuditEvent(
        event_id="EVT_FILTER_QNT",
        timestamp=utc_now(),
        event_type=AuditEventType.QUARANTINE_COMMITTED,
        status=AuditStatus.WARNING,
        target_path="E:\\malware_sample.exe",
        details="Encrypted to vault",
    )
    hub.audit_ledger.append_event(evt_scan)
    hub.audit_ledger.append_event(evt_quarantine)

    # 1. Filter by event_type
    res_q_filter = client.get("/logs?event_type=QUARANTINE_COMMITTED")
    assert res_q_filter.status_code == 200
    assert "EVT_FILTER_QNT" in res_q_filter.text
    assert "EVT_FILTER_SCAN" not in res_q_filter.text

    # 2. Filter by status
    res_status_filter = client.get("/logs?status=SUCCESS")
    assert res_status_filter.status_code == 200
    assert "EVT_FILTER_SCAN" in res_status_filter.text
    assert "EVT_FILTER_QNT" not in res_status_filter.text

    # 3. Filter by search query
    res_search_filter = client.get("/logs?search=malware_sample")
    assert res_search_filter.status_code == 200
    assert "EVT_FILTER_QNT" in res_search_filter.text
    assert "EVT_FILTER_SCAN" not in res_search_filter.text


def test_incident_report_viewing_and_path_traversal_defense(
    client: FlaskClient, web_app: Flask, tmp_path: Path
) -> None:
    """Incident reports can be viewed and downloaded, with directory traversal strictly forbidden."""
    hub = web_app.hub  # type: ignore[attr-defined]
    rep_dir = hub.config.reports_dir
    rep_dir.mkdir(parents=True, exist_ok=True)

    rep_file = rep_dir / "incident_INC-9999.txt"
    rep_file.write_text("SAMPLE INCIDENT REPORT DATA CONTENT", encoding="utf-8")

    # 1. View Report
    res_view = client.get("/reports/view/incident_INC-9999.txt")
    assert res_view.status_code == 200
    assert "SAMPLE INCIDENT REPORT DATA CONTENT" in res_view.text

    # 2. Download Report
    res_dl = client.get("/reports/download/incident_INC-9999.txt")
    assert res_dl.status_code == 200
    assert b"SAMPLE INCIDENT REPORT DATA CONTENT" in res_dl.data

    # 3. Path Traversal Attacks must be blocked
    res_bad_1 = client.get("/reports/view/../../etc/passwd")
    assert res_bad_1.status_code in (400, 404)

    res_bad_2 = client.get("/reports/view/non_incident_file.txt")
    assert res_bad_2.status_code in (400, 404)


def test_html_xss_escaping_in_filenames(client: FlaskClient, tmp_path: Path) -> None:
    """Filenames with script injection tags must be properly HTML-escaped by Jinja2."""
    scan_dir = tmp_path / "xss_dir"
    scan_dir.mkdir()

    # Filename containing HTML / Script tags without slashes
    xss_file = scan_dir / "<img src=x onerror=alert(1)>.bat"
    xss_file.write_text("@echo off", encoding="utf-8")

    csrf = get_csrf_token(client)
    res = client.post(
        "/devices/scan",
        data={"csrf_token": csrf, "target_path": str(scan_dir), "sync": "1"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    # Must NOT have raw <img in page body
    assert "<img src=x onerror=alert(1)>" not in res.text
    # Must be escaped
    assert "&lt;img src=x onerror=alert(1)&gt;.bat" in res.text or "&lt;img" in res.text


def test_localhost_binding_enforcement() -> None:
    """run_web must reject binding to any address other than 127.0.0.1."""
    with pytest.raises(ValueError, match="strictly bind to 127.0.0.1"):
        run_web(host="0.0.0.0")

    with pytest.raises(ValueError, match="strictly bind to 127.0.0.1"):
        run_web(host="192.168.1.100")
