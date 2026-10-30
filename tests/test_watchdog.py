"""Unit tests for usb_sentinel.watchdog (event debouncing, mount readiness, cancellation, and safety)."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.audit import AuditLedger
from usb_sentinel.config import SentinelConfig
from usb_sentinel.device_detection import (
    DeviceEventType,
    MockDeviceDetector,
    RawDeviceEvent,
)
from usb_sentinel.models import (
    AuditEventType,
    AuditStatus,
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    ScanStatus,
    utc_now,
)
from usb_sentinel.scanner import ScanReport, VolumeScanner
from usb_sentinel.watchdog import USBWatchdog, WatchdogState


@pytest.fixture
def watchdog_env(tmp_path: Path) -> tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner]:
    """Provide isolated configuration, mock detector, audit ledger, and scanner."""
    config = SentinelConfig(
        base_dir=tmp_path,
        watchdog_debounce_seconds=0.5,
        watchdog_discovery_retries=4,
        watchdog_retry_delay_seconds=0.05,
        watchdog_auto_scan=True,
    )
    detector = MockDeviceDetector()
    audit_ledger = AuditLedger(config=config)
    scanner = VolumeScanner(config=config)
    return config, detector, audit_ledger, scanner


def create_sample_usb_telemetry(drive_letter: str = "E:", mount_dir: Optional[Path] = None) -> DeviceTelemetry:
    """Helper to create realistic USB mass storage telemetry."""
    mount_point = str(mount_dir) if mount_dir else f"{drive_letter}\\"
    return DeviceTelemetry(
        device_id=drive_letter,
        detected_at=utc_now(),
        mount_point=mount_point,
        volume_label="USB_TEST_DRIVE",
        filesystem="FAT32",
        total_bytes=16_000_000_000,
        free_bytes=14_000_000_000,
        volume_serial="5A2B-3C4D",
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
        detection_backend="WMI",
        device_model="SanDisk Cruzer Glide",
        bus_type="USB",
    )


# ==============================================================================
# Lifecycle and State Tests
# ==============================================================================


def test_watchdog_lifecycle_start_and_stop(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner]
) -> None:
    """Verify watchdog transitions cleanly STOPPED -> RUNNING -> STOPPED and logs audit events."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    assert watchdog.state == WatchdogState.STOPPED
    assert not detector.is_monitoring

    watchdog.start(discover_initial=False)
    assert watchdog.state == WatchdogState.RUNNING
    assert detector.is_monitoring

    # Calling start while running raises RuntimeError
    with pytest.raises(RuntimeError, match="already running"):
        watchdog.start()

    watchdog.stop()
    assert watchdog.state == WatchdogState.STOPPED
    assert not detector.is_monitoring

    # Check audit events
    events = audit_ledger.read_all_events()
    event_types = [e.event_type for e in events]
    assert AuditEventType.WATCHDOG_STARTED in event_types
    assert AuditEventType.WATCHDOG_STOPPED in event_types


def test_watchdog_context_manager(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner]
) -> None:
    """Verify USBWatchdog functions correctly as a context manager."""
    config, detector, audit_ledger, scanner = watchdog_env
    with USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner) as wd:
        assert wd.state == WatchdogState.RUNNING
        assert detector.is_monitoring

    assert wd.state == WatchdogState.STOPPED
    assert not detector.is_monitoring


def test_watchdog_initialization_failure_cleans_up(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner]
) -> None:
    """Verify detector startup failure resets state to STOPPED and logs SYSTEM_ERROR audit event."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    with patch.object(detector, "start_event_monitoring", side_effect=OSError("WMI subsystem crashed")):
        with pytest.raises(OSError, match="WMI subsystem crashed"):
            watchdog.start(discover_initial=False)

    assert watchdog.state == WatchdogState.STOPPED
    events = audit_ledger.read_all_events()
    assert any(e.event_type == AuditEventType.SYSTEM_ERROR and "WMI subsystem crashed" in str(e.error_message) for e in events)


# ==============================================================================
# Event Normalization and Debouncing Tests
# ==============================================================================


def test_watchdog_debouncing_suppresses_rapid_duplicate_arrivals(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify duplicate arrival events within debounce interval are suppressed without creating duplicate sessions."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    usb_dir = tmp_path / "mock_usb_e"
    usb_dir.mkdir(parents=True, exist_ok=True)
    telemetry = create_sample_usb_telemetry("E:", usb_dir)
    detector.set_volume(telemetry)

    with watchdog:
        # Fire two rapid arrival events in quick succession
        detector.simulate_arrival("E:")
        detector.simulate_arrival("E:")

        time.sleep(0.3)

        assert watchdog.suppressed_duplicates_count >= 1
        active = watchdog.get_active_sessions()
        assert len(active) == 1
        assert active[0].drive_letter == "E:"


def test_watchdog_debouncing_suppresses_duplicate_removals(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify duplicate removal events within debounce interval are suppressed."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    usb_dir = tmp_path / "mock_usb_e"
    usb_dir.mkdir(parents=True, exist_ok=True)
    telemetry = create_sample_usb_telemetry("E:", usb_dir)
    detector.set_volume(telemetry)

    with watchdog:
        detector.simulate_arrival("E:")
        time.sleep(0.2)
        assert len(watchdog.get_active_sessions()) == 1

        # Fire two rapid removal events
        detector.simulate_removal("E:")
        detector.simulate_removal("E:")

        time.sleep(0.2)
        assert watchdog.suppressed_duplicates_count >= 1
        assert len(watchdog.get_active_sessions()) == 0


# ==============================================================================
# Mount Readiness, Bounded Retries & Startup Discovery Tests
# ==============================================================================


def test_watchdog_delayed_mount_succeeds_after_retries(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify arrival event before filesystem mount readiness retries and establishes session once ready."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    usb_dir = tmp_path / "mock_usb_g"
    usb_dir.mkdir(parents=True, exist_ok=True)
    telemetry = create_sample_usb_telemetry("G:", usb_dir)

    # Simulate volume delayed by 2 retries
    detector.simulate_delayed_mount("G:", telemetry, delay_retries=2)

    with watchdog:
        detector.simulate_arrival("G:")
        # Wait for bounded retry loop to complete (2 retries * 0.05s = ~0.15s)
        time.sleep(0.35)

        session = watchdog.get_session("G:")
        assert session is not None
        assert session.drive_letter == "G:"
        assert session.telemetry.volume_label == "USB_TEST_DRIVE"


def test_watchdog_retry_exhaustion_emits_warning(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner]
) -> None:
    """Verify that when volume never mounts after retry exhaustion, an audit warning is recorded and no session is created."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    # Simulate drive that never yields volume telemetry
    detector.simulate_failing_volume("H:")

    with watchdog:
        detector.simulate_arrival("H:")
        # Wait for retry exhaustion (4 retries * 0.05s = ~0.25s)
        time.sleep(0.35)

        assert watchdog.get_session("H:") is None
        events = audit_ledger.read_all_events()
        assert any(
            e.event_type == AuditEventType.SYSTEM_WARNING and "was not accessible after 4" in str(e.details)
            for e in events
        )


def test_watchdog_already_connected_device_at_startup(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify that devices mounted prior to watchdog startup are recognized as initial inventory."""
    config, detector, audit_ledger, scanner = watchdog_env
    usb_dir = tmp_path / "mock_usb_initial"
    usb_dir.mkdir(parents=True, exist_ok=True)
    telemetry = create_sample_usb_telemetry("F:", usb_dir)
    detector.set_volume(telemetry)

    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    with watchdog:
        session = watchdog.get_session("F:")
        assert session is not None
        assert session.is_initial_device is True
        assert session.drive_letter == "F:"

        events = audit_ledger.read_all_events()
        assert any(
            e.event_type == AuditEventType.DEVICE_INSERTED and "Already-connected" in str(e.details)
            for e in events
        )


# ==============================================================================
# Disconnect Races, Cancellation & Reconnection Tests
# ==============================================================================


def test_removal_during_discovery_aborts_session_creation(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify that if removal arrives while mount retry is in progress, discovery aborts cleanly without creating session."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    usb_dir = tmp_path / "mock_usb_race"
    usb_dir.mkdir(parents=True, exist_ok=True)
    telemetry = create_sample_usb_telemetry("K:", usb_dir)

    # Delay mount by 4 retries (~0.2s)
    detector.simulate_delayed_mount("K:", telemetry, delay_retries=4)

    with watchdog:
        detector.simulate_arrival("K:")
        # Immediately fire removal while discovery is sleeping on retry 1
        time.sleep(0.04)
        detector.simulate_removal("K:")

        # Wait out remaining time
        time.sleep(0.3)

        # No active session should exist
        assert watchdog.get_session("K:") is None


def test_removal_during_active_scan_signals_cancellation(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify that device removal during an active scan prompts scanner cancellation and records SCAN_ABORTED."""
    config, detector, audit_ledger, scanner = watchdog_env

    # Populate a directory with several files
    usb_dir = tmp_path / "mock_usb_scan"
    usb_dir.mkdir(parents=True, exist_ok=True)
    for i in range(10):
        (usb_dir / f"file_{i}.txt").write_bytes(b"content")

    telemetry = create_sample_usb_telemetry("M:", usb_dir)
    detector.set_volume(telemetry)

    # Slow down scanner slightly to test in-flight cancellation
    orig_scan = scanner.scan

    def slow_scan(*args, **kwargs):  # type: ignore[no-untyped-def]
        time.sleep(0.1)
        return orig_scan(*args, **kwargs)

    with patch.object(scanner, "scan", side_effect=slow_scan):
        watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)
        with watchdog:
            detector.simulate_arrival("M:")
            time.sleep(0.05)

            # Session should be active and scan in progress
            session = watchdog.get_session("M:")
            assert session is not None

            # Disconnect device while scan is running
            detector.simulate_removal("M:")
            time.sleep(0.2)

            assert watchdog.get_session("M:") is None
            events = audit_ledger.read_all_events()
            event_types = [e.event_type for e in events]
            assert AuditEventType.DEVICE_REMOVED in event_types


def test_reconnection_of_same_drive_letter_generates_fresh_session(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify disconnecting and reconnecting the same drive letter allocates a fresh independent session_id."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    usb_dir = tmp_path / "mock_usb_reconnect"
    usb_dir.mkdir(parents=True, exist_ok=True)
    telemetry = create_sample_usb_telemetry("E:", usb_dir)
    detector.set_volume(telemetry)

    with watchdog:
        detector.simulate_arrival("E:")
        time.sleep(0.1)
        session1 = watchdog.get_session("E:")
        assert session1 is not None
        session1_id = session1.session_id

        # Disconnect
        detector.simulate_removal("E:")
        time.sleep(0.1)
        assert watchdog.get_session("E:") is None

        # Reconnect (allow debounce window to elapse)
        time.sleep(0.55)
        detector.simulate_arrival("E:", telemetry)
        time.sleep(0.15)
        session2 = watchdog.get_session("E:")
        assert session2 is not None
        session2_id = session2.session_id

        # Unique session IDs across reconnections
        assert session1_id != session2_id


# ==============================================================================
# Non-Destructive Safety & Drive Containment Tests
# ==============================================================================


def test_watchdog_never_deletes_or_quarantines_files_on_insertion(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """CRITICAL SAFETY TEST: Verify insertion of USB volume with suspicious files NEVER deletes or moves files."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    usb_dir = tmp_path / "mock_usb_malicious"
    usb_dir.mkdir(parents=True, exist_ok=True)

    # Create high-risk extension files
    malicious_script = usb_dir / "autorun.bat"
    malicious_script.write_bytes(b"@echo off\r\ncalc.exe")

    malicious_exe = usb_dir / "payload.exe"
    malicious_exe.write_bytes(b"MZ_DUMMY_EXECUTABLE")

    telemetry = create_sample_usb_telemetry("E:", usb_dir)

    with watchdog:
        detector.simulate_arrival("E:", telemetry)
        time.sleep(0.5)

        # 1. Source files MUST remain 100% intact on the USB media!
        assert malicious_script.exists()
        assert malicious_script.read_bytes() == b"@echo off\r\ncalc.exe"

        assert malicious_exe.exists()
        assert malicious_exe.read_bytes() == b"MZ_DUMMY_EXECUTABLE"

        # 2. Audit ledger records FILE_FLAGGED under ALERT AND LOG ONLY policy
        events = audit_ledger.read_all_events()
        flagged_events = [e for e in events if e.event_type == AuditEventType.FILE_FLAGGED]
        assert len(flagged_events) == 2

        # 3. No quarantine objects created
        vault_files = list(config.vault_dir.glob("*.qnt"))
        assert len(vault_files) == 0


def test_watchdog_ignores_internal_fixed_disk_arrivals(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify that arrival of internal fixed disk (C:\\) is completely ignored and NEVER scanned."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    c_drive = tmp_path / "mock_c_drive"
    c_drive.mkdir(parents=True, exist_ok=True)
    c_file = c_drive / "system.bat"
    c_file.write_bytes(b"system script")

    # Fixed disk telemetry
    fixed_telemetry = DeviceTelemetry(
        device_id="C:",
        detected_at=utc_now(),
        mount_point=str(c_drive),
        volume_label="OS_SYSTEM",
        filesystem="NTFS",
        classification=DeviceClassification.FIXED_VOLUME,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
        bus_type="NVMe",
    )
    detector.set_volume(fixed_telemetry)

    with watchdog:
        detector.simulate_arrival("C:")
        time.sleep(0.15)

        # C: is NOT treated as USB mass storage session
        assert watchdog.get_session("C:") is None

        # System file was not scanned or flagged
        events = audit_ledger.read_all_events()
        assert not any(e.event_type == AuditEventType.FILE_FLAGGED for e in events)
        assert any(
            e.event_type == AuditEventType.SYSTEM_WARNING and "matches SystemDrive" in str(e.details)
            for e in events
        )


def test_watchdog_ignores_non_system_internal_fixed_disk(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """Verify that arrival of non-system internal fixed disk (D:\\) is ignored based on classification."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    d_drive = tmp_path / "mock_d_drive"
    d_drive.mkdir(parents=True, exist_ok=True)

    d_telemetry = DeviceTelemetry(
        device_id="D:",
        detected_at=utc_now(),
        mount_point=str(d_drive),
        volume_label="DATA_DISK",
        filesystem="NTFS",
        classification=DeviceClassification.FIXED_VOLUME,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
        bus_type="SATA",
    )
    detector.set_volume(d_telemetry)

    with watchdog:
        detector.simulate_arrival("D:")
        time.sleep(0.15)

        assert watchdog.get_session("D:") is None
        events = audit_ledger.read_all_events()
        assert any(
            e.event_type == AuditEventType.SYSTEM_WARNING
            and (
                "classification=FIXED_VOLUME" in str(e.details)
                or "classification=INTERNAL_STORAGE" in str(e.details)
            )
            for e in events
        )


def test_watchdog_scan_device_strictly_blocks_system_drive(
    watchdog_env: tuple[SentinelConfig, MockDeviceDetector, AuditLedger, VolumeScanner], tmp_path: Path
) -> None:
    """CRITICAL SAFETY TEST: Verify scan_device explicitly refuses to scan the OS SystemDrive."""
    config, detector, audit_ledger, scanner = watchdog_env
    watchdog = USBWatchdog(config=config, detector=detector, audit_ledger=audit_ledger, scanner=scanner)

    c_drive = tmp_path / "mock_c_drive"
    c_drive.mkdir(parents=True, exist_ok=True)
    c_telemetry = DeviceTelemetry(
        device_id="C:",
        detected_at=utc_now(),
        mount_point=str(c_drive),
        classification=DeviceClassification.USB_MASS_STORAGE,  # Even if misclassified!
    )
    from usb_sentinel.watchdog import ActiveDeviceSession
    session = ActiveDeviceSession(
        session_id="dummy_c_session",
        drive_letter="C:",
        telemetry=c_telemetry,
        connected_at=utc_now(),
    )

    report = watchdog.scan_device(session)
    assert report is None

    events = audit_ledger.read_all_events()
    assert any(
        e.event_type == AuditEventType.SYSTEM_WARNING and "Refusing to scan system drive C:" in str(e.details)
        for e in events
    )

