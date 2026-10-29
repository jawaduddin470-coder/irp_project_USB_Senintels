"""Unit tests for macOS storage device detection and hardware telemetry.

Validates:
1. Parsing diskutil plist output for physical USB mass storage media.
2. Handling paths with spaces (e.g. '/Volumes/NO NAME').
3. Distinguishing USB external media from internal fixed drives (e.g. 'Macintosh HD').
4. Pure standard library fallback via POSIX statvfs when diskutil is unavailable.
5. Exclusion of internal fixed drives from get_mounted_volumes().
6. Background event monitoring lifecycle and simulated arrival/removal dispatch.
7. Platform factory resolution via get_device_detector().
8. UI error visibility when detector encounters operating system failures.
"""

from __future__ import annotations

import plistlib
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask.testing import FlaskClient

from usb_sentinel.config import SentinelConfig
from usb_sentinel.device_detection import (
    BaseDeviceDetector,
    DeviceEventType,
    MacOSDeviceDetector,
    RawDeviceEvent,
    UnsupportedPlatformDetector,
    WindowsDeviceDetector,
    get_device_detector,
    normalize_drive_letter,
    normalize_mount_point,
)
from usb_sentinel.models import (
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    utc_now,
)
from usb_sentinel.web_app import create_app


# Sample realistic diskutil plist payloads
DISKUTIL_USB_PLIST = {
    "Bootable": False,
    "BusProtocol": "USB",
    "DeviceBlockSize": 512,
    "DeviceIdentifier": "disk6",
    "DeviceNode": "/dev/disk6",
    "Ejectable": True,
    "FilesystemName": "MS-DOS FAT32",
    "FilesystemType": "msdos",
    "FreeSpace": 5801263104,
    "Internal": False,
    "MediaName": "USB Ultra",
    "MountPoint": "/Volumes/NO NAME",
    "Removable": True,
    "RemovableMedia": True,
    "TotalSize": 16017063936,
    "VolumeName": "NO NAME",
    "VolumeUUID": "95BF0D8C-4CC5-3335-9509-6A06B8F6981A",
}

DISKUTIL_INTERNAL_PLIST = {
    "Bootable": True,
    "BusProtocol": "Apple Fabric",
    "DeviceBlockSize": 4096,
    "DeviceIdentifier": "disk3s1",
    "DeviceNode": "/dev/disk3s1",
    "Ejectable": False,
    "FilesystemName": "APFS",
    "FilesystemType": "apfs",
    "FreeSpace": 120000000000,
    "Internal": True,
    "MediaName": "Apple SSD",
    "MountPoint": "/",
    "Removable": False,
    "RemovableMedia": False,
    "TotalSize": 500000000000,
    "VolumeName": "Macintosh HD",
    "VolumeUUID": "ABCD-1234-EFGH-5678",
}


def test_normalize_drive_letter_and_mount_point_posix() -> None:
    """Verify normalize_drive_letter and normalize_mount_point preserve POSIX volume paths."""
    assert normalize_drive_letter("/Volumes/NO NAME") == "/Volumes/NO NAME"
    assert normalize_drive_letter("/Volumes/NO NAME/") == "/Volumes/NO NAME"
    assert normalize_drive_letter("/Volumes/Flash Drive/subdir") == "/Volumes/Flash Drive/subdir"
    assert normalize_drive_letter("/") == "/"

    assert normalize_mount_point("/Volumes/NO NAME") == "/Volumes/NO NAME"
    assert normalize_mount_point("/Volumes/NO NAME/") == "/Volumes/NO NAME"
    assert normalize_mount_point("/") == "/"


def test_macos_device_detector_usb_mount_parsing() -> None:
    """Verify diskutil info parsing for a physical USB mass storage device."""
    detector = MacOSDeviceDetector()
    plist_bytes = plistlib.dumps(DISKUTIL_USB_PLIST)

    mock_res = subprocess.CompletedProcess(
        args=["diskutil", "info", "-plist", "/Volumes/NO NAME"],
        returncode=0,
        stdout=plist_bytes,
        stderr=b"",
    )

    with patch("subprocess.run", return_value=mock_res):
        telemetry = detector.get_volume_telemetry("/Volumes/NO NAME")

    assert telemetry is not None
    assert telemetry.mount_point == "/Volumes/NO NAME"
    assert telemetry.volume_label == "NO NAME"
    assert telemetry.filesystem == "MS-DOS FAT32"
    assert telemetry.classification == DeviceClassification.USB_MASS_STORAGE
    assert telemetry.confidence == DetectionConfidence.HIGH_IOCTL_USB
    assert telemetry.bus_type == "USB"
    assert telemetry.detection_backend == "MACOS_DISKUTIL"
    assert telemetry.total_bytes == 16017063936
    assert telemetry.free_bytes == 5801263104
    assert telemetry.volume_serial == "95BF0D8C-4CC5-3335-9509-6A06B8F6981A"
    assert telemetry.device_model == "USB Ultra"


def test_macos_device_detector_internal_disk_parsing() -> None:
    """Verify internal fixed drive is classified as FIXED_VOLUME."""
    detector = MacOSDeviceDetector()
    plist_bytes = plistlib.dumps(DISKUTIL_INTERNAL_PLIST)

    mock_res = subprocess.CompletedProcess(
        args=["diskutil", "info", "-plist", "/Volumes/Macintosh HD"],
        returncode=0,
        stdout=plist_bytes,
        stderr=b"",
    )

    with patch("subprocess.run", return_value=mock_res):
        telemetry = detector.get_volume_telemetry("/Volumes/Macintosh HD")

    assert telemetry is not None
    assert telemetry.classification == DeviceClassification.FIXED_VOLUME
    assert telemetry.bus_type == "Apple Fabric"
    assert telemetry.mount_point == "/"
    assert telemetry.volume_label == "Macintosh HD"


def test_macos_device_detector_statvfs_fallback(tmp_path: Path) -> None:
    """Verify fallback to pure standard library statvfs when diskutil fails or is missing."""
    detector = MacOSDeviceDetector()

    # Simulate diskutil command returning error
    mock_err_res = subprocess.CompletedProcess(
        args=["diskutil", "info", "-plist", str(tmp_path)],
        returncode=1,
        stdout=plistlib.dumps({"Error": True, "ErrorMessage": "Disk not found"}),
        stderr=b"",
    )

    with patch("subprocess.run", return_value=mock_err_res):
        telemetry = detector.get_volume_telemetry(str(tmp_path))

    assert telemetry is not None
    assert telemetry.mount_point == str(tmp_path)
    assert telemetry.detection_backend == "POSIX_STATVFS"
    assert telemetry.confidence == DetectionConfidence.UNVERIFIED
    assert telemetry.total_bytes is not None
    assert telemetry.total_bytes > 0


def test_macos_device_detector_get_mounted_volumes_filters_internal() -> None:
    """Verify get_mounted_volumes returns qualifying USB/removable drives and excludes internal fixed OS root."""
    detector = MacOSDeviceDetector()

    usb_telemetry = DeviceTelemetry(
        device_id="disk6",
        detected_at=utc_now(),
        mount_point="/Volumes/NO NAME",
        volume_label="NO NAME",
        filesystem="MS-DOS FAT32",
        total_bytes=16000000000,
        free_bytes=5000000000,
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.HIGH_IOCTL_USB,
        bus_type="USB",
    )

    internal_telemetry = DeviceTelemetry(
        device_id="disk3s1",
        detected_at=utc_now(),
        mount_point="/",
        volume_label="Macintosh HD",
        filesystem="APFS",
        total_bytes=500000000000,
        free_bytes=100000000000,
        classification=DeviceClassification.FIXED_VOLUME,
        confidence=DetectionConfidence.UNVERIFIED,
        bus_type="Apple Fabric",
    )

    class FakeDirEntry:
        def __init__(self, name: str, path: str) -> None:
            self.name = name
            self.path = path

    mock_entries = [
        FakeDirEntry(name="NO NAME", path="/Volumes/NO NAME"),
        FakeDirEntry(name="Macintosh HD", path="/Volumes/Macintosh HD"),
    ]

    with patch("os.scandir", return_value=mock_entries), \
         patch("pathlib.Path.is_dir", return_value=True), \
         patch.object(detector, "get_volume_telemetry", side_effect=lambda p: usb_telemetry if "NO NAME" in p else internal_telemetry):
        volumes = detector.get_mounted_volumes()

    # Must only contain the USB device
    assert len(volumes) == 1
    assert volumes[0].mount_point == "/Volumes/NO NAME"
    assert volumes[0].classification == DeviceClassification.USB_MASS_STORAGE


def test_macos_device_detector_event_monitoring_and_simulation() -> None:
    """Verify start_event_monitoring, simulate_arrival, simulate_removal, and stop_event_monitoring."""
    detector = MacOSDeviceDetector()
    events_received: list[RawDeviceEvent] = []

    def on_event(ev: RawDeviceEvent) -> None:
        events_received.append(ev)

    detector.start_event_monitoring(on_event)
    assert detector.is_monitoring is True

    telemetry = DeviceTelemetry(
        device_id="disk6",
        detected_at=utc_now(),
        mount_point="/Volumes/NO NAME",
        volume_label="NO NAME",
        filesystem="MS-DOS FAT32",
        total_bytes=16000000000,
        free_bytes=5000000000,
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.HIGH_IOCTL_USB,
        bus_type="USB",
    )

    # Simulate Arrival
    detector.simulate_arrival("/Volumes/NO NAME", telemetry)
    assert len(events_received) == 1
    assert events_received[0].event_type == DeviceEventType.ARRIVED
    assert events_received[0].drive_letter == "/Volumes/NO NAME"
    assert detector.get_volume_telemetry("/Volumes/NO NAME") == telemetry

    # Simulate Removal
    detector.simulate_removal("/Volumes/NO NAME")
    assert len(events_received) == 2
    assert events_received[1].event_type == DeviceEventType.REMOVED
    assert events_received[1].drive_letter == "/Volumes/NO NAME"

    detector.stop_event_monitoring()
    assert detector.is_monitoring is False


def test_get_device_detector_platform_resolution() -> None:
    """Verify get_device_detector returns appropriate backend for each operating system."""
    with patch("sys.platform", "darwin"):
        d = get_device_detector()
        assert isinstance(d, MacOSDeviceDetector)

    with patch("sys.platform", "win32"):
        d = get_device_detector()
        assert isinstance(d, WindowsDeviceDetector)

    with patch("sys.platform", "linux"):
        d = get_device_detector()
        assert isinstance(d, UnsupportedPlatformDetector)


def test_web_error_visibility_on_detection_failure(isolated_config: SentinelConfig) -> None:
    """Verify web dashboard and devices views render visible error banners when detection fails."""
    class FailingDetector(BaseDeviceDetector):
        def get_mounted_volumes(self) -> list[DeviceTelemetry]:
            raise OSError("Hardware bus error: diskutil process timeout")

        def get_volume_telemetry(self, drive_or_path: str):
            return None

        def start_event_monitoring(self, callback) -> None:
            pass

        def stop_event_monitoring(self) -> None:
            pass

        @property
        def is_monitoring(self) -> bool:
            return False

    app = create_app(
        config=isolated_config,
        detector=FailingDetector(),
        test_config={"TESTING": True, "SECRET_KEY": "test-key"},
    )
    client = app.test_client()

    # /devices must show Device Enumeration Warning
    res_devices = client.get("/devices")
    assert res_devices.status_code == 200
    assert "Device Enumeration Warning" in res_devices.text
    assert "diskutil process timeout" in res_devices.text

    # /dashboard must show Device Enumeration Warning
    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    assert "Device Enumeration Warning" in res_dash.text
    assert "diskutil process timeout" in res_dash.text


def test_macos_detector_virtual_disk_image_classification() -> None:
    """Verify virtual disk images are classified as UNKNOWN_REMOVABLE with UNVERIFIED confidence."""
    detector = MacOSDeviceDetector()
    virtual_plist = {
        "Bootable": False,
        "BusProtocol": "Disk Image",
        "DeviceBlockSize": 512,
        "DeviceIdentifier": "disk7s1",
        "Ejectable": True,
        "FilesystemName": "MS-DOS FAT32",
        "Internal": False,
        "MediaName": "Disk Image",
        "MountPoint": "/Volumes/NO NAME",
        "Removable": True,
        "RemovableMedia": True,
        "TotalSize": 1000000,
        "FreeSpace": 500000,
        "Virtual": True,
    }
    telemetry = detector._parse_diskutil_data(virtual_plist, "/Volumes/NO NAME")
    assert telemetry.classification == DeviceClassification.UNKNOWN_REMOVABLE
    assert telemetry.confidence == DetectionConfidence.UNVERIFIED
    assert telemetry.bus_type == "Disk Image (Virtual)"
    assert telemetry.warning is not None
    assert "Virtual disk image" in telemetry.warning

