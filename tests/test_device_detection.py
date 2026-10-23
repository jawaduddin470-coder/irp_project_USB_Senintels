"""Unit tests for usb_sentinel.device_detection (Windows detection pipeline, IOCTL, and mocks)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.config import SentinelConfig
from usb_sentinel.device_detection import (
    BusTypeNvme,
    BusTypeSata,
    BusTypeScsi,
    BusTypeUsb,
    DRIVE_CDROM,
    DRIVE_FIXED,
    DRIVE_RAMDISK,
    DRIVE_REMOTE,
    DRIVE_REMOVABLE,
    DRIVE_UNKNOWN,
    DeviceEventType,
    MockDeviceDetector,
    RawDeviceEvent,
    UnsupportedPlatformDetector,
    WindowsDeviceDetector,
    normalize_drive_letter,
    normalize_mount_point,
)
from usb_sentinel.models import (
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    utc_now,
)


# ==============================================================================
# Path and Drive Letter Normalization Tests
# ==============================================================================


def test_normalize_drive_letter_various_formats() -> None:
    """Verify normalize_drive_letter standardizes all drive letter representations to 'X:'."""
    assert normalize_drive_letter("e") == "E:"
    assert normalize_drive_letter("E:") == "E:"
    assert normalize_drive_letter("E:\\") == "E:"
    assert normalize_drive_letter("e:\\") == "E:"
    assert normalize_drive_letter("\\\\?\\E:\\") == "E:"
    assert normalize_drive_letter("\\\\.\\E:") == "E:"
    assert normalize_drive_letter("  f:  ") == "F:"


def test_normalize_mount_point_formats() -> None:
    """Verify normalize_mount_point formats standard trailing separators."""
    assert normalize_mount_point("E:") == "E:\\"
    assert normalize_mount_point("e") == "E:\\"
    assert normalize_mount_point("E:\\") == "E:\\"
    # POSIX paths remain unchanged
    assert normalize_mount_point("/Volumes/USB_STICK") == "/Volumes/USB_STICK"


# ==============================================================================
# UnsupportedPlatformDetector Tests
# ==============================================================================


def test_unsupported_platform_detector_behavior() -> None:
    """Verify UnsupportedPlatformDetector communicates unmonitored status without pretending."""
    detector = UnsupportedPlatformDetector()
    assert detector.is_monitoring is False
    assert detector.get_mounted_volumes() == []
    assert detector.get_volume_telemetry("E:") is None

    with pytest.raises(RuntimeError, match="Windows WMI device monitoring is not available"):
        detector.start_event_monitoring(lambda ev: None)

    # stop_event_monitoring is a safe no-op
    detector.stop_event_monitoring()


# ==============================================================================
# MockDeviceDetector Tests
# ==============================================================================


def test_mock_device_detector_lifecycle_and_events() -> None:
    """Verify MockDeviceDetector registers volumes and dispatches simulated events."""
    detector = MockDeviceDetector()
    events_received: list[RawDeviceEvent] = []

    def on_event(ev: RawDeviceEvent) -> None:
        events_received.append(ev)

    detector.start_event_monitoring(on_event)
    assert detector.is_monitoring is True

    telemetry = DeviceTelemetry(
        device_id="E:",
        detected_at=utc_now(),
        mount_point="E:\\",
        volume_label="TEST_USB",
        filesystem="NTFS",
        total_bytes=16_000_000_000,
        free_bytes=8_000_000_000,
        classification=DeviceClassification.USB_MASS_STORAGE,
        confidence=DetectionConfidence.DEFINITIVE_WMI_USB,
    )

    # Simulate Arrival
    detector.simulate_arrival("E:", telemetry)
    assert len(events_received) == 1
    assert events_received[0].event_type == DeviceEventType.ARRIVED
    assert events_received[0].drive_letter == "E:"
    assert detector.get_volume_telemetry("E:") == telemetry
    assert detector.get_mounted_volumes() == [telemetry]

    # Simulate Removal
    detector.simulate_removal("E:")
    assert len(events_received) == 2
    assert events_received[1].event_type == DeviceEventType.REMOVED
    assert events_received[1].drive_letter == "E:"
    assert detector.get_volume_telemetry("E:") is None
    assert detector.get_mounted_volumes() == []

    detector.stop_event_monitoring()
    assert detector.is_monitoring is False


def test_mock_device_detector_delayed_mount() -> None:
    """Verify MockDeviceDetector simulate_delayed_mount returns None for N calls then yields volume."""
    detector = MockDeviceDetector()
    telemetry = DeviceTelemetry(
        device_id="F:",
        detected_at=utc_now(),
        mount_point="F:\\",
        volume_label="DELAYED_USB",
        filesystem="FAT32",
        classification=DeviceClassification.USB_MASS_STORAGE,
    )

    detector.simulate_delayed_mount("F:", telemetry, delay_retries=2)

    # First two calls: None (simulating mount not ready)
    assert detector.get_volume_telemetry("F:") is None
    assert detector.get_volume_telemetry("F:") is None

    # Third call: volume is ready
    ready_telem = detector.get_volume_telemetry("F:")
    assert ready_telem is not None
    assert ready_telem.volume_label == "DELAYED_USB"


# ==============================================================================
# WindowsDeviceDetector Classification Pipeline Tests (Mocked Win32/WMI)
# ==============================================================================


def test_windows_detector_requires_windows_or_explicit_flag() -> None:
    """Verify WindowsDeviceDetector raises RuntimeError on non-Windows host unless allow_non_windows is True."""
    if sys.platform != "win32":
        with pytest.raises(RuntimeError, match="requires a Windows operating system"):
            WindowsDeviceDetector(allow_non_windows=False)

        # allow_non_windows=True permits instantiation on macOS for testing
        det = WindowsDeviceDetector(allow_non_windows=True)
        assert det is not None


def test_classify_usb_flash_drive_via_wmi() -> None:
    """Verify Tier 1: WMI identifies USB flash drive with InterfaceType='USB' as USB_MASS_STORAGE."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    # Mock WMI Win32_LogicalDisk and associators
    mock_ldisk = MagicMock()
    mock_ldisk.DeviceID = "E:"

    mock_part = MagicMock()
    mock_disk = MagicMock()
    mock_disk.InterfaceType = "USB"
    mock_disk.PNPDeviceID = "USBSTOR\\DISK&VEN_SANDISK&PROD_CRUZER&REV_1.0\\123456"
    mock_disk.Model = "SanDisk Cruzer Glide USB Device"

    mock_ldisk.associators.return_value = [mock_part]
    mock_part.associators.return_value = [mock_disk]

    mock_wmi = MagicMock()
    mock_wmi.Win32_LogicalDisk.return_value = [mock_ldisk]
    detector._wmi_client = mock_wmi

    classification, confidence, backend, warning, model, bus = detector._classify_drive("E:")

    assert classification == DeviceClassification.USB_MASS_STORAGE
    assert confidence == DetectionConfidence.DEFINITIVE_WMI_USB
    assert backend == "WMI"
    assert warning is None
    assert model == "SanDisk Cruzer Glide USB Device"
    assert bus == "USB"


def test_classify_usb_hdd_ssd_fixed_disk_via_wmi() -> None:
    """CRITICAL: Verify Tier 1: USB external hard drive/SSD reported as fixed disk is classified as USB_MASS_STORAGE."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    # Mock USB HDD: Windows reports MediaType as 'Fixed hard disk media', but InterfaceType is 'USB'
    mock_ldisk = MagicMock()
    mock_ldisk.DeviceID = "G:"
    mock_ldisk.DriveType = DRIVE_FIXED  # Windows reports it as fixed disk!

    mock_part = MagicMock()
    mock_disk = MagicMock()
    mock_disk.InterfaceType = "USB"
    mock_disk.PNPDeviceID = "USBSTOR\\DISK&VEN_WD&PROD_MY_PASSPORT_2627\\012345"
    mock_disk.MediaType = "Fixed hard disk media"
    mock_disk.Model = "WD My Passport 2627 USB Device"

    mock_ldisk.associators.return_value = [mock_part]
    mock_part.associators.return_value = [mock_disk]

    mock_wmi = MagicMock()
    mock_wmi.Win32_LogicalDisk.return_value = [mock_ldisk]
    detector._wmi_client = mock_wmi

    classification, confidence, backend, warning, model, bus = detector._classify_drive("G:")

    assert classification == DeviceClassification.USB_MASS_STORAGE
    assert confidence == DetectionConfidence.DEFINITIVE_WMI_USB
    assert backend == "WMI"
    assert model == "WD My Passport 2627 USB Device"


def test_classify_internal_nvme_sata_disk_via_wmi() -> None:
    """Verify Tier 1: Internal NVMe/SATA fixed disk (C:\\) is classified as FIXED_VOLUME and never USB."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    mock_ldisk = MagicMock()
    mock_ldisk.DeviceID = "C:"
    mock_ldisk.DriveType = DRIVE_FIXED

    mock_part = MagicMock()
    mock_disk = MagicMock()
    mock_disk.InterfaceType = "NVMe"
    mock_disk.PNPDeviceID = "SCSI\\DISK&VEN_NVME&PROD_SAMSUNG_SSD_980\\000000"
    mock_disk.Model = "Samsung SSD 980 PRO 1TB"

    mock_ldisk.associators.return_value = [mock_part]
    mock_part.associators.return_value = [mock_disk]

    mock_wmi = MagicMock()
    mock_wmi.Win32_LogicalDisk.return_value = [mock_ldisk]
    detector._wmi_client = mock_wmi

    classification, confidence, backend, _, model, bus = detector._classify_drive("C:")

    assert classification == DeviceClassification.FIXED_VOLUME
    assert confidence == DetectionConfidence.DEFINITIVE_WMI_USB
    assert backend == "WMI"
    assert model == "Samsung SSD 980 PRO 1TB"
    assert bus == "NVME"


def test_classify_fallback_to_ioctl_when_wmi_fails() -> None:
    """Verify Tier 2: Storage IOCTL is invoked when WMI fails, identifying BusTypeUsb as USB_MASS_STORAGE."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    # Simulate WMI failure
    mock_wmi = MagicMock()
    mock_wmi.Win32_LogicalDisk.side_effect = Exception("WMI service unavailable")
    detector._wmi_client = mock_wmi

    # Mock _query_storage_ioctl returning BusTypeUsb (7)
    with patch.object(detector, "_query_storage_ioctl", return_value=BusTypeUsb):
        classification, confidence, backend, warning, _, bus = detector._classify_drive("E:")

    assert classification == DeviceClassification.USB_MASS_STORAGE
    assert confidence == DetectionConfidence.HIGH_IOCTL_USB
    assert backend == "IOCTL"
    assert bus == "USB"


def test_classify_fallback_to_ioctl_internal_sata() -> None:
    """Verify Tier 2: Storage IOCTL identifies BusTypeSata/BusTypeNvme as FIXED_VOLUME."""
    detector = WindowsDeviceDetector(allow_non_windows=True)
    detector._wmi_client = None  # WMI not available

    with patch.object(detector, "_query_storage_ioctl", return_value=BusTypeSata):
        classification, confidence, backend, _, _, _ = detector._classify_drive("D:")

    assert classification == DeviceClassification.FIXED_VOLUME
    assert confidence == DetectionConfidence.HIGH_IOCTL_USB
    assert backend == "IOCTL"


def test_classify_fallback_to_get_drive_type_removable() -> None:
    """Verify Tier 3: GetDriveType fallback identifies DRIVE_REMOVABLE with degraded warning."""
    detector = WindowsDeviceDetector(allow_non_windows=True)
    detector._wmi_client = None

    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_get_drive_type", return_value=DRIVE_REMOVABLE):
        classification, confidence, backend, warning, _, _ = detector._classify_drive("E:")

    assert classification == DeviceClassification.UNKNOWN_REMOVABLE
    assert confidence == DetectionConfidence.HEURISTIC_REMOVABLE
    assert backend == "GET_DRIVE_TYPE"
    assert warning is not None
    assert "DRIVE_REMOVABLE" in warning


def test_classify_fallback_to_get_drive_type_fixed() -> None:
    """Verify Tier 3: GetDriveType fallback identifies DRIVE_FIXED as FIXED_VOLUME."""
    detector = WindowsDeviceDetector(allow_non_windows=True)
    detector._wmi_client = None

    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_get_drive_type", return_value=DRIVE_FIXED):
        classification, confidence, backend, warning, _, _ = detector._classify_drive("C:")

    assert classification == DeviceClassification.FIXED_VOLUME
    assert confidence == DetectionConfidence.HEURISTIC_REMOVABLE
    assert backend == "GET_DRIVE_TYPE"


def test_classify_fallback_to_get_drive_type_cdrom() -> None:
    """Verify Tier 3: GetDriveType fallback identifies DRIVE_CDROM as OPTICAL_OR_OTHER."""
    detector = WindowsDeviceDetector(allow_non_windows=True)
    detector._wmi_client = None

    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_get_drive_type", return_value=DRIVE_CDROM):
        classification, _, backend, _, _, _ = detector._classify_drive("D:")

    assert classification == DeviceClassification.OPTICAL_OR_OTHER
    assert backend == "GET_DRIVE_TYPE"


def test_get_volume_telemetry_complete(tmp_path: Path) -> None:
    """Verify get_volume_telemetry aggregates classification, volume label, filesystem, and disk usage."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    with patch.object(detector, "_is_drive_mounted", return_value=True), \
         patch.object(detector, "_classify_drive", return_value=(
             DeviceClassification.USB_MASS_STORAGE,
             DetectionConfidence.DEFINITIVE_WMI_USB,
             "WMI",
             None,
             "SanDisk USB 3.0",
             "USB",
         )), \
         patch.object(detector, "_get_volume_information", return_value=("MY_USB", "exFAT", "1234-ABCD")), \
         patch.object(detector, "_get_disk_free_space", return_value=(32_000_000_000, 28_000_000_000)):

        telemetry = detector.get_volume_telemetry("E:")

    assert telemetry is not None
    assert telemetry.device_id == "E:"
    assert telemetry.mount_point == "E:\\"
    assert telemetry.volume_label == "MY_USB"
    assert telemetry.filesystem == "exFAT"
    assert telemetry.volume_serial == "1234-ABCD"
    assert telemetry.total_bytes == 32_000_000_000
    assert telemetry.free_bytes == 28_000_000_000
    assert telemetry.classification == DeviceClassification.USB_MASS_STORAGE
    assert telemetry.confidence == DetectionConfidence.DEFINITIVE_WMI_USB
    assert telemetry.device_model == "SanDisk USB 3.0"
    assert telemetry.bus_type == "USB"


def test_classify_network_drive_remote() -> None:
    """Verify mapped network drives (DRIVE_REMOTE) are classified as OPTICAL_OR_OTHER."""
    detector = WindowsDeviceDetector(allow_non_windows=True)
    detector._wmi_client = None

    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_get_drive_type", return_value=DRIVE_REMOTE):
        classification, confidence, backend, warning, _, bus = detector._classify_drive("Z:")

    assert classification == DeviceClassification.OPTICAL_OR_OTHER
    assert confidence == DetectionConfidence.HEURISTIC_REMOVABLE
    assert backend == "GET_DRIVE_TYPE"
    assert warning is not None
    assert "network share" in warning
    assert bus == "NETWORK"


def test_classify_ramdisk() -> None:
    """Verify RAM disks (DRIVE_RAMDISK) are classified as OPTICAL_OR_OTHER."""
    detector = WindowsDeviceDetector(allow_non_windows=True)
    detector._wmi_client = None

    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_get_drive_type", return_value=DRIVE_RAMDISK):
        classification, confidence, backend, warning, _, bus = detector._classify_drive("R:")

    assert classification == DeviceClassification.OPTICAL_OR_OTHER
    assert confidence == DetectionConfidence.HEURISTIC_REMOVABLE
    assert backend == "GET_DRIVE_TYPE"
    assert warning is not None
    assert "RAM disk" in warning
    assert bus == "RAMDISK"


def test_classify_unknown_drive_type() -> None:
    """Verify unrecognized drive types produce explicit UNKNOWN classification with UNVERIFIED confidence."""
    detector = WindowsDeviceDetector(allow_non_windows=True)
    detector._wmi_client = None

    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_get_drive_type", return_value=DRIVE_UNKNOWN):
        classification, confidence, backend, warning, _, bus = detector._classify_drive("X:")

    assert classification == DeviceClassification.UNKNOWN
    assert confidence == DetectionConfidence.UNVERIFIED
    assert backend == "GENERIC"
    assert warning is not None
    assert "Unable to determine device bus" in warning


def test_drive_removable_alone_never_establishes_definitive_wmi_usb() -> None:
    """CRITICAL SAFETY TEST: Verify DRIVE_REMOVABLE without physical disk associators never yields DEFINITIVE_WMI_USB."""
    detector = WindowsDeviceDetector(allow_non_windows=True)

    # Mock logical disk with DRIVE_REMOVABLE but NO partition/physical disk associator
    mock_ldisk = MagicMock()
    mock_ldisk.DeviceID = "E:"
    mock_ldisk.DriveType = DRIVE_REMOVABLE
    mock_ldisk.associators.return_value = []  # No partitions/disks found

    mock_wmi = MagicMock()
    mock_wmi.Win32_LogicalDisk.return_value = [mock_ldisk]
    detector._wmi_client = mock_wmi

    # Tier 1 fails to establish physical disk, falls through to Tier 2 (None) and Tier 3 (DRIVE_REMOVABLE)
    with patch.object(detector, "_query_storage_ioctl", return_value=None), \
         patch.object(detector, "_get_drive_type", return_value=DRIVE_REMOVABLE):
        classification, confidence, backend, warning, _, _ = detector._classify_drive("E:")

    # MUST be UNKNOWN_REMOVABLE with HEURISTIC_REMOVABLE confidence, NOT DEFINITIVE_WMI_USB!
    assert classification == DeviceClassification.UNKNOWN_REMOVABLE
    assert confidence == DetectionConfidence.HEURISTIC_REMOVABLE
    assert confidence != DetectionConfidence.DEFINITIVE_WMI_USB
    assert backend == "GET_DRIVE_TYPE"
    assert warning is not None
    assert "DRIVE_REMOVABLE" in warning

