"""Automated test suite for physical vs virtual storage device classification.

Validates all 7 required scenarios:
1. One physical USB connected.
2. One physical USB with multiple partitions.
3. A mounted virtual disk image.
4. Internal storage exclusion.
5. Physical USB plus virtual disk image (the user's real-world scenario).
6. No physical USB connected.
7. Unknown or incomplete hardware metadata.

Expected behavior:
- Physical USB devices detected: 1.
- Virtual disk images: 1.
- Physical USB capacity: ~28.89 GB.
- Virtual disk image (3.2 GB) is NEVER counted as a physical USB.
"""

from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient

from usb_sentinel.config import SentinelConfig
from usb_sentinel.device_detection import (
    BaseDeviceDetector,
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    MacOSDeviceDetector,
    utc_now,
)
from usb_sentinel.web_app import (
    DeviceTelemetryViewModel,
    create_app,
    group_and_adapt_storage,
)


# ==============================================================================
# Realistic Mock Device Payloads
# ==============================================================================

# Physical USB (31.02 GB / 28.89 GiB FAT32 partition on physical USB disk6)
MOCK_PHYSICAL_USB_PARTITION = {
    "Bootable": False,
    "BusProtocol": "USB",
    "DeviceIdentifier": "disk6s1",
    "DeviceNode": "/dev/disk6s1",
    "DeviceTreePath": "IODeviceTree:/arm-io/usb-drd0@2280000/usb-drd0-port-hs@00100000",
    "Ejectable": True,
    "FilesystemName": "MS-DOS FAT32",
    "FilesystemType": "msdos",
    "FreeSpace": 30996643840,
    "IORegistryEntryName": "HP USB Flash Drive Media",
    "Internal": False,
    "MediaName": "USB Flash Drive",
    "MountPoint": "/Volumes/NO NAME 1",
    "ParentWholeDisk": "disk6",
    "Removable": True,
    "RemovableMedia": True,
    "RemovableMediaOrExternalDevice": True,
    "TotalSize": 31021154304,  # 28.89 GiB
    "VirtualOrPhysical": "Physical",
    "VolumeName": "NO NAME 1",
    "VolumeUUID": "8763E16A-0429-3C52-A096-1B2205ED11A9",
}

# Virtual Disk Image (3.43 GB / 3.20 GiB attached FAT32 disk image disk7)
MOCK_VIRTUAL_DISK_IMAGE = {
    "Bootable": False,
    "BusProtocol": "Disk Image",
    "DeviceIdentifier": "disk7",
    "DeviceNode": "/dev/disk7",
    "DeviceTreePath": "IODeviceTree:/",
    "Ejectable": True,
    "FilesystemName": "MS-DOS FAT32",
    "FilesystemType": "msdos",
    "FreeSpace": 0,
    "IORegistryEntryName": "Apple Disk Image Media",
    "Internal": False,
    "MediaName": "Disk Image",
    "MountPoint": "/Volumes/NO NAME",
    "ParentWholeDisk": "disk7",
    "Removable": True,
    "RemovableMedia": True,
    "RemovableMediaOrExternalDevice": True,
    "TotalSize": 3430957056,  # 3.20 GiB
    "VirtualOrPhysical": "Virtual",
    "Virtual": True,
    "VolumeName": "NO NAME",
    "VolumeUUID": "95BF0D8C-4CC5-3335-9509-6A06B8F6981A",
}

# Internal Storage (APFS Macintosh HD on disk3s1)
MOCK_INTERNAL_APFS = {
    "Bootable": True,
    "BusProtocol": "Apple Fabric",
    "DeviceIdentifier": "disk3s1",
    "DeviceNode": "/dev/disk3s1",
    "Ejectable": False,
    "FilesystemName": "APFS",
    "Internal": True,
    "OSInternalMedia": True,
    "MediaName": "Apple SSD",
    "MountPoint": "/",
    "ParentWholeDisk": "disk0",
    "Removable": False,
    "TotalSize": 494384795648,
    "VirtualOrPhysical": "Physical",
    "VolumeName": "Macintosh HD",
}


# ==============================================================================
# Scenario 1: One Physical USB Connected
# ==============================================================================


def test_scenario_1_single_physical_usb() -> None:
    """Scenario 1: Exactly one physical USB flash drive is connected."""
    detector = MacOSDeviceDetector()
    telemetry = detector._parse_diskutil_data(MOCK_PHYSICAL_USB_PARTITION, "/Volumes/NO NAME 1")

    assert telemetry.classification == DeviceClassification.PHYSICAL_USB
    assert telemetry.is_physical_usb is True
    assert telemetry.is_virtual is False
    assert telemetry.bus_type == "USB"
    assert telemetry.parent_device_id == "disk6"

    # Grouping test
    physical_usbs, virtual_disks, other_devs = group_and_adapt_storage([telemetry])
    assert len(physical_usbs) == 1
    assert len(virtual_disks) == 0
    assert len(other_devs) == 0

    # Capacity check (~28.89 GB)
    cap_gb = round(physical_usbs[0].total_size_bytes / (1024 ** 3), 2)
    assert cap_gb == 28.89


# ==============================================================================
# Scenario 2: One Physical USB with Multiple Partitions
# ==============================================================================


def test_scenario_2_physical_usb_multiple_partitions() -> None:
    """Scenario 2: One physical USB drive containing two distinct partitions."""
    detector = MacOSDeviceDetector()

    part1_data = dict(MOCK_PHYSICAL_USB_PARTITION)
    part1_data["DeviceIdentifier"] = "disk6s1"
    part1_data["MountPoint"] = "/Volumes/USB_DOCS"
    part1_data["VolumeName"] = "USB_DOCS"
    part1_data["TotalSize"] = 16000000000

    part2_data = dict(MOCK_PHYSICAL_USB_PARTITION)
    part2_data["DeviceIdentifier"] = "disk6s2"
    part2_data["MountPoint"] = "/Volumes/USB_MEDIA"
    part2_data["VolumeName"] = "USB_MEDIA"
    part2_data["TotalSize"] = 15000000000

    tel1 = detector._parse_diskutil_data(part1_data, "/Volumes/USB_DOCS")
    tel2 = detector._parse_diskutil_data(part2_data, "/Volumes/USB_MEDIA")

    # Both belong to same physical parent whole disk 'disk6'
    assert tel1.parent_device_id == "disk6"
    assert tel2.parent_device_id == "disk6"

    physical_usbs, virtual_disks, other_devs = group_and_adapt_storage([tel1, tel2])

    # Must count as EXACTLY 1 physical USB device, not 2!
    assert len(physical_usbs) == 1
    assert physical_usbs[0].partition_count == 2
    assert len(physical_usbs[0].partitions) == 2
    assert len(virtual_disks) == 0

    # Ensure partition mount points are associated
    partition_mounts = [p["mount_point"] for p in physical_usbs[0].partitions]
    assert "/Volumes/USB_DOCS" in partition_mounts
    assert "/Volumes/USB_MEDIA" in partition_mounts


# ==============================================================================
# Scenario 3: Mounted Virtual Disk Image
# ==============================================================================


def test_scenario_3_mounted_virtual_disk_image() -> None:
    """Scenario 3: An attached virtual disk image (.dmg / forensic image)."""
    detector = MacOSDeviceDetector()
    telemetry = detector._parse_diskutil_data(MOCK_VIRTUAL_DISK_IMAGE, "/Volumes/NO NAME")

    assert telemetry.classification == DeviceClassification.VIRTUAL_DISK_IMAGE
    assert telemetry.is_virtual is True
    assert telemetry.is_physical_usb is False
    assert telemetry.bus_type == "Disk Image (Virtual)"

    physical_usbs, virtual_disks, other_devs = group_and_adapt_storage([telemetry])
    # The virtual disk image must NEVER be included in physical USBs
    assert len(physical_usbs) == 0
    assert len(virtual_disks) == 1
    assert virtual_disks[0].mount_point == "/Volumes/NO NAME"
    assert round(virtual_disks[0].total_size_bytes / (1024 ** 3), 2) == 3.20


# ==============================================================================
# Scenario 4: Internal Storage
# ==============================================================================


def test_scenario_4_internal_storage() -> None:
    """Scenario 4: Internal system fixed drive (e.g. Macintosh HD on APFS)."""
    detector = MacOSDeviceDetector()
    telemetry = detector._parse_diskutil_data(MOCK_INTERNAL_APFS, "/")

    assert telemetry.classification == DeviceClassification.INTERNAL_STORAGE
    assert telemetry.is_physical_usb is False

    # get_mounted_volumes must exclude internal storage
    with patch.object(detector, "get_volume_telemetry", return_value=telemetry):
        vols = detector.get_mounted_volumes()
        assert not any(v.classification == DeviceClassification.INTERNAL_STORAGE for v in vols)


# ==============================================================================
# Scenario 5: Physical USB Plus Virtual Disk Image (User's Exact Scenario)
# ==============================================================================


def test_scenario_5_physical_usb_plus_virtual_disk_image(isolated_config: SentinelConfig) -> None:
    """Scenario 5: User scenario with 1 physical USB (28.89 GB) and 1 virtual disk image (3.2 GB)."""
    detector = MacOSDeviceDetector()
    usb_tel = detector._parse_diskutil_data(MOCK_PHYSICAL_USB_PARTITION, "/Volumes/NO NAME 1")
    virt_tel = detector._parse_diskutil_data(MOCK_VIRTUAL_DISK_IMAGE, "/Volumes/NO NAME")

    # 1. Verification of distinct classifications
    assert usb_tel.classification == DeviceClassification.PHYSICAL_USB
    assert virt_tel.classification == DeviceClassification.VIRTUAL_DISK_IMAGE

    # 2. Verification of grouping and separate counts
    physical_usbs, virtual_disks, other_devs = group_and_adapt_storage([usb_tel, virt_tel])

    assert len(physical_usbs) == 1, "Expected exactly 1 physical USB device"
    assert len(virtual_disks) == 1, "Expected exactly 1 virtual disk image"
    assert round(physical_usbs[0].total_size_bytes / (1024 ** 3), 2) == 28.89
    assert round(virtual_disks[0].total_size_bytes / (1024 ** 3), 2) == 3.20
    assert physical_usbs[0].mount_point == "/Volumes/NO NAME 1"
    assert virtual_disks[0].mount_point == "/Volumes/NO NAME"

    # 3. Web Dashboard Integration Verification
    class MockDetector(BaseDeviceDetector):
        def get_mounted_volumes(self) -> list[DeviceTelemetry]:
            return [usb_tel, virt_tel]

        def get_volume_telemetry(self, drive_or_path: str):
            if "NO NAME 1" in drive_or_path:
                return usb_tel
            return virt_tel

        def start_event_monitoring(self, callback) -> None:
            pass

        def stop_event_monitoring(self) -> None:
            pass

        @property
        def is_monitoring(self) -> bool:
            return True

    app = create_app(
        config=isolated_config,
        detector=MockDetector(),
        test_config={"TESTING": True, "SECRET_KEY": "test-key"},
    )
    client = app.test_client()

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")

    # KPI metric must report 1 (for physical USB), not 2!
    assert '<div class="metric-value">1</div>' in html
    assert "Verified physical USB hardware" in html
    assert "1 virtual image" in html

    # Virtual disk image section must be present separately
    assert "Virtual Disk Images &amp; Forensic Mounts" in html
    assert "/Volumes/NO NAME" in html
    assert "Scan Forensic Image" in html


# ==============================================================================
# Scenario 6: No Physical USB Connected
# ==============================================================================


def test_scenario_6_no_physical_usb_connected(isolated_config: SentinelConfig) -> None:
    """Scenario 6: Host has zero connected USB devices."""
    class EmptyDetector(BaseDeviceDetector):
        def get_mounted_volumes(self) -> list[DeviceTelemetry]:
            return []

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
        detector=EmptyDetector(),
        test_config={"TESTING": True, "SECRET_KEY": "test-key"},
    )
    client = app.test_client()

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")

    assert '<div class="metric-value">0</div>' in html
    assert "No Physical USB Storage Devices Detected" in html


# ==============================================================================
# Scenario 7: Unknown or Incomplete Hardware Metadata
# ==============================================================================


def test_scenario_7_unknown_or_incomplete_metadata() -> None:
    """Scenario 7: Volume metadata has no identifiable bus or physical controller."""
    detector = MacOSDeviceDetector()
    ambiguous_plist = {
        "Bootable": False,
        "BusProtocol": "",
        "DeviceIdentifier": "disk99s1",
        "Ejectable": False,
        "FilesystemName": "UnknownFS",
        "Internal": False,
        "MediaName": "",
        "MountPoint": "/Volumes/UNKNOWN_DRIVE",
        "Removable": False,
        "TotalSize": 500000000,
    }

    telemetry = detector._parse_diskutil_data(ambiguous_plist, "/Volumes/UNKNOWN_DRIVE")
    # Must be classified as UNKNOWN rather than guessed as USB!
    assert telemetry.classification == DeviceClassification.UNKNOWN
    assert telemetry.confidence == DetectionConfidence.UNVERIFIED
    assert telemetry.is_physical_usb is False

    physical_usbs, virtual_disks, other_devs = group_and_adapt_storage([telemetry])
    assert len(physical_usbs) == 0
    assert len(virtual_disks) == 0
    assert len(other_devs) == 1
