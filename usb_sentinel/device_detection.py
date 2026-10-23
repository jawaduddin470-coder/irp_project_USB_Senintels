"""Windows USB mass storage detection, classification, and volume discovery.

This module provides hardware-level device detection and volume resolution for USB
Sentinel on Windows platforms, featuring a 3-tier inspection pipeline:
    Tier 1: WMI Volume-to-Physical-Disk Associator Queries (Win32_DiskDrive)
    Tier 2: Windows Storage Device Property IOCTL (IOCTL_STORAGE_QUERY_PROPERTY)
    Tier 3: Degraded Fallback via GetDriveTypeW (DRIVE_REMOVABLE)

Design Principles & Security Guarantees:
1. **Critical USB HDD/SSD Detection**:
   Many USB external hard drives and solid-state drives report to Windows as fixed
   disks (`DRIVE_FIXED`). Sentinel resolves physical bus information and interface
   type via WMI/IOCTL to reliably distinguish USB fixed disks from internal SATA/NVMe
   drives without misclassifying internal system drives.
2. **Defensive Device Minimization**:
   Avoids collecting invasive hardware serial numbers; only queries volume-level
   serial numbers generated upon filesystem formatting.
3. **Cross-Platform Isolation**:
   Windows-native APIs (WMI, ctypes, win32file) are strictly isolated. On non-Windows
   development hosts (macOS/Linux), `UnsupportedPlatformDetector` or `MockDeviceDetector`
   ensures tests run cleanly without attempting invalid Win32 calls.
4. **Deterministic Resource Cleanup**:
   Background event listener threads and WMI notification subscriptions are tracked
   and cleanly shut down when `stop_event_monitoring()` is invoked.
"""

from __future__ import annotations

import abc
import ctypes
import os
import shutil
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Final, List, Optional, Tuple

from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.models import (
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    utc_now,
)

# Win32 Constants
DRIVE_UNKNOWN: Final[int] = 0
DRIVE_NO_ROOT_DIR: Final[int] = 1
DRIVE_REMOVABLE: Final[int] = 2
DRIVE_FIXED: Final[int] = 3
DRIVE_REMOTE: Final[int] = 4
DRIVE_CDROM: Final[int] = 5
DRIVE_RAMDISK: Final[int] = 6

# IOCTL Constants for Storage Device Property Query
IOCTL_STORAGE_QUERY_PROPERTY: Final[int] = 0x002D1400
StorageDeviceProperty: Final[int] = 0
PropertyStandardQuery: Final[int] = 0
BusTypeUnknown: Final[int] = 0x00
BusTypeScsi: Final[int] = 0x01
BusTypeAtapi: Final[int] = 0x02
BusTypeAta: Final[int] = 0x03
BusType1394: Final[int] = 0x04
BusTypeSsa: Final[int] = 0x05
BusTypeFibre: Final[int] = 0x06
BusTypeUsb: Final[int] = 0x07
BusTypeRAID: Final[int] = 0x08
BusTypeiScsi: Final[int] = 0x09
BusTypeSas: Final[int] = 0x0A
BusTypeSata: Final[int] = 0x0B
BusTypeSd: Final[int] = 0x0C
BusTypeMmc: Final[int] = 0x0D
BusTypeVirtual: Final[int] = 0x0E
BusTypeFileBackedVirtual: Final[int] = 0x0F
BusTypeSpaces: Final[int] = 0x10
BusTypeNvme: Final[int] = 0x11


class DeviceEventType(str, Enum):
    """Raw device event type emitted by platform monitor."""

    ARRIVED = "ARRIVED"
    REMOVED = "REMOVED"


@dataclass(frozen=True)
class RawDeviceEvent:
    """Raw volume event emitted by the platform detector."""

    event_type: DeviceEventType
    drive_letter: str
    device_id: Optional[str] = None
    timestamp: datetime = field(default_factory=utc_now)


def normalize_drive_letter(drive_str: str) -> str:
    """Normalize a drive letter representation to standard uppercase 'X:' format.

    Examples:
        'e' -> 'E:'
        'E:' -> 'E:'
        'E:\\' -> 'E:'
        '\\\\?\\E:\\' -> 'E:'
    """
    cleaned = drive_str.strip()
    if cleaned.startswith("\\\\?\\"):
        cleaned = cleaned[4:]
    if cleaned.startswith("\\\\.\\"):
        cleaned = cleaned[4:]
    if len(cleaned) >= 2 and cleaned[1] == ":":
        return f"{cleaned[0].upper()}:"
    if len(cleaned) == 1 and cleaned.isalpha():
        return f"{cleaned.upper()}:"
    return cleaned.upper()


def normalize_mount_point(drive_or_path: str) -> str:
    """Normalize a drive or path to a mount point with appropriate trailing separator.

    On Windows: 'E:' -> 'E:\\'
    On POSIX: '/Volumes/USB' -> '/Volumes/USB'
    """
    cleaned = drive_or_path.strip()
    if len(cleaned) == 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        return f"{cleaned[0].upper()}:\\"
    if len(cleaned) == 1 and cleaned.isalpha():
        return f"{cleaned.upper()}:\\"
    if len(cleaned) >= 3 and cleaned[1] == ":" and cleaned[2] == "\\":
        return f"{cleaned[0].upper()}:\\"
    return cleaned


class BaseDeviceDetector(abc.ABC):
    """Abstract base class for device and volume detection backends."""

    @abc.abstractmethod
    def get_mounted_volumes(self) -> list[DeviceTelemetry]:
        """Return all currently mounted volumes eligible for inspection."""

    @abc.abstractmethod
    def get_volume_telemetry(self, drive_or_path: str) -> Optional[DeviceTelemetry]:
        """Retrieve detailed telemetry for a specific drive letter or volume path."""

    @abc.abstractmethod
    def start_event_monitoring(self, event_callback: Callable[[RawDeviceEvent], None]) -> None:
        """Begin listening for hardware arrival and removal notifications."""

    @abc.abstractmethod
    def stop_event_monitoring(self) -> None:
        """Deterministic cleanup of event listener thread and subscriptions."""

    @property
    @abc.abstractmethod
    def is_monitoring(self) -> bool:
        """Return True if background event monitoring is active."""


class WindowsDeviceDetector(BaseDeviceDetector):
    """Windows-native device detection using WMI associators, IOCTL, and GetDriveType."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        allow_non_windows: bool = False,
        wmi_client: Optional[Any] = None,
    ) -> None:
        """Initialize Windows device detector.

        Args:
            config: Sentinel configuration.
            allow_non_windows: If True, allows instantiation on non-Windows hosts
                               (for testing with mocked Windows APIs).
            wmi_client: Injected WMI client mock or instance.
        """
        if sys.platform != "win32" and not allow_non_windows:
            raise RuntimeError(
                "WindowsDeviceDetector requires a Windows operating system. "
                "Use MockDeviceDetector or UnsupportedPlatformDetector on non-Windows hosts."
            )
        self._config = config or get_config()
        self._allow_non_windows = allow_non_windows
        self._wmi_client = wmi_client
        self._monitoring = False
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[RawDeviceEvent], None]] = None

    @property
    def is_monitoring(self) -> bool:
        return self._monitoring

    def get_mounted_volumes(self) -> list[DeviceTelemetry]:
        """Enumerate all active logical drives and return qualifying USB storage volumes."""
        results: list[DeviceTelemetry] = []
        drive_letters = self._enumerate_logical_drives()
        for drive in drive_letters:
            try:
                telemetry = self.get_volume_telemetry(drive)
                if telemetry is not None:
                    # Collect USB mass storage or unverified removable drives
                    if telemetry.classification in (
                        DeviceClassification.USB_MASS_STORAGE,
                        DeviceClassification.UNKNOWN_REMOVABLE,
                    ):
                        results.append(telemetry)
            except Exception:
                continue
        return results

    def get_volume_telemetry(self, drive_or_path: str) -> Optional[DeviceTelemetry]:
        """Query detailed telemetry for a drive letter using the 3-tier inspection pipeline."""
        drive = normalize_drive_letter(drive_or_path)
        mount_point = normalize_mount_point(drive)

        # Check if the volume is currently mounted and accessible
        if not self._is_drive_mounted(mount_point):
            return None

        # Tier 1 & 2 & 3 Classification
        classification, confidence, backend, warning, model_name, bus_type = self._classify_drive(drive)

        # Volume Attributes Query (Label, Filesystem, Serial, Free Space)
        label, fs_name, vol_serial = self._get_volume_information(mount_point)
        total_bytes, free_bytes = self._get_disk_free_space(mount_point)

        return DeviceTelemetry(
            device_id=drive,
            detected_at=utc_now(),
            mount_point=mount_point,
            volume_label=label,
            filesystem=fs_name,
            total_bytes=total_bytes,
            free_bytes=free_bytes,
            volume_serial=vol_serial,
            classification=classification,
            confidence=confidence,
            detection_backend=backend,
            warning=warning,
            device_model=model_name,
            bus_type=bus_type,
        )

    def _classify_drive(
        self, drive: str
    ) -> tuple[DeviceClassification, DetectionConfidence, str, Optional[str], Optional[str], Optional[str]]:
        """Execute 3-tier classification pipeline for the given drive letter.

        Returns:
            tuple: (classification, confidence, backend_name, warning, model_name, bus_type)
        """
        # --- Tier 1: Query WMI Physical Disk & Associators ---
        wmi_res = self._query_wmi_physical_disk(drive)
        if wmi_res is not None:
            is_usb, model, pnp_id, bus_type_str = wmi_res
            if is_usb:
                return (
                    DeviceClassification.USB_MASS_STORAGE,
                    DetectionConfidence.DEFINITIVE_WMI_USB,
                    "WMI",
                    None,
                    model,
                    bus_type_str or "USB",
                )
            else:
                # WMI explicitly confirmed non-USB physical interface (e.g. IDE, NVMe, SATA)
                return (
                    DeviceClassification.FIXED_VOLUME,
                    DetectionConfidence.DEFINITIVE_WMI_USB,
                    "WMI",
                    None,
                    model,
                    bus_type_str or "INTERNAL",
                )

        # --- Tier 2: Storage Device Property IOCTL Query ---
        ioctl_res = self._query_storage_ioctl(drive)
        if ioctl_res is not None:
            bus_type_num = ioctl_res
            if bus_type_num == BusTypeUsb:
                return (
                    DeviceClassification.USB_MASS_STORAGE,
                    DetectionConfidence.HIGH_IOCTL_USB,
                    "IOCTL",
                    None,
                    None,
                    "USB",
                )
            elif bus_type_num in (BusTypeSata, BusTypeNvme, BusTypeScsi, BusTypeAta, BusTypeRAID):
                return (
                    DeviceClassification.FIXED_VOLUME,
                    DetectionConfidence.HIGH_IOCTL_USB,
                    "IOCTL",
                    None,
                    None,
                    "INTERNAL_BUS",
                )

        # --- Tier 3: GetDriveTypeW Fallback ---
        drive_type = self._get_drive_type(normalize_mount_point(drive))
        if drive_type == DRIVE_REMOVABLE:
            return (
                DeviceClassification.UNKNOWN_REMOVABLE,
                DetectionConfidence.HEURISTIC_REMOVABLE,
                "GET_DRIVE_TYPE",
                "Degraded detection fallback: DRIVE_REMOVABLE; fixed USB drives cannot be confirmed in this mode.",
                None,
                "REMOVABLE",
            )
        elif drive_type == DRIVE_FIXED:
            return (
                DeviceClassification.FIXED_VOLUME,
                DetectionConfidence.HEURISTIC_REMOVABLE,
                "GET_DRIVE_TYPE",
                "Degraded detection fallback: DRIVE_FIXED; internal drive or unverified USB disk.",
                None,
                "FIXED",
            )
        elif drive_type == DRIVE_CDROM:
            return (
                DeviceClassification.OPTICAL_OR_OTHER,
                DetectionConfidence.HEURISTIC_REMOVABLE,
                "GET_DRIVE_TYPE",
                None,
                None,
                "CDROM",
            )
        elif drive_type == DRIVE_REMOTE:
            return (
                DeviceClassification.OPTICAL_OR_OTHER,
                DetectionConfidence.HEURISTIC_REMOVABLE,
                "GET_DRIVE_TYPE",
                "Remote network share detected; ignored by USB Sentinel.",
                None,
                "NETWORK",
            )
        elif drive_type == DRIVE_RAMDISK:
            return (
                DeviceClassification.OPTICAL_OR_OTHER,
                DetectionConfidence.HEURISTIC_REMOVABLE,
                "GET_DRIVE_TYPE",
                "RAM disk detected; ignored by USB Sentinel.",
                None,
                "RAMDISK",
            )

        return (
            DeviceClassification.UNKNOWN,
            DetectionConfidence.UNVERIFIED,
            "GENERIC",
            "Unable to determine device bus or classification.",
            None,
            None,
        )

    def _query_wmi_physical_disk(self, drive: str) -> Optional[tuple[bool, Optional[str], Optional[str], Optional[str]]]:
        """Query WMI to trace logical disk to physical drive.

        Returns:
            Optional tuple of (is_usb, model_name, pnp_device_id, bus_type_str), or None on failure.
        """
        try:
            wmi_obj = self._get_wmi_client()
            if wmi_obj is None:
                return None

            # 1. Query Win32_LogicalDisk
            logical_disks = wmi_obj.Win32_LogicalDisk(DeviceID=drive)
            if not logical_disks:
                return None
            ldisk = logical_disks[0]

            # 2. Query associator partitions
            partitions = ldisk.associators(wmi_result_class="Win32_DiskPartition")
            if not partitions:
                # Without physical disk associators, bus type cannot be established definitively via WMI
                return None

            # 3. Query associator physical disk drives
            for part in partitions:
                disk_drives = part.associators(wmi_result_class="Win32_DiskDrive")
                for disk in disk_drives:
                    interface_type = str(getattr(disk, "InterfaceType", "")).upper()
                    pnp_id = str(getattr(disk, "PNPDeviceID", "")).upper()
                    model = getattr(disk, "Model", None)

                    # CRITICAL: Detect USB flash drives, USB HDDs, and USB SSDs
                    is_usb = (
                        interface_type == "USB"
                        or pnp_id.startswith("USBSTOR\\")
                        or pnp_id.startswith("USB\\")
                    )
                    return (is_usb, model, pnp_id, "USB" if is_usb else interface_type)

            return None
        except Exception:
            return None

    def _query_storage_ioctl(self, drive: str) -> Optional[int]:
        """Issue IOCTL_STORAGE_QUERY_PROPERTY on \\\\.\\<drive> using ctypes.

        Returns:
            Optional[int]: The STORAGE_BUS_TYPE integer, or None on error.
        """
        if sys.platform != "win32":
            return None

        try:
            kernel32 = ctypes.windll.kernel32

            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            device_path = f"\\\\.\\{drive}"
            handle = kernel32.CreateFileW(
                device_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )

            if handle == INVALID_HANDLE_VALUE:
                return None

            try:
                class STORAGE_PROPERTY_QUERY(ctypes.Structure):
                    _fields_ = [
                        ("PropertyId", ctypes.c_ulong),
                        ("QueryType", ctypes.c_ulong),
                        ("AdditionalParameters", ctypes.c_byte * 1),
                    ]

                query = STORAGE_PROPERTY_QUERY()
                query.PropertyId = StorageDeviceProperty
                query.QueryType = PropertyStandardQuery

                # Output buffer for STORAGE_DEVICE_DESCRIPTOR
                out_buffer = (ctypes.c_byte * 1024)()
                bytes_returned = ctypes.c_ulong(0)

                success = kernel32.DeviceIoControl(
                    handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    ctypes.byref(query),
                    ctypes.sizeof(query),
                    ctypes.byref(out_buffer),
                    ctypes.sizeof(out_buffer),
                    ctypes.byref(bytes_returned),
                    None,
                )

                if not success or bytes_returned.value < 28:
                    return None

                # In STORAGE_DEVICE_DESCRIPTOR, BusType is an enum (int32) at byte offset 28
                bus_type = ctypes.c_int.from_buffer_copy(out_buffer, 28).value
                return bus_type
            finally:
                kernel32.CloseHandle(handle)

        except Exception:
            return None

    def _get_drive_type(self, mount_point: str) -> int:
        """Call GetDriveTypeW via ctypes."""
        if sys.platform != "win32":
            return DRIVE_UNKNOWN
        try:
            return int(ctypes.windll.kernel32.GetDriveTypeW(mount_point))
        except Exception:
            return DRIVE_UNKNOWN

    def _get_volume_information(self, mount_point: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Retrieve Volume Name, File System Name, and Volume Serial Number."""
        if sys.platform != "win32":
            return (None, None, None)
        try:
            kernel32 = ctypes.windll.kernel32
            vol_name_buf = ctypes.create_unicode_buffer(261)
            fs_name_buf = ctypes.create_unicode_buffer(261)
            serial_num = ctypes.c_ulong(0)
            max_comp_len = ctypes.c_ulong(0)
            fs_flags = ctypes.c_ulong(0)

            res = kernel32.GetVolumeInformationW(
                mount_point,
                vol_name_buf,
                len(vol_name_buf),
                ctypes.byref(serial_num),
                ctypes.byref(max_comp_len),
                ctypes.byref(fs_flags),
                fs_name_buf,
                len(fs_name_buf),
            )
            if not res:
                return (None, None, None)

            label = vol_name_buf.value or None
            fs_name = fs_name_buf.value or None
            # Format serial number as standard hexadecimal string (e.g., "A1B2-C3D4")
            raw_serial = serial_num.value
            serial_str = f"{(raw_serial >> 16) & 0xFFFF:04X}-{(raw_serial & 0xFFFF):04X}" if raw_serial else None

            return (label, fs_name, serial_str)
        except Exception:
            return (None, None, None)

    def _get_disk_free_space(self, mount_point: str) -> tuple[Optional[int], Optional[int]]:
        """Retrieve total and available capacity in bytes."""
        try:
            usage = shutil.disk_usage(mount_point)
            return (usage.total, usage.free)
        except Exception:
            return (None, None)

    def _is_drive_mounted(self, mount_point: str) -> bool:
        """Check if a volume is mounted and responsive."""
        try:
            return Path(mount_point).exists()
        except Exception:
            return False

    def _enumerate_logical_drives(self) -> list[str]:
        """Return list of active drive letters (e.g. ['C:', 'E:'])."""
        if sys.platform != "win32":
            return []
        try:
            kernel32 = ctypes.windll.kernel32
            buf_len = kernel32.GetLogicalDriveStringsW(0, None)
            if not buf_len:
                return []
            buf = ctypes.create_unicode_buffer(buf_len)
            kernel32.GetLogicalDriveStringsW(buf_len, buf)

            drives = []
            for drive_str in buf.value.split("\x00"):
                if drive_str:
                    drives.append(normalize_drive_letter(drive_str))
            return drives
        except Exception:
            return []

    def _get_wmi_client(self) -> Optional[Any]:
        """Acquire WMI client instance."""
        if self._wmi_client is not None:
            return self._wmi_client
        if sys.platform != "win32":
            return None
        try:
            import wmi
            return wmi.WMI()
        except Exception:
            return None

    def start_event_monitoring(self, event_callback: Callable[[RawDeviceEvent], None]) -> None:
        """Start listening for Windows volume arrival and removal events via WMI."""
        if self._monitoring:
            return

        # Preflight verification of WMI subsystem availability
        wmi_obj = self._get_wmi_client()
        if wmi_obj is None and not self._allow_non_windows:
            raise RuntimeError("Failed to acquire Windows WMI client for event monitoring.")

        self._callback = event_callback
        self._stop_event.clear()
        self._monitoring = True

        self._monitor_thread = threading.Thread(
            target=self._wmi_event_listener_loop,
            name="USBWatchdog-WMI-Listener",
            daemon=True,
        )
        self._monitor_thread.start()

    def _wmi_event_listener_loop(self) -> None:
        """Background thread loop subscribing to Win32_VolumeChangeEvent."""
        co_initialized = False
        try:
            import pythoncom  # type: ignore[import-not-found]
            pythoncom.CoInitialize()
            co_initialized = True
        except Exception:
            co_initialized = False

        try:
            wmi_obj = self._get_wmi_client()
            if wmi_obj is None:
                return

            # EventType 2 = Arrival, EventType 3 = Removal
            watcher = wmi_obj.watch_for(
                notification_type="Creation",
                wmi_class="Win32_VolumeChangeEvent",
            )
            while not self._stop_event.is_set():
                try:
                    # Timeout of 1000ms allows checking _stop_event periodically
                    event = watcher(timeout_ms=1000)
                    if event is None or self._stop_event.is_set():
                        continue

                    drive_name = getattr(event, "DriveName", None)
                    event_type_int = getattr(event, "EventType", None)

                    if not drive_name or event_type_int not in (2, 3):
                        continue

                    ev_type = DeviceEventType.ARRIVED if event_type_int == 2 else DeviceEventType.REMOVED
                    raw_event = RawDeviceEvent(
                        event_type=ev_type,
                        drive_letter=normalize_drive_letter(drive_name),
                    )
                    if self._callback is not None:
                        self._callback(raw_event)

                except Exception as exc:
                    # wmi.x_wmi_timed_out is standard when no event arrived within timeout
                    exc_name = type(exc).__name__
                    if "timed_out" in exc_name.lower():
                        continue
                    if self._stop_event.is_set():
                        break
        except Exception:
            pass
        finally:
            self._monitoring = False
            if co_initialized:
                try:
                    import pythoncom  # type: ignore[import-not-found]
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    def stop_event_monitoring(self) -> None:
        """Clean shutdown of WMI event listener."""
        if not self._monitoring:
            return
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3.0)
        self._monitoring = False


class UnsupportedPlatformDetector(BaseDeviceDetector):
    """Fallback detector for non-Windows hosts that explicitly communicates unmonitored status."""

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self._config = config or get_config()

    @property
    def is_monitoring(self) -> bool:
        return False

    def get_mounted_volumes(self) -> list[DeviceTelemetry]:
        return []

    def get_volume_telemetry(self, drive_or_path: str) -> Optional[DeviceTelemetry]:
        return None

    def start_event_monitoring(self, event_callback: Callable[[RawDeviceEvent], None]) -> None:
        raise RuntimeError(
            f"Windows WMI device monitoring is not available on platform '{sys.platform}'. "
            "Use MockDeviceDetector for local development and testing on macOS/Linux."
        )

    def stop_event_monitoring(self) -> None:
        pass


class MockDeviceDetector(BaseDeviceDetector):
    """Thread-safe simulated device detector for testing arrival, removal, and discovery races."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._volumes: dict[str, DeviceTelemetry] = {}
        self._callback: Optional[Callable[[RawDeviceEvent], None]] = None
        self._monitoring = False
        self._delay_counts: dict[str, int] = {}
        self._delayed_volumes: dict[str, tuple[DeviceTelemetry, int]] = {}
        self._failing_drives: set[str] = set()

    @property
    def is_monitoring(self) -> bool:
        with self._lock:
            return self._monitoring

    def set_volume(self, telemetry: DeviceTelemetry) -> None:
        """Register a mounted volume in the mock state."""
        with self._lock:
            drive = normalize_drive_letter(telemetry.device_id)
            self._volumes[drive] = telemetry

    def remove_volume(self, drive_letter: str) -> None:
        """Remove a mounted volume from mock state."""
        with self._lock:
            drive = normalize_drive_letter(drive_letter)
            self._volumes.pop(drive, None)
            self._delayed_volumes.pop(drive, None)
            self._delay_counts.pop(drive, None)

    def simulate_delayed_mount(self, drive_letter: str, telemetry: DeviceTelemetry, delay_retries: int = 2) -> None:
        """Simulate a volume that is not accessible for the first N queries (testing retry loop)."""
        with self._lock:
            drive = normalize_drive_letter(drive_letter)
            self._delayed_volumes[drive] = (telemetry, delay_retries)
            self._delay_counts[drive] = 0

    def simulate_failing_volume(self, drive_letter: str) -> None:
        """Simulate a drive whose volume telemetry queries always fail/exhaust retries."""
        with self._lock:
            drive = normalize_drive_letter(drive_letter)
            self._failing_drives.add(drive)

    def get_mounted_volumes(self) -> list[DeviceTelemetry]:
        with self._lock:
            return list(self._volumes.values())

    def get_volume_telemetry(self, drive_or_path: str) -> Optional[DeviceTelemetry]:
        with self._lock:
            drive = normalize_drive_letter(drive_or_path)
            if drive in self._failing_drives:
                return None

            # Handle delayed mount simulation
            if drive in self._delayed_volumes:
                telemetry, target_retries = self._delayed_volumes[drive]
                count = self._delay_counts.get(drive, 0) + 1
                self._delay_counts[drive] = count
                if count <= target_retries:
                    # Still delayed / not yet ready
                    return None
                # Ready now
                self._volumes[drive] = telemetry
                self._delayed_volumes.pop(drive, None)
                return telemetry

            return self._volumes.get(drive)

    def start_event_monitoring(self, event_callback: Callable[[RawDeviceEvent], None]) -> None:
        with self._lock:
            self._callback = event_callback
            self._monitoring = True

    def stop_event_monitoring(self) -> None:
        with self._lock:
            self._monitoring = False
            self._callback = None

    def simulate_arrival(self, drive_letter: str, telemetry: Optional[DeviceTelemetry] = None) -> None:
        """Simulate hardware arrival notification for a drive letter."""
        drive = normalize_drive_letter(drive_letter)
        if telemetry is not None:
            self.set_volume(telemetry)

        callback = None
        with self._lock:
            if self._monitoring and self._callback is not None:
                callback = self._callback

        if callback is not None:
            callback(RawDeviceEvent(event_type=DeviceEventType.ARRIVED, drive_letter=drive))

    def simulate_removal(self, drive_letter: str) -> None:
        """Simulate hardware removal notification for a drive letter."""
        drive = normalize_drive_letter(drive_letter)
        self.remove_volume(drive)

        callback = None
        with self._lock:
            if self._monitoring and self._callback is not None:
                callback = self._callback

        if callback is not None:
            callback(RawDeviceEvent(event_type=DeviceEventType.REMOVED, drive_letter=drive))


def get_device_detector(config: Optional[SentinelConfig] = None) -> BaseDeviceDetector:
    """Return the platform-appropriate storage device detector instance.

    On Windows hosts (win32), returns WindowsDeviceDetector.
    On non-Windows development hosts (macOS/Linux), returns UnsupportedPlatformDetector.
    """
    cfg = config or get_config()
    if sys.platform == "win32":
        return WindowsDeviceDetector(config=cfg)
    return UnsupportedPlatformDetector(config=cfg)
