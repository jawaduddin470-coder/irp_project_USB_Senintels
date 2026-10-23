"""Shared typed data models for USB Sentinel.

This module defines immutable and structured dataclasses and enums representing
hardware telemetry, file metadata, scan results, risk assessments, quarantine
records, and audit events.

Design Principles (for beginner developers):
1. **Explicit Unknowns**: Any data that cannot be determined or is not yet available
   is explicitly typed as `None` rather than fabricating dummy defaults (like "" or 0).
2. **Timezone-Aware UTC Timestamps**: All event timestamps use `datetime` with
   explicit UTC timezone info (`timezone.utc`) to prevent timezone ambiguity across systems.
3. **Immutability & Safety**: Telemetry, file metadata, and risk findings are marked
   `frozen=True` where appropriate to prevent accidental in-place mutation.
4. **Privacy-Conscious Telemetry**: Models avoid storing persistent hardware chip serial
   numbers; only volume-level serials (generated during filesystem format) are captured.
5. **Heuristic Clarity**: Findings explicitly identify risks as *heuristic execution vectors*
   (e.g., .bat/.ps1/.exe scripts and executables), avoiding false claims that a file is
   definitively malware.
6. **Zero External / Windows Dependencies**: Pure standard library typing and dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Final, Optional, Tuple


def utc_now() -> datetime:
    """Generate a timezone-aware UTC datetime for current instant."""
    return datetime.now(timezone.utc)


# ==============================================================================
# Enumerations
# ==============================================================================


class DeviceClassification(str, Enum):
    """Classification of an inspected storage volume."""

    USB_MASS_STORAGE = "USB_MASS_STORAGE"
    UNKNOWN_REMOVABLE = "UNKNOWN_REMOVABLE"
    FIXED_VOLUME = "FIXED_VOLUME"
    OPTICAL_OR_OTHER = "OPTICAL_OR_OTHER"
    UNKNOWN = "UNKNOWN"


class DetectionConfidence(str, Enum):
    """Degree of hardware certainty established during device detection."""

    DEFINITIVE_WMI_USB = "DEFINITIVE_WMI_USB"  # Verified USB bus/interface via WMI
    HIGH_IOCTL_USB = "HIGH_IOCTL_USB"          # Verified BusTypeUsb via DeviceIoControl
    HEURISTIC_REMOVABLE = "HEURISTIC_REMOVABLE"# Degraded fallback via DRIVE_REMOVABLE
    UNVERIFIED = "UNVERIFIED"


class ScanStatus(str, Enum):
    """Lifecycle status of a volume or directory scan."""

    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_ERRORS = "COMPLETED_WITH_ERRORS"
    ABORTED_DISCONNECT = "ABORTED_DISCONNECT"


class RiskSeverity(str, Enum):
    """Heuristic risk classification tier."""

    INFORMATIONAL = "INFORMATIONAL"
    SUSPICIOUS = "SUSPICIOUS"  # Heuristically flagged executable or script vector
    HIGH = "HIGH"


class DetectionMethod(str, Enum):
    """Mechanism used to identify a risk or finding."""

    EXTENSION_HEURISTIC = "EXTENSION_HEURISTIC"
    INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"
    ANOMALOUS_ATTRIBUTES = "ANOMALOUS_ATTRIBUTES"


class QuarantineStatus(str, Enum):
    """Transaction state of a quarantined file."""

    STAGED = "STAGED"                                    # Step 1-2: Encrypted in staging .tmp
    COMMITTED = "COMMITTED"                              # Step 3-4: Verified and promoted to vault
    QUARANTINED = "QUARANTINED"                          # Step 5 complete: Source deleted from USB
    QUARANTINE_SOURCE_LOCKED = "QUARANTINE_SOURCE_LOCKED"# Step 5 incomplete: USB write-protected
    ORPHAN_RECONCILED = "ORPHAN_RECONCILED"              # Reconciled from unindexed vault file
    RESTORED = "RESTORED"                                # Successfully restored to target
    FAILED = "FAILED"                                    # Transaction aborted


class AuditEventType(str, Enum):
    """Category of event recorded in the audit ledger."""

    DEVICE_INSERTED = "DEVICE_INSERTED"
    DEVICE_REMOVED = "DEVICE_REMOVED"
    WATCHDOG_STARTED = "WATCHDOG_STARTED"
    WATCHDOG_STOPPED = "WATCHDOG_STOPPED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_ABORTED = "SCAN_ABORTED"
    FILE_FLAGGED = "FILE_FLAGGED"
    QUARANTINE_INITIATED = "QUARANTINE_INITIATED"
    QUARANTINE_COMMITTED = "QUARANTINE_COMMITTED"
    QUARANTINE_SOURCE_LOCKED = "QUARANTINE_SOURCE_LOCKED"
    FILE_RESTORED = "FILE_RESTORED"
    CONFIGURATION_LOADED = "CONFIGURATION_LOADED"
    SYSTEM_WARNING = "SYSTEM_WARNING"
    SYSTEM_ERROR = "SYSTEM_ERROR"


class AuditStatus(str, Enum):
    """Execution outcome status for an audit event."""

    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    INFORMATIONAL = "INFORMATIONAL"


# ==============================================================================
# Domain Data Models
# ==============================================================================


@dataclass(frozen=True)
class DeviceTelemetry:
    """Hardware and volume metadata captured from a mounted storage device.

    Avoids capturing persistent hardware serial numbers to preserve user privacy.
    Captures logical volume serial numbers (assigned upon filesystem formatting) instead.
    """

    device_id: str
    detected_at: datetime
    mount_point: Optional[str] = None          # e.g., "E:\\" (Windows) or "/Volumes/USB" (POSIX)
    volume_label: Optional[str] = None         # e.g., "SANDISK_32"
    filesystem: Optional[str] = None           # e.g., "FAT32", "NTFS", "exFAT"
    total_bytes: Optional[int] = None          # Total capacity in bytes
    free_bytes: Optional[int] = None           # Available space in bytes
    volume_serial: Optional[str] = None        # Filesystem volume serial number
    classification: DeviceClassification = DeviceClassification.UNKNOWN
    confidence: DetectionConfidence = DetectionConfidence.UNVERIFIED
    detection_backend: str = "GENERIC"         # "WMI", "IOCTL", "GET_DRIVE_TYPE", "MOCK"
    warning: Optional[str] = None              # e.g., degraded detection mode warning
    device_model: Optional[str] = None         # Hardware product model name (non-sensitive)
    bus_type: Optional[str] = None             # Physical interface bus type (e.g. "USB", "NVMe")


@dataclass(frozen=True)
class FileMetadata:
    """Filesystem metadata collected during recursive volume inspection.

    Captures file attributes and platform-aware creation/modification timestamps.
    """

    filename: str
    file_path: str                             # Absolute path to the file
    extension: str                             # Lowercase with leading dot, e.g. ".exe"
    size_bytes: int                            # File size in bytes
    modified_at: datetime                      # Last modification timestamp (UTC)
    created_at: Optional[datetime] = None      # Creation timestamp (UTC) if supported
    is_symlink: bool = False                   # True if entry is a symlink or junction
    is_readonly: bool = False                  # True if read-only attribute is set


@dataclass(frozen=True)
class RiskFinding:
    """Heuristic risk finding associated with an inspected file.

    IMPORTANT: A finding indicates a potential execution or security vector,
    such as an executable or script extension on removable media. It does NOT
    constitute verified proof of malicious payload code.
    """

    file_path: str
    severity: RiskSeverity
    matched_rule: str                          # e.g. "RULE_SUSPICIOUS_EXTENSION_BAT"
    explanation: str
    timestamp: datetime = field(default_factory=utc_now)
    detection_method: DetectionMethod = DetectionMethod.EXTENSION_HEURISTIC


@dataclass(frozen=True)
class ScanResult:
    """Summary record of a recursive volume or directory inspection."""

    scan_id: str
    target_path: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    files_inspected: int = 0
    findings_count: int = 0
    errors_count: int = 0
    status: ScanStatus = ScanStatus.IN_PROGRESS
    error_summary: Optional[str] = None


@dataclass(frozen=True)
class QuarantineRecord:
    """Durable tracking record for a quarantined file in the encrypted vault.

    Corresponds to an entry in `quarantine_index.txt`.
    Does NOT store encryption keys, passphrases, or raw file contents.
    """

    quarantine_id: str                         # Unique UUID identifier
    original_path: str                         # Original location on removable drive
    vault_filename: str                        # Filename in vault, e.g. "<id>.qnt"
    quarantined_at: datetime                   # Timestamp of quarantine (UTC)
    sha256_hash: Optional[str] = None          # SHA-256 digest of original plaintext
    file_size_bytes: Optional[int] = None      # Original file size in bytes
    status: QuarantineStatus = QuarantineStatus.COMMITTED
    is_restored: bool = False                  # Restoration flag
    restored_at: Optional[datetime] = None     # Timestamp of restoration (UTC)
    restored_path: Optional[str] = None        # Destination path where restored


@dataclass(frozen=True)
class AuditEvent:
    """Single audit ledger entry for `usb_sentinel_audit.csv`.

    Strictly serialized with RFC 4180 compliance and CSV formula sanitization.
    """

    event_id: str                              # Unique event UUID or sequential ID
    timestamp: datetime                        # Time of event (UTC)
    event_type: AuditEventType                 # Action or incident category
    status: AuditStatus                        # Outcome of event
    device_ref: Optional[str] = None           # Associated drive letter or volume label
    target_path: Optional[str] = None          # Associated file path
    quarantine_id: Optional[str] = None        # Associated quarantine ID if applicable
    sha256_hash: Optional[str] = None          # Associated file SHA-256 hash if applicable
    details: Optional[str] = None              # Human-readable contextual description
    error_message: Optional[str] = None        # Exception or failure description
