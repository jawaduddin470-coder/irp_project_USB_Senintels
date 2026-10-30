"""Platform-independent USB watchdog lifecycle, event debouncing, and scanner coordination.

This module coordinates hardware arrival/removal notifications, normalizes events,
debounces duplicate platform signals, manages mount-readiness retries, tracks active
device sessions, propagates cancellation on disconnection, and safely invokes non-destructive
scans with comprehensive audit logging.

Design Principles & Security Guarantees:
1. **Never Automatically Quarantine or Delete**:
   Upon USB device insertion, Sentinel strictly adheres to the approved default policy
   `ALERT_AND_LOG_ONLY`. Files are inspected and heuristic risks are flagged in the audit
   ledger, but files are NEVER moved, encrypted, or deleted automatically.
2. **Defensive Drive Containment**:
   Sentinel scans ONLY confirmed, mounted USB storage volumes. System drives (`C:\\`),
   internal fixed disks, network shares, and non-USB media are excluded from default
   scanning.
3. **Resilient Event State Machine**:
   Handles insertion before mount readiness (bounded retries), duplicate arrival/removal
   debouncing, device removal while scanning is in progress, and reconnecting the same
   drive letter without state corruption.
4. **Prompt Cancellation Propagation**:
   When a device is unplugged during recursive inspection or SHA-256 calculation, the
   associated session's cancellation event is set immediately. The scanner safely aborts
   traversal and marks status as `ABORTED_DISCONNECT`. An interrupted scan is NEVER
   reported as successful.
5. **Deterministic Lifecycle & Cleanup**:
   Context manager support (`with USBWatchdog(...) as wd:`) and explicit `start()` / `stop()`
   methods ensure all worker threads, discovery loops, and WMI subscriptions terminate
   cleanly.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Final, List, Optional, Tuple

from usb_sentinel.audit import AuditLedger
from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.device_detection import (
    BaseDeviceDetector,
    DeviceEventType,
    RawDeviceEvent,
    UnsupportedPlatformDetector,
    WindowsDeviceDetector,
    get_device_detector,
    normalize_drive_letter,
)
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DeviceClassification,
    DeviceTelemetry,
    ScanStatus,
    utc_now,
)
from usb_sentinel.scanner import ScanReport, VolumeScanner


class WatchdogState(str, Enum):
    """Lifecycle state of the USB watchdog coordinator."""

    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"


@dataclass
class ActiveDeviceSession:
    """Represents a verified, currently connected USB mass-storage device session.

    Attributes:
        session_id: Unique UUID identifier for this connection session.
        drive_letter: Normalized uppercase drive letter (e.g. "E:").
        telemetry: Full hardware and volume telemetry collected for this volume.
        connected_at: UTC timestamp when the session was established.
        cancellation_event: Threading event signaled if device is removed or watcher stops.
        scan_in_progress: Flag indicating whether an active volume scan is underway.
        is_initial_device: True if device was already connected at watcher startup.
    """

    session_id: str
    drive_letter: str
    telemetry: DeviceTelemetry
    connected_at: datetime
    cancellation_event: threading.Event = field(default_factory=threading.Event)
    scan_in_progress: bool = False
    is_initial_device: bool = False

    def is_cancelled(self) -> bool:
        """Return True if session has been cancelled or device removed."""
        return self.cancellation_event.is_set()

    def cancel(self) -> None:
        """Signal cancellation for this active session."""
        self.cancellation_event.set()


class USBWatchdog:
    """Platform-independent coordinator for USB device monitoring, debouncing, and scanning."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        detector: Optional[BaseDeviceDetector] = None,
        audit_ledger: Optional[AuditLedger] = None,
        scanner: Optional[VolumeScanner] = None,
        on_device_arrival: Optional[Callable[[ActiveDeviceSession], None]] = None,
        on_device_removal: Optional[Callable[[str], None]] = None,
        on_scan_completed: Optional[Callable[[ActiveDeviceSession, ScanReport], None]] = None,
    ) -> None:
        """Initialize the USB Watchdog coordinator.

        Args:
            config: Sentinel application configuration.
            detector: Storage device detector backend (defaults to WindowsDeviceDetector on Win32,
                      or UnsupportedPlatformDetector on macOS/Linux).
            audit_ledger: Append-only CSV audit ledger for compliance recording.
            scanner: Recursive volume scanner for non-destructive inspection.
            on_device_arrival: Optional hook invoked when a new USB session is confirmed.
            on_device_removal: Optional hook invoked when a USB device is disconnected.
            on_scan_completed: Optional hook invoked when an inspection scan completes.
        """
        self._config = config or get_config()
        self._audit_ledger = audit_ledger or AuditLedger(config=self._config)
        self._scanner = scanner or VolumeScanner(config=self._config)

        self._detector = detector or get_device_detector(self._config)

        self._on_device_arrival = on_device_arrival
        self._on_device_removal = on_device_removal
        self._on_scan_completed = on_scan_completed

        # Synchronization and state
        self._lock = threading.RLock()
        self._state = WatchdogState.STOPPED
        self._stop_event = threading.Event()
        self._active_sessions: dict[str, ActiveDeviceSession] = {}
        self._pending_discoveries: dict[str, str] = {}  # drive_letter -> discovery_token
        self._last_events: dict[str, tuple[DeviceEventType, float]] = {}  # drive -> (event_type, monotonic_time)
        self._suppressed_duplicates_count = 0
        self._worker_threads: list[threading.Thread] = []

        # Configured timeouts and retries
        self._debounce_interval = self._config.watchdog_debounce_seconds
        self._max_retries = self._config.watchdog_discovery_retries
        self._retry_delay = self._config.watchdog_retry_delay_seconds
        self._auto_scan = self._config.watchdog_auto_scan

    @property
    def config(self) -> SentinelConfig:
        return self._config

    @property
    def detector(self) -> BaseDeviceDetector:
        return self._detector

    @property
    def audit_ledger(self) -> AuditLedger:
        return self._audit_ledger

    @property
    def state(self) -> WatchdogState:
        with self._lock:
            return self._state

    @property
    def suppressed_duplicates_count(self) -> int:
        with self._lock:
            return self._suppressed_duplicates_count

    def get_active_sessions(self) -> list[ActiveDeviceSession]:
        """Return a snapshot of all currently active USB device sessions."""
        with self._lock:
            return list(self._active_sessions.values())

    def get_session(self, drive_letter: str) -> Optional[ActiveDeviceSession]:
        """Retrieve an active device session by drive letter."""
        with self._lock:
            drive = normalize_drive_letter(drive_letter)
            return self._active_sessions.get(drive)

    def start(self, discover_initial: bool = True) -> None:
        """Start the USB watchdog monitoring subsystem.

        Args:
            discover_initial: If True, discovers currently mounted USB devices at startup
                              and lists them as initial baseline sessions.

        Raises:
            RuntimeError: If watchdog is already running or platform detector fails to initialize.
        """
        with self._lock:
            if self._state in (WatchdogState.RUNNING, WatchdogState.STARTING):
                raise RuntimeError("USBWatchdog is already running.")
            self._state = WatchdogState.STARTING
            self._stop_event.clear()

        # Emit WATCHDOG_STARTED audit event
        start_evt = AuditEvent(
            event_id=f"EVT_WDSTART_{uuid.uuid4().hex[:8]}",
            timestamp=utc_now(),
            event_type=AuditEventType.WATCHDOG_STARTED,
            status=AuditStatus.INFORMATIONAL,
            details="USB Watchdog subsystem started.",
        )
        try:
            self._audit_ledger.append_event(start_evt)
        except Exception:
            pass

        # 1. Discover already-connected USB devices at startup
        if discover_initial:
            try:
                initial_volumes = self._detector.get_mounted_volumes()
                for telemetry in initial_volumes:
                    if (
                        telemetry.classification in (
                            DeviceClassification.PHYSICAL_USB,
                            DeviceClassification.OTHER_REMOVABLE,
                        )
                        and not telemetry.is_virtual
                    ):
                        self._register_initial_session(telemetry)
            except Exception as exc:
                err_evt = AuditEvent(
                    event_id=f"EVT_WDINITERR_{uuid.uuid4().hex[:8]}",
                    timestamp=utc_now(),
                    event_type=AuditEventType.SYSTEM_WARNING,
                    status=AuditStatus.WARNING,
                    details=f"Failed to query initial mounted volumes: {exc}",
                    error_message=str(exc),
                )
                try:
                    self._audit_ledger.append_event(err_evt)
                except Exception:
                    pass

        # 2. Begin listening for platform arrival and removal events
        try:
            self._detector.start_event_monitoring(self._handle_raw_event)
            with self._lock:
                self._state = WatchdogState.RUNNING
        except Exception as exc:
            with self._lock:
                self._state = WatchdogState.STOPPED
            err_evt = AuditEvent(
                event_id=f"EVT_WDFAIL_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SYSTEM_ERROR,
                status=AuditStatus.ERROR,
                details=f"Watchdog event listener failed to start: {exc}",
                error_message=str(exc),
            )
            try:
                self._audit_ledger.append_event(err_evt)
            except Exception:
                pass
            raise

    def stop(self) -> None:
        """Deterministically stop the watchdog and clean up all resources and workers."""
        with self._lock:
            if self._state in (WatchdogState.STOPPED, WatchdogState.STOPPING):
                return
            self._state = WatchdogState.STOPPING
            self._stop_event.set()

            # Signal cancellation on all active sessions
            for session in self._active_sessions.values():
                session.cancel()

            # Clear pending discoveries
            self._pending_discoveries.clear()

        # Stop platform detector monitoring
        try:
            self._detector.stop_event_monitoring()
        except Exception:
            pass

        # Wait for worker threads to finish
        with self._lock:
            threads = list(self._worker_threads)
        for thread in threads:
            if thread.is_alive() and thread != threading.current_thread():
                thread.join(timeout=2.0)

        with self._lock:
            self._active_sessions.clear()
            self._worker_threads.clear()
            self._state = WatchdogState.STOPPED

        # Emit WATCHDOG_STOPPED audit event
        stop_evt = AuditEvent(
            event_id=f"EVT_WDSTOP_{uuid.uuid4().hex[:8]}",
            timestamp=utc_now(),
            event_type=AuditEventType.WATCHDOG_STOPPED,
            status=AuditStatus.INFORMATIONAL,
            details="USB Watchdog subsystem stopped cleanly.",
        )
        try:
            self._audit_ledger.append_event(stop_evt)
        except Exception:
            pass

    def __enter__(self) -> USBWatchdog:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    def _handle_raw_event(self, raw_event: RawDeviceEvent) -> None:
        """Normalize raw platform event, apply debouncing, and dispatch to worker."""
        drive = normalize_drive_letter(raw_event.drive_letter)
        now_ts = time.monotonic()

        with self._lock:
            if self._state not in (WatchdogState.RUNNING, WatchdogState.STARTING):
                return

            # Debouncing: suppress identical event types for the same drive within debounce interval
            last_event = self._last_events.get(drive)
            if last_event is not None:
                last_type, last_time = last_event
                if last_type == raw_event.event_type and (now_ts - last_time) < self._debounce_interval:
                    self._suppressed_duplicates_count += 1
                    return

            self._last_events[drive] = (raw_event.event_type, now_ts)

        # Dispatch event asynchronously
        if raw_event.event_type == DeviceEventType.ARRIVED:
            worker = threading.Thread(
                target=self._process_arrival_workflow,
                args=(drive,),
                name=f"USBWatchdog-Arrival-{drive}",
                daemon=True,
            )
            with self._lock:
                self._worker_threads.append(worker)
            worker.start()
        elif raw_event.event_type == DeviceEventType.REMOVED:
            # Process removal synchronously or in worker to avoid delay
            self._process_removal_workflow(drive)

    def _process_arrival_workflow(self, drive: str) -> None:
        """Handle USB arrival: bounded mount retry, classification check, session creation, and optional scan."""
        discovery_token = uuid.uuid4().hex

        with self._lock:
            # Avoid duplicate active sessions for the same drive letter
            existing_session = self._active_sessions.get(drive)
            if existing_session is not None and not existing_session.is_cancelled():
                return
            self._pending_discoveries[drive] = discovery_token

        telemetry: Optional[DeviceTelemetry] = None

        # Bounded mount retry loop
        for attempt in range(self._max_retries):
            if self._stop_event.is_set():
                return

            with self._lock:
                # If removal arrived while discovering, abort immediately!
                if self._pending_discoveries.get(drive) != discovery_token:
                    return

            try:
                telemetry = self._detector.get_volume_telemetry(drive)
            except Exception:
                telemetry = None

            if telemetry is not None and telemetry.mount_point:
                # Volume is accessible!
                break

            # Sleep between retries (checking stop_event)
            if self._stop_event.wait(self._retry_delay):
                return

        # Check if removal arrived during retry loop
        with self._lock:
            if self._pending_discoveries.get(drive) != discovery_token:
                return

        if telemetry is None:
            with self._lock:
                self._pending_discoveries.pop(drive, None)
            # Bounded retry exhaustion: volume never became accessible
            warn_evt = AuditEvent(
                event_id=f"EVT_MOUNTERR_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SYSTEM_WARNING,
                status=AuditStatus.WARNING,
                device_ref=drive,
                details=f"Volume arrived at {drive} but was not accessible after {self._max_retries} discovery retries.",
            )
            try:
                self._audit_ledger.append_event(warn_evt)
            except Exception:
                pass
            return

        # Explicit SystemDrive protection: NEVER process or scan the Windows OS drive
        system_drive = os.environ.get("SystemDrive", "C:").upper()
        if not system_drive.endswith(":"):
            system_drive = f"{system_drive}:"
        if drive.upper() == system_drive:
            with self._lock:
                self._pending_discoveries.pop(drive, None)
            warn_evt = AuditEvent(
                event_id=f"EVT_SYSDRV_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SYSTEM_WARNING,
                status=AuditStatus.WARNING,
                device_ref=drive,
                details=f"Volume arrived at {drive} matches SystemDrive ({system_drive}). Strictly ignored for safety.",
            )
            try:
                self._audit_ledger.append_event(warn_evt)
            except Exception:
                pass
            return

        # Classification check: only process verified physical USB storage or non-virtual removable media
        if (
            telemetry.classification not in (
                DeviceClassification.PHYSICAL_USB,
                DeviceClassification.OTHER_REMOVABLE,
            )
            or telemetry.is_virtual
        ):
            with self._lock:
                self._pending_discoveries.pop(drive, None)
            # Virtual disk image, internal fixed disk, optical drive, or unclassified device: DO NOT TREAT AS USB!
            warn_evt = AuditEvent(
                event_id=f"EVT_IGN_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SYSTEM_WARNING,
                status=AuditStatus.INFORMATIONAL,
                device_ref=drive,
                details=(
                    f"Volume arrived at {drive} but ignored (classification={telemetry.classification.value}). "
                    "Non-USB devices and fixed system disks are not processed."
                ),
            )
            try:
                self._audit_ledger.append_event(warn_evt)
            except Exception:
                pass
            return

        # Create active device session
        session = ActiveDeviceSession(
            session_id=uuid.uuid4().hex,
            drive_letter=drive,
            telemetry=telemetry,
            connected_at=utc_now(),
            is_initial_device=False,
        )

        with self._lock:
            # Atomic transition from pending discovery to active session
            if self._stop_event.is_set():
                self._pending_discoveries.pop(drive, None)
                return
            if self._pending_discoveries.get(drive) != discovery_token:
                # Device was removed while evaluating telemetry; abort cleanly!
                return
            self._pending_discoveries.pop(drive, None)
            self._active_sessions[drive] = session

        # Emit DEVICE_INSERTED audit event
        insert_evt = AuditEvent(
            event_id=f"EVT_INSERT_{uuid.uuid4().hex[:8]}",
            timestamp=session.connected_at,
            event_type=AuditEventType.DEVICE_INSERTED,
            status=AuditStatus.SUCCESS,
            device_ref=drive,
            target_path=telemetry.mount_point,
            details=(
                f"USB mass storage volume connected: Label='{telemetry.volume_label or 'NO_LABEL'}', "
                f"FS='{telemetry.filesystem or 'UNKNOWN'}', Capacity={telemetry.total_bytes or 0} B. "
                f"Confidence={telemetry.confidence.value}."
            ),
        )
        try:
            self._audit_ledger.append_event(insert_evt)
        except Exception:
            pass

        # Trigger arrival hook
        if self._on_device_arrival is not None:
            try:
                self._on_device_arrival(session)
            except Exception:
                pass

        # Optional auto-scan under ALERT_AND_LOG_ONLY policy
        if self._auto_scan and not session.is_cancelled() and not self._stop_event.is_set():
            self.scan_device(session)

    def _process_removal_workflow(self, drive: str) -> None:
        """Handle USB device removal: cancel discovery, signal session cancellation, and audit."""
        with self._lock:
            # 1. Invalidate any in-flight discovery
            self._pending_discoveries.pop(drive, None)

            # 2. Extract and remove active session
            session = self._active_sessions.pop(drive, None)

        if session is not None:
            # Signal cancellation to interrupt active scan
            session.cancel()

            # Emit DEVICE_REMOVED audit event
            remove_evt = AuditEvent(
                event_id=f"EVT_REMOVE_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.DEVICE_REMOVED,
                status=AuditStatus.SUCCESS,
                device_ref=drive,
                target_path=session.telemetry.mount_point,
                details=f"USB storage device removed from {drive}.",
            )
            try:
                self._audit_ledger.append_event(remove_evt)
            except Exception:
                pass

            # Trigger removal hook
            if self._on_device_removal is not None:
                try:
                    self._on_device_removal(drive)
                except Exception:
                    pass

    def _register_initial_session(self, telemetry: DeviceTelemetry) -> None:
        """Register an already-connected volume discovered at startup."""
        drive = normalize_drive_letter(telemetry.device_id)
        session = ActiveDeviceSession(
            session_id=uuid.uuid4().hex,
            drive_letter=drive,
            telemetry=telemetry,
            connected_at=utc_now(),
            is_initial_device=True,
        )
        with self._lock:
            self._active_sessions[drive] = session

        init_evt = AuditEvent(
            event_id=f"EVT_INITDEV_{uuid.uuid4().hex[:8]}",
            timestamp=session.connected_at,
            event_type=AuditEventType.DEVICE_INSERTED,
            status=AuditStatus.INFORMATIONAL,
            device_ref=drive,
            target_path=telemetry.mount_point,
            details=(
                f"Already-connected USB volume detected at startup: Label='{telemetry.volume_label or 'NO_LABEL'}', "
                f"FS='{telemetry.filesystem or 'UNKNOWN'}'. Confidence={telemetry.confidence.value}."
            ),
        )
        try:
            self._audit_ledger.append_event(init_evt)
        except Exception:
            pass

    def scan_device(self, session: ActiveDeviceSession) -> Optional[ScanReport]:
        """Perform a defensive, read-only volume scan for an active USB session.

        Guarantees:
        - NEVER moves, encrypts, or deletes files automatically.
        - Passes cancellation signal so device removal halts scanning immediately.
        - Records SCAN_STARTED, SCAN_COMPLETED, SCAN_ABORTED, and FILE_FLAGGED audit events.
        """
        if session.is_cancelled() or self._stop_event.is_set():
            return None

        target_path = session.telemetry.mount_point
        if not target_path or not Path(target_path).exists():
            return None

        # Explicit safety check: NEVER scan the OS system drive
        system_drive = os.environ.get("SystemDrive", "C:").upper()
        if not system_drive.endswith(":"):
            system_drive = f"{system_drive}:"
        if session.drive_letter.upper() == system_drive:
            warn_evt = AuditEvent(
                event_id=f"EVT_SYSSCAN_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SYSTEM_WARNING,
                status=AuditStatus.WARNING,
                device_ref=session.drive_letter,
                details=f"Refusing to scan system drive {session.drive_letter}.",
            )
            try:
                self._audit_ledger.append_event(warn_evt)
            except Exception:
                pass
            return None

        session.scan_in_progress = True

        # Emit SCAN_STARTED
        scan_start_evt = AuditEvent(
            event_id=f"EVT_SCANSTART_{uuid.uuid4().hex[:8]}",
            timestamp=utc_now(),
            event_type=AuditEventType.SCAN_STARTED,
            status=AuditStatus.INFORMATIONAL,
            device_ref=session.drive_letter,
            target_path=target_path,
            details=f"Starting non-destructive scan of USB volume at {session.drive_letter}.",
        )
        try:
            self._audit_ledger.append_event(scan_start_evt)
        except Exception:
            pass

        def is_cancelled() -> bool:
            return session.is_cancelled() or self._stop_event.is_set()

        try:
            report = self._scanner.scan(
                target_dir=target_path,
                is_cancelled=is_cancelled,
            )
        except Exception as exc:
            session.scan_in_progress = False
            fail_evt = AuditEvent(
                event_id=f"EVT_SCANERR_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SYSTEM_ERROR,
                status=AuditStatus.ERROR,
                device_ref=session.drive_letter,
                target_path=target_path,
                details=f"Volume scan failed with exception: {exc}",
                error_message=str(exc),
            )
            try:
                self._audit_ledger.append_event(fail_evt)
            except Exception:
                pass
            return None

        session.scan_in_progress = False

        # Handle aborted scan (e.g. device removed mid-scan)
        if report.result.status == ScanStatus.ABORTED_DISCONNECT:
            abort_evt = AuditEvent(
                event_id=f"EVT_SCANABRT_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SCAN_ABORTED,
                status=AuditStatus.WARNING,
                device_ref=session.drive_letter,
                target_path=target_path,
                details="Scan was aborted due to device disconnection or cancellation.",
            )
            try:
                self._audit_ledger.append_event(abort_evt)
            except Exception:
                pass
            return report

        # Scan completed successfully
        scan_end_evt = AuditEvent(
            event_id=f"EVT_SCANDONE_{uuid.uuid4().hex[:8]}",
            timestamp=utc_now(),
            event_type=AuditEventType.SCAN_COMPLETED,
            status=AuditStatus.SUCCESS,
            device_ref=session.drive_letter,
            target_path=target_path,
            details=(
                f"Scan completed: {report.result.files_inspected} files inspected, "
                f"{report.result.findings_count} findings, {report.result.errors_count} errors."
            ),
        )
        try:
            self._audit_ledger.append_event(scan_end_evt)
        except Exception:
            pass

        # Log FILE_FLAGGED for each heuristic finding (ALERT AND LOG ONLY)
        for finding in report.findings:
            flag_evt = AuditEvent(
                event_id=f"EVT_FLAG_{uuid.uuid4().hex[:8]}",
                timestamp=finding.timestamp,
                event_type=AuditEventType.FILE_FLAGGED,
                status=AuditStatus.WARNING,
                device_ref=session.drive_letter,
                target_path=finding.file_path,
                details=f"Flagged {finding.severity.value} risk: {finding.explanation}. Rule: {finding.matched_rule}.",
            )
            try:
                self._audit_ledger.append_event(flag_evt)
            except Exception:
                pass

        if self._on_scan_completed is not None:
            try:
                self._on_scan_completed(session, report)
            except Exception:
                pass

        return report
