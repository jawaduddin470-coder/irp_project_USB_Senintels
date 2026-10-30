"""Web dashboard interface for USB Sentinel.

Provides a locally hosted web console (Flask + Jinja2 + CSS) adhering to
the non-destructive ALERT_AND_LOG_ONLY security model.

Key Architecture & Safety Controls:
1. Pure Python Backend & Server-Rendered HTML:
   Zero JavaScript build steps, zero npm/node dependencies. Plain HTML5 forms,
   Jinja2 templating, and accessible styling.
2. Localhost Only:
   Enforces binding to 127.0.0.1 (never 0.0.0.0).
3. CSRF Protection:
   Session-backed cryptographic tokens required for all state-changing POST requests.
4. Path Traversal & Injection Defense:
   Validates all filesystem targets, report downloads, and custom restoration destinations.
5. Background Scanning Worker:
   Executes volume inspection asynchronously without blocking HTTP worker threads,
   while supporting synchronous evaluation in tests.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

logger = logging.getLogger(__name__)

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)

from usb_sentinel.audit import AuditLedger, format_utc_timestamp
from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.device_detection import (
    BaseDeviceDetector,
    get_device_detector,
)
from usb_sentinel.integrity import IntegrityError, IntegrityIOError, compute_sha256
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DeviceClassification,
    DeviceTelemetry,
    QuarantineRecord,
    QuarantineStatus,
    RiskFinding,
    RiskSeverity,
    ScanStatus,
    utc_now,
)
from usb_sentinel.quarantine import QuarantineManager, QuarantinePolicyViolationError, QuarantineError
from usb_sentinel.quarantine_index import QuarantineIndexManager
from usb_sentinel.reporting import IncidentData, IncidentReportGenerator
from usb_sentinel.restoration import (
    RestorationCollisionError,
    RestorationConflictPolicy,
    RestorationError,
    RestorationManager,
)
from usb_sentinel.risk_engine import RiskEngine
from usb_sentinel.scanner import ScanReport, VolumeScanner
from usb_sentinel.vault import VaultManager
from usb_sentinel.watchdog import ActiveDeviceSession, USBWatchdog, WatchdogState


# ==============================================================================
# View Models & Adapters
# ==============================================================================


@dataclass
class QuarantineViewModel:
    """Template adapter for QuarantineRecord ensuring consistent attribute access."""

    quarantine_id: str
    original_path: str
    vault_id: str
    vault_filename: str
    file_size_bytes: int
    quarantined_at: str
    source_sha256: str
    sha256_hash: str
    risk_score: int
    classification: str
    detection_reasons: list[str]
    status: str
    is_restored: bool
    raw_record: QuarantineRecord


def adapt_quarantine_record(record: QuarantineRecord) -> QuarantineViewModel:
    """Adapt a raw QuarantineRecord into a QuarantineViewModel."""
    q_at_str = (
        format_utc_timestamp(record.quarantined_at)
        if hasattr(record, "quarantined_at") and record.quarantined_at
        else "N/A"
    )
    sha_str = record.sha256_hash or "N/A"
    size_val = record.file_size_bytes or 0
    v_fn = record.vault_filename or ""
    v_id = v_fn.removesuffix(".qnt") if v_fn.endswith(".qnt") else v_fn

    # Heuristic scoring default for display
    risk_score = 85
    classification = "MALICIOUS" if record.status == QuarantineStatus.QUARANTINED else "SUSPICIOUS"
    reasons = ["Isolated threat file in encrypted vault"]

    return QuarantineViewModel(
        quarantine_id=record.quarantine_id,
        original_path=record.original_path,
        vault_id=v_id,
        vault_filename=v_fn,
        file_size_bytes=size_val,
        quarantined_at=q_at_str,
        source_sha256=sha_str,
        sha256_hash=sha_str,
        risk_score=risk_score,
        classification=classification,
        detection_reasons=reasons,
        status=record.status.value,
        is_restored=record.is_restored,
        raw_record=record,
    )


@dataclass
class AuditEventViewModel:
    """Template adapter for AuditEvent with safe attribute defaults."""

    event_id: str
    timestamp: str
    event_type: str
    target_path: str
    source_path: str
    outcome: str
    actor: str
    details: dict[str, Any]


def adapt_audit_event(event: AuditEvent) -> AuditEventViewModel:
    """Adapt a raw AuditEvent into an AuditEventViewModel."""
    ts_str = format_utc_timestamp(event.timestamp)
    tgt = event.target_path or event.device_ref or ""
    actor = "SYSTEM" if "WATCHDOG" in event.event_type.value else "OPERATOR"

    # Detail map
    detail_dict: dict[str, Any] = {}
    if event.details:
        detail_dict["info"] = event.details
    if event.quarantine_id:
        detail_dict["quarantine_id"] = event.quarantine_id
    if event.sha256_hash:
        detail_dict["sha256"] = event.sha256_hash[:16] + "..."
    if event.error_message:
        detail_dict["error"] = event.error_message

    return AuditEventViewModel(
        event_id=event.event_id,
        timestamp=ts_str,
        event_type=event.event_type.value,
        target_path=tgt,
        source_path=tgt,
        outcome=event.status.value,
        actor=actor,
        details=detail_dict,
    )


@dataclass
class DeviceTelemetryViewModel:
    """Template adapter for DeviceTelemetry."""

    mount_point: str
    device_path: str
    volume_label: str
    file_system: str
    bus_type: str
    classification: str
    total_bytes: int
    total_size_bytes: int
    free_bytes: int
    parent_device_id: Optional[str] = None
    is_virtual: bool = False
    partitions: list[dict[str, Any]] = field(default_factory=list)
    partition_count: int = 1
    device_model: Optional[str] = None


def adapt_telemetry(t: DeviceTelemetry) -> DeviceTelemetryViewModel:
    """Adapt a raw DeviceTelemetry into a DeviceTelemetryViewModel."""
    mp = t.mount_point or t.device_id
    cls_str = t.classification.value if hasattr(t.classification, "value") else str(t.classification)
    return DeviceTelemetryViewModel(
        mount_point=mp,
        device_path=t.device_id,
        volume_label=t.volume_label or "",
        file_system=t.filesystem or "Unknown",
        bus_type=t.bus_type or ("USB" if cls_str == "PHYSICAL_USB" else "Storage"),
        classification=cls_str,
        total_bytes=t.total_bytes or 0,
        total_size_bytes=t.total_bytes or 0,
        free_bytes=t.free_bytes or 0,
        parent_device_id=t.parent_device_id or t.device_id,
        is_virtual=t.is_virtual or cls_str == DeviceClassification.VIRTUAL_DISK_IMAGE.value,
        partitions=[
            {
                "device_id": t.device_id,
                "mount_point": mp,
                "volume_label": t.volume_label or "(No Label)",
                "filesystem": t.filesystem or "Unknown",
                "total_bytes": t.total_bytes or 0,
                "free_bytes": t.free_bytes or 0,
            }
        ],
        partition_count=1,
        device_model=t.device_model,
    )


def group_and_adapt_storage(
    raw_volumes: Sequence[DeviceTelemetry],
) -> tuple[list[DeviceTelemetryViewModel], list[DeviceTelemetryViewModel], list[DeviceTelemetryViewModel]]:
    """Partition and deduplicate storage telemetry into three distinct operational categories:

    1. physical_usbs: Verified physical USB devices. Multiple partitions on the same
       physical disk are aggregated into a single physical device record with partition telemetry.
    2. virtual_disks: Mounted virtual disk images / forensic loop volumes (retained for targeted analysis).
    3. other_devices: Other removable (e.g. SD cards) or unverified storage.

    Returns:
        tuple[list[DeviceTelemetryViewModel], list[DeviceTelemetryViewModel], list[DeviceTelemetryViewModel]]:
        (physical_usbs, virtual_disks, other_devices)
    """
    physical_map: dict[str, list[DeviceTelemetry]] = {}
    virtual_disks: list[DeviceTelemetryViewModel] = []
    other_devices: list[DeviceTelemetryViewModel] = []

    for v in raw_volumes:
        cls_val = v.classification.value if hasattr(v.classification, "value") else str(v.classification)
        is_virt = (
            v.is_virtual
            or cls_val == DeviceClassification.VIRTUAL_DISK_IMAGE.value
            or "virtual" in (v.bus_type or "").lower()
            or "disk image" in (v.bus_type or "").lower()
        )

        if is_virt:
            virtual_disks.append(adapt_telemetry(v))
        elif (
            cls_val == DeviceClassification.PHYSICAL_USB.value
            or (
                v.bus_type
                and v.bus_type.upper() == "USB"
                and not is_virt
                and cls_val != DeviceClassification.INTERNAL_STORAGE.value
            )
        ):
            parent_key = v.parent_device_id or v.device_id
            physical_map.setdefault(parent_key, []).append(v)
        else:
            other_devices.append(adapt_telemetry(v))

    # Aggregate multi-partition physical USB devices into single physical device records
    physical_usbs: list[DeviceTelemetryViewModel] = []
    for parent_key, parts in physical_map.items():
        if len(parts) == 1:
            vm = adapt_telemetry(parts[0])
            vm.parent_device_id = parent_key
            physical_usbs.append(vm)
        else:
            # Multiple partitions on the same physical hardware drive
            primary = parts[0]
            part_dicts = [
                {
                    "device_id": p.device_id,
                    "mount_point": p.mount_point or p.device_id,
                    "volume_label": p.volume_label or "(No Label)",
                    "filesystem": p.filesystem or "Unknown",
                    "total_bytes": p.total_bytes or 0,
                    "free_bytes": p.free_bytes or 0,
                }
                for p in parts
            ]
            label_summary = f"{primary.volume_label or 'USB Drive'} ({len(parts)} Partitions)"
            fs_summary = "/".join(sorted(set(p["filesystem"] for p in part_dicts)))
            total_cap = sum(p["total_bytes"] for p in part_dicts)
            total_free = sum(p["free_bytes"] for p in part_dicts)

            vm = DeviceTelemetryViewModel(
                mount_point=primary.mount_point or primary.device_id,
                device_path=parent_key,
                volume_label=label_summary,
                file_system=fs_summary,
                bus_type="USB",
                classification=DeviceClassification.PHYSICAL_USB.value,
                total_bytes=total_cap,
                total_size_bytes=total_cap,
                free_bytes=total_free,
                parent_device_id=parent_key,
                is_virtual=False,
                partitions=part_dicts,
                partition_count=len(parts),
                device_model=primary.device_model,
            )
            physical_usbs.append(vm)

    return physical_usbs, virtual_disks, other_devices


# ==============================================================================
# Background Scan Worker
# ==============================================================================


class BackgroundScanWorker:
    """Thread-safe background execution manager for volume scans."""

    def __init__(self, hub: SentinelServiceHub) -> None:
        self._hub = hub
        self._lock = threading.Lock()
        self._status = "IDLE"  # IDLE, RUNNING, COMPLETED, ERROR
        self._current_target: Optional[str] = None
        self._last_report: Optional[ScanReport] = None
        self._error_message: Optional[str] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._status == "RUNNING"

    @property
    def last_report(self) -> Optional[ScanReport]:
        with self._lock:
            return self._last_report

    @property
    def error_message(self) -> Optional[str]:
        with self._lock:
            return self._error_message

    def start_scan(self, target_path: Path, wait_sync: bool = False) -> bool:
        """Start a volume scan in the background.

        Args:
            target_path: Path to directory or mount to scan.
            wait_sync: If True, blocks until scan completion (useful for test suites).

        Returns:
            bool: True if scan was scheduled/started; False if a scan is already running.
        """
        with self._lock:
            if self._status == "RUNNING":
                return False
            self._status = "RUNNING"
            self._current_target = str(target_path)
            self._error_message = None

        def _worker():
            try:
                scanner = VolumeScanner(config=self._hub.config)
                report = scanner.scan(target_path)
                with self._lock:
                    self._last_report = report
                    self._hub.last_scan_report = report
                    self._status = "COMPLETED"

                # Automatically compile incident reports if threat findings exist
                if report.findings:
                    try:
                        telemetry = None
                        for v in self._hub.detector.get_mounted_volumes():
                            if str(target_path).upper().startswith(str(v.mount_point or "").upper()):
                                telemetry = v
                                break

                        incident = IncidentData(
                            incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                            generated_at=utc_now(),
                            telemetry=telemetry,
                            scan_report=report,
                            audit_events=self._hub.audit_ledger.read_all_events()[-10:],
                            action_taken="ALERT_AND_LOG_ONLY: On-demand scan completed via Web Dashboard.",
                            recommended_action="Inspect flagged binaries. Do not execute unverified files.",
                        )
                        self._hub.report_generator.save_reports(incident)
                    except Exception:
                        pass
            except Exception as exc:
                with self._lock:
                    self._status = "ERROR"
                    self._error_message = str(exc)

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()

        if wait_sync:
            self._thread.join()

        return True


# ==============================================================================
# Sentinel Service Hub
# ==============================================================================


class SentinelServiceHub:
    """Central singleton coordinator managing USB Sentinel service instances for the web layer."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        detector: Optional[BaseDeviceDetector] = None,
    ) -> None:
        self.config = config or get_config()
        self.config.ensure_runtime_directories()
        self.detector = detector or get_device_detector(self.config)
        self.audit_ledger = AuditLedger(config=self.config)
        self.index_manager = QuarantineIndexManager(config=self.config)
        self.vault_manager = VaultManager(config=self.config)
        self.quarantine_manager = QuarantineManager(
            config=self.config,
            vault_manager=self.vault_manager,
            index_manager=self.index_manager,
            audit_ledger=self.audit_ledger,
        )
        self.restoration_manager = RestorationManager(
            config=self.config,
            vault_manager=self.vault_manager,
            index_manager=self.index_manager,
            audit_ledger=self.audit_ledger,
        )
        self.report_generator = IncidentReportGenerator(config=self.config)
        self.scan_worker = BackgroundScanWorker(self)
        self.last_scan_report: Optional[ScanReport] = None
        self._watchdog: Optional[USBWatchdog] = None
        self._lock = threading.Lock()

    @property
    def watchdog(self) -> USBWatchdog:
        """Lazily initialize and return the USBWatchdog instance."""
        with self._lock:
            if self._watchdog is None:
                self._watchdog = USBWatchdog(
                    config=self.config,
                    detector=self.detector,
                    audit_ledger=self.audit_ledger,
                    on_scan_completed=self._on_watchdog_scan_completed,
                )
            return self._watchdog

    def _on_watchdog_scan_completed(
        self, session: ActiveDeviceSession, report: ScanReport
    ) -> None:
        """Callback invoked when watchdog background automated scan finishes."""
        self.last_scan_report = report
        if report.findings:
            try:
                incident = IncidentData(
                    incident_id=f"INC-WD-{uuid.uuid4().hex[:8].upper()}",
                    generated_at=utc_now(),
                    telemetry=session.telemetry,
                    scan_report=report,
                    audit_events=self.audit_ledger.read_all_events()[-10:],
                    action_taken="ALERT_AND_LOG_ONLY: Watchdog automated non-destructive volume scan completed.",
                    recommended_action="Inspect flagged binaries. Do not execute unverified files.",
                )
                self.report_generator.save_reports(incident)
            except Exception:
                pass


# ==============================================================================
# Flask Application Factory
# ==============================================================================


def create_app(
    config: Optional[SentinelConfig] = None,
    detector: Optional[BaseDeviceDetector] = None,
    test_config: Optional[dict[str, Any]] = None,
) -> Flask:
    """Create and configure the Flask web dashboard application.

    Args:
        config: SentinelConfig instance (uses default if None).
        detector: Storage device detector backend (defaults to platform backend).
        test_config: Optional dictionary of Flask configuration overrides.

    Returns:
        Flask: The configured Flask application instance.
    """
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    # Base secret key configuration
    app.config["SECRET_KEY"] = secrets.token_hex(32)

    if test_config:
        app.config.update(test_config)

    # Initialize Service Hub
    hub = SentinelServiceHub(config=config, detector=detector)
    app.hub = hub  # type: ignore[attr-defined]

    # --- Session CSRF Protection ---

    @app.context_processor
    def inject_csrf_token():
        """Ensure CSRF token exists in session and inject csrf_token() helper into Jinja2 templates."""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return {"csrf_token": lambda: session["csrf_token"]}

    @app.context_processor
    def inject_environment_context():
        """Inject server environment context for explicit cloud preview vs local host badging."""
        # Detect Vercel / serverless cloud execution
        is_cloud = bool(
            os.environ.get("VERCEL")
            or os.environ.get("VERCEL_ENV")
            or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
            or (request and request.host and "vercel.app" in request.host)
        )
        if is_cloud:
            badge_label = "CLOUD PREVIEW"
            host_info = "Vercel Serverless"
        else:
            badge_label = "LOCAL HOST"
            host_info = request.host if (request and request.host) else "127.0.0.1:5000"

        return {
            "is_cloud_preview": is_cloud,
            "env_badge_label": badge_label,
            "env_host_info": host_info,
        }

    @app.before_request
    def verify_csrf():
        """Verify CSRF token on all modifying HTTP requests."""
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # Allow skipping CSRF check only when app testing flag explicitly enabled and requested
            if app.config.get("TESTING") and request.headers.get("X-Skip-CSRF") == "true":
                return None

            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            expected = session.get("csrf_token")

            if not token or not expected or not hmac.compare_digest(str(token), str(expected)):
                abort(403, description="CSRF token validation failed. Please refresh and try again.")

    # --- Error Handlers ---

    @app.errorhandler(400)
    def bad_request_error(error):
        return (
            render_template(
                "base.html",
                active_page="dashboard",
                content=f"<div class='alert alert-danger'><strong>Bad Request (400):</strong> {error.description}</div>",
            ),
            400,
        )

    @app.errorhandler(403)
    def forbidden_error(error):
        return (
            render_template(
                "base.html",
                active_page="dashboard",
                content=f"<div class='alert alert-danger'><strong>Access Forbidden (403):</strong> {error.description}</div>",
            ),
            403,
        )

    @app.errorhandler(404)
    def not_found_error(error):
        return (
            render_template(
                "base.html",
                active_page="dashboard",
                content="<div class='alert alert-warning'><strong>Not Found (404):</strong> The requested resource does not exist.</div>",
            ),
            404,
        )

    @app.errorhandler(500)
    def internal_error(error):
        return (
            render_template(
                "base.html",
                active_page="dashboard",
                content="<div class='alert alert-danger'><strong>Internal Error (500):</strong> An unexpected error occurred. Original files were preserved.</div>",
            ),
            500,
        )

    # --- Core Routes ---

    @app.route("/static/<path:filename>")
    def serve_custom_static(filename: str):
        """Robust static file delivery supporting local, serverless, and container environments."""
        candidate_dirs = [
            Path(__file__).parent / "static",
            Path(__file__).parent.parent / "static",
            Path(__file__).parent.parent / "public" / "static",
            Path("/var/task/usb_sentinel/static"),
            Path("/var/task/static"),
            Path("/var/task/public/static"),
        ]
        for cdir in candidate_dirs:
            target = cdir / filename
            if target.is_file():
                return send_from_directory(str(cdir), filename)
        abort(404)

    @app.route("/")
    def index():
        """Redirect root URL to Dashboard."""
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    def dashboard():
        """Dashboard overview: watchdog status, detected USBs, inspection stats, recent audit events."""
        detection_error: Optional[str] = None
        physical_usbs: list[DeviceTelemetryViewModel] = []
        virtual_disks: list[DeviceTelemetryViewModel] = []
        other_devices: list[DeviceTelemetryViewModel] = []
        total_storage_devices: int = 0

        # 1. Enumerate storage devices and separate physical USBs, virtual disks, and other storage
        try:
            volumes = hub.detector.get_mounted_volumes()
            physical_usbs, virtual_disks, other_devices = group_and_adapt_storage(volumes)
            total_storage_devices = len(physical_usbs) + len(virtual_disks) + len(other_devices)
        except Exception as exc:
            logger.error("Device detection failed on dashboard: %s", exc, exc_info=True)
            detection_error = f"Device detection failed: {exc}"

        # 2. Watchdog status
        wd_running = hub.watchdog.state == WatchdogState.RUNNING

        # 3. Quarantined records count
        try:
            q_records = hub.index_manager.list_records()
            quarantine_count = len(q_records)
        except Exception:
            quarantine_count = 0

        # 4. Last scan statistics
        last_rep = hub.last_scan_report or hub.scan_worker.last_report
        inspected_count = last_rep.result.files_inspected if last_rep else 0
        flagged_count = last_rep.result.findings_count if last_rep else 0
        last_scan_info = None
        if last_rep:
            res = last_rep.result
            duration = 0.0
            if res.completed_at and res.started_at:
                duration = max(0.0, (res.completed_at - res.started_at).total_seconds())
            last_scan_info = {
                "target_path": res.target_path,
                "status": res.status.value,
                "started_at": format_utc_timestamp(res.started_at),
                "files_inspected": res.files_inspected,
                "findings_count": res.findings_count,
                "duration_seconds": duration,
            }

        # 5. Recent audit events (latest 8)
        try:
            raw_events = hub.audit_ledger.read_all_events()
            recent_events = [adapt_audit_event(ev) for ev in reversed(raw_events[-8:])]
        except Exception:
            recent_events = []

        return render_template(
            "dashboard.html",
            active_page="dashboard",
            watchdog_running=wd_running,
            usb_devices=physical_usbs,
            physical_usb_count=len(physical_usbs),
            virtual_disk_devices=virtual_disks,
            virtual_disk_count=len(virtual_disks),
            other_devices=other_devices,
            total_storage_devices=total_storage_devices,
            inspected_count=inspected_count,
            flagged_count=flagged_count,
            quarantine_count=quarantine_count,
            recent_events=recent_events,
            last_scan_info=last_scan_info,
            detection_error=detection_error,
        )

    @app.route("/devices")
    def devices():
        """USB Devices & Threat Scanner view: active mounts and scan results."""
        detection_error: Optional[str] = None
        physical_usbs: list[DeviceTelemetryViewModel] = []
        virtual_disks: list[DeviceTelemetryViewModel] = []
        other_devices: list[DeviceTelemetryViewModel] = []
        devices_list: list[DeviceTelemetryViewModel] = []
        try:
            volumes = hub.detector.get_mounted_volumes()
            physical_usbs, virtual_disks, other_devices = group_and_adapt_storage(volumes)
            devices_list = physical_usbs + virtual_disks + other_devices
        except Exception as exc:
            logger.error("Storage device detection failed on devices page: %s", exc, exc_info=True)
            detection_error = f"Storage device enumeration failed: {exc}"
            devices_list = []

        is_scanning = hub.scan_worker.is_running
        last_rep = hub.last_scan_report or hub.scan_worker.last_report

        # Prepare scan report presentation model if report exists
        scan_report_view = None
        if last_rep:
            res = last_rep.result
            duration = 0.0
            if res.completed_at and res.started_at:
                duration = max(0.0, (res.completed_at - res.started_at).total_seconds())

            # Format flagged findings with canonical deduplication and error diagnostics
            flagged_files_view = []
            seen_canonical_paths: set[Any] = set()
            target_root = str(res.target_path).rstrip(os.sep)

            for f in last_rep.findings:
                fp = Path(f.file_path)
                canon_key: Any = str(fp)
                f_size = 0
                f_sha = "N/A"
                if fp.exists() and fp.is_file():
                    try:
                        st = fp.stat()
                        f_size = st.st_size
                        canon_key = (st.st_dev, st.st_ino) if st.st_ino else str(fp.resolve())
                    except Exception:
                        try:
                            canon_key = str(fp.resolve())
                        except Exception:
                            canon_key = str(fp)

                    try:
                        f_sha = compute_sha256(fp)
                    except PermissionError:
                        f_sha = "Access Denied (PermissionError)"
                    except IntegrityIOError as io_err:
                        f_sha = f"I/O Read Error ({io_err})"
                    except OSError as os_err:
                        f_sha = f"OS Read Error ({os_err})"
                    except Exception as exc:
                        f_sha = f"Hash Error ({type(exc).__name__})"

                if canon_key in seen_canonical_paths:
                    continue
                seen_canonical_paths.add(canon_key)

                # Calculate user-friendly relative location
                file_str = str(fp)
                if file_str.startswith(target_root) and len(file_str) > len(target_root):
                    rel = file_str[len(target_root):].lstrip(os.sep)
                    parent_rel = os.path.dirname(rel)
                    if not parent_rel:
                        display_loc = "/ (Root)"
                    else:
                        # Cleanly represent non-printable characters e.g. \u00a0 / \xa0
                        clean_parent = "".join(
                            c if c.isprintable() and c != " " else (f"[U+{ord(c):04X}]" if not c.isprintable() else c)
                            for c in parent_rel
                        )
                        display_loc = f"/{clean_parent}"
                else:
                    display_loc = fp.parent.name or str(fp.parent)

                r_score = 90 if f.severity == RiskSeverity.HIGH else (60 if f.severity == RiskSeverity.SUSPICIOUS else 30)
                flagged_files_view.append(
                    {
                        "file_name": fp.name,
                        "file_path": str(fp),
                        "display_location": display_loc,
                        "file_size": f_size,
                        "risk_score": r_score,
                        "classification": f.severity.value,
                        "reasons": [f.explanation],
                        "sha256": f_sha,
                    }
                )

            scan_report_view = {
                "timestamp": format_utc_timestamp(res.started_at),
                "target_path": res.target_path,
                "files_scanned": res.files_inspected,
                "flagged_count": len(flagged_files_view),
                "duration_seconds": duration,
                "flagged_files": flagged_files_view,
            }

        return render_template(
            "devices.html",
            active_page="devices",
            devices_list=devices_list,
            physical_usb_devices=physical_usbs,
            physical_usb_count=len(physical_usbs),
            virtual_disk_devices=virtual_disks,
            virtual_disk_count=len(virtual_disks),
            other_devices=other_devices,
            is_scanning=is_scanning,
            scan_report=scan_report_view,
            detection_error=detection_error,
        )

    @app.route("/devices/scan", methods=["POST"])
    def scan_device():
        """Trigger an on-demand recursive volume or directory scan."""
        target_str = request.form.get("target_path", "").strip()
        if not target_str:
            flash("Target path cannot be empty.", "warning")
            return redirect(url_for("devices"))

        target_path = Path(target_str)
        if not target_path.exists():
            flash(f"Specified target path does not exist: {target_str}", "danger")
            return redirect(url_for("devices"))

        if not target_path.is_dir():
            flash(f"Specified target path is not a directory: {target_str}", "danger")
            return redirect(url_for("devices"))

        # In testing mode or when explicitly requested via sync=1, execute synchronously
        wait_sync = app.config.get("TESTING", False) or request.form.get("sync") == "1"

        started = hub.scan_worker.start_scan(target_path, wait_sync=wait_sync)
        if not started:
            flash("A scan is already actively running. Please wait for it to complete.", "warning")
        else:
            if wait_sync:
                flash(f"Scan completed for: {target_path}", "success")
            else:
                flash(f"Heuristic scan started for: {target_path}", "info")

        return redirect(url_for("devices"))

    @app.route("/watchdog")
    def watchdog_view():
        """Watchdog controls and active telemetry view."""
        wd_running = hub.watchdog.state == WatchdogState.RUNNING

        # Retrieve active device sessions
        raw_sessions = hub.watchdog.get_active_sessions()
        session_devices = []
        for s in raw_sessions:
            t = s.telemetry
            session_devices.append(
                {
                    "device_id": s.session_id,
                    "device_path": s.drive_letter,
                    "mount_point": s.drive_letter,
                    "volume_label": t.volume_label if t else "(No Label)",
                    "file_system": t.filesystem if t else "Unknown",
                    "connected": not s.is_cancelled(),
                    "arrival_time": format_utc_timestamp(s.connected_at),
                }
            )

        return render_template(
            "watchdog.html",
            active_page="watchdog",
            watchdog_running=wd_running,
            session_devices=session_devices,
        )

    @app.route("/watchdog/start", methods=["POST"])
    def watchdog_start():
        """Start the USBWatchdog monitoring subsystem."""
        if hub.watchdog.state == WatchdogState.RUNNING:
            flash("Watchdog engine is already running.", "info")
            return redirect(url_for("watchdog_view"))

        try:
            hub.watchdog.start(discover_initial=True)
            flash("Watchdog engine started successfully. Real-time arrival monitoring active.", "success")
        except Exception as exc:
            flash(f"Failed to start watchdog engine: {exc}", "danger")

        return redirect(url_for("watchdog_view"))

    @app.route("/watchdog/stop", methods=["POST"])
    def watchdog_stop():
        """Stop the USBWatchdog monitoring subsystem."""
        if hub.watchdog.state in (WatchdogState.STOPPED, WatchdogState.STOPPING):
            flash("Watchdog engine is not currently running.", "info")
            return redirect(url_for("watchdog_view"))

        try:
            hub.watchdog.stop()
            flash("Watchdog engine stopped cleanly.", "info")
        except Exception as exc:
            flash(f"Error while stopping watchdog: {exc}", "danger")

        return redirect(url_for("watchdog_view"))

    @app.route("/quarantine")
    def quarantine_view():
        """Quarantine vault management and safe restoration view."""
        inspect_id = request.args.get("inspect", "").strip()
        restore_id = request.args.get("restore_id", "").strip()

        try:
            raw_records = hub.index_manager.list_records()
            records = [adapt_quarantine_record(r) for r in raw_records]
        except Exception:
            records = []

        inspect_record = None
        if inspect_id:
            raw_rec = hub.index_manager.get_record(inspect_id)
            if raw_rec:
                inspect_record = adapt_quarantine_record(raw_rec)
            else:
                flash(f"Quarantine record '{inspect_id}' not found.", "warning")

        return render_template(
            "quarantine.html",
            active_page="quarantine",
            records=records,
            inspect_record=inspect_record,
            target_restore_id=restore_id,
        )

    @app.route("/quarantine/add", methods=["POST"])
    def quarantine_file_action():
        """Encrypt and quarantine a target file with explicit confirmation."""
        confirmed = request.form.get("confirmed", "").strip().lower()
        if confirmed not in ("yes", "1", "true"):
            flash("Quarantine aborted: Explicit user confirmation is required.", "warning")
            return redirect(url_for("quarantine_view"))

        target_str = request.form.get("target_path", "").strip()
        if not target_str:
            flash("Target file path cannot be empty.", "warning")
            return redirect(url_for("quarantine_view"))

        target_path = Path(target_str)
        if not target_path.exists():
            flash(f"Target file does not exist: {target_str}", "danger")
            return redirect(url_for("quarantine_view"))

        if not target_path.is_file():
            flash(f"Target path is a directory, not a file: {target_str}", "danger")
            return redirect(url_for("quarantine_view"))

        remove_source = request.form.get("remove_source", "yes").lower() in ("yes", "1", "true")

        try:
            record = hub.quarantine_manager.quarantine_file(
                source_path=target_path,
                explicit_confirm=True,
                remove_source=remove_source,
            )
            flash(
                f"Successfully encrypted and quarantined '{target_path.name}' (ID: {record.quarantine_id[:12]}...).",
                "success",
            )
        except QuarantinePolicyViolationError as exc:
            flash(f"Quarantine policy violation: {exc}", "danger")
        except QuarantineError as exc:
            flash(f"Quarantine operation failed: {exc}", "danger")
        except Exception as exc:
            flash(f"Unexpected error during quarantine: {exc}", "danger")

        return redirect(url_for("quarantine_view"))

    @app.route("/quarantine/restore", methods=["POST"])
    def restore_file_action():
        """Safely restore a quarantined file with integrity verification."""
        confirmed = request.form.get("confirmed", "").strip().lower()
        if confirmed not in ("yes", "1", "true"):
            flash("Restoration aborted: Explicit user confirmation checkbox is required.", "warning")
            return redirect(url_for("quarantine_view"))

        quarantine_id = request.form.get("quarantine_id", "").strip()
        if not quarantine_id:
            flash("Please select a quarantine record to restore.", "warning")
            return redirect(url_for("quarantine_view"))

        dest_mode = request.form.get("dest_mode", "DESKTOP").strip().upper()
        custom_path_str = request.form.get("custom_path", "").strip()
        collision_choice = request.form.get("collision_policy", "REJECT").strip().upper()

        # Map collision policy enum
        try:
            collision_policy = RestorationConflictPolicy[collision_choice]
        except KeyError:
            collision_policy = RestorationConflictPolicy.REJECT

        allow_overwrite = collision_policy == RestorationConflictPolicy.OVERWRITE

        # Determine target destination directory
        dest_dir: Optional[Path] = None
        if dest_mode == "DESKTOP":
            dest_dir = Path.home() / "Desktop" / "USB_Sentinel_Restored"
            dest_dir.mkdir(parents=True, exist_ok=True)
        elif dest_mode == "CUSTOM":
            if not custom_path_str:
                flash("Custom destination folder path must not be empty.", "warning")
                return redirect(url_for("quarantine_view"))
            dest_dir = Path(custom_path_str).resolve()
            if not dest_dir.exists() or not dest_dir.is_dir():
                flash(f"Custom destination directory does not exist: {custom_path_str}", "danger")
                return redirect(url_for("quarantine_view"))
        elif dest_mode == "ORIGINAL":
            dest_dir = None
        else:
            flash("Invalid destination mode selected.", "warning")
            return redirect(url_for("quarantine_view"))

        try:
            restored_path, updated_record = hub.restoration_manager.restore_file(
                quarantine_id=quarantine_id,
                destination_dir=dest_dir,
                conflict_policy=collision_policy,
                allow_overwrite=allow_overwrite,
            )
            flash(
                f"File successfully restored to '{restored_path}'. Cryptographic integrity verified.",
                "success",
            )
        except RestorationCollisionError as exc:
            flash(f"Restoration collision: {exc}. Try selecting RENAME_NEW or OVERWRITE.", "warning")
        except RestorationError as exc:
            flash(f"Restoration failed: {exc}", "danger")
        except Exception as exc:
            flash(f"Unexpected restoration error: {exc}", "danger")

        return redirect(url_for("quarantine_view"))

    @app.route("/logs")
    def logs_view():
        """Audit ledger table, CSV export link, and incident report list."""
        event_type_filter = request.args.get("event_type", "").strip()
        status_filter = request.args.get("status", "").strip()
        search_query = request.args.get("search", "").strip()

        # 1. Read and optionally filter audit events
        ledger_error: Optional[str] = None
        try:
            raw_events = hub.audit_ledger.read_all_events()
            filtered_events = raw_events
            if event_type_filter:
                filtered_events = [e for e in filtered_events if e.event_type.value == event_type_filter]
            if status_filter:
                filtered_events = [e for e in filtered_events if e.status.value == status_filter]
            if search_query:
                sq = search_query.lower()
                filtered_events = [
                    e
                    for e in filtered_events
                    if sq in (e.target_path or "").lower()
                    or sq in (e.device_ref or "").lower()
                    or sq in (e.event_id or "").lower()
                    or sq in (e.quarantine_id or "").lower()
                    or sq in (e.sha256_hash or "").lower()
                    or sq in (e.error_message or "").lower()
                    or sq in (e.details or "").lower()
                ]
            events = [adapt_audit_event(ev) for ev in reversed(filtered_events[-100:])]
            total_count = len(raw_events)
            filtered_count = len(filtered_events)
        except Exception as exc:
            logger.error("Audit ledger read error: %s", exc, exc_info=True)
            ledger_error = f"Audit ledger read failed: {exc}"
            events = []
            total_count = 0
            filtered_count = 0

        # 2. Enumerate generated incident reports
        reports: list[dict[str, Any]] = []
        try:
            r_dir = hub.config.reports_dir
            if r_dir.exists():
                for p in sorted(
                    r_dir.glob("incident_*.*"),
                    key=lambda x: x.stat().st_mtime,
                    reverse=True,
                ):
                    st = p.stat()
                    reports.append(
                        {
                            "filename": p.name,
                            "size": st.st_size,
                            "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                                "%Y-%m-%d %H:%M:%S UTC"
                            ),
                        }
                    )
        except Exception:
            reports = []

        available_event_types = sorted([e.value for e in AuditEventType])
        available_statuses = sorted([s.value for s in AuditStatus])

        return render_template(
            "logs.html",
            active_page="logs",
            events=events,
            reports=reports,
            available_event_types=available_event_types,
            available_statuses=available_statuses,
            current_filters={
                "event_type": event_type_filter,
                "status": status_filter,
                "search": search_query,
            },
            total_count=total_count,
            filtered_count=filtered_count,
            ledger_error=ledger_error,
        )

    @app.route("/logs/export")
    def export_logs():
        """Export canonical audit ledger as a sanitized, spreadsheet-safe CSV."""
        try:
            temp_export = Path(tempfile.gettempdir()) / f"usb_sentinel_ledger_export_{uuid.uuid4().hex}.csv"
            hub.audit_ledger.export_to_csv(temp_export)

            download_filename = (
                f"usb_sentinel_audit_ledger_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
            )
            return send_file(
                temp_export,
                as_attachment=True,
                download_name=download_filename,
                mimetype="text/csv",
            )
        except Exception as exc:
            flash(f"Failed to export audit ledger: {exc}", "danger")
            return redirect(url_for("logs_view"))

    @app.route("/reports/view/<filename>")
    def view_report(filename: str):
        """View incident report contents in sandboxed template."""
        # Path traversal validation
        safe_name = Path(filename).name
        if safe_name != filename or not filename.startswith("incident_"):
            abort(400, description="Invalid report filename.")

        report_path = (hub.config.reports_dir / safe_name).resolve()
        base_dir = hub.config.reports_dir.resolve()

        if not report_path.is_relative_to(base_dir) or not report_path.is_file():
            abort(404, description="Report file not found.")

        try:
            content = report_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            abort(500, description=f"Could not read report file: {exc}")

        return render_template(
            "report_view.html",
            active_page="logs",
            filename=safe_name,
            content=content,
        )

    @app.route("/reports/download/<filename>")
    def download_report(filename: str):
        """Download incident report file directly."""
        safe_name = Path(filename).name
        if safe_name != filename or not filename.startswith("incident_"):
            abort(400, description="Invalid report filename.")

        report_path = (hub.config.reports_dir / safe_name).resolve()
        base_dir = hub.config.reports_dir.resolve()

        if not report_path.is_relative_to(base_dir) or not report_path.is_file():
            abort(404, description="Report file not found.")

        return send_from_directory(
            hub.config.reports_dir,
            safe_name,
            as_attachment=True,
        )

    return app


# ==============================================================================
# Standalone Server Entry Point
# ==============================================================================


def run_web(
    host: str = "127.0.0.1",
    port: int = 5000,
    debug: bool = False,
    config: Optional[SentinelConfig] = None,
) -> None:
    """Launch the USB Sentinel web dashboard on localhost.

    Security Warning:
        Never bind to 0.0.0.0 or public interfaces. This service executes local
        cryptographic quarantine and restoration transactions.
    """
    if host != "127.0.0.1":
        raise ValueError("USB Sentinel web dashboard must strictly bind to 127.0.0.1 (localhost).")

    import socket

    # Test if the specified host:port is genuinely bindable (using SO_REUSEADDR)
    # Note: connect_ex must NOT be used because it connects to macOS wildcard listeners (e.g. AirPlay on 0.0.0.0:5000)
    target_port = port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, target_port))
        except OSError:
            fallback_port = 5050 if target_port == 5000 else target_port + 1
            print(f"[!] Port {target_port} is already actively bound on {host}. Falling back to port {fallback_port}.")
            target_port = fallback_port

    app = create_app(config=config)
    print(f"[*] Starting USB Sentinel Web Dashboard on http://{host}:{target_port}/")
    print(f"[*] Open http://{host}:{target_port}/ in your web browser (Safari / Chrome).")
    print("[*] Press Ctrl+C to terminate the web server.")
    app.run(host=host, port=target_port, debug=debug)

