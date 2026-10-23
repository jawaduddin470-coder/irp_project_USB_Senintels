"""Interactive Command-Line Interface (CLI) for USB Sentinel.

Provides the primary user interface with exactly five main operations:
1. Display Active System Mounts & USB Device Telemetry
2. Start Real-Time USB Insertion Watchdog
3. Inspect & Restore Quarantined Files
4. Export USB Audit Ledger to CSV
5. Exit

Design Principles & Security Controls:
1. Strict Five-Option Main Menu:
   The main menu presents exactly the five numbered options. Submenus and prompts
   exist only within the context of an invoked option.
2. Non-Destructive Default Policy:
   The watchdog operates strictly under ALERT_AND_LOG_ONLY. No automated file deletion
   or quarantine is initiated on insertion.
3. Cryptographic & Secret Hygiene:
   Encryption keys, subkeys, salts, and nonces are NEVER displayed in terminal output
   or incident reports.
4. Safe Restoration:
   Never restores silently. When the original volume is detached, prompts for destination
   with %USERPROFILE%\\Desktop\\Restored_Files\\ offered as selectable default. Anti-collision
   policies prevent unintended overwrites.
5. Cross-Platform Graceful Execution:
   Uses Colorama for cross-platform ANSI terminal formatting with graceful fallback
   when stdout is redirected or unsupported.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import colorama
from colorama import Fore, Style

import usb_sentinel
from usb_sentinel.audit import AuditLedger, format_utc_timestamp
from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.device_detection import (
    BaseDeviceDetector,
    get_device_detector,
)
from usb_sentinel.integrity import compute_sha256
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    QuarantineRecord,
    QuarantineStatus,
    RiskSeverity,
    ScanStatus,
    utc_now,
)
from usb_sentinel.quarantine import QuarantineManager, QuarantinePolicyViolationError
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
from usb_sentinel.watchdog import ActiveDeviceSession, USBWatchdog


class SentinelCLI:
    """Interactive command-line interface coordinator for USB Sentinel."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        detector: Optional[BaseDeviceDetector] = None,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        use_color: bool = True,
    ) -> None:
        """Initialize the CLI coordinator.

        Args:
            config: Sentinel application configuration.
            detector: Storage device detector backend.
            input_func: Function for collecting user input (default: input).
            output_func: Function for printing text output (default: print).
            use_color: Whether to use ANSI terminal colors.
        """
        self._config = config or get_config()
        self._detector = detector or get_device_detector(self._config)
        self._input = input_func
        self._output = output_func
        self._use_color = use_color and sys.stdout.isatty()

        # Ensure runtime directories exist
        self._config.ensure_runtime_directories()

        # Service Managers
        self._audit_ledger = AuditLedger(config=self._config)
        self._index_manager = QuarantineIndexManager(config=self._config)
        self._restoration_manager = RestorationManager(
            config=self._config,
            index_manager=self._index_manager,
            audit_ledger=self._audit_ledger,
        )
        self._quarantine_manager = QuarantineManager(
            config=self._config,
            index_manager=self._index_manager,
            audit_ledger=self._audit_ledger,
        )
        self._report_generator = IncidentReportGenerator(config=self._config)

        # Active Watchdog reference for cleanup
        self._active_watchdog: Optional[USBWatchdog] = None
        self._watchdog_stop_event = threading.Event()

    @property
    def config(self) -> SentinelConfig:
        """Active Sentinel configuration."""
        return self._config

    # --- Terminal Styling Helpers ---

    def _c(self, text: str, color: str) -> str:
        """Colorize text if coloring is enabled."""
        if not self._use_color:
            return text
        return f"{color}{text}{Style.RESET_ALL}"

    def _print(self, text: str = "") -> None:
        """Output text through configured output function."""
        self._output(text)

    def _prompt(self, prompt_text: str, default: Optional[str] = None) -> str:
        """Prompt user with optional default value."""
        suffix = f" [{default}]" if default is not None else ""
        formatted = self._c(f"{prompt_text}{suffix}: ", Fore.CYAN)
        response = self._input(formatted).strip()
        if not response and default is not None:
            return default
        return response

    def _confirm(self, prompt_text: str, default: bool = False) -> bool:
        """Prompt user for binary confirmation (yes/no)."""
        hint = "[y/N]" if not default else "[Y/n]"
        formatted = self._c(f"{prompt_text} {hint}: ", Fore.YELLOW)
        response = self._input(formatted).strip().lower()
        if not response:
            return default
        return response in ("y", "yes")

    @staticmethod
    def _format_bytes(byte_count: Optional[int]) -> str:
        """Format raw byte counts to human-readable string (e.g. 14.5 GB)."""
        if byte_count is None:
            return "N/A"
        if byte_count < 1024:
            return f"{byte_count} B"
        elif byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.1f} KB"
        elif byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.1f} MB"
        else:
            return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"

    # --- Menu Banners & Display ---

    def _display_banner(self) -> None:
        """Print the top application header."""
        title = f"USB Sentinel v{usb_sentinel.__version__}"
        desc = "Automated USB Mass Storage Threat Detection & File Quarantine Watchdog"
        policy = f"Watchdog Policy: {self._config.watchdog_policy} (Zero Automatic File Modification)"
        sep = "=" * 74
        self._print(self._c(sep, Fore.BLUE))
        self._print(self._c(f"   {title}", Fore.GREEN + Style.BRIGHT))
        self._print(f"   {desc}")
        self._print(self._c(sep, Fore.BLUE))
        self._print(self._c(f" [POLICY] {policy}", Fore.YELLOW))
        self._print("-" * 74)

    def _display_main_menu(self) -> None:
        """Display the exactly five numbered options required by specifications."""
        self._print("Main Menu Operations:")
        self._print(f"  {self._c('1.', Fore.CYAN + Style.BRIGHT)} Display Active System Mounts & USB Device Telemetry")
        self._print(f"  {self._c('2.', Fore.CYAN + Style.BRIGHT)} Start Real-Time USB Insertion Watchdog")
        self._print(f"  {self._c('3.', Fore.CYAN + Style.BRIGHT)} Inspect & Restore Quarantined Files")
        self._print(f"  {self._c('4.', Fore.CYAN + Style.BRIGHT)} Export USB Audit Ledger to CSV")
        self._print(f"  {self._c('5.', Fore.CYAN + Style.BRIGHT)} Exit")
        self._print("-" * 74)

    # --- Option 1: Display Active System Mounts & USB Device Telemetry ---

    def option_1_display_mounts(self) -> None:
        """Display active system mounts, hardware telemetry, and offer on-demand scan."""
        self._print()
        self._print(self._c("=== [1] Active Storage Mounts & Device Telemetry ===", Fore.GREEN + Style.BRIGHT))
        self._print("Querying storage subsystems and hardware telemetry...")

        try:
            volumes = self._detector.get_mounted_volumes()
        except Exception as exc:
            self._print(self._c(f"[ERROR] Failed to query mounted volumes: {exc}", Fore.RED))
            return

        if not volumes:
            self._print(self._c("No active storage volumes detected on the system.", Fore.YELLOW))
        else:
            # Format and display volumes table
            self._print()
            header = f"{'Mount':<8} {'Volume Label':<16} {'FS':<8} {'Total':<10} {'Free':<10} {'Bus Type':<8} {'Classification':<20} {'Confidence':<10}"
            self._print(self._c(header, Fore.CYAN + Style.BRIGHT))
            self._print("-" * len(header))

            has_fallback = False
            for v in volumes:
                label = (v.volume_label or "NO_LABEL")[:15]
                fs = (v.filesystem or "UNKNOWN")[:7]
                total_str = self._format_bytes(v.total_bytes)
                free_str = self._format_bytes(v.free_bytes)
                bus_str = (v.bus_type or "UNKNOWN")[:7]
                class_str = v.classification.value[:19]
                conf_str = v.confidence.value

                if v.confidence in (DetectionConfidence.HEURISTIC_REMOVABLE, DetectionConfidence.UNVERIFIED) or v.classification == DeviceClassification.UNKNOWN_REMOVABLE:
                    has_fallback = True

                mount_display = (v.mount_point or v.device_id)[:7]
                line = f"{mount_display:<8} {label:<16} {fs:<8} {total_str:<10} {free_str:<10} {bus_str:<8} {class_str:<20} {conf_str:<10}"
                if (v.bus_type and v.bus_type.upper() == "USB") or v.classification == DeviceClassification.USB_MASS_STORAGE:
                    self._print(self._c(line, Fore.GREEN))
                else:
                    self._print(line)

            self._print("-" * len(header))
            if has_fallback:
                self._print(
                    self._c(
                        "[NOTICE] One or more volumes detected using fallback heuristics. "
                        "Hardware WMI queries may be unavailable or restricted on this host.",
                        Fore.YELLOW,
                    )
                )

        # Offer on-demand scan
        self._print()
        scan_target = self._prompt(
            "Enter drive letter or path to scan immediately (or press Enter to return to menu)",
            default="",
        )
        if not scan_target:
            return

        target_path = Path(scan_target)
        if not target_path.exists():
            self._print(self._c(f"[ERROR] Path '{target_path}' does not exist.", Fore.RED))
            return
        if not target_path.is_dir():
            self._print(self._c(f"[ERROR] Path '{target_path}' is not a directory.", Fore.RED))
            return

        self._run_on_demand_scan(target_path)

    def _run_on_demand_scan(self, target_path: Path) -> None:
        """Execute an interactive on-demand heuristic scan of a selected path."""
        self._print()
        self._print(self._c(f"Starting heuristic scan on: {target_path}", Fore.CYAN))
        self._print(f"Policy: {self._config.watchdog_policy} (Inspection mode)")

        scanner = VolumeScanner(config=self._config)
        risk_engine = RiskEngine(config=self._config)

        try:
            scan_report = scanner.scan(target_path)
        except Exception as exc:
            self._print(self._c(f"[ERROR] Scan execution failed: {exc}", Fore.RED))
            return

        res = scan_report.result
        self._print(
            f"Scan Completed: {res.files_inspected} files inspected, "
            f"{res.findings_count} flagged items, {res.errors_count} errors. "
            f"Status: {res.status.value}"
        )

        if not scan_report.findings:
            self._print(self._c("[CLEAN] Zero suspicious executable or script vectors flagged.", Fore.GREEN))
            return

        # Display findings
        self._print()
        self._print(self._c(f"=== Flagged Heuristic Findings ({len(scan_report.findings)}) ===", Fore.RED + Style.BRIGHT))
        for idx, f in enumerate(scan_report.findings, start=1):
            sev_color = Fore.RED if f.severity == RiskSeverity.HIGH else Fore.YELLOW
            self._print(f"  {idx}. [{self._c(f.severity.value, sev_color)}] {f.file_path}")
            self._print(f"     Rule: {f.matched_rule} | Explanation: {f.explanation}")

        # Offer Incident Report Generation
        self._print()
        if self._confirm("Generate and save incident reports (HTML & Text)?", default=True):
            # Find matching telemetry if available
            telemetry = None
            try:
                for v in self._detector.get_mounted_volumes():
                    if str(target_path).upper().startswith(v.mount_point.upper()):
                        telemetry = v
                        break
            except Exception:
                pass

            incident = IncidentData(
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                generated_at=utc_now(),
                telemetry=telemetry,
                scan_report=scan_report,
                audit_events=self._audit_ledger.read_all_events()[-10:],
                action_taken="ALERT_AND_LOG_ONLY: Manual on-demand scan completed; threat detection logged.",
                recommended_action="Inspect flagged binaries. Do not execute unverified scripts or executables.",
            )
            try:
                html_p, txt_p = self._report_generator.save_reports(incident)
                self._print(self._c(f"[SAVED] HTML Report: {html_p}", Fore.GREEN))
                self._print(self._c(f"[SAVED] Text Report: {txt_p}", Fore.GREEN))
            except Exception as exc:
                self._print(self._c(f"[ERROR] Failed to save reports: {exc}", Fore.RED))

        # Offer Manual Quarantine Option
        self._print()
        if self._confirm("Would you like to manually quarantine any of the flagged files?", default=False):
            choice = self._prompt(f"Enter finding number to quarantine [1-{len(scan_report.findings)}]", default="")
            if choice.isdigit() and 1 <= int(choice) <= len(scan_report.findings):
                finding = scan_report.findings[int(choice) - 1]
                self._print(f"Selected: {finding.file_path}")
                if self._confirm(f"Are you sure you want to encrypt and quarantine '{finding.file_path}'?", default=False):
                    remove_src = self._confirm("Remove original source file after secure vault storage?", default=False)
                    try:
                        record = self._quarantine_manager.quarantine_file(
                            source_path=finding.file_path,
                            explicit_confirm=True,
                            remove_source=remove_src,
                            device_ref=str(target_path)[:2],
                        )
                        self._print(self._c(f"[SUCCESS] File quarantined successfully! QID: {record.quarantine_id}", Fore.GREEN))
                        self._print(f"Vault Object: {record.vault_filename} (Status: {record.status.value})")
                    except Exception as exc:
                        self._print(self._c(f"[ERROR] Quarantine operation failed: {exc}", Fore.RED))

    # --- Option 2: Start Real-Time USB Insertion Watchdog ---

    def option_2_start_watchdog(self) -> None:
        """Start the background USB insertion watchdog with real-time console telemetry."""
        self._print()
        self._print(self._c("=== [2] Real-Time USB Insertion Watchdog ===", Fore.GREEN + Style.BRIGHT))
        self._print(f"Policy: {self._c(self._config.watchdog_policy, Fore.YELLOW)} (Zero automatic deletion/quarantine)")
        self._print("Monitoring storage insertion and removal events...")
        self._print(self._c("Press Enter or type 'q' to stop watchdog and return to menu.", Fore.CYAN))
        self._print("-" * 74)

        def _on_device_arrival(session: ActiveDeviceSession) -> None:
            t = session.telemetry
            label = t.volume_label or "NO_LABEL"
            fs = t.filesystem or "UNKNOWN"
            self._print()
            self._print(
                self._c(
                    f"[{format_utc_timestamp(session.connected_at)}] [DEVICE ARRIVED] "
                    f"Drive {session.drive_letter} (Label: '{label}', FS: '{fs}', "
                    f"Bus: {t.bus_type.value}, Confidence: {t.confidence.value})",
                    Fore.GREEN + Style.BRIGHT,
                )
            )
            self._print(f" -> Automated read-only heuristic scan starting for {session.drive_letter}...")

        def _on_device_removal(drive_letter: str) -> None:
            self._print()
            self._print(
                self._c(
                    f"[{format_utc_timestamp(utc_now())}] [DEVICE REMOVED] "
                    f"USB storage device removed from {drive_letter}. In-flight operations cancelled.",
                    Fore.YELLOW,
                )
            )

        def _on_scan_completed(session: ActiveDeviceSession, report: ScanReport) -> None:
            res = report.result
            self._print()
            self._print(
                self._c(
                    f"[{format_utc_timestamp(utc_now())}] [SCAN COMPLETED] {session.drive_letter} - "
                    f"{res.files_inspected} files inspected, {res.findings_count} flagged, {res.errors_count} errors.",
                    Fore.CYAN,
                )
            )
            if report.findings:
                self._print(
                    self._c(
                        f" [ALERT] {len(report.findings)} suspicious executable/script file(s) flagged on {session.drive_letter}:",
                        Fore.RED + Style.BRIGHT,
                    )
                )
                for f in report.findings[:5]:
                    self._print(f"   * [{f.severity.value}] {f.file_path} ({f.matched_rule})")
                if len(report.findings) > 5:
                    self._print(f"   * ... and {len(report.findings) - 5} more.")

                # Automatically generate incident reports
                try:
                    incident = IncidentData(
                        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                        generated_at=utc_now(),
                        telemetry=session.telemetry,
                        scan_report=report,
                        audit_events=self._audit_ledger.read_all_events()[-15:],
                        action_taken="ALERT_AND_LOG_ONLY: Threat detection alert generated; zero files modified or removed.",
                        recommended_action="Inspect flagged executable/script binaries. Do not launch unverified executables.",
                    )
                    html_p, txt_p = self._report_generator.save_reports(incident)
                    self._print(self._c(f" [INCIDENT REPORT SAVED] HTML: {html_p}", Fore.GREEN))
                    self._print(self._c(f" [INCIDENT REPORT SAVED] Text: {txt_p}", Fore.GREEN))
                except Exception as exc:
                    self._print(self._c(f" [REPORT ERROR] Could not save incident report: {exc}", Fore.RED))

        watchdog = USBWatchdog(
            config=self._config,
            detector=self._detector,
            audit_ledger=self._audit_ledger,
            on_device_arrival=_on_device_arrival,
            on_device_removal=_on_device_removal,
            on_scan_completed=_on_scan_completed,
        )
        self._active_watchdog = watchdog

        try:
            watchdog.start()
            self._print(self._c("[WATCHDOG RUNNING] Background monitor active.", Fore.GREEN))
            # Block until user stops via prompt or keyboard interrupt
            while watchdog.is_running:
                try:
                    user_cmd = self._input("").strip().lower()
                    if user_cmd in ("q", "quit", "exit", ""):
                        break
                except (EOFError, KeyboardInterrupt):
                    break
        finally:
            self._print(self._c("\nStopping USB Watchdog...", Fore.YELLOW))
            watchdog.stop()
            self._active_watchdog = None
            self._print(self._c("USB Watchdog stopped. Returning to main menu.\n", Fore.GREEN))

    # --- Option 3: Inspect & Restore Quarantined Files ---

    def option_3_inspect_and_restore(self) -> None:
        """Inspect quarantined vault objects and perform safe cryptographic restoration."""
        self._print()
        self._print(self._c("=== [3] Inspect & Restore Quarantined Files ===", Fore.GREEN + Style.BRIGHT))

        try:
            records = self._index_manager.list_records()
        except Exception as exc:
            self._print(self._c(f"[ERROR] Failed to read quarantine index: {exc}", Fore.RED))
            return

        if not records:
            self._print(self._c(f"No quarantined files found in index ({self._config.quarantine_index_path}).", Fore.YELLOW))
            self._print()
            return

        # Display quarantined records table
        self._print()
        header = f"{'#':<4} {'Quarantine ID':<38} {'Status':<16} {'Size':<10} {'Original Path'}"
        self._print(self._c(header, Fore.CYAN + Style.BRIGHT))
        self._print("-" * 80)

        for idx, rec in enumerate(records, start=1):
            is_active = rec.status in (
                QuarantineStatus.COMMITTED,
                QuarantineStatus.QUARANTINED,
                QuarantineStatus.QUARANTINE_SOURCE_LOCKED,
                QuarantineStatus.ORPHAN_RECONCILED,
            )
            stat_color = Fore.GREEN if is_active else Fore.YELLOW
            status_str = self._c(f"{rec.status.value:<16}", stat_color)
            size_str = self._format_bytes(rec.file_size_bytes)
            orig_path = rec.original_path
            if len(orig_path) > 35:
                orig_path = "..." + orig_path[-32:]
            self._print(f"{idx:<4} {rec.quarantine_id:<38} {status_str} {size_str:<10} {orig_path}")

        self._print("-" * 80)
        selection = self._prompt(f"Select record # to inspect [1-{len(records)}] or 'B' to return to menu", default="B")
        if selection.upper() == "B" or not selection.isdigit():
            return

        rec_idx = int(selection)
        if not (1 <= rec_idx <= len(records)):
            self._print(self._c(f"[ERROR] Invalid record index: {rec_idx}", Fore.RED))
            return

        record = records[rec_idx - 1]
        self._display_quarantine_record_details(record)

    def _display_quarantine_record_details(self, record: QuarantineRecord) -> None:
        """Display full details of a quarantine record and present restoration options."""
        self._print()
        self._print(self._c(f"--- Quarantine Record: {record.quarantine_id} ---", Fore.CYAN + Style.BRIGHT))
        self._print(f"  Quarantine ID  : {record.quarantine_id}")
        is_active = record.status in (
            QuarantineStatus.COMMITTED,
            QuarantineStatus.QUARANTINED,
            QuarantineStatus.QUARANTINE_SOURCE_LOCKED,
            QuarantineStatus.ORPHAN_RECONCILED,
        )
        self._print(f"  Current Status : {self._c(record.status.value, Fore.GREEN if is_active else Fore.YELLOW)}")
        self._print(f"  Original Path  : {record.original_path}")
        self._print(f"  Vault Filename : {record.vault_filename}")
        size_display = (
            f"{record.file_size_bytes} bytes ({self._format_bytes(record.file_size_bytes)})"
            if record.file_size_bytes is not None
            else "N/A"
        )
        self._print(f"  Original Size  : {size_display}")
        self._print(f"  SHA-256 Digest : {record.sha256_hash or 'N/A'}")
        self._print(f"  Quarantined At : {format_utc_timestamp(record.quarantined_at)} UTC")
        if record.restored_at:
            self._print(f"  Restored At    : {format_utc_timestamp(record.restored_at)} UTC")
            self._print(f"  Restored Path  : {record.restored_path or 'N/A'}")
        self._print("-" * 74)

        # Restoration menu
        self._print("Restoration Destination Options:")
        self._print("  1. Original Location (if available)")
        self._print(f"  2. Desktop Convenience Directory ({self._config.default_restored_dir})")
        self._print("  3. Custom Destination Directory")
        self._print("  4. Cancel / Return to Record List")
        self._print("-" * 74)

        opt = self._prompt("Select restoration destination [1-4]", default="4")
        if opt == "4" or opt not in ("1", "2", "3"):
            return

        destination_dir: Optional[Path] = None
        if opt == "1":
            orig_parent = Path(record.original_path).parent
            if not orig_parent.exists() or not os.access(orig_parent, os.W_OK):
                self._print(self._c(f"[WARNING] Original location '{orig_parent}' is not accessible or volume is disconnected.", Fore.YELLOW))
                if self._confirm(f"Fallback to Desktop directory '{self._config.default_restored_dir}'?", default=True):
                    destination_dir = self._config.default_restored_dir
                else:
                    return
            else:
                destination_dir = None  # Use original path
        elif opt == "2":
            destination_dir = self._config.default_restored_dir
        elif opt == "3":
            custom_input = self._prompt("Enter destination directory path")
            if not custom_input:
                self._print(self._c("[CANCELLED] No destination directory provided.", Fore.YELLOW))
                return
            destination_dir = Path(custom_input)

        self._execute_restoration(record.quarantine_id, destination_dir=destination_dir)

    def _execute_restoration(
        self,
        quarantine_id: str,
        destination_dir: Optional[Path] = None,
    ) -> None:
        """Perform verified restoration handling collision resolution."""
        policy = RestorationConflictPolicy.REJECT
        allow_overwrite = False

        # Attempt initial restoration under default REJECT collision policy
        try:
            target_path, updated_record = self._restoration_manager.restore_file(
                quarantine_id=quarantine_id,
                destination_dir=destination_dir,
                conflict_policy=policy,
                allow_overwrite=False,
            )
            self._print(self._c(f"[SUCCESS] File successfully restored to: {target_path}", Fore.GREEN + Style.BRIGHT))
            self._print(self._c(f"[VERIFIED] Plaintext SHA-256 integrity verified against baseline: {updated_record.sha256_hash}", Fore.GREEN))
            return
        except RestorationCollisionError as col_err:
            self._print(self._c(f"[COLLISION DETECTED] {col_err}", Fore.YELLOW))
            self._print("Destination conflict options:")
            self._print("  1. Rename with timestamp suffix (Safely retain both files)")
            self._print("  2. Overwrite existing file (Explicit authorization required)")
            self._print("  3. Cancel restoration")
            col_choice = self._prompt("Select conflict resolution [1-3]", default="1")

            if col_choice == "1":
                policy = RestorationConflictPolicy.RENAME_NEW
                allow_overwrite = False
            elif col_choice == "2":
                if self._confirm("Are you ABSOLUTELY sure you want to OVERWRITE the existing file?", default=False):
                    policy = RestorationConflictPolicy.OVERWRITE
                    allow_overwrite = True
                else:
                    self._print(self._c("[CANCELLED] Overwrite authorization rejected.", Fore.YELLOW))
                    return
            else:
                self._print(self._c("[CANCELLED] Restoration aborted.", Fore.YELLOW))
                return
        except RestorationError as r_err:
            self._print(self._c(f"[ERROR] Restoration failed: {r_err}", Fore.RED))
            return
        except Exception as exc:
            self._print(self._c(f"[UNEXPECTED ERROR] Restoration failed: {exc}", Fore.RED))
            return

        # Re-attempt with chosen conflict policy
        try:
            target_path, updated_record = self._restoration_manager.restore_file(
                quarantine_id=quarantine_id,
                destination_dir=destination_dir,
                conflict_policy=policy,
                allow_overwrite=allow_overwrite,
            )
            self._print(self._c(f"[SUCCESS] File successfully restored to: {target_path}", Fore.GREEN + Style.BRIGHT))
            self._print(self._c(f"[VERIFIED] Plaintext SHA-256 integrity verified against baseline: {updated_record.sha256_hash}", Fore.GREEN))
        except Exception as exc:
            self._print(self._c(f"[ERROR] Restoration failed: {exc}", Fore.RED))

    # --- Option 4: Export USB Audit Ledger to CSV ---

    def option_4_export_audit_ledger(self) -> None:
        """Export the canonical audit ledger to an external CSV with formula-injection defenses."""
        self._print()
        self._print(self._c("=== [4] Export USB Audit Ledger to CSV ===", Fore.GREEN + Style.BRIGHT))

        try:
            events = self._audit_ledger.read_all_events()
        except Exception as exc:
            self._print(self._c(f"[ERROR] Failed to read audit ledger: {exc}", Fore.RED))
            return

        if not events:
            self._print(self._c(f"Audit ledger is empty ({self._config.audit_csv_path}). No events to export.", Fore.YELLOW))
            self._print()
            return

        default_export = Path.home() / "Desktop" / "usb_sentinel_audit_export.csv"
        user_dest = self._prompt(f"Enter target export CSV path", default=str(default_export))
        target_path = Path(user_dest)

        if target_path.exists():
            if not self._confirm(f"File '{target_path}' already exists. Overwrite?", default=False):
                self._print(self._c("[CANCELLED] Export aborted.", Fore.YELLOW))
                return

        try:
            count = self._audit_ledger.export_to_csv(target_path)
            self._print(self._c(f"[SUCCESS] Exported {count} audit events to: {target_path}", Fore.GREEN + Style.BRIGHT))
            self._print(
                self._c(
                    "[SECURITY] Spreadsheet formula-injection protection applied: "
                    "cells with dangerous leading characters escaped for Microsoft Excel / LibreOffice.",
                    Fore.CYAN,
                )
            )

            # Display breakdown metrics
            type_counts = Counter(e.event_type.value for e in events)
            status_counts = Counter(e.status.value for e in events)

            self._print()
            self._print(self._c("--- Audit Ledger Summary Metrics ---", Fore.CYAN))
            self._print(f"  Total Logged Events   : {count}")
            self._print("  Event Breakdown:")
            for evt_type, c in sorted(type_counts.items()):
                self._print(f"    * {evt_type:<24}: {c}")
            self._print("  Status Distribution:")
            for st, c in sorted(status_counts.items()):
                self._print(f"    * {st:<24}: {c}")
            self._print("-" * 40)
        except Exception as exc:
            self._print(self._c(f"[ERROR] Export failed: {exc}", Fore.RED))

    # --- Option 5: Exit ---

    def option_5_exit(self) -> None:
        """Perform graceful application shutdown."""
        self._print()
        self._print(self._c("Exiting USB Sentinel. Background monitoring deactivated.", Fore.GREEN))
        if self._active_watchdog and self._active_watchdog.is_running:
            self._active_watchdog.stop()
            self._active_watchdog = None
        self._print("Goodbye.")

    # --- Main Interactive Loop ---

    def run(self) -> int:
        """Run the interactive main menu loop until Option 5 is selected."""
        self._display_banner()

        while True:
            self._display_main_menu()
            try:
                choice = self._prompt("Select an option [1-5]")
            except (EOFError, KeyboardInterrupt, OSError):
                self._print()
                self.option_5_exit()
                return 0

            if choice == "1":
                try:
                    self.option_1_display_mounts()
                except (EOFError, KeyboardInterrupt, OSError):
                    self._print(self._c("\n[CANCELLED] Operation aborted by user.", Fore.YELLOW))
            elif choice == "2":
                try:
                    self.option_2_start_watchdog()
                except (EOFError, KeyboardInterrupt, OSError):
                    self._print(self._c("\n[STOPPED] Watchdog interrupted.", Fore.YELLOW))
            elif choice == "3":
                try:
                    self.option_3_inspect_and_restore()
                except (EOFError, KeyboardInterrupt, OSError):
                    self._print(self._c("\n[CANCELLED] Operation aborted by user.", Fore.YELLOW))
            elif choice == "4":
                try:
                    self.option_4_export_audit_ledger()
                except (EOFError, KeyboardInterrupt, OSError):
                    self._print(self._c("\n[CANCELLED] Operation aborted by user.", Fore.YELLOW))
            elif choice == "5":
                self.option_5_exit()
                return 0
            else:
                self._print(self._c("[ERROR] Invalid selection. Please enter a number between 1 and 5.", Fore.RED))

            self._print()


def main() -> int:
    """CLI entry point."""
    colorama.init(autoreset=True)
    cli = SentinelCLI()
    try:
        return cli.run()
    except KeyboardInterrupt:
        print("\nShutdown requested by user. Exiting USB Sentinel.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
