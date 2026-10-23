"""Persistent CSV audit ledger for USB Sentinel.

This module provides append-only, durable logging of all security events to
`usb_sentinel_audit.csv` with formula injection sanitization, UTF-8 encoding,
durable disk syncing (fsync), and in-process thread safety.

Design Decisions (for beginner developers):
1. **Audit Ledger Fidelity vs. Export Sanitization**:
   Canonical audit records in `usb_sentinel_audit.csv` store genuine raw event values
   verbatim using standard RFC 4180 CSV escaping, guaranteeing 100% round-trip fidelity
   without data truncation or corruption of legitimate apostrophes. When exporting the
   ledger for external spreadsheet consumption (e.g., Microsoft Excel or LibreOffice Calc)
   via `export_to_csv()`, formula injection sanitization is applied by prepending an
   apostrophe (`'`) to any value starting with `=`, `+`, `-`, `@`, `\\t`, or `\\r`. This
   neutralizes macro/DDE formula execution in spreadsheet software without compromising
   the canonical security ledger.
2. **Durability via fsync**:
   When events are logged, Python and the OS buffer writes in RAM. If the system crashes
   or a USB drive is abruptly yanked, buffered logs could be lost. We call `file.flush()`
   and `os.fsync()` after each append to force bytes to physical storage. Note: fsync
   dramatically reduces data loss risk, though no software can guarantee immunity against
   sudden hardware power failure.
3. **In-Process Concurrency**:
   Writes are synchronized using a `threading.Lock` to prevent interleaved records
   when multiple threads (such as the watchdog and scanner) log concurrently.
   Cross-process locking across independent Python interpreters is not supported.
4. **Header Idempotency**:
   The header is written only if the file does not exist or is empty. Re-opening
   the ledger across application restarts appends cleanly without duplicating the header.
"""

from __future__ import annotations

import csv
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Iterable, List, Optional, Sequence

from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.models import AuditEvent, AuditEventType, AuditStatus

# Stable CSV Ledger Schema
CSV_HEADER: Final[tuple[str, ...]] = (
    "event_id",
    "timestamp",
    "event_type",
    "status",
    "device_ref",
    "target_path",
    "quarantine_id",
    "sha256_hash",
    "details",
    "error_message",
)

INJECTION_CHARS: Final[tuple[str, ...]] = ("=", "+", "-", "@", "\t", "\r")


class AuditLedgerError(Exception):
    """Raised when an error occurs reading or writing to the audit ledger."""


def sanitize_csv_value(value: Optional[str]) -> str:
    """Sanitize a string value against CSV / spreadsheet formula injection for exported CSVs.

    If the value starts with '=', '+', '-', '@', '\\t', or '\\r', or starts with a
    single quote followed by an injection character, an apostrophe is prepended
    so that spreadsheet applications (e.g. Microsoft Excel, LibreOffice Calc)
    treat the cell strictly as literal text rather than executable formulas or commands.
    """
    if value is None:
        return ""
    str_val = str(value)
    if not str_val:
        return ""
    if str_val[0] in INJECTION_CHARS:
        return f"'{str_val}"
    if str_val[0] == "'" and len(str_val) > 1 and str_val[1] in INJECTION_CHARS:
        return f"'{str_val}"
    return str_val


def desanitize_csv_value(value: Optional[str]) -> Optional[str]:
    """Strip spreadsheet formula injection protective single-quote prefix if present.

    Note: In USB Sentinel, canonical audit records store raw values verbatim.
    This utility is provided for parsing externally exported and sanitized CSV files.
    """
    if value is None or value == "":
        return None
    if len(value) >= 2 and value[0] == "'" and (value[1] in INJECTION_CHARS or value[1] == "'"):
        return value[1:]
    return value


def format_utc_timestamp(dt: datetime) -> str:
    """Format a datetime as an unambiguous UTC ISO 8601 string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_timestamp(iso_str: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp string back into a timezone-aware datetime."""
    clean_str = iso_str.strip()
    if clean_str.endswith("Z"):
        clean_str = clean_str[:-1] + "+00:00"
    return datetime.fromisoformat(clean_str)


class AuditLedger:
    """Thread-safe, append-only persistent CSV audit ledger."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        csv_path: Optional[Path] = None,
    ) -> None:
        """Initialize the AuditLedger.

        Args:
            config: Optional SentinelConfig.
            csv_path: Optional explicit file path overriding config.audit_csv_path.
        """
        self._config = config or get_config()
        self._csv_path = Path(csv_path) if csv_path else self._config.audit_csv_path
        self._lock = threading.RLock()

    @property
    def csv_path(self) -> Path:
        """Return the target filesystem path for this audit ledger."""
        return self._csv_path

    def initialize(self) -> None:
        """Ensure parent directory exists and CSV header is written if file is missing."""
        with self._lock:
            self._ensure_header_unlocked()

    def _ensure_header_unlocked(self) -> None:
        """Internal helper to write the CSV header if needed (must be called with lock)."""
        try:
            self._csv_path.parent.mkdir(parents=True, exist_ok=True)
            needs_header = not self._csv_path.exists() or self._csv_path.stat().st_size == 0
            if needs_header:
                with open(self._csv_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(CSV_HEADER)
                    f.flush()
                    os.fsync(f.fileno())
        except OSError as exc:
            raise AuditLedgerError(
                f"Failed to initialize audit ledger at '{self._csv_path}': {exc}"
            ) from exc

    def append_event(self, event: AuditEvent) -> None:
        """Append a single AuditEvent to the canonical ledger with immediate fsync durability.

        In the canonical ledger (`usb_sentinel_audit.csv`), raw values are stored
        verbatim using RFC 4180 CSV escaping to ensure complete round-trip data
        integrity. Formula injection sanitization is strictly applied during export
        via `export_to_csv()`.

        Args:
            event: AuditEvent instance to persist.

        Raises:
            AuditLedgerError: If the record cannot be written or synced to disk.
        """
        with self._lock:
            self._ensure_header_unlocked()

            row = [
                event.event_id,
                format_utc_timestamp(event.timestamp),
                event.event_type.value,
                event.status.value,
                event.device_ref or "",
                event.target_path or "",
                event.quarantine_id or "",
                event.sha256_hash or "",
                event.details or "",
                event.error_message or "",
            ]

            try:
                with open(self._csv_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(row)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as exc:
                raise AuditLedgerError(
                    f"Failed to write event '{event.event_id}' to ledger '{self._csv_path}': {exc}"
                ) from exc

    def read_all_events(self) -> list[AuditEvent]:
        """Read and deserialize all audit events from the canonical ledger.

        Guarantees 100% round-trip fidelity for all original values, including
        strings containing quotes, apostrophes, commas, and newlines.

        Returns:
            list[AuditEvent]: Ordered list of events from the CSV.

        Raises:
            AuditLedgerError: If the ledger is unreadable or malformed.
        """
        with self._lock:
            if not self._csv_path.exists() or self._csv_path.stat().st_size == 0:
                return []

            events: list[AuditEvent] = []
            try:
                with open(self._csv_path, "r", newline="", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    if not header:
                        return []

                    # Validate header compatibility
                    if header[: len(CSV_HEADER)] != list(CSV_HEADER):
                        raise AuditLedgerError(
                            f"Incompatible CSV header in '{self._csv_path}'. "
                            f"Expected: {list(CSV_HEADER)}, Found: {header}"
                        )

                    def _to_optional_str(val: str) -> Optional[str]:
                        return val if val != "" else None

                    for row_idx, row in enumerate(reader, start=2):
                        if not row:
                            continue
                        if len(row) < len(CSV_HEADER):
                            raise AuditLedgerError(
                                f"Malformed audit row {row_idx} in '{self._csv_path}': "
                                f"expected {len(CSV_HEADER)} columns, found {len(row)}"
                            )

                        event = AuditEvent(
                            event_id=row[0],
                            timestamp=parse_utc_timestamp(row[1]),
                            event_type=AuditEventType(row[2]),
                            status=AuditStatus(row[3]),
                            device_ref=_to_optional_str(row[4]),
                            target_path=_to_optional_str(row[5]),
                            quarantine_id=_to_optional_str(row[6]),
                            sha256_hash=_to_optional_str(row[7]),
                            details=_to_optional_str(row[8]),
                            error_message=_to_optional_str(row[9]),
                        )
                        events.append(event)
            except OSError as exc:
                raise AuditLedgerError(
                    f"Failed to read audit ledger from '{self._csv_path}': {exc}"
                ) from exc
            except (ValueError, KeyError) as exc:
                raise AuditLedgerError(
                    f"Data deserialization error reading audit ledger '{self._csv_path}': {exc}"
                ) from exc

            return events

    def export_to_csv(self, destination_path: Path | str) -> int:
        """Export the current audit ledger to an external destination with formula sanitization.

        All cells starting with formula injection characters ('=', '+', '-', '@', '\\t', '\\r')
        or single quotes followed by formula characters are escaped by prepending an apostrophe,
        ensuring spreadsheet applications (Microsoft Excel, LibreOffice Calc) display them safely
        without executing macros or dynamic data exchange (DDE) commands.

        Args:
            destination_path: Target path for the exported CSV.

        Returns:
            int: Total number of audit records exported.

        Raises:
            AuditLedgerError: If the destination cannot be written.
        """
        import uuid

        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        events = self.read_all_events()

        # Write to destination atomically using unique temporary file in same directory
        temp_dest = dest.with_name(f"{dest.name}.tmp_{os.getpid()}_{uuid.uuid4().hex}")
        try:
            with open(temp_dest, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)
                for event in events:
                    row = [
                        sanitize_csv_value(event.event_id),
                        format_utc_timestamp(event.timestamp),
                        sanitize_csv_value(event.event_type.value),
                        sanitize_csv_value(event.status.value),
                        sanitize_csv_value(event.device_ref),
                        sanitize_csv_value(event.target_path),
                        sanitize_csv_value(event.quarantine_id),
                        sanitize_csv_value(event.sha256_hash),
                        sanitize_csv_value(event.details),
                        sanitize_csv_value(event.error_message),
                    ]
                    writer.writerow(row)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_dest, dest)
        except OSError as exc:
            if temp_dest.exists():
                try:
                    temp_dest.unlink()
                except OSError:
                    pass
            raise AuditLedgerError(
                f"Failed to export audit ledger to '{dest}': {exc}"
            ) from exc

        return len(events)
