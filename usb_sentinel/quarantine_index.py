"""Persistent quarantine index manager for USB Sentinel.

This module manages `quarantine_index.txt` using a durable, versioned JSON Lines format.
It maps original removable media file paths to their encrypted vault objects, tracks
restoration and write-protection statuses, prevents duplicate identifiers, enforces
atomic replacement on write, and safely preserves corrupted data for manual recovery.

Design Decisions (for beginner developers):
1. **JSON Lines in .txt Format**:
   While the file is named `quarantine_index.txt` to satisfy project specifications,
   each line is a self-contained, valid JSON document with an explicit `schema_version`.
   This guarantees full Unicode and Windows path compatibility without complex delimiter
   escaping issues.
2. **Atomic Replacement (Safe Persistence)**:
   Modifications rewrite the index to a unique temporary file (`.tmp_<pid>_<uuid>`) in the same
   directory, flush and `fsync` the bytes to disk, and then atomically replace the target using
   `os.replace()`. This prevents index file truncation if power is lost midway through a write.
3. **In-Memory Rollback on I/O Failure**:
   If a disk write fails, the in-memory registry rolls back to its prior state. The caller
   is never left with an in-memory state falsely indicating that an uncommitted change was saved.
4. **Never Discard Corrupted Data**:
   If an index contains corrupted lines or an unsupported schema version, Sentinel
   raises `QuarantineIndexCorruptedError` and refuses to overwrite the corrupted file,
   protecting existing quarantine records from being destroyed.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Final, List, Optional

from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.models import QuarantineRecord, QuarantineStatus

CURRENT_SCHEMA_VERSION: Final[int] = 1


class QuarantineIndexError(Exception):
    """Base exception for quarantine index operations."""


class DuplicateRecordError(QuarantineIndexError):
    """Raised when an attempt is made to insert a quarantine record with an existing ID."""


class RecordNotFoundError(QuarantineIndexError):
    """Raised when attempting to retrieve or update a non-existent quarantine ID."""


class QuarantineIndexCorruptedError(QuarantineIndexError):
    """Raised when quarantine_index.txt contains invalid JSON or an unsupported schema."""

    def __init__(self, message: str, file_path: Path, line_number: int, raw_content: str) -> None:
        super().__init__(f"{message} (at {file_path}:{line_number})")
        self.file_path = file_path
        self.line_number = line_number
        self.raw_content = raw_content


def format_utc_timestamp(dt: Optional[datetime]) -> Optional[str]:
    """Format a timezone-aware datetime into UTC ISO 8601 string."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_timestamp(iso_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 UTC timestamp string."""
    if not iso_str:
        return None
    clean = iso_str.strip()
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    return datetime.fromisoformat(clean)


def serialize_record_to_dict(record: QuarantineRecord) -> dict[str, Any]:
    """Serialize a QuarantineRecord to a versioned dictionary."""
    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "quarantine_id": record.quarantine_id,
        "original_path": record.original_path,
        "vault_filename": record.vault_filename,
        "quarantined_at": format_utc_timestamp(record.quarantined_at),
        "sha256_hash": record.sha256_hash,
        "file_size_bytes": record.file_size_bytes,
        "status": record.status.value,
        "is_restored": record.is_restored,
        "restored_at": format_utc_timestamp(record.restored_at),
        "restored_path": record.restored_path,
    }


def deserialize_record_from_dict(
    data: dict[str, Any], file_path: Path, line_num: int
) -> QuarantineRecord:
    """Deserialize a dictionary into a QuarantineRecord with strict schema validation."""
    version = data.get("schema_version")
    if version != CURRENT_SCHEMA_VERSION:
        raise QuarantineIndexCorruptedError(
            f"Unsupported schema version '{version}', expected '{CURRENT_SCHEMA_VERSION}'",
            file_path=file_path,
            line_number=line_num,
            raw_content=json.dumps(data),
        )

    quarantined_at = parse_utc_timestamp(data.get("quarantined_at"))
    if quarantined_at is None:
        raise QuarantineIndexCorruptedError(
            "Missing or invalid 'quarantined_at' timestamp",
            file_path=file_path,
            line_number=line_num,
            raw_content=json.dumps(data),
        )

    try:
        status_val = QuarantineStatus(data.get("status", QuarantineStatus.COMMITTED.value))
    except ValueError as exc:
        raise QuarantineIndexCorruptedError(
            f"Invalid quarantine status: {exc}",
            file_path=file_path,
            line_number=line_num,
            raw_content=json.dumps(data),
        ) from exc

    return QuarantineRecord(
        quarantine_id=str(data["quarantine_id"]),
        original_path=str(data["original_path"]),
        vault_filename=str(data["vault_filename"]),
        quarantined_at=quarantined_at,
        sha256_hash=data.get("sha256_hash"),
        file_size_bytes=data.get("file_size_bytes"),
        status=status_val,
        is_restored=bool(data.get("is_restored", False)),
        restored_at=parse_utc_timestamp(data.get("restored_at")),
        restored_path=data.get("restored_path"),
    )


class QuarantineIndexManager:
    """Thread-safe persistent manager for quarantine_index.txt."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        index_path: Optional[Path] = None,
    ) -> None:
        """Initialize the QuarantineIndexManager.

        Args:
            config: Optional SentinelConfig.
            index_path: Optional explicit file path overriding config.quarantine_index_path.
        """
        self._config = config or get_config()
        self._index_path = Path(index_path) if index_path else self._config.quarantine_index_path
        self._lock = threading.RLock()
        self._records: dict[str, QuarantineRecord] = {}
        self._loaded: bool = False

    @property
    def index_path(self) -> Path:
        """Return the target file path for the quarantine index."""
        return self._index_path

    def load(self) -> None:
        """Load and parse records from quarantine_index.txt into memory.

        If the file does not exist, starts with an empty index.

        Raises:
            QuarantineIndexCorruptedError: If file contains corrupted or invalid JSON.
            QuarantineIndexError: If an I/O error occurs reading the file.
        """
        with self._lock:
            self._load_unlocked()

    def _load_unlocked(self) -> None:
        """Internal loader executing without acquiring lock."""
        if not self._index_path.exists() or self._index_path.stat().st_size == 0:
            self._records = {}
            self._loaded = True
            return

        new_records: dict[str, QuarantineRecord] = {}
        try:
            with open(self._index_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    clean_line = line.strip()
                    if not clean_line:
                        continue
                    try:
                        payload = json.loads(clean_line)
                    except json.JSONDecodeError as exc:
                        raise QuarantineIndexCorruptedError(
                            f"Malformed JSON: {exc}",
                            file_path=self._index_path,
                            line_number=line_num,
                            raw_content=clean_line,
                        ) from exc

                    record = deserialize_record_from_dict(payload, self._index_path, line_num)
                    if record.quarantine_id in new_records:
                        raise QuarantineIndexCorruptedError(
                            f"Duplicate quarantine_id '{record.quarantine_id}' found in index",
                            file_path=self._index_path,
                            line_number=line_num,
                            raw_content=clean_line,
                        )
                    new_records[record.quarantine_id] = record

        except OSError as exc:
            raise QuarantineIndexError(
                f"Failed to read quarantine index from '{self._index_path}': {exc}"
            ) from exc

        self._records = new_records
        self._loaded = True

    def _ensure_loaded_unlocked(self) -> None:
        """Helper to ensure index is loaded before accessing records (must be called with lock)."""
        if not self._loaded:
            self._load_unlocked()

    def _persist_unlocked(self, candidate_records: dict[str, QuarantineRecord]) -> None:
        """Atomically persist records to disk with fsync and replace."""
        self._index_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._index_path.with_name(
            f"{self._index_path.name}.tmp_{os.getpid()}_{uuid.uuid4().hex}"
        )

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                for record in candidate_records.values():
                    dict_rep = serialize_record_to_dict(record)
                    f.write(json.dumps(dict_rep) + "\n")
                f.flush()
                os.fsync(f.fileno())

            # Atomic file replacement
            os.replace(temp_path, self._index_path)

            # Best-effort directory entry sync on platforms supporting directory fsync
            try:
                parent_fd = os.open(str(self._index_path.parent), os.O_RDONLY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            except (OSError, AttributeError):
                pass
        except OSError as exc:
            # Clean up abandoned temporary file if present
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise QuarantineIndexError(
                f"Failed to persist quarantine index to '{self._index_path}': {exc}"
            ) from exc

    def add_record(self, record: QuarantineRecord) -> None:
        """Add a new QuarantineRecord and persist it to disk atomically.

        Args:
            record: QuarantineRecord to store.

        Raises:
            DuplicateRecordError: If record.quarantine_id already exists.
            QuarantineIndexError: If disk persistence fails (in-memory state is preserved).
        """
        with self._lock:
            self._ensure_loaded_unlocked()

            if record.quarantine_id in self._records:
                raise DuplicateRecordError(
                    f"Quarantine record with ID '{record.quarantine_id}' already exists."
                )

            # Stage update into candidate map
            candidate = dict(self._records)
            candidate[record.quarantine_id] = record

            # Persist to disk first; if persistence fails, self._records is not modified
            self._persist_unlocked(candidate)
            self._records = candidate

    def get_record(self, quarantine_id: str) -> Optional[QuarantineRecord]:
        """Retrieve a QuarantineRecord by its ID."""
        with self._lock:
            self._ensure_loaded_unlocked()
            return self._records.get(quarantine_id)

    def list_records(
        self, status_filter: Optional[QuarantineStatus] = None
    ) -> list[QuarantineRecord]:
        """List all QuarantineRecords, optionally filtered by status."""
        with self._lock:
            self._ensure_loaded_unlocked()
            records = list(self._records.values())
            if status_filter is not None:
                return [r for r in records if r.status == status_filter]
            return records

    def update_record(
        self,
        quarantine_id: str,
        status: Optional[QuarantineStatus] = None,
        is_restored: Optional[bool] = None,
        restored_at: Optional[datetime] = None,
        restored_path: Optional[str] = None,
    ) -> QuarantineRecord:
        """Update an existing quarantine record and persist changes atomically.

        Args:
            quarantine_id: ID of the record to update.
            status: New QuarantineStatus.
            is_restored: New restoration boolean flag.
            restored_at: Timestamp when restored.
            restored_path: Path where restored.

        Returns:
            QuarantineRecord: The updated record instance.

        Raises:
            RecordNotFoundError: If quarantine_id does not exist.
            QuarantineIndexError: If disk persistence fails.
        """
        with self._lock:
            self._ensure_loaded_unlocked()

            existing = self._records.get(quarantine_id)
            if existing is None:
                raise RecordNotFoundError(
                    f"Quarantine record with ID '{quarantine_id}' not found."
                )

            updated = QuarantineRecord(
                quarantine_id=existing.quarantine_id,
                original_path=existing.original_path,
                vault_filename=existing.vault_filename,
                quarantined_at=existing.quarantined_at,
                sha256_hash=existing.sha256_hash,
                file_size_bytes=existing.file_size_bytes,
                status=status if status is not None else existing.status,
                is_restored=is_restored if is_restored is not None else existing.is_restored,
                restored_at=restored_at if restored_at is not None else existing.restored_at,
                restored_path=restored_path if restored_path is not None else existing.restored_path,
            )

            candidate = dict(self._records)
            candidate[quarantine_id] = updated

            self._persist_unlocked(candidate)
            self._records = candidate
            return updated
