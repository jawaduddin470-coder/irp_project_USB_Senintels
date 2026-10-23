"""Recursive volume and directory scanner for USB Sentinel.

This module provides defensive recursive inspection of mounted removable media volumes
or specific directories. It extracts file metadata, tags heuristic execution risks via
the RiskEngine, defensively prevents traversal loops and symlink boundary escapes,
and handles operating system access errors gracefully.

Design Decisions (for beginner developers):
1. **Defensive Non-Destructive Traversal**:
   This module ONLY performs read-only filesystem inspection (`os.stat` / `os.scandir`).
   It NEVER opens files for execution, writing, deletion, encryption, or relocation.
2. **Symlink and Junction Boundary Containment**:
   Removable media may contain malicious symbolic links or Windows NTFS directory
   junctions that point to parent directories (creating infinite recursion loops) or
   to internal system drives (e.g. `C:\\Windows`). Traversal explicitly passes
   `followlinks=False`, skips symlinks and junctions, and verifies that real paths
   remain strictly within the designated target boundary.
3. **Graceful Error Handling**:
   USB drives are frequently pulled out mid-scan, or files are locked by the operating
   system indexing service or Windows Defender. The scanner catches `PermissionError`,
   `FileNotFoundError`, and `OSError` without aborting the entire application.
4. **Targeted Long Path Handling**:
   Rather than blindly prepending the extended-length prefix `\\\\?\\` to all paths,
   Sentinel prepends it conditionally only on Windows, for absolute drive paths, when
   length approaches or exceeds Win32 `MAX_PATH` (>= 240 chars).
"""

from __future__ import annotations

import os
import stat
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Final, List, Optional, Set, Tuple

from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.models import (
    FileMetadata,
    RiskFinding,
    ScanResult,
    ScanStatus,
    utc_now,
)
from usb_sentinel.risk_engine import RiskEngine


@dataclass(frozen=True)
class ScanReport:
    """Comprehensive aggregated outcome of a recursive volume scan.

    Attributes:
        result: High-level scan summary and status statistics.
        scanned_files: List of all inspected FileMetadata objects.
        findings: List of all heuristically flagged RiskFinding objects.
        errors: List of human-readable error descriptions encountered during scan.
        skipped_paths: List of skipped paths (e.g. symlinks, junctions, boundary escapes).
    """

    result: ScanResult
    scanned_files: tuple[FileMetadata, ...] = field(default_factory=tuple)
    findings: tuple[RiskFinding, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    skipped_paths: tuple[str, ...] = field(default_factory=tuple)


def normalize_scan_path(path: Path) -> Path:
    """Conditionally normalize a path with extended-length prefix on Windows if needed.

    Avoids blindly prepending `\\\\?\\` on POSIX systems, relative paths, or network paths.
    """
    if sys.platform != "win32":
        return path

    path_str = str(path)
    # Check if path is an absolute local drive path approaching MAX_PATH
    if (
        len(path_str) >= 240
        and len(path_str) >= 3
        and path_str[1] == ":"
        and path_str[2] == "\\"
        and not path_str.startswith("\\\\?\\")
    ):
        return Path(f"\\\\?\\{path_str}")

    return path


def extract_platform_timestamps(stat_res: os.stat_result) -> tuple[datetime, Optional[datetime]]:
    """Extract platform-aware modification and creation timestamps in UTC.

    Returns:
        tuple[datetime, Optional[datetime]]: (modified_at, created_at)
        - modified_at: Always available from `st_mtime`.
        - created_at: `st_birthtime` on BSD/macOS, `st_ctime` on Windows, or None if unsupported.
    """
    modified_at = datetime.fromtimestamp(stat_res.st_mtime, tz=timezone.utc)

    created_at: Optional[datetime] = None
    if hasattr(stat_res, "st_birthtime") and stat_res.st_birthtime:
        created_at = datetime.fromtimestamp(stat_res.st_birthtime, tz=timezone.utc)
    elif sys.platform == "win32" and stat_res.st_ctime:
        # On Windows, st_ctime represents file creation time
        created_at = datetime.fromtimestamp(stat_res.st_ctime, tz=timezone.utc)

    return modified_at, created_at


def is_reparse_point_or_symlink(path: Path) -> bool:
    """Check if a path is a symbolic link or Windows NTFS reparse point (junction).

    Defensively prevents traversing into junctions or external directory mount points.
    """
    try:
        if path.is_symlink() or os.path.islink(path):
            return True
        # On Windows, directory junctions report file attributes containing FILE_ATTRIBUTE_REPARSE_POINT (0x400)
        st = path.stat()
        if stat.S_ISLNK(st.st_mode):
            return True
        file_attrs = getattr(st, "st_file_attributes", 0)
        if file_attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            return True
    except (OSError, PermissionError, FileNotFoundError):
        return False
    return False


class VolumeScanner:
    """Defensive recursive volume and directory scanner."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        risk_engine: Optional[RiskEngine] = None,
    ) -> None:
        """Initialize the VolumeScanner.

        Args:
            config: Optional SentinelConfig.
            risk_engine: Optional RiskEngine instance for heuristic evaluation.
        """
        self._config = config or get_config()
        self._risk_engine = risk_engine or RiskEngine(config=self._config)

    def scan(
        self,
        target_dir: Path | str,
        scan_id: Optional[str] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> ScanReport:
        """Perform a recursive, non-destructive inspection of the target directory.

        Args:
            target_dir: Absolute or relative path to the directory to inspect.
            scan_id: Optional unique identifier for this scan session.
            is_cancelled: Optional callback returning True if scan should abort early.

        Returns:
            ScanReport: Aggregated results containing metadata, findings, and error statistics.

        Raises:
            FileNotFoundError: If target_dir does not exist.
            NotADirectoryError: If target_dir is a file instead of a directory.
        """
        raw_path = Path(target_dir)
        if not raw_path.exists():
            raise FileNotFoundError(f"Scan target path does not exist: {target_dir}")
        if not raw_path.is_dir():
            raise NotADirectoryError(f"Scan target is not a directory: {target_dir}")

        # Canonicalize base path to establish strict scan boundary
        scan_root = raw_path.resolve()
        active_scan_id = scan_id or f"SCAN_{uuid.uuid4().hex[:12].upper()}"
        started_at = utc_now()

        scanned_files: list[FileMetadata] = []
        findings: list[RiskFinding] = []
        errors: list[str] = []
        skipped_paths: list[str] = []

        visited_dirs: set[str] = set()
        visited_dirs.add(str(scan_root))

        status = ScanStatus.IN_PROGRESS
        aborted = False

        # Directory error handler for os.walk
        def on_walk_error(err: OSError) -> None:
            nonlocal errors
            errors.append(f"Directory access error on '{err.filename}': {err.strerror}")

        # Recursive traversal with explicit followlinks=False
        for root, dirs, files in os.walk(scan_root, followlinks=False, onerror=on_walk_error):
            # Check for cancellation before processing each directory
            if is_cancelled and is_cancelled():
                status = ScanStatus.ABORTED_DISCONNECT
                aborted = True
                errors.append("Scan was cancelled by user or caller request.")
                break

            current_root = Path(root)

            # --- Defensive Directory Pruning ---
            # Prune directory symlinks, junctions, and directories escaping scan boundary
            safe_dirs: list[str] = []
            for d in dirs:
                dir_path = current_root / d
                try:
                    if is_reparse_point_or_symlink(dir_path):
                        skipped_paths.append(str(dir_path))
                        continue

                    # Boundary containment: ensure canonical realpath resides inside scan_root
                    real_dir = dir_path.resolve()
                    try:
                        real_dir.relative_to(scan_root)
                    except ValueError:
                        # Path traverses outside permitted root; skip
                        skipped_paths.append(str(dir_path))
                        continue

                    real_dir_str = str(real_dir)
                    if real_dir_str in visited_dirs:
                        # Prevent cyclic loops
                        skipped_paths.append(str(dir_path))
                        continue

                    visited_dirs.add(real_dir_str)
                    safe_dirs.append(d)
                except (PermissionError, FileNotFoundError, OSError) as exc:
                    errors.append(f"Error checking directory '{dir_path}': {exc}")
                    skipped_paths.append(str(dir_path))

            # Modify dirs in-place to instruct os.walk to descend only into safe directories
            dirs[:] = safe_dirs

            # --- File Inspection Loop ---
            for filename in files:
                if is_cancelled and is_cancelled():
                    status = ScanStatus.ABORTED_DISCONNECT
                    aborted = True
                    errors.append("Scan was cancelled by user or caller request.")
                    break

                raw_file_path = current_root / filename
                normalized_file_path = normalize_scan_path(raw_file_path)

                # Skip file-level symlinks to prevent reading external targets
                try:
                    if raw_file_path.is_symlink() or os.path.islink(raw_file_path):
                        skipped_paths.append(str(raw_file_path))
                        continue
                except (OSError, PermissionError):
                    skipped_paths.append(str(raw_file_path))
                    continue

                # Defensive stat inspection
                try:
                    st = raw_file_path.stat()
                except PermissionError as exc:
                    errors.append(f"Permission denied reading '{raw_file_path}': {exc}")
                    continue
                except FileNotFoundError:
                    # File disappeared between walk enumeration and stat
                    errors.append(f"File disappeared during scan: '{raw_file_path}'")
                    continue
                except OSError as exc:
                    errors.append(f"I/O error reading '{raw_file_path}': {exc}")
                    continue

                modified_at, created_at = extract_platform_timestamps(st)
                extension = raw_file_path.suffix.lower()

                # Check read-only status defensively
                is_readonly = not os.access(raw_file_path, os.W_OK)

                metadata = FileMetadata(
                    filename=filename,
                    file_path=str(raw_file_path),
                    extension=extension,
                    size_bytes=st.st_size,
                    modified_at=modified_at,
                    created_at=created_at,
                    is_symlink=False,
                    is_readonly=is_readonly,
                )
                scanned_files.append(metadata)

                # Evaluate file against heuristic risk rules
                file_findings = self._risk_engine.evaluate_file(metadata)
                if file_findings:
                    findings.extend(file_findings)

            if aborted:
                break

        completed_at = utc_now()
        if not aborted:
            if errors:
                status = ScanStatus.COMPLETED_WITH_ERRORS
            else:
                status = ScanStatus.COMPLETED

        error_summary = "; ".join(errors[:5]) if errors else None

        scan_result = ScanResult(
            scan_id=active_scan_id,
            target_path=str(scan_root),
            started_at=started_at,
            completed_at=completed_at,
            files_inspected=len(scanned_files),
            findings_count=len(findings),
            errors_count=len(errors),
            status=status,
            error_summary=error_summary,
        )

        return ScanReport(
            result=scan_result,
            scanned_files=tuple(scanned_files),
            findings=tuple(findings),
            errors=tuple(errors),
            skipped_paths=tuple(skipped_paths),
        )
