"""Streaming cryptographic hash calculation and file stability verification.

This module provides memory-bounded SHA-256 calculation for arbitrary-sized files,
verifies file stability during reading, and enforces symlink boundary safety.

Design Decisions (for beginner developers):
1. **Incremental Streaming**:
   Large binary files (e.g. disk images, installer payloads) must never be loaded
   entirely into RAM. Files are read in fixed 64 KB chunks, bounding memory usage.
2. **File Stability Detection (Mid-Hash Mutation Detection)**:
   If a file is being actively written to or truncated by another process during
   hashing, returning a partial digest would result in storing an invalid hash in the
   vault or audit log. We inspect file size and nanosecond modification timestamps
   before and after reading. If a mismatch is detected, a `FileIntegrityUnstableError`
   is raised.
3. **Symlink Boundary Policy**:
   In alignment with the project's defensive traversal policy, symbolic links are
   rejected by default (`follow_symlinks=False`) to prevent reading external files
   or following malicious links outside target boundaries.
4. **Non-Destructive Guarantee**:
   This module opens files strictly in binary read mode (`"rb"`). It never writes,
   renames, moves, executes, or deletes the source file.
5. **Concurrency and TOCTOU Race Condition Boundaries**:
   Inspecting file size and modification timestamps before and after reading detects
   mid-hash mutations. However, on shared filesystems (especially FAT32/exFAT USB drives)
   where exclusive OS locking is unavailable, a TOCTOU (Time-Of-Check to Time-Of-Use) window
   remains if a file is altered and restored between checks. Stability detection provides
   defense-in-depth, while authoritative cryptographic integrity is achieved via
   authenticated encryption (AEAD) in the quarantine vault.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Final, Optional

from usb_sentinel.config import DEFAULT_STREAM_CHUNK_SIZE_BYTES, SentinelConfig, get_config


class IntegrityError(Exception):
    """Base exception for file integrity and hashing errors."""


class FileIntegrityUnstableError(IntegrityError):
    """Raised when file metadata changes between start and completion of hashing."""


class SymlinkNotPermittedError(IntegrityError):
    """Raised when an attempt is made to hash a symbolic link under follow_symlinks=False."""


class InvalidTargetError(IntegrityError):
    """Raised when the target path is a directory or unsupported filesystem object."""


class IntegrityIOError(IntegrityError):
    """Raised when an unexpected I/O or permissions failure occurs during hashing."""


class IntegrityCancelledError(IntegrityError):
    """Raised when SHA-256 calculation is aborted due to caller cancellation signal."""


def compute_sha256(
    file_path: Path | str,
    chunk_size_bytes: int = DEFAULT_STREAM_CHUNK_SIZE_BYTES,
    follow_symlinks: bool = False,
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> str:
    """Compute the SHA-256 hexadecimal digest of a file using incremental streaming.

    Args:
        file_path: Path to the target file.
        chunk_size_bytes: Buffer size for incremental reads (default 65,536 bytes).
        follow_symlinks: Whether to follow symbolic links (default False).

    Returns:
        str: Lowercase 64-character hexadecimal SHA-256 digest.

    Raises:
        FileNotFoundError: If the target file does not exist.
        InvalidTargetError: If the target is a directory or non-regular file.
        SymlinkNotPermittedError: If the target is a symbolic link and follow_symlinks=False.
        FileIntegrityUnstableError: If the file was modified while being hashed.
        PermissionError: If the file cannot be read due to operating system access limits.
        IntegrityIOError: If an I/O error occurs during streaming.
    """
    path = Path(file_path)

    # 1. Existence and Symlink Validation
    if not path.exists():
        raise FileNotFoundError(f"Target file does not exist: {file_path}")

    if not follow_symlinks and (path.is_symlink() or os.path.islink(path)):
        raise SymlinkNotPermittedError(
            f"Refusing to hash symbolic link under strict boundary policy: {file_path}"
        )

    if path.is_dir():
        raise InvalidTargetError(
            f"Cannot compute SHA-256 digest of a directory: {file_path}"
        )

    if chunk_size_bytes <= 0:
        raise ValueError(f"chunk_size_bytes must be positive, got {chunk_size_bytes}")

    # 2. Pre-Hash File Metadata Capture (Stability Baseline)
    try:
        st_pre = path.stat()
    except PermissionError:
        raise
    except OSError as exc:
        raise IntegrityIOError(f"Failed to inspect metadata for '{file_path}': {exc}") from exc

    hasher = hashlib.sha256()

    # 3. Incremental Streaming Read Loop
    try:
        with open(path, "rb") as stream:
            while True:
                if is_cancelled is not None and is_cancelled():
                    raise IntegrityCancelledError(
                        f"SHA-256 calculation aborted due to cancellation signal: '{file_path}'"
                    )
                chunk = stream.read(chunk_size_bytes)
                if not chunk:
                    break
                hasher.update(chunk)
    except PermissionError:
        raise
    except FileNotFoundError:
        # File was deleted while attempting to open/read
        raise
    except OSError as exc:
        raise IntegrityIOError(f"I/O error streaming '{file_path}': {exc}") from exc

    # 4. Post-Hash File Metadata Capture (Stability Verification)
    try:
        st_post = path.stat()
    except FileNotFoundError:
        raise FileIntegrityUnstableError(
            f"File disappeared immediately after hashing: {file_path}"
        )
    except OSError as exc:
        raise IntegrityIOError(f"Failed to verify post-hash metadata for '{file_path}': {exc}") from exc

    # Check for mid-hash modification: size or modification timestamp changed
    if (
        st_pre.st_size != st_post.st_size
        or st_pre.st_mtime_ns != st_post.st_mtime_ns
    ):
        raise FileIntegrityUnstableError(
            f"File was modified during integrity hashing (size {st_pre.st_size}->{st_post.st_size}, "
            f"mtime {st_pre.st_mtime_ns}->{st_post.st_mtime_ns}): {file_path}"
        )

    return hasher.hexdigest().lower()


def verify_sha256(
    file_path: Path | str,
    expected_digest: str,
    chunk_size_bytes: int = DEFAULT_STREAM_CHUNK_SIZE_BYTES,
    follow_symlinks: bool = False,
) -> bool:
    """Verify whether a file's calculated SHA-256 digest matches an expected digest.

    Validates that the expected digest is a valid 64-character hexadecimal string
    and uses constant-time comparison (`hmac.compare_digest`) to prevent timing
    side-channel attacks.

    Args:
        file_path: Path to the target file.
        expected_digest: Expected 64-character hexadecimal digest (case-insensitive).
        chunk_size_bytes: Buffer size for incremental reads.
        follow_symlinks: Whether to follow symbolic links.

    Returns:
        bool: True if digests match exactly; False otherwise.

    Raises:
        ValueError: If expected_digest is not a valid 64-character hexadecimal string.
        Same exceptions as compute_sha256 if file access or stability fails.
    """
    if not isinstance(expected_digest, str):
        raise ValueError(
            f"expected_digest must be a string, got {type(expected_digest).__name__}"
        )

    clean_expected = expected_digest.strip().lower()
    if len(clean_expected) != 64 or not all(c in "0123456789abcdef" for c in clean_expected):
        raise ValueError(
            f"Invalid expected SHA-256 digest format: must be a 64-character hexadecimal string, got '{expected_digest}'"
        )

    calculated = compute_sha256(
        file_path=file_path,
        chunk_size_bytes=chunk_size_bytes,
        follow_symlinks=follow_symlinks,
    )
    return hmac.compare_digest(calculated, clean_expected)
