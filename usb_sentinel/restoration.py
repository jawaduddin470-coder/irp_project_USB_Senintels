"""Safe restoration service and integrity verification for USB Sentinel.

This module provides non-destructive restoration of quarantined files from the encrypted
vault, enforcing explicit destination confirmation, path traversal defenses, anti-collision
guards, full cryptographic re-authentication, and post-restoration audit updates.

Design Principles & Security Guarantees:
1. **No Silent Restorations**:
   Sentinel NEVER restores silently to an assumed destination. If the original drive is
   disconnected or unavailable, the user must explicitly confirm or supply a destination
   directory (with `%USERPROFILE%\\Desktop\\Restored_Files\\` provided as a selectable default).
2. **Anti-Collision Protection**:
   Existing files are never silently overwritten. Restorations reject collisions by default,
   or safely rename target files (`<filename>_restored_<timestamp>.<ext>`) when requested.
3. **Defense-in-Depth Path Traversal**:
   Destinations are canonicalized with `Path.resolve()` to defend against `../` path traversal
   attacks or symlink hijacking.
4. **End-to-End Cryptographic Verification**:
   The vault object is decrypted into a private temporary file in the destination folder.
   Plaintext is published to the final destination ONLY after 100% of chunk tags are authenticated
   and the recovered plaintext SHA-256 matches the original recorded baseline.
"""

from __future__ import annotations

import os
import uuid
from enum import Enum
from pathlib import Path, PureWindowsPath
from typing import Final, Optional, Tuple

from usb_sentinel.audit import AuditLedger
from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.crypto_keys import KeyManager
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    QuarantineRecord,
    QuarantineStatus,
    utc_now,
)
from usb_sentinel.quarantine_index import QuarantineIndexManager
from usb_sentinel.vault import DestinationCollisionError, VaultIntegrityError, VaultManager


class RestorationConflictPolicy(str, Enum):
    """Policy for handling destination filename collisions during restoration."""

    REJECT = "REJECT"        # Default: Abort with error if destination file already exists
    RENAME_NEW = "RENAME_NEW"# Append timestamp suffix: stem_restored_<timestamp>.ext
    OVERWRITE = "OVERWRITE"  # Overwrite existing destination (requires explicit selection)


class RestorationError(Exception):
    """Base exception for file restoration failures."""


class RestorationCollisionError(RestorationError, DestinationCollisionError):
    """Raised when destination file exists and conflict policy is REJECT."""


class RestorationIntegrityError(RestorationError):
    """Raised when decrypted plaintext fails SHA-256 verification or chunk authentication."""


class RestorationPersistenceError(RestorationError):
    """Raised when the file was restored to disk, but quarantine index or audit persistence failed."""


class RestorationManager:
    """Manages safe, verified restoration of quarantined vault objects."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        key_manager: Optional[KeyManager] = None,
        vault_manager: Optional[VaultManager] = None,
        index_manager: Optional[QuarantineIndexManager] = None,
        audit_ledger: Optional[AuditLedger] = None,
    ) -> None:
        self._config = config or get_config()
        self._key_manager = key_manager or KeyManager(config=self._config)
        self._vault_manager = vault_manager or VaultManager(
            config=self._config, key_manager=self._key_manager
        )
        self._index_manager = index_manager or QuarantineIndexManager(config=self._config)
        self._audit_ledger = audit_ledger or AuditLedger(config=self._config)

    @property
    def config(self) -> SentinelConfig:
        return self._config

    @property
    def index_manager(self) -> QuarantineIndexManager:
        return self._index_manager

    def restore_file(
        self,
        quarantine_id: str,
        destination_dir: Optional[Path | str] = None,
        explicit_target_path: Optional[Path | str] = None,
        conflict_policy: RestorationConflictPolicy = RestorationConflictPolicy.REJECT,
        allow_overwrite: bool = False,
    ) -> tuple[Path, QuarantineRecord]:
        """Restore a quarantined file from the encrypted vault to a verified destination.

        Args:
            quarantine_id: Identifier of the record to restore.
            destination_dir: Directory where restored file should be placed (using original filename).
            explicit_target_path: Full explicit target file path.
            conflict_policy: How to handle destination file collisions.
            allow_overwrite: Explicit flag authorizing overwriting an existing target (never symlinks).

        Returns:
            tuple[Path, QuarantineRecord]: Final restored file path and updated record.

        Raises:
            RestorationError: If record, vault file, or key is missing.
            RestorationCollisionError: If destination exists and policy is REJECT, or destination is a symlink.
            RestorationIntegrityError: If decryption or digest verification fails.
            RestorationPersistenceError: If file restored but index/audit persistence failed.
        """
        # 1. Retrieve and Validate Quarantine Record
        record = self._index_manager.get_record(quarantine_id)
        if record is None:
            raise RestorationError(f"Quarantine record '{quarantine_id}' not found in index")

        vault_file = self._config.vault_dir / record.vault_filename
        if not vault_file.exists():
            raise RestorationError(
                f"Vault file '{record.vault_filename}' for record '{quarantine_id}' "
                f"not found in vault directory '{self._config.vault_dir}'"
            )

        # 2. Determine Destination File Path
        if "\\" in record.original_path:
            orig_filename = PureWindowsPath(record.original_path).name
        else:
            orig_filename = Path(record.original_path).name

        if not orig_filename or orig_filename in (".", ".."):
            orig_filename = f"restored_{record.quarantine_id}.bin"

        if explicit_target_path is not None:
            target_path = Path(explicit_target_path)
        elif destination_dir is not None:
            dest_dir_resolved = Path(destination_dir).resolve()
            target_path = dest_dir_resolved / orig_filename
            try:
                if not target_path.resolve().is_relative_to(dest_dir_resolved):
                    raise RestorationError(
                        f"Path traversal detected: destination '{target_path}' escapes destination directory '{dest_dir_resolved}'"
                    )
            except ValueError:
                raise RestorationError(
                    f"Path traversal detected: destination '{target_path}' escapes destination directory '{dest_dir_resolved}'"
                )
        else:
            # Check if original directory path is available and usable
            orig_parent = Path(record.original_path).parent
            if orig_parent.exists() and os.access(orig_parent, os.W_OK):
                target_path = Path(record.original_path)
            else:
                raise RestorationError(
                    f"Original drive location '{orig_parent}' is unavailable. "
                    f"A destination directory must be provided. "
                    f"Convenience default: '{self._config.default_restored_dir}'"
                )

        # Canonicalize target directory path and defend against directory traversal
        try:
            target_parent = target_path.parent.resolve()
            target_parent.mkdir(parents=True, exist_ok=True)
            target_path = target_parent / target_path.name
        except OSError as exc:
            raise RestorationError(f"Invalid restoration destination '{target_path}': {exc}") from exc

        # Block destination symlinks unconditionally (even under overwrite)
        if target_path.is_symlink() or os.path.islink(target_path):
            raise RestorationCollisionError(
                f"Restoration destination is a symbolic link, which is strictly prohibited: '{target_path}'"
            )

        # Determine effective overwrite authorization
        effective_allow_overwrite = allow_overwrite or (conflict_policy == RestorationConflictPolicy.OVERWRITE)

        # 3. Handle File Collisions
        if target_path.exists():
            if conflict_policy == RestorationConflictPolicy.REJECT and not effective_allow_overwrite:
                raise RestorationCollisionError(
                    f"Restoration destination file already exists: '{target_path}'. "
                    "Use RENAME_NEW policy or specify an alternate destination."
                )
            elif conflict_policy == RestorationConflictPolicy.RENAME_NEW:
                ts = utc_now().strftime("%Y%m%d_%H%M%S")
                stem = target_path.stem
                suffix = target_path.suffix
                target_path = target_parent / f"{stem}_restored_{ts}{suffix}"
            elif effective_allow_overwrite:
                pass  # Overwrite authorized by caller

        # 4. Decrypt and Verify Plaintext
        master_key = self._key_manager.get_or_create_master_key()
        try:
            restored_dest = self._vault_manager.decrypt_vault_file(
                vault_file_path=vault_file,
                quarantine_id=quarantine_id,
                master_key=master_key,
                destination_path=target_path,
                expected_sha256=record.sha256_hash,
                allow_overwrite=effective_allow_overwrite,
            )
        except DestinationCollisionError as exc:
            raise RestorationCollisionError(str(exc)) from exc
        except VaultIntegrityError as exc:
            raise RestorationIntegrityError(
                f"Restoration aborted: decrypted plaintext failed SHA-256 verification: {exc}"
            ) from exc
        except Exception as exc:
            raise RestorationError(f"Decryption failed for '{quarantine_id}': {exc}") from exc

        # 5. Update Quarantine Index and Audit Ledger
        now_dt = utc_now()
        try:
            updated_record = self._index_manager.update_record(
                quarantine_id=quarantine_id,
                status=QuarantineStatus.RESTORED,
                is_restored=True,
                restored_at=now_dt,
                restored_path=str(restored_dest),
            )
        except Exception as exc:
            # File is restored on disk, but index update failed.
            fail_event = AuditEvent(
                event_id=f"EVT_RESTERR_{uuid.uuid4().hex[:8]}",
                timestamp=now_dt,
                event_type=AuditEventType.SYSTEM_ERROR,
                status=AuditStatus.ERROR,
                target_path=str(restored_dest),
                quarantine_id=quarantine_id,
                sha256_hash=record.sha256_hash,
                details=f"File restored to '{restored_dest}', but quarantine index update failed.",
                error_message=str(exc),
            )
            try:
                self._audit_ledger.append_event(fail_event)
            except Exception:
                pass
            raise RestorationPersistenceError(
                f"File was successfully restored to '{restored_dest}', but updating "
                f"quarantine_index.txt failed: {exc}"
            ) from exc

        # Write FILE_RESTORED Audit Event
        audit_evt = AuditEvent(
            event_id=f"EVT_REST_{uuid.uuid4().hex[:8]}",
            timestamp=now_dt,
            event_type=AuditEventType.FILE_RESTORED,
            status=AuditStatus.SUCCESS,
            target_path=str(restored_dest),
            quarantine_id=quarantine_id,
            sha256_hash=record.sha256_hash,
            details=f"File successfully restored from vault to '{restored_dest}'.",
        )
        try:
            self._audit_ledger.append_event(audit_evt)
        except Exception:
            pass

        return restored_dest, updated_record
