"""Crash-safe quarantine service and transaction engine for USB Sentinel.

This module coordinates five-step crash-safe quarantine operations, enforcing strict
source validation, staging verification before promotion, audit logging, persistent indexing,
and safe handling of write-protected media (QUARANTINE_SOURCE_LOCKED).

Design Principles & Transaction Guarantees:
1. **Policy Enforcement**:
   The default watchdog policy is ALERT AND LOG ONLY. Automatic quarantine is disabled
   by default. Quarantine operations require explicit caller confirmation (`explicit_confirm=True`)
   or an active policy override.
2. **Crash-Safe Ordering (Five-Step Transaction)**:
   - Step 1: Read source, compute SHA-256, stream-encrypt to staging (`<id>.tmp`).
   - Step 2: Full verification pass authenticating all tags and verifying plaintext digest.
             If verification fails: abort, staging cleaned up, source file untouched.
   - Step 3: Atomically promote `<id>.tmp` -> `<id>.qnt` in the vault.
   - Step 4: Persist quarantine record (status COMMITTED) and audit event.
   - Step 5: Only if explicitly requested and authorized, delete original source file.
3. **Non-Destructive Deletion Fallback**:
   If source deletion fails (e.g. write-protected USB storage), the verified encrypted
   vault copy is retained, the state is recorded as `QUARANTINE_SOURCE_LOCKED`, and the user
   is prominently warned. Deletion is never reported as successful when it failed.
4. **Pre-Deletion Revalidation**:
   Immediately before any authorized source deletion, the source file's size and mtime are
   re-verified. If the file changed during the process, deletion is aborted.
"""

from __future__ import annotations

import hmac
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Optional

from usb_sentinel.audit import AuditLedger
from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.crypto_keys import KeyManager
from usb_sentinel.integrity import compute_sha256
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    QuarantineRecord,
    QuarantineStatus,
    utc_now,
)
from usb_sentinel.quarantine_index import QuarantineIndexManager
from usb_sentinel.vault import VaultManager


class QuarantineError(Exception):
    """Base exception for quarantine operations."""


class QuarantinePolicyViolationError(QuarantineError):
    """Raised when quarantine is attempted without explicit confirmation under ALERT_AND_LOG_ONLY."""


class QuarantineVerificationError(QuarantineError):
    """Raised when staged encrypted object fails integrity verification before vault promotion."""


class QuarantinePersistenceError(QuarantineError):
    """Raised when quarantine record or audit persistence fails after vault promotion."""


class QuarantineManager:
    """Coordinates the crash-safe five-step quarantine workflow."""

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
    def vault_manager(self) -> VaultManager:
        return self._vault_manager

    @property
    def index_manager(self) -> QuarantineIndexManager:
        return self._index_manager

    @property
    def audit_ledger(self) -> AuditLedger:
        return self._audit_ledger

    def quarantine_file(
        self,
        source_path: Path | str,
        explicit_confirm: bool = False,
        remove_source: bool = False,
        device_ref: Optional[str] = None,
    ) -> QuarantineRecord:
        """Execute the five-step crash-safe quarantine transaction for a target file.

        Args:
            source_path: Path to the suspicious file on storage media.
            explicit_confirm: Must be True to proceed unless auto-quarantine is enabled.
            remove_source: Whether to delete the original source file after vault commit.
            device_ref: Optional drive letter or volume reference (e.g. 'E:').

        Returns:
            QuarantineRecord: The committed or quarantined record.

        Raises:
            FileNotFoundError: If source_path does not exist.
            QuarantinePolicyViolationError: If quarantine is not authorized.
            QuarantineError: On validation, encryption, or verification failure.
        """
        src = Path(source_path)

        # 1. Validation & Policy Enforcement
        if not src.exists():
            raise FileNotFoundError(f"Source file to quarantine does not exist: {source_path}")

        if src.is_symlink() or os.path.islink(src):
            raise QuarantineError(
                f"Refusing to quarantine symbolic link under defensive boundary policy: {source_path}"
            )

        if src.is_dir():
            raise QuarantineError(f"Cannot quarantine a directory: {source_path}")

        if not explicit_confirm and not self._config.auto_quarantine_enabled:
            raise QuarantinePolicyViolationError(
                "Quarantine operation rejected: default policy is ALERT AND LOG ONLY. "
                "Explicit user confirmation is required to quarantine files."
            )

        quarantine_id = str(uuid.uuid4())
        master_key = self._key_manager.get_or_create_master_key()

        # 2. Record Quarantine Initiation Audit Event
        init_event = AuditEvent(
            event_id=f"EVT_QINIT_{uuid.uuid4().hex[:8]}",
            timestamp=utc_now(),
            event_type=AuditEventType.QUARANTINE_INITIATED,
            status=AuditStatus.INFORMATIONAL,
            device_ref=device_ref,
            target_path=str(src),
            quarantine_id=quarantine_id,
            details=f"Initiating crash-safe quarantine for '{src.name}'. remove_source={remove_source}",
        )
        try:
            self._audit_ledger.append_event(init_event)
        except Exception:
            # Audit logging failure on initiation should not block defensive action, but we note it
            pass

        # Capture pre-quarantine metadata baseline
        try:
            st_pre = src.stat()
            file_size_bytes = st_pre.st_size
        except OSError as exc:
            raise QuarantineError(f"Failed to inspect source file metadata: {exc}") from exc

        # Step 1: Encrypt to Staging File (<quarantine_id>.tmp)
        staging_path: Optional[Path] = None
        try:
            staging_path, header = self._vault_manager.encrypt_to_staging(
                source_path=src,
                quarantine_id=quarantine_id,
                master_key=master_key,
            )
            sha256_hash = header.sha256_hex
        except Exception as exc:
            raise QuarantineError(f"Step 1 encryption failed for '{src}': {exc}") from exc

        # Step 2: Verify Staged Encrypted Object & Plaintext Digest
        try:
            self._vault_manager.authenticate_and_verify_stream(
                vault_file_path=staging_path,
                quarantine_id=quarantine_id,
                master_key=master_key,
                expected_sha256=sha256_hash,
            )
        except Exception as exc:
            # Clean up unverified staging file; original remains untouched on USB
            if staging_path and staging_path.exists():
                try:
                    staging_path.unlink()
                except OSError:
                    pass
            fail_event = AuditEvent(
                event_id=f"EVT_QFAIL_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.QUARANTINE_INITIATED,
                status=AuditStatus.ERROR,
                device_ref=device_ref,
                target_path=str(src),
                quarantine_id=quarantine_id,
                details="Staged encrypted object failed verification check. Source remains intact.",
                error_message=str(exc),
            )
            try:
                self._audit_ledger.append_event(fail_event)
            except Exception:
                pass
            raise QuarantineVerificationError(
                f"Step 2 verification failed for '{src}': {exc}. Staging file cleaned up."
            ) from exc

        # Step 3: Atomically Promote Verified Object to Final Vault Path
        try:
            vault_path = self._vault_manager.promote_staging_to_vault(quarantine_id)
        except Exception as exc:
            raise QuarantineError(f"Step 3 vault promotion failed for '{quarantine_id}': {exc}") from exc

        # Step 4: Persist Quarantine Record and Audit State
        now_dt = utc_now()
        record = QuarantineRecord(
            quarantine_id=quarantine_id,
            original_path=str(src),
            vault_filename=vault_path.name,
            quarantined_at=now_dt,
            sha256_hash=sha256_hash,
            file_size_bytes=file_size_bytes,
            status=QuarantineStatus.COMMITTED,
            is_restored=False,
            restored_at=None,
            restored_path=None,
        )

        try:
            self._index_manager.add_record(record)
        except Exception as exc:
            # Vault object exists, but index failed. Record this failure explicitly.
            commit_err_event = AuditEvent(
                event_id=f"EVT_QERR_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.SYSTEM_ERROR,
                status=AuditStatus.ERROR,
                device_ref=device_ref,
                target_path=str(src),
                quarantine_id=quarantine_id,
                sha256_hash=sha256_hash,
                details="Vault promotion succeeded but quarantine index persistence failed.",
                error_message=str(exc),
            )
            try:
                self._audit_ledger.append_event(commit_err_event)
            except Exception:
                pass
            raise QuarantinePersistenceError(
                f"Quarantine object committed to '{vault_path}', but quarantine_index.txt "
                f"persistence failed: {exc}"
            ) from exc

        # Log QUARANTINE_COMMITTED
        committed_event = AuditEvent(
            event_id=f"EVT_QCOMM_{uuid.uuid4().hex[:8]}",
            timestamp=utc_now(),
            event_type=AuditEventType.QUARANTINE_COMMITTED,
            status=AuditStatus.SUCCESS,
            device_ref=device_ref,
            target_path=str(src),
            quarantine_id=quarantine_id,
            sha256_hash=sha256_hash,
            details=f"File successfully encrypted and committed to vault object '{vault_path.name}'.",
        )
        try:
            self._audit_ledger.append_event(committed_event)
        except Exception as exc:
            raise QuarantinePersistenceError(
                f"Quarantine object committed to '{vault_path}' and indexed, but audit logging failed: {exc}. "
                "Aborting source deletion to preserve audit consistency."
            ) from exc

        # Step 5: Optional Source Deletion
        if not remove_source:
            # Caller did not request deletion: source retained, status remains COMMITTED
            return record

        # Re-verify source file stability, identity, and content digest immediately prior to deletion
        try:
            if not src.exists() or src.is_symlink() or os.path.islink(src) or not src.is_file():
                abort_event = AuditEvent(
                    event_id=f"EVT_QABRT_{uuid.uuid4().hex[:8]}",
                    timestamp=utc_now(),
                    event_type=AuditEventType.SYSTEM_WARNING,
                    status=AuditStatus.WARNING,
                    device_ref=device_ref,
                    target_path=str(src),
                    quarantine_id=quarantine_id,
                    details="Source file disappeared, is a symlink, or is not a regular file; aborting deletion. Original retained.",
                )
                try:
                    self._audit_ledger.append_event(abort_event)
                except Exception:
                    pass
                return record

            st_post = src.stat()
            if st_post.st_size != st_pre.st_size or st_post.st_mtime_ns != st_pre.st_mtime_ns:
                # Source mutated while encrypting: ABORT deletion to prevent data loss
                abort_event = AuditEvent(
                    event_id=f"EVT_QABRT_{uuid.uuid4().hex[:8]}",
                    timestamp=utc_now(),
                    event_type=AuditEventType.SYSTEM_WARNING,
                    status=AuditStatus.WARNING,
                    device_ref=device_ref,
                    target_path=str(src),
                    quarantine_id=quarantine_id,
                    details="Source file metadata modified during quarantine; aborting deletion. Original retained.",
                )
                try:
                    self._audit_ledger.append_event(abort_event)
                except Exception:
                    pass
                return record

            # On POSIX: verify file identity (inode and device)
            if hasattr(st_post, "st_ino") and hasattr(st_pre, "st_ino"):
                if st_post.st_ino != st_pre.st_ino or st_post.st_dev != st_pre.st_dev:
                    abort_event = AuditEvent(
                        event_id=f"EVT_QABRT_{uuid.uuid4().hex[:8]}",
                        timestamp=utc_now(),
                        event_type=AuditEventType.SYSTEM_WARNING,
                        status=AuditStatus.WARNING,
                        device_ref=device_ref,
                        target_path=str(src),
                        quarantine_id=quarantine_id,
                        details="Source file identity (inode/dev) changed during quarantine; aborting deletion. Original retained.",
                    )
                    try:
                        self._audit_ledger.append_event(abort_event)
                    except Exception:
                        pass
                    return record

            # Hash source immediately prior to deletion and compare with recorded digest
            current_digest = compute_sha256(src)
            if not hmac.compare_digest(current_digest.lower(), sha256_hash.lower()):
                abort_event = AuditEvent(
                    event_id=f"EVT_QABRT_{uuid.uuid4().hex[:8]}",
                    timestamp=utc_now(),
                    event_type=AuditEventType.SYSTEM_WARNING,
                    status=AuditStatus.WARNING,
                    device_ref=device_ref,
                    target_path=str(src),
                    quarantine_id=quarantine_id,
                    details="Source file content mutated during quarantine (hash mismatch); aborting deletion. Original retained.",
                )
                try:
                    self._audit_ledger.append_event(abort_event)
                except Exception:
                    pass
                return record

        except (FileNotFoundError, OSError):
            # Source disappeared before deletion
            return record

        # Attempt deletion
        try:
            src.unlink()
            # Deletion succeeded: update status to QUARANTINED
            updated_record = self._index_manager.update_record(
                quarantine_id=quarantine_id,
                status=QuarantineStatus.QUARANTINED,
            )
            del_event = AuditEvent(
                event_id=f"EVT_QDEL_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.QUARANTINE_COMMITTED,
                status=AuditStatus.SUCCESS,
                device_ref=device_ref,
                target_path=str(src),
                quarantine_id=quarantine_id,
                sha256_hash=sha256_hash,
                details="Source file removed from storage media. Full quarantine completed.",
            )
            try:
                self._audit_ledger.append_event(del_event)
            except Exception:
                pass
            return updated_record

        except (PermissionError, OSError) as exc:
            # Write-protected USB or locked file: retain verified vault copy and mark QUARANTINE_SOURCE_LOCKED
            locked_record = self._index_manager.update_record(
                quarantine_id=quarantine_id,
                status=QuarantineStatus.QUARANTINE_SOURCE_LOCKED,
            )
            locked_event = AuditEvent(
                event_id=f"EVT_QLOCK_{uuid.uuid4().hex[:8]}",
                timestamp=utc_now(),
                event_type=AuditEventType.QUARANTINE_SOURCE_LOCKED,
                status=AuditStatus.WARNING,
                device_ref=device_ref,
                target_path=str(src),
                quarantine_id=quarantine_id,
                sha256_hash=sha256_hash,
                details="Source file removal failed (write-protected media). Encrypted vault copy retained.",
                error_message=str(exc),
            )
            try:
                self._audit_ledger.append_event(locked_event)
            except Exception:
                pass
            return locked_record
