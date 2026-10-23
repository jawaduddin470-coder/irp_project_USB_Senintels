"""Crash-recovery reconciler for USB Sentinel.

This module inspects staging and vault directories across application restarts,
safely resolving incomplete transactions without data loss.

Recovery Guarantees:
1. **Never Silently Purge**:
   Sentinel NEVER automatically deletes files that may be needed for recovery or forensic
   investigation. Abandoned staging artifacts are safely quarantined into `vault/recovery/`.
2. **Orphan Reconciler**:
   If a valid, verified `.qnt` file exists in the vault but lacks an entry in `quarantine_index.txt`
   (e.g., power failed between vault promotion and index write), the reconciler verifies
   the object's cryptographic integrity and adds it to the index with status
   `ORPHAN_RECONCILED`.
3. **Never Delete USB Sources during Recovery**:
   Reconciling an orphaned vault object NEVER touches or deletes the original file on the USB
   storage media.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, List, Optional

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
from usb_sentinel.vault import VaultError, VaultManager


@dataclass(frozen=True)
class RecoverySummary:
    """Summary of operations performed during crash recovery reconciliation."""

    orphans_reconciled: int = 0
    incomplete_archived: int = 0
    uncommitted_archived: int = 0
    unindexed_archived: int = 0
    errors: list[str] = field(default_factory=list)


class CrashRecoveryReconciler:
    """Safely reconciles incomplete or orphaned quarantine transactions."""

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

    def reconcile(self) -> RecoverySummary:
        """Run startup sweep across staging and vault directories to reconcile interrupted state.

        Returns:
            RecoverySummary: Counts of reconciled and archived items.
        """
        orphans_reconciled = 0
        incomplete_archived = 0
        uncommitted_archived = 0
        unindexed_archived = 0
        errors: list[str] = []

        incomplete_dir = self._config.recovery_dir / "incomplete"
        uncommitted_dir = self._config.recovery_dir / "uncommitted"
        unindexed_dir = self._config.recovery_dir / "unindexed"
        incomplete_dir.mkdir(parents=True, exist_ok=True)
        uncommitted_dir.mkdir(parents=True, exist_ok=True)
        unindexed_dir.mkdir(parents=True, exist_ok=True)

        master_key = self._key_manager.get_or_create_master_key()

        # 1. Sweep Staging Directory for Abandoned In-Flight Files (*.tmp)
        if self._config.staging_dir.exists():
            for tmp_file in list(self._config.staging_dir.glob("*.tmp")):
                quarantine_id = tmp_file.stem
                is_valid = False
                try:
                    # Check if file has a valid header and authenticates completely
                    header = self._vault_manager.inspect_vault_file(tmp_file)
                    is_valid = self._vault_manager.authenticate_and_verify_stream(
                        vault_file_path=tmp_file,
                        quarantine_id=header.quarantine_id,
                        master_key=master_key,
                    )
                except Exception:
                    is_valid = False

                dest_target = uncommitted_dir / tmp_file.name if is_valid else incomplete_dir / tmp_file.name
                try:
                    os.replace(tmp_file, dest_target)
                    if is_valid:
                        uncommitted_archived += 1
                    else:
                        incomplete_archived += 1

                    arch_evt = AuditEvent(
                        event_id=f"EVT_RECOV_{tmp_file.stem[:8]}",
                        timestamp=utc_now(),
                        event_type=AuditEventType.SYSTEM_WARNING,
                        status=AuditStatus.WARNING,
                        quarantine_id=quarantine_id,
                        details=(
                            f"Archived abandoned staging file to '{dest_target.name}'. "
                            f"Valid={is_valid}. Source on USB media remains intact."
                        ),
                    )
                    try:
                        self._audit_ledger.append_event(arch_evt)
                    except Exception:
                        pass
                except OSError as exc:
                    err_msg = f"Failed to archive staging file '{tmp_file}': {exc}"
                    errors.append(err_msg)

        # 2. Sweep Vault Directory for Unindexed .qnt Objects
        if self._config.vault_dir.exists():
            self._index_manager.load()
            existing_records = {r.quarantine_id: r for r in self._index_manager.list_records()}

            for qnt_file in list(self._config.vault_dir.glob("*.qnt")):
                quarantine_id = qnt_file.stem
                if quarantine_id not in existing_records:
                    # Unindexed vault object found!
                    try:
                        header = self._vault_manager.inspect_vault_file(qnt_file)

                        # Verify quarantine ID matches filename and header
                        if header.quarantine_id != quarantine_id:
                            raise VaultError(
                                f"Vault file stem '{quarantine_id}' does not match header "
                                f"quarantine ID '{header.quarantine_id}'"
                            )

                        # Verify authentic original_path is present in header
                        if not header.original_path or not header.original_path.strip():
                            raise VaultError(
                                f"Vault file '{qnt_file.name}' header lacks authentic original_path"
                            )

                        # Verify object integrity and authenticity
                        self._vault_manager.authenticate_and_verify_stream(
                            vault_file_path=qnt_file,
                            quarantine_id=header.quarantine_id,
                            master_key=master_key,
                        )

                        # Reconcile into index as ORPHAN_RECONCILED with authentic original_path
                        rec = QuarantineRecord(
                            quarantine_id=header.quarantine_id,
                            original_path=header.original_path,
                            vault_filename=qnt_file.name,
                            quarantined_at=utc_now(),
                            sha256_hash=header.sha256_hex,
                            file_size_bytes=header.original_size_bytes,
                            status=QuarantineStatus.ORPHAN_RECONCILED,
                            is_restored=False,
                        )
                        self._index_manager.add_record(rec)
                        orphans_reconciled += 1

                        recov_evt = AuditEvent(
                            event_id=f"EVT_ORPHAN_{header.quarantine_id[:8]}",
                            timestamp=utc_now(),
                            event_type=AuditEventType.QUARANTINE_COMMITTED,
                            status=AuditStatus.WARNING,
                            quarantine_id=header.quarantine_id,
                            sha256_hash=header.sha256_hex,
                            details=(
                                f"Reconciled orphaned vault object '{qnt_file.name}' into index with "
                                f"status ORPHAN_RECONCILED and authentic original path '{header.original_path}'."
                            ),
                        )
                        try:
                            self._audit_ledger.append_event(recov_evt)
                        except Exception:
                            pass
                    except Exception as exc:
                        # Move unauthenticated/malformed/untrustworthy object to recovery/unindexed/
                        dest_unindexed = unindexed_dir / qnt_file.name
                        try:
                            os.replace(qnt_file, dest_unindexed)
                            unindexed_archived += 1
                            arch_evt = AuditEvent(
                                event_id=f"EVT_UNINDEX_{quarantine_id[:8]}",
                                timestamp=utc_now(),
                                event_type=AuditEventType.SYSTEM_WARNING,
                                status=AuditStatus.WARNING,
                                quarantine_id=quarantine_id,
                                details=(
                                    f"Archived untrusted/corrupted unindexed vault object '{qnt_file.name}' "
                                    f"to recovery/unindexed/: {exc}"
                                ),
                            )
                            try:
                                self._audit_ledger.append_event(arch_evt)
                            except Exception:
                                pass
                        except OSError as move_exc:
                            errors.append(
                                f"Failed to archive untrusted vault file '{qnt_file}' to '{dest_unindexed}': {move_exc}"
                            )

        return RecoverySummary(
            orphans_reconciled=orphans_reconciled,
            incomplete_archived=incomplete_archived,
            uncommitted_archived=uncommitted_archived,
            unindexed_archived=unindexed_archived,
            errors=errors,
        )
