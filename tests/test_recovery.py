"""Unit tests for usb_sentinel.recovery (crash recovery reconciler and orphan handling)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from usb_sentinel.config import SentinelConfig
from usb_sentinel.crypto_keys import KeyManager
from usb_sentinel.models import QuarantineStatus
from usb_sentinel.quarantine import QuarantineManager
from usb_sentinel.recovery import CrashRecoveryReconciler
from usb_sentinel.vault import VaultManager


@pytest.fixture
def recovery_env(tmp_path: Path) -> tuple[SentinelConfig, CrashRecoveryReconciler, VaultManager, bytes]:
    config = SentinelConfig(base_dir=tmp_path, stream_chunk_size_bytes=4096)
    key_mgr = KeyManager(config=config)
    master_key = key_mgr.get_or_create_master_key()
    vault_mgr = VaultManager(config=config, key_manager=key_mgr)
    reconciler = CrashRecoveryReconciler(config=config, key_manager=key_mgr, vault_manager=vault_mgr)
    return config, reconciler, vault_mgr, master_key


def test_reconcile_incomplete_staging_file(
    recovery_env: tuple[SentinelConfig, CrashRecoveryReconciler, VaultManager, bytes], tmp_path: Path
) -> None:
    """Verify an incomplete or corrupted staging .tmp file is archived to recovery/incomplete, not purged."""
    config, reconciler, _, _ = recovery_env
    config.staging_dir.mkdir(parents=True, exist_ok=True)

    bad_tmp = config.staging_dir / "interrupted_file.tmp"
    bad_tmp.write_bytes(b"CORRUPTED_TRUNCATED_CIPHERTEXT_STAGE_1")

    summary = reconciler.reconcile()

    assert summary.incomplete_archived == 1
    assert not bad_tmp.exists()  # Moved out of staging

    incomplete_archived = config.recovery_dir / "incomplete" / "interrupted_file.tmp"
    assert incomplete_archived.exists()
    assert incomplete_archived.read_bytes() == b"CORRUPTED_TRUNCATED_CIPHERTEXT_STAGE_1"


def test_reconcile_valid_uncommitted_staging_file(
    recovery_env: tuple[SentinelConfig, CrashRecoveryReconciler, VaultManager, bytes], tmp_path: Path
) -> None:
    """Verify a valid complete staging .tmp file is archived to recovery/uncommitted for audit."""
    config, reconciler, vault_mgr, master_key = recovery_env
    src = tmp_path / "valid_src.bin"
    src.write_bytes(b"Valid payload that completed encryption before crash")

    qid = "550e8400-e29b-41d4-a716-446655440010"
    staging_file, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)
    assert staging_file.exists()

    summary = reconciler.reconcile()

    assert summary.uncommitted_archived == 1
    assert not staging_file.exists()

    uncommitted_archived = config.recovery_dir / "uncommitted" / f"{qid}.tmp"
    assert uncommitted_archived.exists()


def test_reconcile_orphaned_vault_file(
    recovery_env: tuple[SentinelConfig, CrashRecoveryReconciler, VaultManager, bytes], tmp_path: Path
) -> None:
    """Verify an unindexed .qnt file in vault is reconciled into quarantine_index.txt as ORPHAN_RECONCILED."""
    config, reconciler, vault_mgr, master_key = recovery_env
    src = tmp_path / "usb_drive" / "unindexed.bat"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(b"Batch file content on USB")

    qid = "550e8400-e29b-41d4-a716-446655440020"
    staging_file, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)
    # Promote staging to vault manually (simulating crash between Step 3 and Step 4)
    vault_file = vault_mgr.promote_staging_to_vault(qid)
    assert vault_file.exists()

    # Index currently has NO record of this file
    assert reconciler._index_manager.get_record(qid) is None

    summary = reconciler.reconcile()

    assert summary.orphans_reconciled == 1

    # Index now contains the record with ORPHAN_RECONCILED
    rec = reconciler._index_manager.get_record(qid)
    assert rec is not None
    assert rec.quarantine_id == qid
    assert rec.status == QuarantineStatus.ORPHAN_RECONCILED
    assert rec.vault_filename == f"{qid}.qnt"
    # CRITICAL: Verify authentic original_path extracted from header
    assert rec.original_path == str(src.resolve() if src.is_absolute() else src)

    # CRITICAL: Verify source file on USB storage was NEVER deleted or modified!
    assert src.exists()
    assert src.read_bytes() == b"Batch file content on USB"


def test_reconcile_unindexed_vault_file_mismatched_stem_archived(
    recovery_env: tuple[SentinelConfig, CrashRecoveryReconciler, VaultManager, bytes], tmp_path: Path
) -> None:
    """Verify an unindexed .qnt file whose filename stem does not match header quarantine_id is archived to unindexed/."""
    config, reconciler, vault_mgr, master_key = recovery_env
    src = tmp_path / "usb_drive" / "suspicious.exe"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(b"Suspicious payload")

    real_qid = "550e8400-e29b-41d4-a716-446655440030"
    staging_file, _ = vault_mgr.encrypt_to_staging(src, real_qid, master_key)
    vault_file = vault_mgr.promote_staging_to_vault(real_qid)

    # Tamper with filename stem: rename to spoofed_name.qnt
    spoofed_file = vault_file.parent / "spoofed_id_name.qnt"
    os.replace(vault_file, spoofed_file)

    summary = reconciler.reconcile()

    # Reconciler refuses to index untrusted spoofed object
    assert summary.orphans_reconciled == 0
    assert summary.unindexed_archived == 1
    assert not spoofed_file.exists()

    archived = config.recovery_dir / "unindexed" / "spoofed_id_name.qnt"
    assert archived.exists()
    assert reconciler._index_manager.get_record(real_qid) is None


def test_reconcile_corrupted_vault_file_archived(
    recovery_env: tuple[SentinelConfig, CrashRecoveryReconciler, VaultManager, bytes], tmp_path: Path
) -> None:
    """Verify an unindexed .qnt file failing authentication is moved to recovery/unindexed/."""
    config, reconciler, vault_mgr, master_key = recovery_env
    src = tmp_path / "usb_drive" / "corrupted_target.exe"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(b"Target content")

    qid = "550e8400-e29b-41d4-a716-446655440040"
    staging_file, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)
    vault_file = vault_mgr.promote_staging_to_vault(qid)

    # Corrupt ciphertext bytes in the vault file (beyond the 1192-byte header)
    data = bytearray(vault_file.read_bytes())
    data[-5] ^= 0xFF
    vault_file.write_bytes(data)

    summary = reconciler.reconcile()

    # Reconciler refuses to index corrupted object
    assert summary.orphans_reconciled == 0
    assert summary.unindexed_archived == 1
    assert not vault_file.exists()

    archived = config.recovery_dir / "unindexed" / f"{qid}.qnt"
    assert archived.exists()
    assert reconciler._index_manager.get_record(qid) is None

