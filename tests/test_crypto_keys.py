"""Unit tests for usb_sentinel.crypto_keys (master key management and HKDF subkey derivation)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.config import SentinelConfig
from usb_sentinel.crypto_keys import (
    MASTER_KEY_LENGTH_BYTES,
    PER_OBJECT_SALT_LENGTH_BYTES,
    KeyManager,
    KeyProtectionError,
    LocalDevKeyBackend,
    WindowsDPAPIKeyBackend,
)


def test_key_manager_generates_and_persists_256bit_master_key(tmp_path: Path) -> None:
    """Verify KeyManager generates a 32-byte (256-bit) cryptographically random master key."""
    config = SentinelConfig(base_dir=tmp_path)
    backend = LocalDevKeyBackend(config=config)
    mgr = KeyManager(config=config, backend=backend)

    assert not backend.has_master_key()
    key1 = mgr.get_or_create_master_key()

    assert isinstance(key1, bytes)
    assert len(key1) == MASTER_KEY_LENGTH_BYTES
    assert backend.has_master_key()

    # Re-reading should yield the exact same key across sessions
    mgr2 = KeyManager(config=config, backend=backend)
    key2 = mgr2.get_or_create_master_key()
    assert key1 == key2


def test_local_dev_key_backend_permissions_enforced(tmp_path: Path) -> None:
    """Verify LocalDevKeyBackend creates file with 0600 mode and rejects overly permissive files."""
    config = SentinelConfig(base_dir=tmp_path)
    backend = LocalDevKeyBackend(config=config)

    test_key = os.urandom(32)
    backend.save_master_key(test_key)
    assert backend.has_master_key()

    # On POSIX, check mode
    if sys.platform != "win32":
        file_mode = backend.key_path.stat().st_mode & 0o777
        assert file_mode == 0o600

        # Simulate insecure permissions (e.g. 0644 - group/world readable)
        os.chmod(backend.key_path, 0o644)
        with pytest.raises(KeyProtectionError, match="Insecure file permissions"):
            backend.load_master_key()

        # Restore secure permissions
        os.chmod(backend.key_path, 0o600)
        assert backend.load_master_key() == test_key


def test_hkdf_subkey_derivation_isolation_and_determinism(tmp_path: Path) -> None:
    """Verify HKDF produces deterministic subkeys for identical inputs and unique subkeys for different inputs."""
    config = SentinelConfig(base_dir=tmp_path)
    mgr = KeyManager(config=config)

    master_key = os.urandom(32)
    salt1 = os.urandom(32)
    salt2 = os.urandom(32)
    qid1 = "550e8400-e29b-41d4-a716-446655440001"
    qid2 = "550e8400-e29b-41d4-a716-446655440002"

    # Determinism: same master key, salt, and quarantine ID -> identical subkey
    k1a = mgr.derive_object_key(master_key, salt1, qid1)
    k1b = mgr.derive_object_key(master_key, salt1, qid1)
    assert k1a == k1b
    assert len(k1a) == 32

    # Key separation: different quarantine ID -> completely different subkey
    k2 = mgr.derive_object_key(master_key, salt1, qid2)
    assert k1a != k2

    # Key separation: different salt -> completely different subkey
    k3 = mgr.derive_object_key(master_key, salt2, qid1)
    assert k1a != k3


def test_hkdf_subkey_uniqueness_across_many_objects(tmp_path: Path) -> None:
    """Verify that 1,000 distinct quarantine objects with fresh salts produce 1,000 unique subkeys."""
    config = SentinelConfig(base_dir=tmp_path)
    mgr = KeyManager(config=config)
    master_key = os.urandom(32)

    derived_keys = set()
    num_samples = 1000
    for i in range(num_samples):
        salt = os.urandom(32)
        qid = f"obj_{i:04d}"
        sub_key = mgr.derive_object_key(master_key, salt, qid)
        derived_keys.add(sub_key)

    assert len(derived_keys) == num_samples


def test_hkdf_parameter_validation(tmp_path: Path) -> None:
    """Verify derive_object_key validates lengths and raises ValueError on invalid inputs."""
    config = SentinelConfig(base_dir=tmp_path)
    mgr = KeyManager(config=config)
    valid_key = os.urandom(32)
    valid_salt = os.urandom(32)

    with pytest.raises(ValueError, match="Master key must be exactly 32 bytes"):
        mgr.derive_object_key(b"short", valid_salt, "qid")

    with pytest.raises(ValueError, match="Per-object salt must be exactly 32 bytes"):
        mgr.derive_object_key(valid_key, b"short", "qid")

    with pytest.raises(ValueError, match="quarantine_id must be a non-empty string"):
        mgr.derive_object_key(valid_key, valid_salt, "")


def test_windows_dpapi_backend_on_non_windows_raises(tmp_path: Path) -> None:
    """Verify WindowsDPAPIKeyBackend fails closed when executed on non-Windows host."""
    config = SentinelConfig(base_dir=tmp_path)
    backend = WindowsDPAPIKeyBackend(config=config)

    if sys.platform != "win32":
        with pytest.raises(KeyProtectionError, match="only supported on Windows"):
            backend.save_master_key(os.urandom(32))

        with pytest.raises(KeyProtectionError, match="only supported on Windows"):
            backend.load_master_key()


def test_windows_dpapi_mock_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify WindowsDPAPIKeyBackend round-trip when Win32 DPAPI APIs are mocked."""
    monkeypatch.setattr(sys, "platform", "win32")
    config = SentinelConfig(base_dir=tmp_path)
    backend = WindowsDPAPIKeyBackend(config=config)

    # Mock _dpapi_protect and _dpapi_unprotect
    test_key = os.urandom(32)
    mock_blob = b"MOCK_DPAPI_BLOB_" + test_key

    with patch.object(backend, "_dpapi_protect", return_value=mock_blob), \
         patch.object(backend, "_dpapi_unprotect", return_value=test_key):
        backend.save_master_key(test_key)
        assert backend.has_master_key()
        loaded = backend.load_master_key()
        assert loaded == test_key


def test_key_manager_concurrent_thread_safety(tmp_path: Path) -> None:
    """Verify KeyManager.get_or_create_master_key is thread-safe under concurrent execution."""
    import concurrent.futures

    config = SentinelConfig(base_dir=tmp_path)
    backend = LocalDevKeyBackend(config=config)
    mgr = KeyManager(config=config, backend=backend)

    results = []

    def get_key() -> bytes:
        return mgr.get_or_create_master_key()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(get_key) for _ in range(20)]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    # All threads must receive the identical 32-byte master key
    first_key = results[0]
    assert len(first_key) == MASTER_KEY_LENGTH_BYTES
    assert all(k == first_key for k in results)


def test_local_dev_key_backend_prohibited_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify LocalDevKeyBackend fails closed on Windows to prevent accidental plaintext key storage."""
    monkeypatch.setattr(sys, "platform", "win32")
    config = SentinelConfig(base_dir=tmp_path)

    backend = LocalDevKeyBackend(config=config)
    test_key = os.urandom(32)

    with pytest.raises(KeyProtectionError, match="strictly prohibited on Windows"):
        backend.save_master_key(test_key)

    with pytest.raises(KeyProtectionError, match="strictly prohibited on Windows"):
        backend.load_master_key()

    # With explicit allow_insecure_windows_dev flag (for test/debug only)
    dev_backend = LocalDevKeyBackend(config=config, allow_insecure_windows_dev=True)
    dev_backend.save_master_key(test_key)
    assert dev_backend.load_master_key() == test_key


def test_key_manager_defaults_to_dpapi_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify KeyManager automatically selects WindowsDPAPIKeyBackend when running on win32."""
    monkeypatch.setattr(sys, "platform", "win32")
    config = SentinelConfig(base_dir=tmp_path)
    mgr = KeyManager(config=config)
    assert isinstance(mgr.backend, WindowsDPAPIKeyBackend)

