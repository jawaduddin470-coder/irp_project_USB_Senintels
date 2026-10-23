"""Key management and root key protection for USB Sentinel.

This module handles 256-bit root master key generation, OS-backed secret protection
(Windows DPAPI with a restricted POSIX development fallback), and per-object subkey
derivation using HKDF-SHA256.

Design Principles & Security Guarantees:
1. **Zero Secret Exposure**:
   Plaintext master keys and derived subkeys are NEVER logged, written to the audit CSV,
   stored in the quarantine index, or exposed in error messages or exception tracebacks.
2. **Platform-Isolated Protection**:
   - On Windows: The master key is encrypted via Windows DPAPI (`CryptProtectData`)
     bound to the active Windows user account with UI prompt forbidden (`CRYPTPROTECT_UI_FORBIDDEN`).
   - On macOS/Linux Development Hosts: Key storage uses `LocalDevKeyBackend` restricted
     strictly by POSIX permissions (`0600`).
3. **Fail-Closed**:
   If the protected key cannot be decrypted (e.g. corrupted file, access denied, or
   different user account), the system fails closed by raising `KeyProtectionError`.
4. **Permanent Loss Warning**:
   If the only protected master key is destroyed or lost, quarantined files cannot be
   recovered. Sentinel does not install backdoors or escrow keys.
5. **Per-Object Key Separation via HKDF-SHA256**:
   Every quarantined object receives a unique 256-bit subkey derived from the master key,
   a fresh 256-bit cryptographic salt, and domain-separated context including the format
   version and quarantine ID.
"""

from __future__ import annotations

import abc
import ctypes
import os
import stat
import sys
import threading
from pathlib import Path
from typing import Final, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from usb_sentinel.config import SentinelConfig, get_config

MASTER_KEY_LENGTH_BYTES: Final[int] = 32  # 256-bit AES master key
PER_OBJECT_SALT_LENGTH_BYTES: Final[int] = 32  # 256-bit HKDF salt
HKDF_INFO_PREFIX: Final[str] = "USBSentinel-FileVault-v2"


class KeyProtectionError(Exception):
    """Raised when master key generation, wrapping, unwrapping, or access fails."""


class KeyStoreBackend(abc.ABC):
    """Abstract interface for protected master key persistence."""

    @abc.abstractmethod
    def save_master_key(self, master_key: bytes) -> None:
        """Protect and persist the master key to durable storage."""

    @abc.abstractmethod
    def load_master_key(self) -> bytes:
        """Unprotect and return the 32-byte master key."""

    @abc.abstractmethod
    def has_master_key(self) -> bool:
        """Return True if a master key exists in the backend."""


class WindowsDPAPIKeyBackend(KeyStoreBackend):
    """Windows Data Protection API (DPAPI) master key backend.

    Encrypts the 256-bit master key using `CryptProtectData` in the current-user scope,
    storing the resulting encrypted blob at `%LOCALAPPDATA%\\USBSentinel\\keys\\master.key.dpapi`.
    """

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self._config = config or get_config()
        self._key_path = self._config.keys_dir / "master.key.dpapi"

    @property
    def key_path(self) -> Path:
        """Return filesystem path to the DPAPI-encrypted key blob."""
        return self._key_path

    def has_master_key(self) -> bool:
        return self._key_path.exists() and self._key_path.stat().st_size > 0

    def save_master_key(self, master_key: bytes) -> None:
        if len(master_key) != MASTER_KEY_LENGTH_BYTES:
            raise KeyProtectionError(
                f"Master key must be exactly {MASTER_KEY_LENGTH_BYTES} bytes, got {len(master_key)}"
            )

        if sys.platform != "win32":
            raise KeyProtectionError(
                "WindowsDPAPIKeyBackend is only supported on Windows platforms. "
                "Use LocalDevKeyBackend for macOS/Linux development hosts."
            )

        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        encrypted_blob = self._dpapi_protect(master_key)

        # Write to temporary file and atomically replace
        temp_path = self._key_path.with_name(f"{self._key_path.name}.tmp_{os.getpid()}")
        try:
            with open(temp_path, "wb") as f:
                f.write(encrypted_blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self._key_path)
        except OSError as exc:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise KeyProtectionError(
                f"Failed to persist DPAPI key blob to '{self._key_path}': {exc}"
            ) from exc

    def load_master_key(self) -> bytes:
        if sys.platform != "win32":
            raise KeyProtectionError(
                "WindowsDPAPIKeyBackend is only supported on Windows platforms."
            )

        if not self.has_master_key():
            raise KeyProtectionError(f"Master key file not found at '{self._key_path}'")

        try:
            with open(self._key_path, "rb") as f:
                encrypted_blob = f.read()
        except OSError as exc:
            raise KeyProtectionError(
                f"Failed to read DPAPI key blob from '{self._key_path}': {exc}"
            ) from exc

        master_key = self._dpapi_unprotect(encrypted_blob)
        if len(master_key) != MASTER_KEY_LENGTH_BYTES:
            raise KeyProtectionError(
                f"Unwrapped DPAPI key length mismatch: expected {MASTER_KEY_LENGTH_BYTES} bytes, "
                f"got {len(master_key)}"
            )
        return master_key

    def _dpapi_protect(self, plaintext: bytes) -> bytes:
        """Call CryptProtectData via ctypes."""
        try:
            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte)),
                ]

            crypt32 = ctypes.windll.crypt32

            in_blob = DATA_BLOB(
                len(plaintext),
                ctypes.cast(ctypes.create_string_buffer(plaintext), ctypes.POINTER(ctypes.c_byte)),
            )
            out_blob = DATA_BLOB()
            CRYPTPROTECT_UI_FORBIDDEN = 0x1

            res = crypt32.CryptProtectData(
                ctypes.byref(in_blob),
                "USBSentinelMasterKey",
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(out_blob),
            )
            if not res:
                error_code = ctypes.GetLastError()
                raise KeyProtectionError(f"CryptProtectData failed with Win32 error {error_code}")

            try:
                encrypted_data = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            finally:
                kernel32 = ctypes.windll.kernel32
                kernel32.LocalFree(out_blob.pbData)

            return encrypted_data
        except Exception as exc:
            if isinstance(exc, KeyProtectionError):
                raise
            raise KeyProtectionError(f"Windows DPAPI protection failure: {exc}") from exc

    def _dpapi_unprotect(self, ciphertext: bytes) -> bytes:
        """Call CryptUnprotectData via ctypes."""
        try:
            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte)),
                ]

            crypt32 = ctypes.windll.crypt32

            in_blob = DATA_BLOB(
                len(ciphertext),
                ctypes.cast(ctypes.create_string_buffer(ciphertext), ctypes.POINTER(ctypes.c_byte)),
            )
            out_blob = DATA_BLOB()
            CRYPTPROTECT_UI_FORBIDDEN = 0x1

            res = crypt32.CryptUnprotectData(
                ctypes.byref(in_blob),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(out_blob),
            )
            if not res:
                error_code = ctypes.GetLastError()
                raise KeyProtectionError(f"CryptUnprotectData failed with Win32 error {error_code}")

            try:
                plaintext = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            finally:
                kernel32 = ctypes.windll.kernel32
                kernel32.LocalFree(out_blob.pbData)

            return plaintext
        except Exception as exc:
            if isinstance(exc, KeyProtectionError):
                raise
            raise KeyProtectionError(f"Windows DPAPI unprotection failure: {exc}") from exc


class LocalDevKeyBackend(KeyStoreBackend):
    """POSIX Development / Test Key Backend.

    Explicitly identified for macOS/Linux development hosts and local testing.
    Stores the master key in `config.keys_dir / 'master.key.dev'`, strictly enforcing
    file permissions of `0600` (read/write restricted exclusively to current user).
    Fails closed if permissions are overly permissive.
    """

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        *,
        allow_insecure_windows_dev: bool = False,
    ) -> None:
        self._config = config or get_config()
        self._key_path = self._config.keys_dir / "master.key.dev"
        self._allow_insecure_windows_dev = allow_insecure_windows_dev

    @property
    def key_path(self) -> Path:
        return self._key_path

    def has_master_key(self) -> bool:
        return self._key_path.exists() and self._key_path.stat().st_size > 0

    def save_master_key(self, master_key: bytes) -> None:
        if sys.platform == "win32" and not self._allow_insecure_windows_dev:
            raise KeyProtectionError(
                "LocalDevKeyBackend is strictly prohibited on Windows in production. "
                "WindowsDPAPIKeyBackend must be used to protect the root master key."
            )

        if len(master_key) != MASTER_KEY_LENGTH_BYTES:
            raise KeyProtectionError(
                f"Master key must be exactly {MASTER_KEY_LENGTH_BYTES} bytes, got {len(master_key)}"
            )

        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._key_path.with_name(f"{self._key_path.name}.tmp_{os.getpid()}")

        try:
            # Create file with 0600 mode
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(temp_path, flags, 0o600)
            try:
                with open(fd, "wb", closefd=True) as f:
                    f.write(master_key)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                # closefd handles closing
                raise

            # Ensure permissions are strictly 0600
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass

            os.replace(temp_path, self._key_path)
        except OSError as exc:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise KeyProtectionError(
                f"Failed to persist dev master key to '{self._key_path}': {exc}"
            ) from exc

    def load_master_key(self) -> bytes:
        if sys.platform == "win32" and not self._allow_insecure_windows_dev:
            raise KeyProtectionError(
                "LocalDevKeyBackend is strictly prohibited on Windows in production. "
                "WindowsDPAPIKeyBackend must be used to protect the root master key."
            )

        if not self.has_master_key():
            raise KeyProtectionError(f"Dev master key file not found at '{self._key_path}'")

        # Check permissions on POSIX
        if sys.platform != "win32":
            try:
                file_stat = self._key_path.stat()
                mode = file_stat.st_mode
                # Check for group or others read/write/exec permissions
                if mode & (stat.S_IRWXG | stat.S_IRWXO) != 0:
                    raise KeyProtectionError(
                        f"Insecure file permissions on '{self._key_path}' ({oct(mode & 0o777)}). "
                        "Permissions must be restricted strictly to 0600 (owner only)."
                    )
            except OSError as exc:
                raise KeyProtectionError(
                    f"Failed to inspect permissions on '{self._key_path}': {exc}"
                ) from exc

        try:
            with open(self._key_path, "rb") as f:
                key = f.read()
        except OSError as exc:
            raise KeyProtectionError(
                f"Failed to read dev master key from '{self._key_path}': {exc}"
            ) from exc

        if len(key) != MASTER_KEY_LENGTH_BYTES:
            raise KeyProtectionError(
                f"Corrupted master key in '{self._key_path}': expected {MASTER_KEY_LENGTH_BYTES} bytes, "
                f"got {len(key)}"
            )
        return key


class KeyManager:
    """Coordinates master key protection and per-object subkey derivation."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        backend: Optional[KeyStoreBackend] = None,
    ) -> None:
        self._config = config or get_config()
        self._lock = threading.Lock()
        if backend is not None:
            self._backend = backend
        elif sys.platform == "win32":
            self._backend = WindowsDPAPIKeyBackend(config=self._config)
        else:
            self._backend = LocalDevKeyBackend(config=self._config)

    @property
    def backend(self) -> KeyStoreBackend:
        """Return the active key protection backend."""
        return self._backend

    def get_or_create_master_key(self) -> bytes:
        """Load the existing master key or generate and persist a fresh 256-bit key.

        Returns:
            bytes: The 32-byte (256-bit) plaintext master key.

        Raises:
            KeyProtectionError: If key creation or loading fails.
        """
        with self._lock:
            if self._backend.has_master_key():
                return self._backend.load_master_key()

            new_key = os.urandom(MASTER_KEY_LENGTH_BYTES)
            self._backend.save_master_key(new_key)
            return new_key

    def derive_object_key(
        self,
        master_key: bytes,
        salt: bytes,
        quarantine_id: str,
    ) -> bytes:
        """Derive a dedicated 256-bit encryption subkey for a specific quarantine object.

        Uses HKDF (RFC 5869) with SHA-256:
        - Salt: fresh 256-bit cryptographically random salt per object.
        - Info: domain-separated context string `USBSentinel-FileVault-v2:<quarantine_id>`.

        Args:
            master_key: 32-byte master vault key.
            salt: 32-byte per-object cryptographic salt.
            quarantine_id: Unique identifier of the quarantine object.

        Returns:
            bytes: 32-byte (256-bit) derived subkey for AES-256-GCM.

        Raises:
            ValueError: If key, salt, or quarantine_id format is invalid.
        """
        if len(master_key) != MASTER_KEY_LENGTH_BYTES:
            raise ValueError(
                f"Master key must be exactly {MASTER_KEY_LENGTH_BYTES} bytes, got {len(master_key)}"
            )
        if len(salt) != PER_OBJECT_SALT_LENGTH_BYTES:
            raise ValueError(
                f"Per-object salt must be exactly {PER_OBJECT_SALT_LENGTH_BYTES} bytes, got {len(salt)}"
            )
        if not quarantine_id or not isinstance(quarantine_id, str):
            raise ValueError("quarantine_id must be a non-empty string")

        info_context = f"{HKDF_INFO_PREFIX}:{quarantine_id}".encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info_context,
        )
        return hkdf.derive(master_key)
