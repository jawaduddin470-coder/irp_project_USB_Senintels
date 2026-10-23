"""Centralized configuration and path management for USB Sentinel.

This module defines all application constants, default heuristic rules, policy toggles,
and platform-aware runtime directory structures.

Design Decisions (for beginner developers):
1. **Side-Effect-Free Import**: Simply importing this module does NOT create any directories,
   files, vaults, or encryption keys. Directory creation is deferred until runtime initialization.
2. **Platform-Aware Defaults**: Uses %LOCALAPPDATA% on Windows, ~/Library/Application Support
   on macOS, and ~/.local/share on Linux. Never hardcodes usernames or absolute home paths.
3. **Repository Cleanliness**: All runtime data (vault ciphertext, staging temporary files,
   audit logs, and persistent indexes) resides outside the source-code repository.
4. **Configurable / Testable**: The `SentinelConfig` class allows passing a custom `base_dir`
   so automated tests can execute inside temporary directories without modifying system paths.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, FrozenSet

from usb_sentinel import __version__ as APP_VERSION

# --- Application Constants ---
APP_NAME: Final[str] = "USB Sentinel"
APP_DESCRIPTION: Final[str] = (
    "Automated USB Mass Storage Threat Detection & File Quarantine Watchdog"
)

# --- Required File Names (Preserved from Specification) ---
AUDIT_LOG_FILENAME: Final[str] = "usb_sentinel_audit.csv"
QUARANTINE_INDEX_FILENAME: Final[str] = "quarantine_index.txt"

# --- Default Heuristic Risk Settings ---
# Extensions associated with potentially risky executable payloads or script vectors.
# Note: Flagging by extension alone is a heuristic indicator and does NOT prove malware.
DEFAULT_SUSPICIOUS_EXTENSIONS: Final[FrozenSet[str]] = frozenset(
    {".exe", ".bat", ".vbs", ".ps1", ".scr"}
)

# --- Watchdog Policy Defaults ---
# Default policy is strictly non-destructive: ALERT AND LOG ONLY.
DEFAULT_WATCHDOG_POLICY: Final[str] = "ALERT_AND_LOG_ONLY"
AUTO_QUARANTINE_DEFAULT: Final[bool] = False
DEFAULT_WATCHDOG_DEBOUNCE_SECONDS: Final[float] = 1.5
DEFAULT_WATCHDOG_DISCOVERY_RETRIES: Final[int] = 5
DEFAULT_WATCHDOG_RETRY_DELAY_SECONDS: Final[float] = 0.25
DEFAULT_WATCHDOG_AUTO_SCAN: Final[bool] = True

# --- Cryptographic & I/O Defaults (Phase 4 Foundation) ---
# Streaming buffer size (64 KB). Binds peak RAM usage to < 2 MB for large file transfers.
DEFAULT_STREAM_CHUNK_SIZE_BYTES: Final[int] = 65536


def get_default_system_app_dir(app_name: str = "USBSentinel") -> Path:
    """Resolve the platform-appropriate application data directory for the current user.

    Resolution Strategy:
    - Custom override: Respects $SENTINEL_BASE_DIR if set.
    - Cloud / Serverless (Vercel, AWS Lambda): Resolves to `/tmp/<app_name>` for read-only filesystem safety.
    - Windows: Resolves to `%LOCALAPPDATA%\\<app_name>` (e.g. C:\\Users\\<user>\\AppData\\Local\\USBSentinel).
    - macOS: Resolves to `~/Library/Application Support/<app_name>`.
    - Linux / Other: Respects `$XDG_DATA_HOME/<app_name>` or falls back to `~/.local/share/<app_name>`.

    Returns:
        Path: The base application data directory path (uncreated).
    """
    if os.environ.get("SENTINEL_BASE_DIR"):
        return Path(os.environ["SENTINEL_BASE_DIR"])
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        import tempfile
        return Path(tempfile.gettempdir()) / app_name
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / app_name
        return Path.home() / "AppData" / "Local" / app_name
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / app_name
    else:
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            return Path(xdg_data) / app_name
        return Path.home() / ".local" / "share" / app_name


def get_default_restoration_dir(folder_name: str = "Restored_Files") -> Path:
    """Resolve the convenience restoration directory on the current user's Desktop.

    Used when restoring quarantined files whose original removable volume is unavailable.

    Returns:
        Path: `%USERPROFILE%\\Desktop\\Restored_Files` (Windows), `~/Desktop/Restored_Files` (macOS/POSIX),
        or `/tmp/Restored_Files` (Vercel/Serverless).
    """
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        import tempfile
        return Path(tempfile.gettempdir()) / folder_name
    return Path.home() / "Desktop" / folder_name


@dataclass(frozen=True)
class SentinelConfig:
    """Immutable application configuration and path resolver.

    Attributes:
        base_dir: Root directory for application runtime data (vault, logs, reports, staging).
        suspicious_extensions: Set of lowercased file extensions considered high-risk.
        auto_quarantine_enabled: Whether automatic quarantine is active (default False).
        watchdog_policy: Default behavior mode ("ALERT_AND_LOG_ONLY").
        stream_chunk_size_bytes: Buffer chunk size for streaming hashing and encryption.
        default_restored_dir: Selectable convenience directory for file restoration.
    """

    base_dir: Path = field(default_factory=get_default_system_app_dir)
    suspicious_extensions: FrozenSet[str] = field(
        default_factory=lambda: DEFAULT_SUSPICIOUS_EXTENSIONS
    )
    auto_quarantine_enabled: bool = AUTO_QUARANTINE_DEFAULT
    watchdog_policy: str = DEFAULT_WATCHDOG_POLICY
    stream_chunk_size_bytes: int = DEFAULT_STREAM_CHUNK_SIZE_BYTES
    default_restored_dir: Path = field(default_factory=get_default_restoration_dir)
    watchdog_debounce_seconds: float = DEFAULT_WATCHDOG_DEBOUNCE_SECONDS
    watchdog_discovery_retries: int = DEFAULT_WATCHDOG_DISCOVERY_RETRIES
    watchdog_retry_delay_seconds: float = DEFAULT_WATCHDOG_RETRY_DELAY_SECONDS
    watchdog_auto_scan: bool = DEFAULT_WATCHDOG_AUTO_SCAN

    def __post_init__(self) -> None:
        """Validate configuration values upon instantiation."""
        if self.stream_chunk_size_bytes <= 0:
            raise ValueError(
                f"stream_chunk_size_bytes must be positive, got {self.stream_chunk_size_bytes}"
            )
        if self.watchdog_debounce_seconds < 0:
            raise ValueError(
                f"watchdog_debounce_seconds cannot be negative, got {self.watchdog_debounce_seconds}"
            )
        if self.watchdog_discovery_retries <= 0:
            raise ValueError(
                f"watchdog_discovery_retries must be positive, got {self.watchdog_discovery_retries}"
            )
        if self.watchdog_retry_delay_seconds <= 0:
            raise ValueError(
                f"watchdog_retry_delay_seconds must be positive, got {self.watchdog_retry_delay_seconds}"
            )
        for ext in self.suspicious_extensions:
            if not ext.startswith("."):
                raise ValueError(
                    f"Suspicious extension must start with a leading dot ('.'), got '{ext}'"
                )
            if ext != ext.lower():
                raise ValueError(
                    f"Suspicious extension must be lowercased, got '{ext}'"
                )

    # --- Derived Path Properties ---

    @property
    def vault_dir(self) -> Path:
        """Directory housing encrypted quarantine objects (.qnt)."""
        return self.base_dir / "vault"

    @property
    def staging_dir(self) -> Path:
        """Directory for in-flight temporary encryption files (.tmp) during two-phase commit."""
        return self.base_dir / "staging"

    @property
    def keys_dir(self) -> Path:
        """Directory for protected master vault keys."""
        return self.base_dir / "keys"

    @property
    def logs_dir(self) -> Path:
        """Directory housing audit ledgers and quarantine indexes."""
        return self.base_dir / "logs"

    @property
    def reports_dir(self) -> Path:
        """Directory for generated HTML and plain-text incident reports."""
        return self.base_dir / "reports"

    @property
    def recovery_dir(self) -> Path:
        """Directory holding unindexed or recovered objects for administrative review."""
        return self.vault_dir / "recovery"

    @property
    def audit_csv_path(self) -> Path:
        """Canonical path to usb_sentinel_audit.csv."""
        return self.logs_dir / AUDIT_LOG_FILENAME

    @property
    def quarantine_index_path(self) -> Path:
        """Canonical path to quarantine_index.txt."""
        return self.logs_dir / QUARANTINE_INDEX_FILENAME

    def ensure_runtime_directories(self) -> None:
        """Explicitly create required runtime directories on disk.

        IMPORTANT: This method must be called intentionally during runtime startup
        or during explicit setup. It is NEVER called automatically upon import.
        """
        for directory in (
            self.base_dir,
            self.vault_dir,
            self.staging_dir,
            self.keys_dir,
            self.logs_dir,
            self.reports_dir,
            self.recovery_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


# Default shared configuration instance (points to platform-appropriate user AppData)
DEFAULT_CONFIG: Final[SentinelConfig] = SentinelConfig()


def get_config() -> SentinelConfig:
    """Return the active default Sentinel configuration."""
    return DEFAULT_CONFIG
