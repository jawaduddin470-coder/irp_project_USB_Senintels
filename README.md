# USB Sentinel: Automated USB Mass Storage Threat Detection & File Quarantine Watchdog

## 1. Project Overview & Scope
**USB Sentinel** is a modular security monitoring and file quarantine watchdog engineered for removable USB mass storage media. The application monitors removable storage insertions, inspects mounted filesystems recursively, classifies suspicious execution and script vectors (`.exe`, `.bat`, `.vbs`, `.ps1`, `.scr`), provides authenticated encrypted vault quarantine with non-destructive restoration, records append-only audit ledgers (`usb_sentinel_audit.csv`), and generates structured incident reports.

---

## 2. Current Implementation Status: Phase 7 & Web Dashboard Complete

> [!IMPORTANT]
> **Current Status: Phase 7 & Web Dashboard Complete (215 Passing Tests).**
> - **Phase 1 (Foundation):** Configuration, path resolution, and shared typed data models.
> - **Phase 2 (Scanner & Risk Engine):** Recursive volume traversal (`usb_sentinel/scanner.py`) and heuristic risk assessment (`usb_sentinel/risk_engine.py`).
> - **Phase 3 (Integrity, Ledger & Index):** Streaming SHA-256 calculation (`usb_sentinel/integrity.py`), durable CSV audit logging (`usb_sentinel/audit.py`), and atomic JSON Lines quarantine index management (`usb_sentinel/quarantine_index.py`).
> - **Phase 4 (Encrypted Vault & Restoration):** Authenticated streaming AES-256-GCM vault storage (`usb_sentinel/vault.py`), Windows DPAPI & Local Dev key management (`usb_sentinel/crypto_keys.py`), crash-safe 5-step quarantine workflow (`usb_sentinel/quarantine.py`), conflict-aware safe restoration (`usb_sentinel/restoration.py`), and crash recovery reconciler (`usb_sentinel/recovery.py`).
> - **Phase 5 (USB Watchdog & Device Telemetry):** 3-tier Windows volume inspection pipeline (`usb_sentinel/device_detection.py`), external USB HDD/SSD fixed-disk disambiguation, event debouncing, bounded mount readiness retry loop, disconnect cancellation propagation, and non-destructive defensive scanning coordinator (`usb_sentinel/watchdog.py`).
> - **Phase 6 (CLI & Incident Reporting):** Exactly five-option interactive CLI menu (`usb_sentinel/cli.py`), on-demand scanning with manual quarantine confirmation, background watchdog execution with live console telemetry, safe restoration flow with collision policies, audit export with spreadsheet formula escaping, and automated dual HTML/plain-text incident report generation (`usb_sentinel/reporting.py`).
> - **Phase 7 (Security Review & End-to-End Validation):** Key management hardening against unintended Windows dev backend execution, restoration path traversal defenses, cross-platform path leaf extraction, and 10 realistic operational end-to-end integration scenarios (`tests/test_e2e.py`).
> - **Web Dashboard:** Full local Flask web console (`usb_sentinel/web_app.py`, `run_web.py`) with 5 dedicated views (`/dashboard`, `/devices`, `/watchdog`, `/quarantine`, `/logs`), session CSRF protection, and zero JS build dependencies.

---

## 3. Supported Platforms & Environments

- **Target Operating System (Production Deployment):**
  - Windows 10 (version 1809 and higher)
  - Windows 11
  - Windows Server 2019 / Windows Server 2022
- **Development & Test Host:**
  - macOS (tested on Darwin) / Linux
  - Cross-platform development is supported through backend abstractions and pytest mocks.
- **Python Compatibility Matrix:**
  - **Approved Target Versions:** Python 3.10, 3.11, 3.12, 3.13 (per `PROJECT_PLAN.md`).
  - **Local Development Host Interpreter:** Python 3.14.2 (Darwin/macOS).
  - **Compatibility Safeguards:** All code strictly adheres to Python 3.10+ standard syntax (`from __future__ import annotations`, builtin generic typing `list[T]`, `tuple[T, ...]`, union operators `X | None`). No 3.14-exclusive language features or deprecated modules are utilized.
  - **Multi-Version Testing:** In CI/CD or production environments, `tox` or matrix testing across 3.10–3.13 should be executed.

---

## 4. Development Environment Setup

### 4.1 Setup on macOS / Linux (Current Development Host)

1. **Navigate to the repository:**
   ```bash
   cd /path/to/IRP_PROJECT
   ```

2. **Create and activate a Python virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
   *Note: Windows-specific packages (`pywin32`, `wmi`) are automatically bypassed on macOS/Linux via PEP 508 environment markers.*

### 4.2 Setup on Windows (Target Hardware Integration Host)

1. **Open PowerShell or Command Prompt as Administrator** (recommended for hardware device testing):
   ```powershell
   cd C:\path\to\IRP_PROJECT
   ```

2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. **Install all dependencies (including Windows native bindings):**
   ```powershell
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## 5. Running the Application & Test Suite

### 5.1 Run Application Startup Validation
```bash
python -m usb_sentinel
```

### 5.2 Execute the Automated Test Suite
To run all 202 unit, scanner, risk engine, integrity, audit, index, vault, key, quarantine, restoration, recovery, device detection, watchdog, reporting, CLI, and end-to-end tests:
```bash
pytest -v
```

---

## 6. Implementation Roadmap

The project adheres strictly to an 8-phase sequential engineering roadmap:

| Phase | Description | Status |
| :---: | :--- | :---: |
| **Phase 0** | Planning, Threat Modeling & Architecture Review | **Completed** |
| **Phase 1** | Project Foundation, Configuration & Shared Data Models | **Completed** |
| **Phase 2** | Recursive Volume Scanner & Heuristic Risk Assessment | **Completed** |
| **Phase 3** | Streaming SHA-256 Hashing, Audit CSV & Persistent Quarantine Index | **Completed** |
| **Phase 4** | Authenticated AES-256-GCM Streaming Vault & Safe Restoration Engine | **Completed & Security Reviewed** |
| **Phase 5** | Windows USB Insertion/Removal Watchdog & Telemetry Engine | **Completed & Audited** (164 passing tests) |
| **Phase 6** | 5-Option Interactive CLI Integration & Incident Report Generation | **Completed** (189 passing tests) |
| **Phase 7** | Comprehensive Security Review & End-to-End System Verification | **Completed** (202 passing tests) |

---

## 7. Phase 3 Architecture: Core Capabilities & Guarantees

### 7.1 Streaming SHA-256 Integrity Engine (`usb_sentinel/integrity.py`)
- **Incremental Streaming:** Reads files in configurable 64 KB chunks, keeping RAM usage strictly bounded.
- **Mid-Hash File Stability Detection:** Captures `st_size` and `st_mtime_ns` before and after streaming. If the file was modified or truncated while being hashed, raises `FileIntegrityUnstableError`.
- **Symlink Defense:** Rejects symbolic links by default (`SymlinkNotPermittedError`) to prevent reading unauthorized targets outside scan boundaries.
- **Constant-Time Comparison & Digest Validation:** Validates 64-character hexadecimal digests and uses `hmac.compare_digest()`.

### 7.2 CSV Audit Ledger (`usb_sentinel/audit.py`)
- **Canonical Ledger Fidelity:** Stores raw, genuine event values verbatim using standard RFC 4180 CSV escaping, guaranteeing 100% round-trip fidelity.
- **Spreadsheet Formula Injection Defense on Export:** Prepends an apostrophe (`'`) to any untrusted exported cell starting with `=`, `+`, `-`, `@`, `\t`, or `\r`.
- **Durability & Safety:** Executes `f.flush()` and `os.fsync(f.fileno())` after each append; uses UUID-randomized temporary files for atomic export.

### 7.3 Persistent Quarantine Index (`usb_sentinel/quarantine_index.py`)
- **Format:** Versioned JSON Lines in `quarantine_index.txt`.
- **Atomic File Replacement:** Staged to a unique temporary file (`.tmp_<pid>_<uuid>`), synced via `fsync()`, and atomically replaced via `os.replace()`.
- **In-Memory Rollback:** If persistence failure occurs, in-memory state is rolled back, preventing false success states.

---

## 8. Phase 4 Architecture: Cryptography, Vault & Restoration

### 8.1 Key Hierarchy & Protection (`usb_sentinel/crypto_keys.py`)
- **Master Key:** 256-bit root key generated via `os.urandom(32)`.
- **Windows DPAPI Backend:** Protected via Windows DPAPI (`CryptProtectData`) bound to the active user's credentials with `CRYPTPROTECT_UI_FORBIDDEN`. Fails closed if protected key cannot be unwrapped.
- **Local Dev Backend:** Restricted by POSIX `0600` permissions on macOS/Linux hosts; fails closed if permissions are insecure.
- **Thread Safety:** `KeyManager` enforces synchronization via `threading.Lock()` to prevent race conditions during key generation.
- **HKDF-SHA256 Subkey Derivation:** Every quarantine object receives a statistically isolated 256-bit subkey derived from the master key, a fresh 256-bit salt, and domain info `USBSentinel-FileVault-v2:<quarantine_id>`.

### 8.2 Streaming Authenticated Vault Storage (`usb_sentinel/vault.py`)
- **Canonical Binary Header (1,192 Bytes):** Magic (`USBSQNT2`), format version (2), flags (2B), quarantine ID (36B), salt (32B), nonce prefix (4B), chunk size (4B), original size (8B), expected chunks (8B), plaintext SHA-256 (64B), authentic original path (1024B).
- **Nonce Construction:** 96-bit IV = 4-byte random prefix + 8-byte big-endian chunk counter ($i = 0, 1, 2, \dots$).
- **Associated Authenticated Data (AAD):** Each chunk binds `HeaderDigest (32B) || QuarantineID (36B) || ChunkIndex (8B) || PayloadLen (4B) || IsFinal (1B)`. Any modification to the header, original path, chunk payload, or auth tag causes immediate rejection.
- **Strict Chunk Bounds:** Chunk sizes must fall within [1 KB, 16 MB], chunk count is strictly bounded, and trailing garbage is prohibited.

### 8.3 Crash-Safe 5-Step Quarantine (`usb_sentinel/quarantine.py`)
- **Policy Enforcement:** Rejects automatic quarantine unless explicitly confirmed or policy is overridden.
- **Pre-Deletion Re-Verification:** Immediately prior to source deletion, verifies file existence, symlink absence, size, modification timestamp, inode/dev identity (POSIX), and computes SHA-256 digest with `hmac.compare_digest`. Aborts removal if file was modified, replaced, or swapped.
- **Persistence First:** If audit append or index persistence fails, source deletion is aborted (`QuarantinePersistenceError`), ensuring zero data loss.
- **Write-Protected USB Handling:** If source deletion fails, verified vault copy is retained, state is recorded as `QUARANTINE_SOURCE_LOCKED`, and the user is warned.

### 8.4 Safe Restoration Engine (`usb_sentinel/restoration.py`)
- **Explicit Destination:** Never restores silently; requires user destination or offers `%USERPROFILE%\Desktop\Restored_Files\`.
- **Atomic No-Clobber Publication:** Enforces `atomic_publish_no_clobber` (`os.link` + `os.unlink` on POSIX, `os.rename` on Windows); existing destination files remain 100% byte-for-byte unchanged upon collision.
- **Symlink Defense:** Destination symbolic links are strictly prohibited even under overwrite policies.
- **Complete Verification:** Plaintext is released to destination only after 100% of chunk tags authenticate and recovered SHA-256 matches the recorded baseline.

### 8.5 Crash Recovery Reconciler (`usb_sentinel/recovery.py`)
- **Authentic Metadata Extraction:** Extracts genuine `original_path` from the authenticated 1,192-byte header; never invents dummy paths.
- **Stem/Header Identity Matching:** Verifies `.qnt` filename stem matches internal header quarantine ID; unauthenticated or corrupted objects are archived to `vault/recovery/unindexed/`.
- **Zero USB Deletion:** Reconciling orphaned vault files never touches or deletes files on USB storage media.

---

## 9. Phase 5 Architecture: USB Hardware Watchdog & Telemetry Engine

### 9.1 Three-Tier Volume Inspection Pipeline (`usb_sentinel/device_detection.py`)
- **Tier 1 (WMI Subsystem):** Queries `Win32_LogicalDisk` -> `Win32_DiskPartition` -> `Win32_DiskDrive`. Confirms USB storage via `InterfaceType == "USB"` or `PNPDeviceID.startswith("USBSTOR\\")`. Correctly identifies USB external hard drives and SSDs (which Windows reports as `DRIVE_FIXED`) while definitively rejecting internal SATA/NVMe fixed disks.
- **Tier 2 (Storage Property IOCTL):** Issues `IOCTL_STORAGE_QUERY_PROPERTY` via `DeviceIoControl` using `ctypes` on Windows. Queries `STORAGE_DEVICE_DESCRIPTOR.BusType` (`BusTypeUsb == 7` vs `BusTypeSata == 11`, `BusTypeNvme == 17`).
- **Tier 3 (Kernel32 Drive Type Fallback):** Calls `GetDriveTypeW` as a degraded fallback (`DRIVE_REMOVABLE == 2` vs `DRIVE_FIXED == 3`), emitting explicit warnings that bus verification could not be performed.
- **Clean Cross-Platform Abstraction:** Isolates Windows-specific modules (`wmi`, `win32file`, `win32api`, `ctypes`) inside `WindowsDeviceDetector`. `UnsupportedPlatformDetector` handles non-Windows runtimes safely without crashing, while `MockDeviceDetector` provides deterministic arrival, removal, delay, and retry testing on macOS/Linux.

### 9.2 USB Watchdog Coordinator (`usb_sentinel/watchdog.py`)
- **Thread-Safe State Machine:** Managed states (`STOPPED` -> `STARTING` -> `RUNNING` -> `STOPPED`) with context manager support (`with USBWatchdog(...) as wd:`).
- **Startup Baseline Inventory:** Discovers already-connected USB volumes at startup (`is_initial_device=True`), avoiding duplicate processing or missed devices.
- **Event Debouncing:** Suppresses rapid hardware switch bounces or duplicate arrival/removal events within a configurable debounce window (`watchdog_debounce_seconds=1.5s`).
- **Bounded Mount Readiness Retries:** Hardware arrival events often precede volume filesystem readiness. Employs bounded retries (`watchdog_discovery_retries=5`, `watchdog_retry_delay_seconds=0.25s`). If the device is unplugged during discovery retry sleep, discovery immediately aborts without creating orphaned sessions.
- **Per-Connection Unique Sessions:** Reconnecting the same drive letter allocates a fresh unique `session_id`, ensuring historical telemetry and audit events remain strictly isolated across insertion cycles.
- **Non-Destructive Scanning Integration:** Upon device arrival, optionally triggers read-only volume scan (`VolumeScanner.scan()`) under the strict default policy of `ALERT_AND_LOG_ONLY`. **NEVER automatically deletes, moves, or quarantines files upon insertion.**
- **Disconnect Cancellation Propagation:** If a USB drive is unplugged while a scan is in progress, the session cancellation token halts scanning immediately, yielding `ABORTED_DISCONNECT` and emitting `SCAN_ABORTED` and `DEVICE_REMOVED` audit events without dangling locks.

---

## 10. Phase 6 Architecture: Interactive CLI Integration & Incident Reporting

### 10.1 Five-Option Interactive CLI (`usb_sentinel/cli.py`)
Provides a beginner-friendly, clean terminal interface presenting **strictly the five required top-level operations**:
1. **Display Active System Mounts & USB Device Telemetry:** Queries storage subsystems, formats human-readable metrics (capacity, free space, filesystem, bus type, classification, confidence), displays degraded fallback warnings when applicable, and offers immediate on-demand heuristic scanning.
2. **Start Real-Time USB Insertion Watchdog:** Launches background hardware event monitoring under the strict default policy of `ALERT_AND_LOG_ONLY`. Prints timestamped arrival/removal telemetry in real time. Upon detecting flagged threats, prints alerts and automatically compiles and publishes HTML and text incident reports. Stops cleanly upon pressing Enter, typing `q`, or `Ctrl+C`.
3. **Inspect & Restore Quarantined Files:** Lists persistent quarantine records from `quarantine_index.txt`. Provides detailed record inspection (SHA-256 digest, vault filename, original path, timestamp, file size). Supports safe restoration to original location (if accessible), desktop convenience folder (`%USERPROFILE%\Desktop\Restored_Files\`), or custom path. Enforces anti-collision choices (rename with timestamp suffix vs. authorized overwrite) and verifies plaintext SHA-256 integrity upon restoration.
4. **Export USB Audit Ledger to CSV:** Reads canonical audit records, prompts for destination path with desktop default, confirms overwrite if target exists, escapes formula-injection prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) for spreadsheet software safety, and prints summary event and status metrics.
5. **Exit:** Performs graceful shutdown, deactivates background monitoring, flushes buffers, and exits with status 0.

### 10.2 Incident Report Generation Engine (`usb_sentinel/reporting.py`)
Compiles structured incident reports in dual formats (HTML5 and monospace plain text) with atomic file persistence:
- **Strict Anti-XSS Sanitization:** All untrusted filesystem strings (file paths, volume labels, filenames) are sanitized using `html.escape(..., quote=True)` before rendering into HTML templates.
- **Visual Severity Indicators:** Applies clean CSS styling, metadata cards, stat counters, and color-coded risk severity badges (`.badge-high` for executables, `.badge-warn` for scripts).
- **Audit & Telemetry Correlation:** Correlates target hardware telemetry, scan summary metrics, flagged risk rules, actions taken, and the recent audit trail.
- **Atomic Publication:** Uses UUID-randomized temporary files (`.rep_*.tmp`) and atomic file replacement (`os.replace`) to write reports safely to `<base_dir>/reports/`.
- **Mandatory Security Notice:** Features prominent legal and technical disclaimers stating that heuristic extension analysis identifies potential execution vectors but does not guarantee protection against advanced stealth malware.

---

## 11. Phase 7 Architecture: Security Hardening & End-to-End Validation

### 11.1 Key Management Hardening (`usb_sentinel/crypto_keys.py`)
- **Fail-Closed on Windows:** `LocalDevKeyBackend` strictly raises `KeyProtectionError` on `win32` unless an explicit developer/test flag (`allow_insecure_windows_dev=True`) is provided. This prevents accidental unencrypted key storage in Windows production environments.
- **Automatic DPAPI Selection:** `KeyManager` defaults strictly to `WindowsDPAPIKeyBackend` on Windows and `LocalDevKeyBackend` on POSIX hosts.

### 11.2 Path Traversal & Cross-Platform Defenses (`usb_sentinel/restoration.py`)
- **Containment Verification:** Restored file target paths are validated with `target_path.resolve().is_relative_to(dest_dir_resolved)`, preventing directory traversal escapes (`../`).
- **Cross-Platform Leaf Extraction:** Uses `PureWindowsPath(record.original_path).name` for Windows-style paths, preventing backslash directory corruption on POSIX systems.
- **Dot/Dot-Dot Defense:** Sanitizes empty, `.`, or `..` leaves to fallback safe filenames (`restored_<quarantine_id>.bin`).

### 11.3 End-to-End Validation Matrix (`tests/test_e2e.py`)

The complete operational lifecycle is validated against 10 realistic scenarios:
1. **Full Lifecycle:** Insertion -> Detection -> Scan -> File Flagged -> Manual Quarantine -> Inspect Index -> Safe Restore -> Audit Export.
2. **Fixed-Disk USB Disambiguation:** Windows reports `DRIVE_FIXED`, but WMI identifies `BusType.USB` and `USBSTOR\\...`; classified as `USB_MASS_STORAGE` while NVMe drives remain `FIXED_VOLUME`.
3. **Degraded & Unknown Fallback:** WMI and IOCTL failures produce explicit `UNKNOWN` classification with `UNVERIFIED` confidence and auditable warnings.
4. **Read-Only Non-Destructive Guard:** `ALERT_AND_LOG_ONLY` insertion scans never modify, move, or delete files; verified via pre/post byte hashes, sizes, and timestamps.
5. **Quarantine with Deletion & Verification:** Source deletion removes file from USB; restoration re-authenticates and verifies SHA-256 byte-for-byte.
6. **Interrupted Quarantine Safety:** Write-protected media sets `QUARANTINE_SOURCE_LOCKED`; pre-deletion hash mismatch aborts deletion and preserves source.
7. **Vault Cryptographic Integrity:** Bit flips, truncated ciphertext, and incorrect master keys fail AES-256-GCM authentication and abort cleanly.
8. **Restoration Collision Policies:** Strict support for `REJECT`, `RENAME_NEW` (timestamp suffix), `OVERWRITE` (with explicit confirmation), and unconditional symlink refusal.
9. **Formula Sanitization & Reports:** Audit export prefixes dangerous prefixes (`=`, `+`, `-`, `@`) with `'`; HTML reports escape untrusted strings (`<script>`).
10. **Watchdog Lifecycle & Restart:** Clean shutdown during discovery/scan and successful re-initialization without resource exhaustion.

---

## 12. Windows Native Verification Guidelines

While all 215 tests pass on macOS using platform abstraction layers and mock harnesses, final production verification on Windows hardware should validate:
1. **Physical USB Insertion:** Insert physical FAT32/NTFS USB flash drives; verify WMI `Win32_VolumeChangeEvent` triggers watchdog within 1.5 seconds.
2. **DPAPI Credential Binding:** Confirm `%LOCALAPPDATA%\USBSentinel\keys\master.key.dpapi` is created and cannot be decrypted under a different Windows user profile.
3. **Extended Path Prefixes:** Validate deeply nested paths (>260 characters) using `\\?\` prefixing under NTFS.
4. **Hardware Write-Protection Switch:** Insert physical write-protected flash drive and attempt quarantine; confirm `QUARANTINE_SOURCE_LOCKED` event is logged and source remains on USB.

---

## 13. Web Dashboard Interface (Localhost Console)

USB Sentinel features an interactive, locally hosted web console built with **Flask**, **HTML5/CSS3**, and **Jinja2 server-rendered templates**. It integrates directly with the existing security core while maintaining zero JavaScript build dependencies.

### 13.1 Launching the Web Dashboard

You can start the web dashboard using either the dedicated root launcher or the package entry point:

```bash
# Method 1: Dedicated root launcher (default port 5000)
python run_web.py

# Optional parameters
python run_web.py --port 8080 --debug

# Method 2: Package module CLI flag
python -m usb_sentinel --web --port 5000
```

Once running, navigate to: **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

*(Note: The terminal CLI interface remains completely intact and accessible by executing `python -m usb_sentinel` without the `--web` flag).*

### 13.2 Five Navigation Sections & URLs

1. **Dashboard (`/dashboard` or `/`):**
   - High-level security posture overview.
   - Status indicators for Watchdog engine (`RUNNING` / `STOPPED`), connected USB mass storage devices, files inspected, flagged threats, and vault record count.
   - Quick telemetry table of active removable mounts and latest 8 canonical audit ledger events.
2. **USB Devices & Threat Scanner (`/devices`):**
   - System storage telemetry table: mount path, volume label, filesystem, bus type, classification status, and total capacity.
   - On-demand directory or drive path scanner with non-blocking background worker (`BackgroundScanWorker`).
   - Detailed threat findings table: filename, relative location, size, heuristic risk score, classification (`MALICIOUS` / `SUSPICIOUS`), detected indicators, SHA-256 hash, and one-click quarantine button with confirmation.
3. **Watchdog (`/watchdog`):**
   - Interactive watchdog controls: Start and Stop engine (POST forms with CSRF validation).
   - Real-time status display and active device session tracking (device ID, drive letter, arrival time, connection state).
   - Prominent notice reiterating the non-destructive `ALERT_AND_LOG_ONLY` policy.
4. **Quarantine Vault & Restoration (`/quarantine`):**
   - Quarantined records inventory: Quarantine ID, original filename, timestamp, size, heuristic score, and vault ID.
   - Detailed inspection drawer (`/quarantine?inspect=<quarantine_id>`): full original path, verified plaintext SHA-256 hash, detection rationale, and AES-256-GCM authenticated cipher scheme details.
   - Safe restoration engine form (`/quarantine/restore`): destination selector (desktop safe folder, original location, or verified custom directory), collision policies (`REJECT`, `RENAME_NEW`, `OVERWRITE`), and explicit authorization checkbox.
   - Manual quarantine form (`/quarantine/add`): enables security analysts to directly encrypt and isolate any suspicious file.
5. **Audit Logs & Incident Reports (`/logs`):**
   - Append-only canonical audit ledger table (latest 100 events) displaying timestamp, event type, target path, outcome, actor, and structured metadata.
   - One-click CSV export (`/logs/export`) with automatic spreadsheet formula injection escaping (`'`, `=`, `+`, `-`, `@`).
   - Generated incident reports table with in-dashboard sandboxed viewing (`/reports/view/<filename>`) and raw text downloading (`/reports/download/<filename>`).

### 13.3 Web Security Architecture & Safeguards

- **Localhost Only:** Strictly enforces binding to `127.0.0.1` (`run_web` rejects `0.0.0.0` or external network interfaces).
- **Session CSRF Protection:** Cryptographic session tokens (`session["csrf_token"]`) are automatically injected into forms via context processor and verified in `before_request` on all state-modifying requests (`POST`, `PUT`, `DELETE`).
- **Strict Path Traversal Defense:** Report file viewing and downloads validate `Path(filename).name == filename`, verify containment within `config.reports_dir` using `is_relative_to()`, and block unauthorized traversal attempts with 400/404 errors.
- **XSS Mitigation:** Automatic Jinja2 HTML escaping protects against hostile filenames containing script or HTML injection sequences.
- **Fail-Safe Operations:** Quarantining and restoration preserve source files until transactions and cryptographic checksums are fully committed and verified.

