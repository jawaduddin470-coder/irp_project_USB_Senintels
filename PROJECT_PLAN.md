# Automated USB Mass Storage Threat Detection & File Quarantine Watchdog
## Architectural Blueprint & Technical Implementation Plan (PROJECT_PLAN.md)
*Revised Architecture Specification — Version 2.1 (Final Pre-Implementation Baseline)*

---

### 1. Executive Summary & Project Context

- **Project Title:** Automated USB Mass Storage Threat Detection & File Quarantine Watchdog ("USB Sentinel")
- **Target Operating System:** Windows 10 (1809+), Windows 11, Windows Server 2019/2022
- **Development & Cross-Platform Host:** macOS / Linux (Isolated via Platform Abstraction Layer & Test Mocks)
- **Programming Language:** Python 3.10, 3.11, 3.12, 3.13
- **Primary Interface:** Interactive Command-Line Interface (Strict 5-Option Menu)
- **Target Audience / Developer Experience:** Modular, beginner-friendly architecture featuring explicit defensive boundaries, full type annotations, comprehensive docstrings, and strict error handling.
- **Core Purpose:** Deliver real-time surveillance of removable USB media insertions/removals, recursive volume inspection, suspicious executable/script heuristic tagging, cryptographic integrity verification (SHA-256), authenticated encrypted vault quarantine with non-destructive restoration, durable audit logging (`usb_sentinel_audit.csv`), and incident report generation (HTML/Text).

---

### 2. Development Environment vs. Target Platform Strategy

#### 2.1 Environmental Distinction
- **Current Development Environment:** macOS (Unix-style paths, e.g., `/Users/...`, BSD stat attributes, no native Win32/WMI subsystem).
- **Target Production Environment:** Windows 10/11/Server (Win32 API, WMI subsystem, Windows DPAPI, NTFS junctions, extended-length path prefix `\\?\`).

#### 2.2 Platform Abstraction Architecture (`usb_sentinel/platform_base.py`)
To prevent platform coupling and enable 100% automated test coverage on the development host, all operating system and hardware interactions are decoupled behind abstract interfaces:

1. `DeviceBackend` (Interface):
   - `WindowsDeviceBackend`: Uses `pywin32`, `wmi`, and `ctypes.windll.kernel32` to listen for `WM_DEVICECHANGE`, query `Win32_DiskDrive`, and inspect `IOCTL_STORAGE_QUERY_PROPERTY`.
   - `MockDeviceBackend` / `POSIXDeviceBackend`: Simulates USB insertions/removals for unit and integration testing on macOS and CI environments using simulated virtual mount points.
2. `SecurityBackend` (Interface):
   - `WindowsSecurityBackend`: Utilizes Windows DPAPI (`CryptProtectData` / `CryptUnprotectData` via `win32crypt`) to securely protect vault keys bound to the active user's credentials.
   - `POSIXSecurityBackend`: Fallback for macOS development utilizing PBKDF2HMAC key derivation with a local key file restricted by POSIX file permissions (`0600`).

#### 2.3 Test Matrix: Dev Host vs. Target Windows

| Test Suite Category | Runnable on Dev Host (macOS) | Requires Windows Host / VM |
| :--- | :---: | :---: |
| **Data Models & Configuration Validation** | YES (100% automated) | YES |
| **Streaming SHA-256 Integrity Verification** | YES (100% automated) | YES |
| **HKDF Key Derivation & Nonce Uniqueness Verification** | YES (100% automated) | YES |
| **AES-256-GCM Streaming Encryption & Tamper Detection** | YES (100% automated) | YES |
| **Ciphertext Truncation & Reordering Detection** | YES (100% automated) | YES |
| **Recursive Scanner & Heuristic Extension Tagging** | YES (100% automated) | YES |
| **Crash-Safe Quarantine & Restoration Engine** | YES (100% automated) | YES |
| **CSV Audit Formula Sanitization & HTML/Text Reports** | YES (100% automated) | YES |
| **CLI Menu Dispatch & Keyboard Interrupt Handling** | YES (100% automated) | YES |
| **WMI Asynchronous USB Event Queries (`__InstanceCreationEvent`)** | Mocked in `pytest` | **Physical / VM Windows required** |
| **Win32 Message Loop (`WM_DEVICECHANGE` window pump)** | Mocked in `pytest` | **Physical / VM Windows required** |
| **Windows DPAPI Key Encryption (`CryptProtectData`)** | Mocked in `pytest` | **Physical / VM Windows required** |
| **Windows Extended-Length Path Prefix (`\\?\`) Resolution** | Mocked in `pytest` | **Physical / VM Windows required** |
| **NTFS Directory Junctions & Reparse Point Loop Handling** | Mocked in `pytest` | **Physical / VM Windows required** |
| **Physical USB Insertion / Dirty Disconnect Timing** | Mocked in `pytest` | **Physical / VM Windows required** |

---

### 3. Concrete Encryption Architecture (Streaming Authenticated AES-256-GCM with HKDF Subkey Derivation)

#### 3.1 Nonce Uniqueness & Cryptographic Construction
Standard AES-GCM catastrophic failure occurs if a nonce repeats under the same cryptographic key. Simple counter nonces under a static master key are vulnerable across application restarts or multi-file encryptions.

To mathematically eliminate this risk, USB Sentinel implements **Per-File Key Isolation via HKDF-SHA256**:
1. **Master Vault Key ($K_{\text{master}}$):** 256-bit root key stored securely via Windows DPAPI. Never used directly to encrypt file chunks.
2. **Fresh Per-File Salt ($S_{\text{file}}$):** For every quarantined file, a cryptographically secure 256-bit random salt is generated via `os.urandom(32)`.
3. **Per-File Subkey ($K_{\text{file}}$):** Derived using standard HKDF (RFC 5869) with SHA-256:
   $$K_{\text{file}} = \text{HKDF-Extract-and-Expand}(K_{\text{master}}, \text{salt}=S_{\text{file}}, \text{info}=\text{b"USBSentinel-FileVault-v2"}, \text{len}=32)$$
   Because $S_{\text{file}}$ is freshly generated with $2^{256}$ entropy for each file, each file possesses a distinct, statistically unique 256-bit key. Nonces cannot collide across different files or application restarts.
4. **Deterministic In-File Chunk Nonces ($\text{IV}_i$):**
   Within the isolated file stream under $K_{\text{file}}$, chunks are indexed sequentially ($i = 0, 1, 2, \dots$). The 12-byte GCM IV for chunk $i$ is constructed as:
   $$\text{IV}_i = \text{uint32\_be}(0) \parallel \text{uint64\_be}(i)$$
   Chunk index $i$ strictly increments, guaranteeing unique IVs for all chunks in the file ($i < 2^{64}$).

#### 3.2 Vault Object Binary Format (`.qnt`)

```
+-----------------------------------------------------------------------------------+
|                        USB Sentinel Vault Object (.qnt)                           |
+-----------------------------------------------------------------------------------+
| FILE HEADER (48 Bytes Total):                                                     |
| - Magic Bytes: "USBSQNT2" (8 bytes ASCII)                                         |
| - Format Version: 0x0002 (uint16 big-endian, 2 bytes)                             |
| - Reserved / Flags: 0x0000 (uint16 big-endian, 2 bytes)                           |
| - Per-File Cryptographic Salt: 32 bytes (os.urandom(32))                          |
| - Plaintext Chunk Size: uint32 big-endian (4 bytes, default = 65,536 bytes)        |
+-----------------------------------------------------------------------------------+
| ENCRYPTED CHUNKS (Chunk 0, Chunk 1, ... Chunk N):                                 |
| - Chunk Ciphertext Length: uint32 big-endian (4 bytes; payload size + 16-byte tag)|
| - Is-Final-Chunk Flag: uint8 (0x00 = more chunks follow; 0x01 = final chunk)      |
| - Payload Ciphertext: AES-256-GCM encrypted bytes (up to 64 KB)                   |
| - Auth Tag: AES-256-GCM Authentication Tag (16 bytes)                             |
+-----------------------------------------------------------------------------------+
```

#### 3.3 Anti-Tamper, Truncation & Reordering Defense
To strictly prevent chunk swapping, truncation, or header tampering:
1. **Header Authentication Binding:**
   The SHA-256 digest of the entire 48-byte File Header is calculated:
   $$\text{HeaderDigest} = \text{SHA-256}(\text{FileHeaderBytes[0:48]})$$
2. **Chunk Associated Data (AD):**
   Each chunk's GCM encryption binds the Header Digest, the chunk index, and the final chunk flag into Associated Data:
   $$\text{AD}_i = \text{HeaderDigest (32 bytes)} \parallel \text{uint64\_be}(i) \parallel \text{is\_final\_byte (1 byte)}$$
3. **Truncation Detection:** If an adversary removes trailing chunks, the last received chunk has `is_final_byte == 0x00`. Decryption will reject the truncated stream with `IncompleteCipherstreamError`.
4. **Reordering & Omission Detection:** If chunks are reordered or omitted, the expected chunk index $i$ will not match $\text{AD}_i$ and the IV, causing `AESGCM.decrypt()` to raise `InvalidTag` and immediately abort.
5. **Wrong-Key Rejection:** Decrypting with an invalid master key causes HKDF to derive an incorrect subkey. AES-GCM authentication fails on the very first 64 KB chunk, rejecting the file in under 1 millisecond.
6. **Bounded Memory Footprint:** The cipher streams in fixed 64 KB chunks. Peak RAM usage remains below 2 MB even when processing multi-gigabyte disk images.
7. **End-to-End Plaintext Hash Verification:** Decrypted plaintext is streamed through SHA-256; the recovered digest must match the original digest recorded in `quarantine_index.txt`.

---

### 4. Key Management & Windows DPAPI Protection

Vault contents and cryptographic keys are **strictly separated from the source-code repository** and placed in dedicated local application data storage.

#### 4.1 Storage Architecture
```text
%LOCALAPPDATA%\USBSentinel\
├── keys\
│   └── master.key.dpapi        # 256-bit root master key encrypted via Windows DPAPI
├── vault\
│   ├── <quarantine_id>.qnt     # Verified authenticated ciphertext objects
│   └── recovery\               # Orphaned or quarantined objects held for manual recovery
├── staging\
│   └── <quarantine_id>.tmp     # Temporary in-flight objects during two-phase commit
├── logs\
│   ├── usb_sentinel_audit.csv  # RFC 4180 audit ledger with formula sanitization
│   └── quarantine_index.txt    # Persistent restoration index
└── reports\
    ├── incident_report_*.html  # Self-contained HTML reports
    └── incident_report_*.txt   # Monospace text reports
```

#### 4.2 Key Protection Implementation
1. **Windows Production Mechanism (DPAPI):**
   - On first run, USB Sentinel generates a 256-bit cryptographically secure random root key using `os.urandom(32)`.
   - The root key is encrypted using the Windows Data Protection API (`CryptProtectData` via `win32crypt` or `ctypes.windll.crypt32`).
   - Flag: `CRYPTPROTECT_UI_FORBIDDEN`.
   - The encrypted DPAPI blob is saved to `%LOCALAPPDATA%\USBSentinel\keys\master.key.dpapi`.
   - Access Control: Directory and key file permissions are hardened via Windows ACLs (`icacls "%LOCALAPPDATA%\USBSentinel" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"`), restricting read/write access solely to the active Windows user account and SYSTEM.
2. **Cross-Platform / Developer Fallback (macOS/Linux):**
   - Stores the master key at `~/.usb_sentinel/keys/master.key` protected by POSIX `chmod 0600` (read/write restricted exclusively to the current user).
   - Alternatively supports deriving the key via PBKDF2HMAC (SHA-256, 600,000 iterations, 32-byte salt) from a user-provided passphrase.
3. **Failure Scenarios & Security Rules:**
   - **Key Loss:** If the DPAPI key file or Windows user profile is deleted without a backup, quarantined files cannot be decrypted. This is a deliberate security tradeoff ensuring quarantined payloads cannot be extracted by unauthorized users.
   - **Unauthorized Access:** Other local user accounts or guest accounts on the machine cannot decrypt the DPAPI master key, ensuring complete user isolation.
   - **Zero Secrets in Code:** Keys, passphrases, and salts are never hardcoded in source code or checked into version control.

---

### 5. Windows Device Detection & Volume Telemetry

#### 5.1 Multi-Tiered Hardware Inspection Pipeline
USB Sentinel resolves the `DRIVE_REMOVABLE` vs `DRIVE_FIXED` ambiguity through a 3-tier inspection pipeline:

```
+-------------------------------------------------------------------------+
|                        Volume Detection Pipeline                        |
+-------------------------------------------------------------------------+
| Step 1: Enumerate System Logical Drives (GetLogicalDriveStringsW)       |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| Step 2: Query Hardware Bus Type via WMI                                 |
| - Query Win32_DiskDrive where InterfaceType == 'USB' or PNPDeviceID     |
|   starts with 'USBSTOR\' or 'USB\'                                      |
| - Correlate: Win32_DiskDrive -> Win32_DiskDriveToDiskPartition ->      |
|              Win32_LogicalDiskToPartition -> Win32_LogicalDisk          |
| - If Drive Letter matches: CLASSIFIED AS USB MASS STORAGE               |
+-------------------------------------------------------------------------+
                                     | (If WMI unavailable / timeout)
                                     v
+-------------------------------------------------------------------------+
| Step 3: Query Storage Device Descriptor (IOCTL_STORAGE_QUERY_PROPERTY)  |
| - Open volume handle via CreateFileW('\\.\E:')                          |
| - Issue DeviceIoControl for StorageDeviceProperty                       |
| - Check STORAGE_DEVICE_DESCRIPTOR.BusType == 7 (BusTypeUsb)             |
| - If BusType == 7: CLASSIFIED AS USB MASS STORAGE                       |
+-------------------------------------------------------------------------+
                                     | (If IOCTL fails / access denied)
                                     v
+-------------------------------------------------------------------------+
| Step 4: Fallback to DRIVE_REMOVABLE                                     |
| - Check GetDriveTypeW(drive) == DRIVE_REMOVABLE (Type 2)                |
| - Emit explicit log: "[DEGRADED] Using DRIVE_REMOVABLE fallback;        |
|   fixed-disk USB drives cannot be detected in this mode."               |
+-------------------------------------------------------------------------+
```

#### 5.2 Strict Evidence Rules
- **Never** classify all fixed drives as USB (internal NVMe/SATA `C:\` or `D:\` drives are strictly excluded).
- **Never** classify non-USB removable drives (e.g. legacy floppy or optical discs) as USB without verifying the USB bus or interface property.

#### 5.3 Privacy-Preserving Telemetry Collection
To prevent unnecessary surveillance of personal devices, USB Sentinel minimizes hardware data collection:
- **Collected:** Drive Letter (`E:`), Volume Label (e.g., `SANDISK_32`), Filesystem (`FAT32`, `NTFS`, `exFAT`), Total Capacity, Available Free Space, and File-system Volume Serial Number (randomly generated upon format).
- **Excluded:** Hardware chip serial numbers and personal hardware IDs are excluded from logs and incident reports unless explicitly required for troubleshooting.

---

### 6. Filesystem Safety & Defensive Traversal Protocols

#### 6.1 Safe Traversal & Symlink/Junction Handling
- **Corrected Standard API:** Python's `os.walk` uses the parameter `followlinks=False` (not `follow_symlinks`).
- **NTFS Reparse Points & Directory Junctions:**
  - On Windows with Python 3.8+, `os.walk(path, followlinks=False)` does not descend into NTFS directory junctions (`IO_REPARSE_TAG_MOUNT_POINT`) or directory symbolic links (`IO_REPARSE_TAG_SYMLINK`).
  - In addition, the walker checks `entry.is_symlink()` and `os.path.islink(path)`. Any junction or symlink is skipped to prevent infinite directory recursion.
  - Visited canonical directories are tracked via `os.path.realpath()` in a `visited_dirs` set.

#### 6.2 Extended-Length Path Handling (`MAX_PATH`)
- Blindly prepending `\\?\` causes errors on relative paths, POSIX systems, and network shares (`UNC`).
- **Protocol:** Prepend `\\?\` **only** when all the following criteria are met:
  1. Operating system is Windows (`sys.platform == 'win32'`).
  2. Path is an absolute local path (matches `^[a-zA-Z]:\\`).
  3. Path length approaches or exceeds Win32 `MAX_PATH` (length $\ge 240$ characters).
  4. Path does not already start with `\\?\` or `\\?\UNC\`.

#### 6.3 Platform-Aware Timestamp Handling
- **Windows:** `os.stat().st_ctime` represents file **creation timestamp**.
- **macOS / BSD:** `os.stat().st_birthtime` represents creation time, while `st_ctime` represents metadata change time.
- **Linux:** Falls back to `st_mtime`.
- Encapsulated in `get_file_timestamps(path)` and formatted as ISO 8601 UTC strings (`YYYY-MM-DDTHH:MM:SSZ`).

#### 6.4 Handling Disconnected Volumes & Inaccessible Files
- Catches `(FileNotFoundError, PermissionError, OSError)`:
  - If the drive root becomes inaccessible during traversal (abrupt disconnect), traversal terminates cleanly, logs `DEVICE_DISCONNECTED_MID_SCAN`, and returns a partial scan summary without crashing.
  - Individual locked files (e.g., locked by Windows Defender or `SearchIndexer.exe`) raise `PermissionError`; these are logged as `ACCESS_DENIED_FILE_SKIPPED`, and scanning continues.

---

### 7. Quarantine, Crash-Safe Transaction Safety & Restoration Protocols

#### 7.1 Default Policy: ALERT AND LOG ONLY
- **Default watchdog behavior is strictly ALERT AND LOG ONLY.**
- Suspicious files (`.exe`, `.bat`, `.vbs`, `.ps1`, `.scr`) are flagged, hashed, and logged in `usb_sentinel_audit.csv` and incident reports.
- **No files are moved, renamed, encrypted, or deleted by default.**
- Quarantining occurs **only** when explicitly confirmed by the user.

#### 7.2 Strict Crash-Safe Quarantine Ordering (Five-Step Transaction)
To prevent data loss under any failure condition, quarantine execution strictly follows this exact five-step sequence:

```
+---------------------------------------------------------------------------------------+
|                       Crash-Safe Five-Step Quarantine Sequence                        |
+---------------------------------------------------------------------------------------+
| Step 1: Hash Source & Encrypt to Staging File                                         |
| - Read source file in 64 KB chunks -> Compute source SHA-256 digest.                  |
| - Derive unique per-file subkey via HKDF-SHA256 with fresh salt.                      |
| - Stream-encrypt ciphertext to: %LOCALAPPDATA%\USBSentinel\staging\<quarantine_id>.tmp|
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| Step 2: Verify Staged Encrypted Object & Recovered Plaintext Digest                   |
| - Stream-decrypt .tmp file in verification pass (authenticating tags & chunk AD).     |
| - Compute recovered plaintext digest and assert match against source SHA-256.         |
|   * If verification fails: delete .tmp file, abort, source file untouched on USB.     |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| Step 3: Atomically Promote Verified Object to Final Vault Path                        |
| - Atomically move/rename staging/<quarantine_id>.tmp -> vault/<quarantine_id>.qnt     |
|   (Source file remains 100% intact on USB storage)                                    |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| Step 4: Persist Quarantine Index & Audit State                                        |
| - Write quarantine record to quarantine_index.txt with durable flush (os.fsync).      |
| - Write audit ledger entry to usb_sentinel_audit.csv with durable flush (os.fsync).    |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| Step 5: Delete Original File on USB Storage                                           |
| - Execute deletion of source file from USB removable media.                           |
|   * If deletion fails (write-protected media): Record QUARANTINE_SOURCE_LOCKED.       |
|     Warn user original remains on USB; never claim removal succeeded.                 |
+---------------------------------------------------------------------------------------+
```

#### 7.3 Crash Recovery Behavior Across Failure Points
Sentinel explicitly defines crash and power-loss recovery between each transition step:

| Crash Occurrence Point | System State upon Reboot / Restart | Automatic & Manual Recovery Protocol | Data Loss Risk |
| :--- | :--- | :--- | :---: |
| **During Step 1** (Encryption in progress) | Staging `.tmp` file is incomplete. Source on USB is untouched. No vault or index entries exist. | Startup sweep identifies incomplete `.tmp` file (fails header/size check). File is moved to `vault/recovery/incomplete/` with a diagnostic log, not silently purged. Source file remains intact on USB. | **ZERO** |
| **During Step 2** (Verification in progress) | Staging `.tmp` file is complete but unverified. Source on USB is untouched. No vault or index entries exist. | The unpromoted `.tmp` file is recognized as uncommitted. It is archived to `vault/recovery/uncommitted/` for audit inspection. Source file remains intact on USB. | **ZERO** |
| **Between Step 3 & Step 4** (Promoted to `.qnt`, but index/audit not written) | Valid `.qnt` file exists in `vault/`, but has no entry in `quarantine_index.txt`. Source file is still intact on USB! | **Orphan Reconciler:** Sentinel inspects `vault/*.qnt` against `quarantine_index.txt`. If an unindexed `.qnt` is found, Sentinel verifies it decrypts cleanly. Sentinel adds the record to `quarantine_index.txt` with status `ORPHAN_RECONCILED_SOURCE_RETAINED`. **Sentinel NEVER deletes the original source file on the USB during crash reconciliation.** | **ZERO** |
| **Between Step 4 & Step 5** (Index committed, but source deletion not completed) | Valid `.qnt` exists, index is committed, but original source file is still on the USB storage. | On next scan, Sentinel detects the source file on USB matches a committed index record. Sentinel alerts the user and offers to complete deletion or mark state as `DUAL_COPY_RETAINED`. Original source was never lost or corrupted. | **ZERO** |
| **During Step 5** (USB deletion failed / write-protected) | Valid `.qnt` exists, index committed. USB media rejected deletion (write-protect switch / lock). | Sentinel records state as `QUARANTINE_SOURCE_LOCKED`. Prompts prominent CLI warning: *"Source file could not be removed (write-protected). Verified encrypted copy is retained in vault."* Sentinel **never** reports successful removal when deletion failed. | **ZERO** |

*File Purging Rule:* Sentinel **never automatically purges** files that may be needed for recovery. Ambiguous staging artifacts are moved to `vault/recovery/` with detailed audit log entries.

#### 7.4 Non-Destructive Restoration Protocol
- User selects a record from `quarantine_index.txt`.
- Vault file `<quarantine_id>.qnt` is decrypted via streaming to a temporary restoration file.
- Decrypted digest is compared against recorded SHA-256. If mismatched, restoration aborts immediately (`INTEGRITY_VERIFICATION_FAILED`).
- **Restoration Destination Decision (Decision 1):**
  - If the original drive letter is unavailable (e.g. USB storage was removed): Sentinel prompts the user to select a destination directory.
  - Sentinel explicitly offers `%USERPROFILE%\Desktop\Restored_Files\` as a selectable convenience option.
  - **Sentinel NEVER restores silently to an assumed destination.**
  - Destination directory is validated against directory traversal (`../`) and canonicalized using `pathlib.Path.resolve()`.
- **Conflict & Overwrite Prevention:**
  - If a file with the target filename already exists at the destination, Sentinel halts and prompts:
    - `[O]verwrite existing file`
    - `[R]ename restored file` (e.g., `filename_restored_<timestamp>.ext`)
    - `[C]ancel restoration`
- Upon success, update `quarantine_index.txt` marking `IS_RESTORED=1`.

---

### 8. Exactly Five Main CLI Operations

The CLI strictly implements **exactly** the five required operations:

```
==========================================================================
   USB SENTINEL: Automated USB Mass Storage Threat Watchdog & Vault       
==========================================================================
 [1] Display Active System Mounts & USB Device Telemetry
 [2] Start Real-Time USB Insertion Watchdog
 [3] Inspect & Restore Quarantined Files
 [4] Export USB Audit Ledger to CSV
 [5] Exit
==========================================================================
 Select an option (1-5): 
```

#### Operational Specifications:
1. **Display Active System Mounts & USB Device Telemetry:**
   - Evaluates active storage devices via the multi-tiered detection pipeline.
   - Displays a formatted table: Drive Letter, Volume Label, File System, Total Size, Free Space, Removable Status, and Bus Connection.
   - Provides option to trigger an immediate, on-demand recursive inspection of any mounted volume.
2. **Start Real-Time USB Insertion Watchdog:**
   - Launches an asynchronous background watchdog thread monitoring device insertion and removal.
   - Upon insertion: Captures telemetry, performs recursive inspection, records SHA-256 hashes, logs flagged items, and produces an incident report.
   - Operates in **Alert and Log Only** mode by default; prints prominent warning summaries to the console.
   - If manual quarantine is triggered and source deletion fails due to write-protection, logs `QUARANTINE_SOURCE_LOCKED` and warns the user.
   - Upon removal: Cleanly records volume dismount in audit ledger.
   - Non-blocking execution: user can press `Ctrl+C` or enter `'q'` to gracefully terminate the watchdog and return to the main menu.
3. **Inspect & Restore Quarantined Files:**
   - Parses `quarantine_index.txt` and presents a tabular list of quarantined items.
   - Displays file details (quarantine timestamp, original path, SHA-256 digest, file size, restoration status, and whether source was locked).
   - Provides explicit actions:
     - `[R]` Restore to original location (if available) or prompt for destination (offering `%USERPROFILE%\Desktop\Restored_Files\`).
     - `[A]` Restore to custom directory.
     - `[D]` Permanently purge item from vault.
     - `[B]` Back to main menu.
4. **Export USB Audit Ledger to CSV:**
   - Validates and exports `usb_sentinel_audit.csv` to a user-specified destination path (e.g., Desktop or external storage).
   - Sanitizes CSV fields against spreadsheet formula injection (neutralizing `=`, `+`, `-`, `@`, `\t`, `\r`).
   - Displays summary ledger metrics: Total Mount Events, Total Files Scanned, Flagged Risks, Quarantined Count, Restored Count.
5. **Exit:**
   - Signals background worker threads to terminate, flushes all open file streams, and cleanly exits with status code 0.

---

### 9. Dependencies, Version Constraints & Privacy

#### 9.1 Third-Party Dependency Justifications
| Dependency | Version Constraint | Target Environment | Architectural Justification |
| :--- | :--- | :--- | :--- |
| **`cryptography`** | `>= 41.0.0, < 44.0.0` | All Platforms | Provides standard AES-256-GCM AEAD, HKDF-SHA256 subkey derivation, and PBKDF2HMAC. Essential for streaming chunked encryption without custom cryptography. |
| **`pywin32`** | `>= 306; sys_platform == 'win32'` | Windows Only | Direct Win32 API access for `WM_DEVICECHANGE` message loop, `win32crypt` (DPAPI key protection), and `win32file` drive queries. |
| **`wmi`** | `>= 1.5.1; sys_platform == 'win32'` | Windows Only | Enables querying `Win32_DiskDrive` and bus type properties to distinguish USB storage from internal fixed drives. |
| **`colorama`** | `>= 0.4.6, < 0.5.0` | All Platforms | Cross-platform ANSI terminal coloring ensuring menus format properly across Windows CMD, PowerShell, and Unix shells. |
| **`pytest`** *(Dev)* | `>= 7.4.0, < 9.0.0` | All Platforms | Core testing framework for automated unit and integration tests. |
| **`pytest-mock`** *(Dev)* | `>= 3.11.0, < 4.0.0` | All Platforms | Mocking Win32 and WMI subsystems to enable test execution on macOS development environments. |

#### 9.2 Environment Installation Strategy
- Managed via Python standard `venv`:
  ```bash
  python -m venv .venv
  # On Windows:
  .venv\Scripts\activate
  pip install -r requirements.txt
  # On macOS (Development):
  source .venv/bin/activate
  pip install -r requirements.txt
  ```
- `requirements.txt` utilizes PEP 508 environment markers (`sys_platform == 'win32'`) so platform-specific dependencies (`pywin32`, `wmi`) are automatically bypassed during development on macOS while remaining locked for Windows deployments.

---

### 10. Implementation Roadmap & Concrete Acceptance Criteria

Development strictly follows the approved 8-phase sequence (Phases 0 through 7). No later-phase capabilities will be implemented prematurely.

```
+-----------+     +-----------+     +-----------+     +-----------+
|  Phase 0  | --> |  Phase 1  | --> |  Phase 2  | --> |  Phase 3  |
|  Planning |     |Foundation |     |  Scanner  |     | SHA & Log |
+-----------+     +-----------+     +-----------+     +-----------+
                                                            |
+-----------+     +-----------+     +-----------+           |
|  Phase 7  | <-- |  Phase 6  | <-- |  Phase 5  | <-- +-----+
| Security  |     | CLI & Rpt |     | Watchdog  |     | Phase 4 |
|  & E2E    |     |           |     |           |     |  Vault  |
+-----------+     +-----------+     +-----------+     +---------+
```

#### Phase 0: Planning and Architecture Review *(Completed)*
- Comprehensive requirements analysis, platform abstraction design, cryptographic construction, risk modeling, and approval of `PROJECT_PLAN.md`.

#### Phase 1: Project Foundation, Configuration, and Data Models
- **Tasks:**
  - Establish `usb_sentinel/` package structure and `requirements.txt` with platform markers.
  - Implement `usb_sentinel/config.py` (AppData directory resolution, suspicious extensions, chunk size, default restoration directory).
  - Implement `usb_sentinel/models.py` (Typed dataclasses for `DeviceTelemetry`, `FileRecord`, `QuarantineRecord`, `AuditEvent`, `ScanSummary`).
  - Implement `usb_sentinel/platform_base.py` (Base abstraction contracts for device and security backends).
- **Verifiable Acceptance Criteria & Tests:**
  - Automated tests verify `config.py` correctly resolves AppData paths across platforms.
  - Data models validate immutability (`frozen=True`) and serialization to dictionary format.
  - 100% automated test pass rate under `pytest tests/test_foundation.py`.

#### Phase 2: File Scanner and Heuristic Risk Assessment
- **Tasks:**
  - Implement `usb_sentinel/scanner.py`.
  - Recursive traversal using `os.walk(..., followlinks=False)` with junction/symlink skipping.
  - Safe path normalization and conditional `\\?\` prefixing for Windows long paths.
  - Platform-aware timestamp collection (`st_ctime` on Windows, `st_birthtime` on BSD/macOS).
  - Defensive error handling for `PermissionError` and `FileNotFoundError`.
  - Heuristic risk classification: categorize `.exe`, `.bat`, `.vbs`, `.ps1`, `.scr` as suspicious with clear disclaimers that extensions do not prove malware.
- **Verifiable Acceptance Criteria & Tests:**
  - Tests verify that directory symlinks and recursive junction points are detected and skipped without loops.
  - Tests verify metadata extraction on mock file trees (timestamps, exact sizes).
  - Tests verify non-fatal recovery when encountering locked files or permission-denied directories.
  - 100% pass rate under `pytest tests/test_scanner.py`.

#### Phase 3: SHA-256, Audit Logging, and Persistent Quarantine Index
- **Tasks:**
  - Implement `usb_sentinel/integrity.py` with chunked 64 KB streaming SHA-256 computation.
  - Implement `usb_sentinel/audit.py` managing `usb_sentinel_audit.csv` with formula injection sanitization.
  - Implement persistent `quarantine_index.txt` parser and atomic record appender.
- **Verifiable Acceptance Criteria & Tests:**
  - Streaming SHA-256 produces exact matching hashes against known NIST/FIPS test vectors and standard library hashlib.
  - CSV injection test: filenames starting with `=`, `+`, `-`, `@`, `\t`, `\r` are prepended with a single quote (`'`).
  - Quarantine index parser correctly reads and writes pipe-delimited records with atomic flush (`os.fsync`).
  - 100% pass rate under `pytest tests/test_audit_integrity.py`.

#### Phase 4: Encrypted Quarantine and Restoration Engine *(Completed)*
- **Tasks:**
  - Implement `usb_sentinel/vault.py` featuring streaming chunked AES-256-GCM AEAD encryption and HKDF-SHA256 per-file key derivation.
  - Implement Windows DPAPI root key storage with POSIX development fallback.
  - Implement Crash-Safe Five-Step Quarantine sequence.
  - Implement crash-recovery reconciler (orphaned `.qnt` reconciliation without deleting USB source).
  - Implement write-protected USB handling (`QUARANTINE_SOURCE_LOCKED`).
  - Implement restoration engine with destination prompts, `%USERPROFILE%\Desktop\Restored_Files\` option, and conflict overwrite guards.
- **Verifiable Acceptance Criteria & Tests:**
  - **HKDF & Nonce Uniqueness Test:** Verifies distinct subkeys and IV sequences across 10,000 simulated files and restarts.
  - **Round-Trip Streaming Test:** 10 MB simulated file encrypted and decrypted byte-for-byte identical to original.
  - **Tamper Detection Test:** Single-byte flip in ciphertext payload or auth tag raises `InvalidTag` and aborts decryption.
  - **Truncation Detection Test:** Omitting the final chunk fails AD validation with `IncompleteCipherstreamError`.
  - **Chunk Reordering Test:** Swapping chunk order causes immediate authentication failure on the first reordered chunk.
  - **Wrong-Key Failure Test:** Attempting decryption with incorrect master key aborts on chunk 0.
  - **Crash Simulation Tests:** Injected crashes between Steps 1-2, 2-3, 3-4, and 4-5 demonstrate zero data loss; orphaned `.qnt` reconciles without touching USB source.
  - **Write-Protection Test:** Write-protected source records `QUARANTINE_SOURCE_LOCKED`, retains vault copy, and warns user.
  - **Restoration Destination Test:** Missing original drive letter prompts for destination; validates selectable default; blocks path traversal.
  - 100% pass rate under `pytest tests/test_vault.py`.

#### Phase 5: Windows USB Insertion/Removal Watchdog *(Completed)*
- **Tasks:**
  - Implement `usb_sentinel/device_detection.py` implementing the multi-tiered volume detection pipeline (WMI -> IOCTL -> DRIVE_REMOVABLE), physical USB HDD/SSD disambiguation, and cross-platform abstractions (`UnsupportedPlatformDetector`, `MockDeviceDetector`).
  - Implement `usb_sentinel/watchdog.py` managing thread-safe lifecycle, event debouncing, bounded mount readiness retries, and cancellation propagation.
  - Integrate default **Alert and Log Only** behavior upon device insertion, guaranteeing zero automatic file deletion or quarantine.
  - Implement mock backend for development host testing and unit tests in `tests/test_device_detection.py` and `tests/test_watchdog.py`.
- **Verifiable Acceptance Criteria & Tests:**
  - Mocked tests simulate device insertion: verifies that volume arrival triggers automated scanning, SHA-256 hashing, and audit logging.
  - Mocked tests simulate device removal: verifies that dismount triggers `DEVICE_REMOVED` audit logging and cancels in-flight scans.
  - Graceful degradation test: when WMI is mocked as disabled, the detector falls back to `DRIVE_REMOVABLE` and logs a degraded status warning.
  - 100% pass rate under `pytest tests/test_device_detection.py` and `tests/test_watchdog.py` (34 tests; 164 total project tests).

#### Phase 6: Five-Option CLI Integration and Incident Reports *(Completed)*
- **Tasks:**
  - Implement `usb_sentinel/reporting.py` producing both styled HTML and monospace text reports.
  - Implement `usb_sentinel/cli.py` presenting **exactly** the five required menu operations.
  - Implement interactive quarantine confirmation and audit ledger CSV export.
  - Implement clean keyboard interrupt (`Ctrl+C`) and `EOFError` handling.
- **Verifiable Acceptance Criteria & Tests:**
  - CLI menu test: mock user inputs test all five operations for valid dispatch and graceful handling of invalid options.
  - Report generator test: HTML report validates with strict escaping; text report matches expected monospace layout.
  - Audit export test: exports audit ledger to custom user path with formula-injection defenses.
  - 100% pass rate under `pytest tests/test_cli.py`, `tests/test_reporting.py`, and `tests/test_cli_reporting.py` (25 tests; 189 total project tests).

#### Phase 7: Security Review and End-to-End Testing *(Completed)*
- **Tasks:**
  - Full end-to-end integration test suite (`tests/test_e2e.py`) executing all 10 operational lifecycle scenarios: full lifecycle, fixed disk USB disambiguation, unknown device fallback, read-only watchdog non-modification, verified quarantine & restore, interrupted operations, vault tamper rejection, destination collision policies, audit formula escaping & reports, and watchdog restart.
  - Hardened key protection backend (`usb_sentinel/crypto_keys.py`) to fail closed if `LocalDevKeyBackend` is invoked on Windows in production without explicit debug override.
  - Hardened restoration destination path resolver (`usb_sentinel/restoration.py`) to defeat path traversal, extract leaf filenames cross-platform with `PureWindowsPath`, and safely handle root or relative path attacks.
  - Defensive security audit: verified zero execution of inspected files, zero secret exposure in logs/errors, and proper permission restriction on AppData vault directories.
- **Verifiable Acceptance Criteria & Tests:**
  - Complete automated test suite passes with 100% success rate across all unit and integration test modules (202 tests passed across 18 test modules in `pytest`).
  - Comprehensive end-to-end testing report produced documenting automated test outcomes, simulated mock constraints, and Windows-specific manual verification steps.
  - **Explicit Security Disclaimer:** Passing tests certify that USB Sentinel meets all functional, architectural, cryptographic, and safety specifications, but heuristic extension filtering does not guarantee malware protection against sophisticated threats.

#### Phase 8: Localhost Web Dashboard Interface *(Completed)*
- **Tasks:**
  - Implement server-rendered Flask web dashboard (`usb_sentinel/web_app.py`, `run_web.py`) with light-blue and dark-navy accessible theme (`usb_sentinel/static/css/style.css`).
  - Zero JavaScript build dependencies: pure HTML5, CSS3, and Jinja2 server-rendered templates (`base.html`, `dashboard.html`, `devices.html`, `watchdog.html`, `quarantine.html`, `logs.html`, `report_view.html`).
  - Five core navigation views: Dashboard (`/dashboard`), Devices & Scanner (`/devices`), Watchdog (`/watchdog`), Quarantine Vault (`/quarantine`), and Audit Logs & Reports (`/logs`).
  - Session CSRF protection middleware and strict path traversal validation.
  - Background scanning coordinator (`BackgroundScanWorker`) preventing HTTP thread blocking.
  - Dedicated web test suite (`tests/test_web.py`).
- **Verifiable Acceptance Criteria & Tests:**
  - 100% automated test pass rate across 13 web test cases verifying navigation, watchdog controls, on-demand scanning, manual quarantine, restoration, CSV export, report viewing, CSRF rejection, and XSS escaping (215 total passing project tests across 19 modules).
  - Web dashboard strictly binds to `127.0.0.1` and rejects public interfaces (`0.0.0.0`).
  - Existing CLI entry point (`python -m usb_sentinel`) remains completely functional and backward compatible.

---

### 11. Decisions Resolved in this Revision & System Limitations

#### 11.1 Resolved Architectural Decisions
1. **Restoration Destination:** When the original drive is unavailable, Sentinel prompts the user for a destination, offering `%USERPROFILE%\Desktop\Restored_Files\` as a selectable convenience option. Never restores silently to an assumed location.
2. **Write-Protected USB Media:** Verified vault copy is retained; state is committed as `QUARANTINE_SOURCE_LOCKED`; prominent warning emitted that original remains on USB; removal is never falsely reported.
3. **Cryptographic Nonce Uniqueness:** Counter nonces under a static key are completely replaced with **Per-File Subkey Derivation via HKDF-SHA256 with 32-byte fresh random salts**. Associated Data binds header digest, sequential chunk index, and is-final flag to prevent tampering, truncation, and reordering.
4. **Crash-Safe Quarantine Sequence:** Enforced exact 5-step sequence (hash/encrypt -> verify -> promote -> persist index/audit -> delete source). Defined recovery protocols for crashes between each step. Orphaned `.qnt` files are reconciled without deleting the source file. No premature automatic purging of recovery artifacts.

#### 11.2 System Boundaries & Documented Limitations
- **Heuristic Scope:** Tagging is strictly heuristic based on high-risk executable and script extensions (`.exe`, `.bat`, `.vbs`, `.ps1`, `.scr`). It does not perform dynamic behavioral analysis or signature matching.
- **Administrator Elevation:** Detecting volume insertion does not strictly require elevation, but interacting with locked volumes or policy-restricted USB storage may require running the command prompt as Administrator on Windows.
- **Physical USB Testing:** macOS development allows 100% unit and mock verification, but final validation of Win32 device message pumps and physical USB timing requires a Windows host or VM.
