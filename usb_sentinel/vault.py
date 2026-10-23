r"""Encrypted quarantine vault storage with authenticated streaming for USB Sentinel.

This module implements authenticated streaming encryption (AES-256-GCM) with per-file
key isolation (HKDF-SHA256) into `.qnt` vault objects.

Security & Architectural Guarantees:
1. **Memory-Bounded Streaming**:
   Plaintext is read and encrypted in fixed 64 KB chunks by default. Multi-gigabyte files
   are processed with bounded memory usage (< 2 MB RAM).
2. **Per-Object Key Isolation**:
   Every quarantined object receives a statistically unique 256-bit subkey derived from the
   master key, a fresh 256-bit cryptographic salt, and a domain-separated context string
   including the format version and quarantine ID.
3. **Nonce Construction & Nonce Uniqueness**:
   The 96-bit AES-GCM nonce combines a 4-byte random per-object prefix with an 8-byte
   monotonically increasing big-endian chunk counter ($i = 0, 1, 2, \dots$).
   Nonce uniqueness is practically guaranteed through two-tier separation:
   (a) Each quarantine object derives an isolated 256-bit subkey via HKDF-SHA256 with 256 bits
       of fresh salt entropy and unique quarantine ID domain separation.
   (b) Within any single object stream under that subkey, chunk counters monotonically increment
       without repetition ($i < 2^{64}$).
4. **Anti-Tamper & Cryptographic Binding**:
   - The canonical 1,192-byte file header includes the authentic original file path.
   - The SHA-256 digest of the entire header is computed.
   - Each chunk's Associated Authenticated Data (AAD) binds:
     `HeaderDigest (32B) || QuarantineID (36B) || ChunkIndex (8B) || PayloadLen (4B) || IsFinal (1B)`
   - Any modification to header metadata, original path, chunk ordering, chunk payload, auth tag,
     or truncation causes `AESGCM.decrypt()` to reject the stream immediately.
5. **No Premature Plaintext Release & No-Clobber Publication**:
   Decryption streams into a private temporary file. Plaintext is published to the destination
   ONLY after every chunk is authenticated, the complete object is validated, and the final
   SHA-256 matches the original baseline. By default, publication is strictly no-clobber,
   refusing to overwrite existing user files.
6. **Explicit Empty File Support**:
   0-byte files are handled securely via a single final chunk containing an authenticated
   empty payload.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from usb_sentinel.config import DEFAULT_STREAM_CHUNK_SIZE_BYTES, SentinelConfig, get_config
from usb_sentinel.crypto_keys import KeyManager

# Binary Vault Format Constants
VAULT_MAGIC: Final[bytes] = b"USBSQNT2"  # 8 bytes ASCII
VAULT_FORMAT_VERSION: Final[int] = 2    # uint16 big-endian
HEADER_FORMAT: Final[str] = ">8sHH36s32s4sIQQ64s1024s"
HEADER_LENGTH_BYTES: Final[int] = struct.calcsize(HEADER_FORMAT)  # 1192 bytes
CHUNK_TAG_LENGTH_BYTES: Final[int] = 16  # AES-GCM tag length
CHUNK_FRAME_HEADER_FORMAT: Final[str] = ">IB"  # ciphertext_length (uint32), is_final (uint8)
CHUNK_FRAME_HEADER_BYTES: Final[int] = struct.calcsize(CHUNK_FRAME_HEADER_FORMAT)  # 5 bytes

MAX_SUPPORTED_CHUNK_COUNT: Final[int] = (1 << 32) - 1
MIN_CHUNK_SIZE_BYTES: Final[int] = 1024
MAX_CHUNK_SIZE_BYTES: Final[int] = 16 * 1024 * 1024


class VaultError(Exception):
    """Base exception for quarantine vault operations."""


class VaultHeaderError(VaultError):
    """Raised when a vault object header is invalid, malformed, or has an unsupported version."""


class VaultAuthenticationError(VaultError):
    """Raised when AES-GCM tag authentication or AAD validation fails (tampering/wrong key)."""


class IncompleteCipherstreamError(VaultError):
    """Raised when an encrypted vault object is unexpectedly truncated or missing chunks."""


class TrailingCipherstreamError(VaultError):
    """Raised when unexpected trailing bytes follow the declared final chunk."""


class VaultIntegrityError(VaultError):
    """Raised when recovered plaintext fails final SHA-256 verification or size check."""


class DestinationCollisionError(VaultError):
    """Raised when destination file exists and no-clobber publication is enforced."""


@dataclass(frozen=True)
class VaultHeader:
    """Parsed, validated metadata from the 1,192-byte vault object header."""

    magic: bytes
    format_version: int
    flags: int
    quarantine_id: str
    salt: bytes
    nonce_prefix: bytes
    chunk_size_bytes: int
    original_size_bytes: int
    expected_chunks: int
    sha256_hex: str
    original_path: str
    header_digest: bytes


def construct_chunk_iv(nonce_prefix: bytes, chunk_index: int) -> bytes:
    """Construct 96-bit (12-byte) AES-GCM nonce for chunk i."""
    if len(nonce_prefix) != 4:
        raise ValueError(f"nonce_prefix must be exactly 4 bytes, got {len(nonce_prefix)}")
    return nonce_prefix + struct.pack(">Q", chunk_index)


def construct_chunk_aad(
    header_digest: bytes,
    quarantine_id: str,
    chunk_index: int,
    payload_length: int,
    is_final: bool,
) -> bytes:
    """Construct 81-byte Associated Authenticated Data (AAD) for chunk i."""
    qid_bytes = quarantine_id.encode("utf-8").ljust(36, b"\x00")[:36]
    is_final_byte = 1 if is_final else 0
    return (
        header_digest
        + qid_bytes
        + struct.pack(">QIB", chunk_index, payload_length, is_final_byte)
    )


def atomic_publish_no_clobber(temp_file: Path, target_file: Path) -> None:
    """Atomically publish temp_file to target_file without overwriting an existing target.

    Raises:
        DestinationCollisionError: If target_file already exists or is a symbolic link.
        VaultError: On filesystem I/O errors during publication.
    """
    if target_file.exists() or target_file.is_symlink() or os.path.islink(target_file):
        raise DestinationCollisionError(f"Restoration destination already exists: '{target_file}'")

    # On POSIX: os.link + os.unlink is atomic and fails if target_file exists
    if hasattr(os, "link"):
        try:
            os.link(temp_file, target_file)
            try:
                os.unlink(temp_file)
            except OSError:
                pass
            return
        except FileExistsError:
            raise DestinationCollisionError(
                f"Destination collision detected during atomic publication: '{target_file}'"
            )
        except (OSError, NotImplementedError):
            # Fallback for filesystems that do not support hard links (e.g. FAT)
            pass

    # On Windows: os.rename fails with FileExistsError if target exists (unlike os.replace)
    if sys.platform == "win32":
        try:
            os.rename(temp_file, target_file)
            return
        except FileExistsError:
            raise DestinationCollisionError(
                f"Destination collision detected during atomic publication: '{target_file}'"
            )

    # General fallback with existence re-check
    if target_file.exists() or target_file.is_symlink() or os.path.islink(target_file):
        raise DestinationCollisionError(f"Restoration destination already exists: '{target_file}'")
    try:
        os.rename(temp_file, target_file)
    except FileExistsError:
        raise DestinationCollisionError(
            f"Destination collision detected during atomic publication: '{target_file}'"
        )
    except OSError as exc:
        raise VaultError(f"Failed to publish restored file to '{target_file}': {exc}") from exc


class VaultManager:
    """Manages streaming encryption, decryption, authentication, and vault object lifecycle."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        key_manager: Optional[KeyManager] = None,
    ) -> None:
        self._config = config or get_config()
        self._key_manager = key_manager or KeyManager(config=self._config)

    @property
    def config(self) -> SentinelConfig:
        return self._config

    @property
    def key_manager(self) -> KeyManager:
        return self._key_manager

    def parse_header(self, raw_header: bytes) -> VaultHeader:
        """Parse and strictly validate the 1,192-byte vault file header.

        Args:
            raw_header: Exactly 1,192 bytes from start of a .qnt or .tmp file.

        Returns:
            VaultHeader: Validated header metadata.

        Raises:
            VaultHeaderError: If format, version, or field values are invalid.
        """
        if len(raw_header) != HEADER_LENGTH_BYTES:
            raise VaultHeaderError(
                f"Invalid header size: expected {HEADER_LENGTH_BYTES} bytes, got {len(raw_header)}"
            )

        try:
            (
                magic,
                version,
                flags,
                qid_bytes,
                salt,
                nonce_prefix,
                chunk_size,
                orig_size,
                expected_chunks,
                sha_bytes,
                path_bytes,
            ) = struct.unpack(HEADER_FORMAT, raw_header)
        except struct.error as exc:
            raise VaultHeaderError(f"Failed to unpack vault header: {exc}") from exc

        if magic != VAULT_MAGIC:
            raise VaultHeaderError(
                f"Invalid vault magic: expected {VAULT_MAGIC!r}, got {magic!r}"
            )

        if version != VAULT_FORMAT_VERSION:
            raise VaultHeaderError(
                f"Unsupported vault format version {version}, expected {VAULT_FORMAT_VERSION}"
            )

        quarantine_id = qid_bytes.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
        if not quarantine_id:
            raise VaultHeaderError("Vault header contains an empty quarantine ID")

        sha256_hex = sha_bytes.decode("ascii", errors="replace").strip().lower()
        if len(sha256_hex) != 64 or not all(c in "0123456789abcdef" for c in sha256_hex):
            raise VaultHeaderError(f"Invalid SHA-256 hash in vault header: '{sha256_hex}'")

        if chunk_size < MIN_CHUNK_SIZE_BYTES or chunk_size > MAX_CHUNK_SIZE_BYTES:
            raise VaultHeaderError(
                f"Vault header chunk_size {chunk_size} out of supported bounds "
                f"[{MIN_CHUNK_SIZE_BYTES}, {MAX_CHUNK_SIZE_BYTES}]"
            )

        if expected_chunks == 0 or expected_chunks > MAX_SUPPORTED_CHUNK_COUNT:
            raise VaultHeaderError(
                f"Vault header expected_chunks {expected_chunks} invalid or exceeds maximum limit"
            )

        if orig_size < 0:
            raise VaultHeaderError(f"Vault header original_size {orig_size} cannot be negative")

        original_path = path_bytes.rstrip(b"\x00").decode("utf-8", errors="replace").strip()

        header_digest = hashlib.sha256(raw_header).digest()

        return VaultHeader(
            magic=magic,
            format_version=version,
            flags=flags,
            quarantine_id=quarantine_id,
            salt=salt,
            nonce_prefix=nonce_prefix,
            chunk_size_bytes=chunk_size,
            original_size_bytes=orig_size,
            expected_chunks=expected_chunks,
            sha256_hex=sha256_hex,
            original_path=original_path,
            header_digest=header_digest,
        )

    def inspect_vault_file(self, file_path: Path | str) -> VaultHeader:
        """Inspect and parse the header of a vault file without decrypting its contents."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Vault file not found: {file_path}")

        try:
            with open(path, "rb") as f:
                header_bytes = f.read(HEADER_LENGTH_BYTES)
        except OSError as exc:
            raise VaultError(f"Failed to read vault header from '{path}': {exc}") from exc

        return self.parse_header(header_bytes)

    def encrypt_to_staging(
        self,
        source_path: Path | str,
        quarantine_id: str,
        master_key: bytes,
    ) -> tuple[Path, VaultHeader]:
        """Stream-encrypt a source file to a unique staging file in config.staging_dir.

        Args:
            source_path: Target file to encrypt.
            quarantine_id: Unique UUID string for the quarantine object.
            master_key: 32-byte master key.

        Returns:
            tuple[Path, VaultHeader]: Path to the created staging file and its header.

        Raises:
            FileNotFoundError: If source_path does not exist.
            VaultError: On I/O, encryption, or staging creation failure.
        """
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")
        if src.is_dir():
            raise VaultError(f"Cannot encrypt directory: {source_path}")

        self._config.staging_dir.mkdir(parents=True, exist_ok=True)
        staging_path = self._config.staging_dir / f"{quarantine_id}.tmp"

        # 1. Determine file size and expected chunk count
        try:
            stat_info = src.stat()
            orig_size = stat_info.st_size
        except OSError as exc:
            raise VaultError(f"Failed to inspect source file '{src}': {exc}") from exc

        chunk_size = self._config.stream_chunk_size_bytes
        if orig_size == 0:
            expected_chunks = 1  # Exactly 1 chunk containing empty payload
        else:
            expected_chunks = (orig_size + chunk_size - 1) // chunk_size

        if expected_chunks > MAX_SUPPORTED_CHUNK_COUNT:
            raise VaultError(
                f"File size exceeds maximum supported capacity: {expected_chunks} chunks"
            )

        # 2. Pre-compute source SHA-256 digest to embed in authenticated header
        source_hasher = hashlib.sha256()
        try:
            with open(src, "rb") as f_src:
                while True:
                    buf = f_src.read(chunk_size)
                    if not buf:
                        break
                    source_hasher.update(buf)
        except OSError as exc:
            raise VaultError(f"Failed to read source file '{src}' for hashing: {exc}") from exc
        orig_sha256_hex = source_hasher.hexdigest().lower()

        # 3. Generate fresh per-object cryptographic salt and nonce prefix
        salt = os.urandom(32)
        nonce_prefix = os.urandom(4)

        # 4. Derive unique per-object subkey via HKDF-SHA256
        sub_key = self._key_manager.derive_object_key(master_key, salt, quarantine_id)
        aesgcm = AESGCM(sub_key)

        # 5. Pack canonical 1,192-byte file header including original path
        orig_path_str = str(src.resolve() if src.is_absolute() else src)
        qid_raw = quarantine_id.encode("utf-8")
        if len(qid_raw) > 36:
            raise VaultHeaderError(
                f"Quarantine ID exceeds maximum header field length of 36 bytes: {len(qid_raw)} bytes"
            )
        qid_bytes = qid_raw.ljust(36, b"\x00")

        sha_bytes = orig_sha256_hex.encode("ascii")[:64]

        path_raw = orig_path_str.encode("utf-8")
        if len(path_raw) > 1024:
            raise VaultHeaderError(
                f"Original file path exceeds maximum supported header length of 1,024 bytes "
                f"({len(path_raw)} bytes): '{orig_path_str[:64]}...'"
            )
        path_bytes = path_raw.ljust(1024, b"\x00")

        raw_header = struct.pack(
            HEADER_FORMAT,
            VAULT_MAGIC,
            VAULT_FORMAT_VERSION,
            0,  # flags
            qid_bytes,
            salt,
            nonce_prefix,
            chunk_size,
            orig_size,
            expected_chunks,
            sha_bytes,
            path_bytes,
        )
        header_digest = hashlib.sha256(raw_header).digest()

        # 6. Stream encrypt into staging file with restricted permissions (0600 on POSIX)
        temp_staging = staging_path.with_name(f"{staging_path.name}.tmp_{os.getpid()}_{uuid.uuid4().hex}")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(temp_staging, flags, 0o600)
            with open(fd, "wb", closefd=True) as f_out:
                # Write header
                f_out.write(raw_header)

                with open(src, "rb") as f_in:
                    chunk_idx = 0
                    total_bytes_read = 0

                    if orig_size == 0:
                        # Handle 0-byte file: 1 empty chunk with is_final=True
                        iv = construct_chunk_iv(nonce_prefix, 0)
                        aad = construct_chunk_aad(header_digest, quarantine_id, 0, 0, True)
                        ct_and_tag = aesgcm.encrypt(iv, b"", aad)
                        frame = struct.pack(CHUNK_FRAME_HEADER_FORMAT, len(ct_and_tag), 1)
                        f_out.write(frame + ct_and_tag)
                    else:
                        while True:
                            chunk = f_in.read(chunk_size)
                            if not chunk:
                                break
                            total_bytes_read += len(chunk)
                            is_final = total_bytes_read >= orig_size or (chunk_idx + 1) == expected_chunks

                            iv = construct_chunk_iv(nonce_prefix, chunk_idx)
                            aad = construct_chunk_aad(
                                header_digest, quarantine_id, chunk_idx, len(chunk), is_final
                            )
                            ct_and_tag = aesgcm.encrypt(iv, chunk, aad)
                            frame = struct.pack(
                                CHUNK_FRAME_HEADER_FORMAT, len(ct_and_tag), 1 if is_final else 0
                            )
                            f_out.write(frame + ct_and_tag)
                            chunk_idx += 1

                f_out.flush()
                os.fsync(f_out.fileno())

            # Atomic replace into target staging path
            os.replace(temp_staging, staging_path)
        except Exception as exc:
            if temp_staging.exists():
                try:
                    temp_staging.unlink()
                except OSError:
                    pass
            raise VaultError(f"Failed to stream-encrypt '{src}' to staging: {exc}") from exc

        header = VaultHeader(
            magic=VAULT_MAGIC,
            format_version=VAULT_FORMAT_VERSION,
            flags=0,
            quarantine_id=quarantine_id,
            salt=salt,
            nonce_prefix=nonce_prefix,
            chunk_size_bytes=chunk_size,
            original_size_bytes=orig_size,
            expected_chunks=expected_chunks,
            sha256_hex=orig_sha256_hex,
            original_path=orig_path_str,
            header_digest=header_digest,
        )
        return staging_path, header

    def authenticate_and_verify_stream(
        self,
        vault_file_path: Path | str,
        quarantine_id: str,
        master_key: bytes,
        expected_sha256: Optional[str] = None,
    ) -> bool:
        """Authenticate all chunks and verify recovered plaintext SHA-256 without saving plaintext.

        Args:
            vault_file_path: Path to .tmp staging file or .qnt vault file.
            quarantine_id: Expected quarantine ID.
            master_key: 32-byte master key.
            expected_sha256: Optional expected plaintext SHA-256 digest.

        Returns:
            bool: True if authentication and digest verification succeed.

        Raises:
            VaultHeaderError: If header is invalid.
            VaultAuthenticationError: If any chunk tag or AAD fails authentication.
            IncompleteCipherstreamError: If truncated or missing chunks.
            TrailingCipherstreamError: If unexpected trailing bytes follow final chunk.
            VaultIntegrityError: If recovered plaintext digest mismatches expected digest.
        """
        path = Path(vault_file_path)
        if not path.exists():
            raise FileNotFoundError(f"Vault file not found: {vault_file_path}")

        try:
            with open(path, "rb") as f:
                raw_header = f.read(HEADER_LENGTH_BYTES)
                header = self.parse_header(raw_header)

                if header.quarantine_id != quarantine_id:
                    raise VaultHeaderError(
                        f"Quarantine ID mismatch in header: expected '{quarantine_id}', "
                        f"found '{header.quarantine_id}'"
                    )

                # Derive subkey
                sub_key = self._key_manager.derive_object_key(master_key, header.salt, quarantine_id)
                aesgcm = AESGCM(sub_key)

                recovered_hasher = hashlib.sha256()
                total_recovered_bytes = 0
                chunk_idx = 0
                encountered_final = False

                while True:
                    frame = f.read(CHUNK_FRAME_HEADER_BYTES)
                    if not frame:
                        if not encountered_final:
                            raise IncompleteCipherstreamError(
                                f"Vault file '{path}' truncated: reached EOF after chunk {chunk_idx - 1} "
                                f"before encountering declared final chunk (expected {header.expected_chunks} chunks)"
                            )
                        break

                    if len(frame) < CHUNK_FRAME_HEADER_BYTES:
                        raise IncompleteCipherstreamError(
                            f"Vault file '{path}' truncated midway through chunk frame header at index {chunk_idx}"
                        )

                    if encountered_final:
                        raise TrailingCipherstreamError(
                            f"Vault file '{path}' contains unexpected trailing data after declared final chunk"
                        )

                    ct_len, is_final_int = struct.unpack(CHUNK_FRAME_HEADER_FORMAT, frame)
                    if ct_len < CHUNK_TAG_LENGTH_BYTES:
                        raise VaultAuthenticationError(
                            f"Invalid chunk ciphertext length {ct_len} at index {chunk_idx}"
                        )

                    ct_and_tag = f.read(ct_len)
                    if len(ct_and_tag) < ct_len:
                        raise IncompleteCipherstreamError(
                            f"Vault file '{path}' truncated: expected {ct_len} bytes for chunk {chunk_idx}, "
                            f"got {len(ct_and_tag)}"
                        )

                    is_final = bool(is_final_int == 1)
                    expected_payload_len = ct_len - CHUNK_TAG_LENGTH_BYTES

                    iv = construct_chunk_iv(header.nonce_prefix, chunk_idx)
                    aad = construct_chunk_aad(
                        header.header_digest, quarantine_id, chunk_idx, expected_payload_len, is_final
                    )

                    try:
                        pt_chunk = aesgcm.decrypt(iv, ct_and_tag, aad)
                    except InvalidTag as exc:
                        raise VaultAuthenticationError(
                            f"AES-GCM authentication failed on chunk {chunk_idx} of '{path}' "
                            "(tampered ciphertext, invalid key, or corrupt tag)"
                        ) from exc

                    if len(pt_chunk) != expected_payload_len:
                        raise VaultAuthenticationError(
                            f"Decrypted chunk length mismatch on chunk {chunk_idx}: "
                            f"expected {expected_payload_len}, got {len(pt_chunk)}"
                        )

                    recovered_hasher.update(pt_chunk)
                    total_recovered_bytes += len(pt_chunk)

                    if is_final:
                        encountered_final = True

                    chunk_idx += 1

                # Check for trailing bytes after EOF loop
                trailing = f.read(1)
                if trailing:
                    raise TrailingCipherstreamError(
                        f"Vault file '{path}' contains unexpected trailing garbage after final chunk"
                    )

                if chunk_idx != header.expected_chunks:
                    raise IncompleteCipherstreamError(
                        f"Vault file chunk count mismatch: expected {header.expected_chunks}, processed {chunk_idx}"
                    )

                if total_recovered_bytes != header.original_size_bytes:
                    raise VaultIntegrityError(
                        f"Decrypted plaintext size mismatch: expected {header.original_size_bytes} bytes, "
                        f"recovered {total_recovered_bytes} bytes"
                    )

                recovered_sha256 = recovered_hasher.hexdigest().lower()
                if recovered_sha256 != header.sha256_hex:
                    raise VaultIntegrityError(
                        f"Decrypted plaintext SHA-256 mismatch with vault header: "
                        f"expected {header.sha256_hex}, calculated {recovered_sha256}"
                    )

                target_expected = expected_sha256.strip().lower() if expected_sha256 else header.sha256_hex
                if recovered_sha256 != target_expected:
                    raise VaultIntegrityError(
                        f"Decrypted plaintext SHA-256 mismatch with expected baseline: "
                        f"expected {target_expected}, calculated {recovered_sha256}"
                    )

                return True
        except (VaultError, FileNotFoundError):
            raise
        except OSError as exc:
            raise VaultError(f"I/O error reading vault file '{path}': {exc}") from exc

    def promote_staging_to_vault(self, quarantine_id: str) -> Path:
        """Atomically promote a verified staging file to its final vault location.

        Args:
            quarantine_id: Identifier of the staging object.

        Returns:
            Path: Final promoted path in config.vault_dir.

        Raises:
            FileNotFoundError: If staging file does not exist.
            VaultError: If atomic promotion fails.
        """
        staging_path = self._config.staging_dir / f"{quarantine_id}.tmp"
        vault_path = self._config.vault_dir / f"{quarantine_id}.qnt"

        if not staging_path.exists():
            raise FileNotFoundError(f"Staging file not found for promotion: {staging_path}")

        self._config.vault_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(staging_path, vault_path)
            return vault_path
        except OSError as exc:
            raise VaultError(
                f"Failed to atomically promote staging object '{staging_path}' to '{vault_path}': {exc}"
            ) from exc

    def decrypt_vault_file(
        self,
        vault_file_path: Path | str,
        quarantine_id: str,
        master_key: bytes,
        destination_path: Path | str,
        expected_sha256: Optional[str] = None,
        allow_overwrite: bool = False,
    ) -> Path:
        """Decrypt a vault object to a destination path, releasing plaintext ONLY after full verification.

        Args:
            vault_file_path: Path to the .qnt vault object.
            quarantine_id: Expected quarantine ID.
            master_key: 32-byte master key.
            destination_path: Final destination path for the decrypted plaintext.
            expected_sha256: Optional expected SHA-256 digest.
            allow_overwrite: Whether to allow overwriting an existing file (default False).

        Returns:
            Path: Destination path of the verified restored plaintext file.

        Raises:
            DestinationCollisionError: If destination exists and allow_overwrite is False.
            VaultError: On authentication, integrity, or decryption failure.
        """
        vault_path = Path(vault_file_path)
        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        if not allow_overwrite and (dest.exists() or dest.is_symlink() or os.path.islink(dest)):
            raise DestinationCollisionError(f"Restoration destination already exists: '{dest}'")

        # Decrypt into a unique private temporary file with 0600 permissions
        temp_dest = dest.with_name(f"{dest.name}.tmp_{os.getpid()}_{uuid.uuid4().hex}")

        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(temp_dest, flags, 0o600)
            with open(vault_path, "rb") as f_in, open(fd, "wb", closefd=True) as f_out:
                raw_header = f_in.read(HEADER_LENGTH_BYTES)
                header = self.parse_header(raw_header)

                if header.quarantine_id != quarantine_id:
                    raise VaultHeaderError(
                        f"Quarantine ID mismatch in vault header: expected '{quarantine_id}', "
                        f"got '{header.quarantine_id}'"
                    )

                sub_key = self._key_manager.derive_object_key(master_key, header.salt, quarantine_id)
                aesgcm = AESGCM(sub_key)

                recovered_hasher = hashlib.sha256()
                total_recovered_bytes = 0
                chunk_idx = 0
                encountered_final = False

                while True:
                    frame = f_in.read(CHUNK_FRAME_HEADER_BYTES)
                    if not frame:
                        if not encountered_final:
                            raise IncompleteCipherstreamError(
                                f"Vault file '{vault_path}' truncated: reached EOF before final chunk"
                            )
                        break

                    if len(frame) < CHUNK_FRAME_HEADER_BYTES:
                        raise IncompleteCipherstreamError(
                            f"Vault file '{vault_path}' truncated in chunk frame header {chunk_idx}"
                        )

                    if encountered_final:
                        raise TrailingCipherstreamError(
                            f"Vault file '{vault_path}' contains unexpected trailing bytes"
                        )

                    ct_len, is_final_int = struct.unpack(CHUNK_FRAME_HEADER_FORMAT, frame)
                    if ct_len < CHUNK_TAG_LENGTH_BYTES:
                        raise VaultAuthenticationError(f"Invalid chunk length {ct_len} at chunk {chunk_idx}")

                    ct_and_tag = f_in.read(ct_len)
                    if len(ct_and_tag) < ct_len:
                        raise IncompleteCipherstreamError(
                            f"Vault file '{vault_path}' truncated in chunk {chunk_idx} payload"
                        )

                    is_final = bool(is_final_int == 1)
                    expected_payload_len = ct_len - CHUNK_TAG_LENGTH_BYTES

                    iv = construct_chunk_iv(header.nonce_prefix, chunk_idx)
                    aad = construct_chunk_aad(
                        header.header_digest, quarantine_id, chunk_idx, expected_payload_len, is_final
                    )

                    try:
                        pt_chunk = aesgcm.decrypt(iv, ct_and_tag, aad)
                    except InvalidTag as exc:
                        raise VaultAuthenticationError(
                            f"AES-GCM authentication failed on chunk {chunk_idx} "
                            "(tampered data or wrong key)"
                        ) from exc

                    if len(pt_chunk) != expected_payload_len:
                        raise VaultAuthenticationError(f"Decrypted length mismatch at chunk {chunk_idx}")

                    f_out.write(pt_chunk)
                    recovered_hasher.update(pt_chunk)
                    total_recovered_bytes += len(pt_chunk)

                    if is_final:
                        encountered_final = True

                    chunk_idx += 1

                trailing = f_in.read(1)
                if trailing:
                    raise TrailingCipherstreamError(f"Trailing garbage in '{vault_path}'")

                f_out.flush()
                os.fsync(f_out.fileno())

            # Verification of recovered data before publication
            if total_recovered_bytes != header.original_size_bytes:
                raise VaultIntegrityError(
                    f"Recovered file size mismatch: expected {header.original_size_bytes}, got {total_recovered_bytes}"
                )

            recovered_sha = recovered_hasher.hexdigest().lower()
            target_expected = expected_sha256.strip().lower() if expected_sha256 else header.sha256_hex
            if recovered_sha != target_expected:
                raise VaultIntegrityError(
                    f"Recovered file SHA-256 mismatch: expected {target_expected}, got {recovered_sha}"
                )

            # Atomic publication: no-clobber by default
            if allow_overwrite:
                os.replace(temp_dest, dest)
            else:
                atomic_publish_no_clobber(temp_dest, dest)

            return dest
        except Exception:
            # Safely clean up unverified plaintext temporary file
            if temp_dest.exists():
                try:
                    temp_dest.unlink()
                except OSError:
                    pass
            raise
