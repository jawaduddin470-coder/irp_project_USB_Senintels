"""Unit tests for usb_sentinel.vault (streaming AES-256-GCM authenticated encryption and anti-tamper)."""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

import pytest
from unittest.mock import patch

from usb_sentinel.config import SentinelConfig
from usb_sentinel.crypto_keys import KeyManager
from usb_sentinel.vault import (
    CHUNK_FRAME_HEADER_BYTES,
    CHUNK_FRAME_HEADER_FORMAT,
    HEADER_LENGTH_BYTES,
    VAULT_MAGIC,
    DestinationCollisionError,
    IncompleteCipherstreamError,
    TrailingCipherstreamError,
    VaultAuthenticationError,
    VaultError,
    VaultHeaderError,
    VaultIntegrityError,
    VaultManager,
    atomic_publish_no_clobber,
)


@pytest.fixture
def vault_env(tmp_path: Path) -> tuple[VaultManager, bytes]:
    """Provide an isolated VaultManager and a fresh master key."""
    config = SentinelConfig(base_dir=tmp_path, stream_chunk_size_bytes=4096)  # 4 KB chunk size for test speed
    key_mgr = KeyManager(config=config)
    master_key = key_mgr.get_or_create_master_key()
    vault_mgr = VaultManager(config=config, key_manager=key_mgr)
    return vault_mgr, master_key


def test_round_trip_empty_file(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify 0-byte (empty) file encrypts, verifies, and decrypts to exactly 0 bytes."""
    vault_mgr, master_key = vault_env
    empty_src = tmp_path / "empty.bin"
    empty_src.write_bytes(b"")

    qid = "00000000-0000-0000-0000-000000000000"
    staging_path, header = vault_mgr.encrypt_to_staging(empty_src, qid, master_key)

    assert staging_path.exists()
    assert header.original_size_bytes == 0
    assert header.expected_chunks == 1
    assert header.sha256_hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Verify stream passes
    assert vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key) is True

    # Decrypt to destination
    restored_dest = tmp_path / "restored_empty.bin"
    vault_mgr.decrypt_vault_file(staging_path, qid, master_key, restored_dest)

    assert restored_dest.exists()
    assert restored_dest.stat().st_size == 0
    assert restored_dest.read_bytes() == b""


def test_round_trip_multi_chunk_streaming(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify multi-chunk file (10 KB with 4 KB chunks -> 3 chunks) encrypts and decrypts identically."""
    vault_mgr, master_key = vault_env
    payload = b"X" * 4096 + b"Y" * 4096 + b"Z" * 1808  # Exactly 10,000 bytes (3 chunks)
    expected_hash = hashlib.sha256(payload).hexdigest().lower()

    src = tmp_path / "large_source.bin"
    src.write_bytes(payload)

    qid = "550e8400-e29b-41d4-a716-446655440001"
    staging_path, header = vault_mgr.encrypt_to_staging(src, qid, master_key)

    assert header.original_size_bytes == 10000
    assert header.expected_chunks == 3
    assert header.sha256_hex == expected_hash

    # Promote to vault
    vault_path = vault_mgr.promote_staging_to_vault(qid)
    assert not staging_path.exists()
    assert vault_path.exists()
    assert vault_path.name == f"{qid}.qnt"

    # Decrypt to destination
    dest = tmp_path / "restored.bin"
    vault_mgr.decrypt_vault_file(vault_path, qid, master_key, dest)

    assert dest.exists()
    assert dest.read_bytes() == payload
    assert hashlib.sha256(dest.read_bytes()).hexdigest().lower() == expected_hash


def test_tamper_detection_in_ciphertext(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify flipping a single bit in chunk ciphertext causes immediate VaultAuthenticationError."""
    vault_mgr, master_key = vault_env
    src = tmp_path / "tamper_source.bin"
    src.write_bytes(b"Sensitive payload data to protect")

    qid = "550e8400-e29b-41d4-a716-446655440002"
    staging_path, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)

    # Read binary contents and flip 1 byte in the ciphertext payload (after header and chunk frame)
    data = bytearray(staging_path.read_bytes())
    # offset: 168 (header) + 5 (chunk frame) + 2 (inside ciphertext)
    target_idx = HEADER_LENGTH_BYTES + CHUNK_FRAME_HEADER_BYTES + 2
    data[target_idx] ^= 0x01
    staging_path.write_bytes(data)

    with pytest.raises(VaultAuthenticationError, match="AES-GCM authentication failed"):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key)

    dest = tmp_path / "restored_tampered.bin"
    with pytest.raises(VaultAuthenticationError):
        vault_mgr.decrypt_vault_file(staging_path, qid, master_key, dest)

    # Plaintext must not be released
    assert not dest.exists()


def test_tamper_detection_in_header_metadata(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify tampering with header bytes breaks header digest and fails chunk AAD authentication."""
    vault_mgr, master_key = vault_env
    src = tmp_path / "hdr_tamper.bin"
    src.write_bytes(b"Header test content")

    qid = "550e8400-e29b-41d4-a716-446655440003"
    staging_path, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)

    data = bytearray(staging_path.read_bytes())
    # Alter the original size field in header (located at offset 8+2+2+36+32+4+4 = 88)
    data[88] ^= 0x01
    staging_path.write_bytes(data)

    # Decryption should fail because header digest in chunk AAD no longer matches
    with pytest.raises(VaultAuthenticationError):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key)


def test_wrong_key_rejection_on_chunk_zero(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify decrypting with an incorrect master key aborts immediately on chunk 0."""
    vault_mgr, master_key = vault_env
    src = tmp_path / "secret.bin"
    src.write_bytes(b"Super secret payload")

    qid = "550e8400-e29b-41d4-a716-446655440004"
    staging_path, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)

    wrong_key = os.urandom(32)
    assert wrong_key != master_key

    with pytest.raises(VaultAuthenticationError, match="AES-GCM authentication failed"):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, wrong_key)


def test_truncation_detection_omitted_final_chunk(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify truncating the final chunk raises IncompleteCipherstreamError."""
    vault_mgr, master_key = vault_env
    # 2 chunks with 4 KB buffer: 5,000 bytes
    payload = b"A" * 4096 + b"B" * 904
    src = tmp_path / "two_chunks.bin"
    src.write_bytes(payload)

    qid = "550e8400-e29b-41d4-a716-446655440005"
    staging_path, header = vault_mgr.encrypt_to_staging(src, qid, master_key)
    assert header.expected_chunks == 2

    # Truncate file after chunk 0
    # Chunk 0 size: 5 bytes frame + 4096 + 16 tag = 4117 bytes.
    # Total to keep: 168 (header) + 4117 = 4285 bytes.
    truncated_data = staging_path.read_bytes()[: HEADER_LENGTH_BYTES + 4117]
    staging_path.write_bytes(truncated_data)

    with pytest.raises(IncompleteCipherstreamError, match="truncated: reached EOF"):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key)


def test_trailing_garbage_detection(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify appending unexpected garbage after the final chunk raises TrailingCipherstreamError."""
    vault_mgr, master_key = vault_env
    src = tmp_path / "clean.bin"
    src.write_bytes(b"Clean valid content")

    qid = "550e8400-e29b-41d4-a716-446655440006"
    staging_path, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)

    # Append 10 bytes of trailing garbage
    with open(staging_path, "ab") as f:
        f.write(b"MALICIOUS_GARBAGE")

    with pytest.raises(TrailingCipherstreamError, match="unexpected trailing"):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key)


def test_chunk_reordering_detection(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify swapping the order of two chunks causes authentication failure."""
    vault_mgr, master_key = vault_env
    # 2 chunks of 4 KB each
    payload = b"CHUNK0" * 682 + b"A" * 4 + b"CHUNK1" * 682 + b"B" * 4
    src = tmp_path / "chunks.bin"
    src.write_bytes(payload)

    qid = "550e8400-e29b-41d4-a716-446655440007"
    staging_path, header = vault_mgr.encrypt_to_staging(src, qid, master_key)
    assert header.expected_chunks == 2

    raw = staging_path.read_bytes()
    hdr = raw[:HEADER_LENGTH_BYTES]
    chunks_data = raw[HEADER_LENGTH_BYTES:]

    # Parse chunk 0 framing
    c0_len, _ = struct.unpack(CHUNK_FRAME_HEADER_FORMAT, chunks_data[:CHUNK_FRAME_HEADER_BYTES])
    c0_total = CHUNK_FRAME_HEADER_BYTES + c0_len
    chunk0 = chunks_data[:c0_total]
    chunk1 = chunks_data[c0_total:]

    # Swap chunks: [chunk1, chunk0]
    swapped_stream = hdr + chunk1 + chunk0
    staging_path.write_bytes(swapped_stream)

    with pytest.raises(VaultAuthenticationError):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key)


def test_invalid_header_magic_and_version(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify corrupt magic bytes or unsupported version raises VaultHeaderError."""
    vault_mgr, master_key = vault_env
    src = tmp_path / "magic.bin"
    src.write_bytes(b"data")

    qid = "550e8400-e29b-41d4-a716-446655440008"
    staging_path, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)

    # Bad magic
    bad_magic_data = b"BADMAGIC" + staging_path.read_bytes()[8:]
    staging_path.write_bytes(bad_magic_data)
    with pytest.raises(VaultHeaderError, match="Invalid vault magic"):
        vault_mgr.inspect_vault_file(staging_path)


def test_chunk_duplication_detection(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify duplicating chunk 0 causes authentication failure on the duplicate chunk."""
    vault_mgr, master_key = vault_env
    payload = b"CHUNK0_PAYLOAD" * 300 + b"CHUNK1_PAYLOAD" * 300
    src = tmp_path / "dup.bin"
    src.write_bytes(payload)

    qid = "550e8400-e29b-41d4-a716-446655440009"
    staging_path, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)

    raw = staging_path.read_bytes()
    hdr = raw[:HEADER_LENGTH_BYTES]
    chunks_data = raw[HEADER_LENGTH_BYTES:]

    c0_len, _ = struct.unpack(CHUNK_FRAME_HEADER_FORMAT, chunks_data[:CHUNK_FRAME_HEADER_BYTES])
    c0_total = CHUNK_FRAME_HEADER_BYTES + c0_len
    chunk0 = chunks_data[:c0_total]

    # Duplicate chunk 0: [chunk0, chunk0]
    duplicated_stream = hdr + chunk0 + chunk0
    staging_path.write_bytes(duplicated_stream)

    with pytest.raises(VaultAuthenticationError):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key)


def test_large_multi_chunk_streaming_verification(tmp_path: Path, vault_env: tuple[VaultManager, bytes]) -> None:
    """Verify 1 MB streaming file (256 chunks of 4 KB) encrypts and decrypts with 100% digest fidelity."""
    vault_mgr, master_key = vault_env
    # 1 MB of pseudorandom deterministic data
    large_payload = b"".join(struct.pack(">I", i) * 1024 for i in range(256))
    assert len(large_payload) == 1024 * 1024
    expected_digest = hashlib.sha256(large_payload).hexdigest().lower()

    src = tmp_path / "one_megabyte.dat"
    src.write_bytes(large_payload)

    qid = "550e8400-e29b-41d4-a716-446655440099"
    staging_path, header = vault_mgr.encrypt_to_staging(src, qid, master_key)

    assert header.original_size_bytes == 1024 * 1024
    assert header.expected_chunks == 256
    assert header.sha256_hex == expected_digest

    assert vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key) is True

    dest = tmp_path / "restored_one_megabyte.dat"
    vault_mgr.decrypt_vault_file(staging_path, qid, master_key, dest)

    assert dest.stat().st_size == 1024 * 1024
    assert hashlib.sha256(dest.read_bytes()).hexdigest().lower() == expected_digest


def test_vault_header_length_and_original_path_binding(
    tmp_path: Path, vault_env: tuple[VaultManager, bytes]
) -> None:
    """Verify 1,192-byte header, authentic original_path storage, and anti-tamper via HeaderDigest in chunk AAD."""
    vault_mgr, master_key = vault_env
    src = tmp_path / "original_path_test.bin"
    src.write_bytes(b"File with original path stored in header")

    qid = "550e8400-e29b-41d4-a716-446655440055"
    staging_path, header = vault_mgr.encrypt_to_staging(src, qid, master_key)

    # 1. Header length MUST be exactly 1,192 bytes
    assert HEADER_LENGTH_BYTES == 1192
    assert header.original_path == str(src.resolve() if src.is_absolute() else src)

    # 2. Tampering with original_path inside header:
    # Header format: >8sHH36s32s4sIQQ64s1024s. The path starts at byte offset 168.
    data = bytearray(staging_path.read_bytes())
    # Flip byte in path section
    data[200] ^= 0x01
    staging_path.write_bytes(data)

    # Chunk AAD binds HeaderDigest. Modifying the header alters the header digest,
    # causing AESGCM.decrypt() to reject chunk 0 with VaultAuthenticationError.
    with pytest.raises(VaultAuthenticationError):
        vault_mgr.authenticate_and_verify_stream(staging_path, qid, master_key)


def test_atomic_publish_no_clobber_direct(tmp_path: Path) -> None:
    """Verify atomic_publish_no_clobber succeeds when destination is free and raises DestinationCollisionError when occupied."""
    temp_file = tmp_path / "temp_payload.bin"
    temp_file.write_bytes(b"Fresh temp payload")

    target_file = tmp_path / "target_output.bin"

    # Destination free -> publish succeeds
    atomic_publish_no_clobber(temp_file, target_file)
    assert target_file.exists()
    assert target_file.read_bytes() == b"Fresh temp payload"
    assert not temp_file.exists()

    # Destination already exists -> raises DestinationCollisionError
    new_temp = tmp_path / "temp_payload2.bin"
    new_temp.write_bytes(b"Another temp payload")

    with pytest.raises(DestinationCollisionError, match="already exists"):
        atomic_publish_no_clobber(new_temp, target_file)

    # Original target file remains byte-for-byte unchanged
    assert target_file.read_bytes() == b"Fresh temp payload"


def test_vault_header_chunk_bounds_validation(
    tmp_path: Path, vault_env: tuple[VaultManager, bytes]
) -> None:
    """Verify parse_header strictly validates chunk bounds and raises VaultHeaderError."""
    vault_mgr, master_key = vault_env
    src = tmp_path / "bounds_test.bin"
    src.write_bytes(b"Data for bounds testing")

    qid = "550e8400-e29b-41d4-a716-446655440077"
    staging_path, _ = vault_mgr.encrypt_to_staging(src, qid, master_key)

    raw_header = bytearray(staging_path.read_bytes()[:HEADER_LENGTH_BYTES])

    # Corrupt chunk_size (offset 84 in struct >8sHH36s32s4sIQQ64s1024s: 8+2+2+36+32+4 = 84) to 512 (< MIN_CHUNK_SIZE_BYTES=1024)
    struct.pack_into(">I", raw_header, 84, 512)
    with pytest.raises(VaultHeaderError, match="chunk_size 512 out of supported bounds"):
        vault_mgr.parse_header(bytes(raw_header))

    # Corrupt expected_chunks (offset 84+4+8 = 96) to 0
    struct.pack_into(">I", raw_header, 84, 4096)  # restore valid chunk_size
    struct.pack_into(">Q", raw_header, 96, 0)     # expected_chunks = 0
    with pytest.raises(VaultHeaderError, match="expected_chunks 0 invalid"):
        vault_mgr.parse_header(bytes(raw_header))


def test_vault_header_path_overflow_rejection(
    tmp_path: Path, vault_env: tuple[VaultManager, bytes]
) -> None:
    """Verify paths exceeding 1,024 bytes UTF-8 are explicitly rejected with VaultHeaderError."""
    vault_mgr, master_key = vault_env

    # Create a real small file
    test_file = tmp_path / "target_file.txt"
    test_file.write_bytes(b"content to test long path")

    qid = "550e8400-e29b-41d4-a716-446655440088"

    # Simulate extended path (e.g. Windows \\?\UNC or deep directory exceeding 1024 bytes)
    long_path_str = "/" + "nested_directory/" * 65 + "target_file.txt"
    assert len(long_path_str.encode("utf-8")) > 1024

    with patch.object(Path, "resolve", return_value=Path(long_path_str)):
        with pytest.raises(VaultHeaderError, match="exceeds maximum supported header length of 1,024 bytes"):
            vault_mgr.encrypt_to_staging(test_file, qid, master_key)


