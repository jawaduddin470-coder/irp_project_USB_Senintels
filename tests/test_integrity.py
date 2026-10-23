"""Unit tests for usb_sentinel.integrity (streaming SHA-256 calculation and stability)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from usb_sentinel.integrity import (
    FileIntegrityUnstableError,
    IntegrityCancelledError,
    IntegrityIOError,
    InvalidTargetError,
    SymlinkNotPermittedError,
    compute_sha256,
    verify_sha256,
)


def test_sha256_known_test_vectors(tmp_path: Path) -> None:
    """Verify SHA-256 against official NIST/FIPS test vectors."""
    vectors = [
        # (content, expected_sha256)
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        ),
    ]

    for content, expected in vectors:
        test_file = tmp_path / f"vec_{len(content)}.dat"
        test_file.write_bytes(content)
        digest = compute_sha256(test_file)
        assert digest == expected
        assert verify_sha256(test_file, expected) is True
        assert verify_sha256(test_file, expected.upper()) is True  # Case-insensitive


def test_sha256_multi_chunk_streaming(tmp_path: Path) -> None:
    """Verify incremental streaming across multiple chunks matches full-content digest."""
    import hashlib

    # 100 KB payload with arbitrary bytes
    payload = b"A" * 30000 + b"B" * 40000 + b"C" * 30000 + b"\x00\xFF" * 1200
    expected = hashlib.sha256(payload).hexdigest()

    test_file = tmp_path / "large_chunked.bin"
    test_file.write_bytes(payload)

    # Use small 4 KB chunk size to force ~25 read iterations
    digest = compute_sha256(test_file, chunk_size_bytes=4096)
    assert digest == expected


def test_sha256_unicode_filenames_and_spaces(tmp_path: Path) -> None:
    """Verify hashing handles Unicode and spaces in filenames."""
    test_file = tmp_path / "русский файл с пробелами 🚀.dat"
    test_content = b"unicode content 123"
    test_file.write_bytes(test_content)

    import hashlib
    expected_hash = hashlib.sha256(test_content).hexdigest()

    digest = compute_sha256(test_file)
    assert len(digest) == 64
    assert digest == expected_hash


def test_sha256_raises_on_nonexistent_file(tmp_path: Path) -> None:
    """Verify FileNotFoundError is raised when target does not exist."""
    missing = tmp_path / "not_there.bin"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        compute_sha256(missing)


def test_sha256_raises_on_directory_target(tmp_path: Path) -> None:
    """Verify InvalidTargetError is raised when given a directory."""
    dir_path = tmp_path / "sub_directory"
    dir_path.mkdir()
    with pytest.raises(InvalidTargetError, match="directory"):
        compute_sha256(dir_path)


def test_sha256_raises_on_symlink_under_strict_policy(tmp_path: Path) -> None:
    """Verify SymlinkNotPermittedError is raised for symlinks when follow_symlinks=False."""
    target_file = tmp_path / "real.txt"
    target_file.write_text("real content", encoding="utf-8")

    link_path = tmp_path / "symlink_to_real.txt"
    try:
        link_path.symlink_to(target_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not supported in this test environment.")

    # With follow_symlinks=False (default)
    with pytest.raises(SymlinkNotPermittedError, match="symbolic link"):
        compute_sha256(link_path, follow_symlinks=False)

    # With follow_symlinks=True
    digest = compute_sha256(link_path, follow_symlinks=True)
    assert digest == compute_sha256(target_file)


def test_sha256_detects_mid_hash_file_mutation(tmp_path: Path) -> None:
    """Verify FileIntegrityUnstableError is raised if file size or mtime changes during hashing."""
    test_file = tmp_path / "unstable.dat"
    test_file.write_bytes(b"initial data")

    orig_stat = Path.stat
    call_count = 0

    def mock_stat(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        res = orig_stat(self, *args, **kwargs)
        if call_count > 1:
            # Simulate file size or timestamp change upon post-hash stat
            mocked = MagicMock(wraps=res)
            mocked.st_size = res.st_size + 10  # Size altered
            mocked.st_mtime_ns = res.st_mtime_ns + 5000
            return mocked
        return res

    with patch.object(Path, "stat", mock_stat):
        with pytest.raises(FileIntegrityUnstableError, match="modified during integrity hashing"):
            compute_sha256(test_file)


def test_sha256_non_destructive_guarantee(tmp_path: Path) -> None:
    """Verify compute_sha256 does not alter source file content, size, or timestamps."""
    test_file = tmp_path / "untouched.bin"
    original_bytes = b"Sample Binary Content That Must Remain Completely Intact"
    test_file.write_bytes(original_bytes)

    stat_before = test_file.stat()
    digest = compute_sha256(test_file)

    stat_after = test_file.stat()
    assert test_file.read_bytes() == original_bytes
    assert stat_before.st_size == stat_after.st_size
    assert stat_before.st_mtime_ns == stat_after.st_mtime_ns


def test_sha256_invalid_chunk_size(tmp_path: Path) -> None:
    """Verify ValueError is raised if chunk_size_bytes is non-positive."""
    test_file = tmp_path / "f.dat"
    test_file.write_bytes(b"data")
    with pytest.raises(ValueError, match="must be positive"):
        compute_sha256(test_file, chunk_size_bytes=0)


def test_verify_sha256_digest_validation_and_comparison(tmp_path: Path) -> None:
    """Verify verify_sha256 validates format strictly and performs accurate comparison."""
    test_file = tmp_path / "target.bin"
    test_file.write_bytes(b"hello world")
    valid_matching = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    valid_non_matching = "0000000000000000000000000000000000000000000000000000000000000000"

    # Matching digest
    assert verify_sha256(test_file, valid_matching) is True
    # Non-matching valid digest
    assert verify_sha256(test_file, valid_non_matching) is False

    # Invalid formats: length != 64, non-hex, or non-string
    with pytest.raises(ValueError, match="Invalid expected SHA-256 digest format"):
        verify_sha256(test_file, "too_short")

    with pytest.raises(ValueError, match="Invalid expected SHA-256 digest format"):
        verify_sha256(test_file, "a" * 63)

    with pytest.raises(ValueError, match="Invalid expected SHA-256 digest format"):
        verify_sha256(test_file, "a" * 65)

    with pytest.raises(ValueError, match="Invalid expected SHA-256 digest format"):
        verify_sha256(test_file, "g" * 64)  # 'g' is non-hex

    with pytest.raises(ValueError, match="expected_digest must be a string"):
        verify_sha256(test_file, 123456789)  # type: ignore[arg-type]


def test_compute_sha256_cancellation(tmp_path: Path) -> None:
    """Verify compute_sha256 aborts promptly when cancellation signal is set."""
    test_file = tmp_path / "large_cancellable.bin"
    # Write 256 KB file so it requires multiple 64 KB chunks
    test_file.write_bytes(b"A" * (256 * 1024))

    call_count = 0

    def cancel_after_one_chunk() -> bool:
        nonlocal call_count
        call_count += 1
        return call_count > 1

    with pytest.raises(IntegrityCancelledError, match="cancellation signal"):
        compute_sha256(test_file, chunk_size_bytes=64 * 1024, is_cancelled=cancel_after_one_chunk)

