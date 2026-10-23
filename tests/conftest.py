"""Pytest configuration and shared fixtures for USB Sentinel tests."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

import pytest

from usb_sentinel.config import SentinelConfig


@pytest.fixture
def sample_utc_time() -> datetime:
    """Provide a fixed, timezone-aware UTC datetime for predictable testing."""
    return datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def isolated_config(tmp_path: Path) -> SentinelConfig:
    """Provide an isolated SentinelConfig rooted in a temporary test directory."""
    return SentinelConfig(base_dir=tmp_path)


@pytest.fixture
def mock_clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure environment variables do not leak developer-specific paths into tests."""
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
