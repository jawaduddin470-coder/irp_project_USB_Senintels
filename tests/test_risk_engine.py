"""Unit tests for usb_sentinel.risk_engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from usb_sentinel.models import FileMetadata, RiskSeverity
from usb_sentinel.risk_engine import (
    DEFAULT_EXTENSION_RULES,
    ExtensionRiskRule,
    RiskEngine,
)


@pytest.fixture
def risk_engine() -> RiskEngine:
    return RiskEngine()


def make_metadata(filename: str, size: int = 100) -> FileMetadata:
    p = Path(filename)
    return FileMetadata(
        filename=p.name,
        file_path=str(p),
        extension=p.suffix.lower(),
        size_bytes=size,
        modified_at=datetime.now(timezone.utc),
    )


def test_matching_standard_extensions(risk_engine: RiskEngine) -> None:
    """Verify all five mandated suspicious extensions produce expected heuristic findings."""
    test_cases = [
        ("payload.exe", "RULE_SUSPICIOUS_EXTENSION_EXE"),
        ("setup.bat", "RULE_SUSPICIOUS_EXTENSION_BAT"),
        ("worm.vbs", "RULE_SUSPICIOUS_EXTENSION_VBS"),
        ("invoke.ps1", "RULE_SUSPICIOUS_EXTENSION_PS1"),
        ("screensaver.scr", "RULE_SUSPICIOUS_EXTENSION_SCR"),
    ]
    for filename, expected_rule in test_cases:
        meta = make_metadata(filename)
        findings = risk_engine.evaluate_file(meta)
        assert len(findings) == 1, f"Expected 1 finding for {filename}"
        assert findings[0].matched_rule == expected_rule
        assert findings[0].severity == RiskSeverity.SUSPICIOUS
        assert findings[0].file_path == str(Path(filename))
        # Ensure explanation contains non-empty context
        assert len(findings[0].explanation) > 10


def test_case_insensitive_matching(risk_engine: RiskEngine) -> None:
    """Verify that uppercase and mixed-case extensions match properly."""
    cases = [
        "PAYLOAD.EXE",
        "script.BAT",
        "helper.VbS",
        "task.Ps1",
        "screen.SCR",
    ]
    for filename in cases:
        meta = make_metadata(filename)
        findings = risk_engine.evaluate_file(meta)
        assert len(findings) == 1, f"Failed case-insensitive match for {filename}"


def test_non_matching_extensions_produce_no_findings(risk_engine: RiskEngine) -> None:
    """Verify benign extensions produce no findings and are not labeled safe."""
    benign_files = [
        "document.txt",
        "report.pdf",
        "data.csv",
        "image.png",
        "archive.zip",
        "notes.md",
    ]
    for filename in benign_files:
        meta = make_metadata(filename)
        findings = risk_engine.evaluate_file(meta)
        assert findings == []


def test_extensionless_files(risk_engine: RiskEngine) -> None:
    """Verify files without an extension do not raise errors and produce no findings."""
    meta = make_metadata("README")
    assert meta.extension == ""
    findings = risk_engine.evaluate_file(meta)
    assert findings == []


def test_double_extensions(risk_engine: RiskEngine) -> None:
    """Verify deceptive double extensions match the actual executable suffix."""
    meta = make_metadata("Invoice_2026.pdf.exe")
    assert meta.extension == ".exe"
    findings = risk_engine.evaluate_file(meta)
    assert len(findings) == 1
    assert findings[0].matched_rule == "RULE_SUSPICIOUS_EXTENSION_EXE"


def test_custom_rules_initialization() -> None:
    """Verify RiskEngine accepts custom rules and enforces validation."""
    custom = [
        ExtensionRiskRule(
            rule_id="RULE_CUSTOM_CMD",
            target_extension=".cmd",
            severity=RiskSeverity.HIGH,
            description="Custom command script rule.",
        )
    ]
    engine = RiskEngine(custom_rules=custom)
    meta = make_metadata("run.cmd")
    findings = engine.evaluate_file(meta)
    assert len(findings) == 1
    assert findings[0].matched_rule == "RULE_CUSTOM_CMD"
    assert findings[0].severity == RiskSeverity.HIGH


def test_extension_rule_validation() -> None:
    """Verify ExtensionRiskRule rejects missing leading dots or uppercase extensions."""
    with pytest.raises(ValueError, match="leading dot"):
        ExtensionRiskRule("R1", "exe", RiskSeverity.SUSPICIOUS, "desc")

    with pytest.raises(ValueError, match="must be lowercase"):
        ExtensionRiskRule("R2", ".EXE", RiskSeverity.SUSPICIOUS, "desc")
