"""Heuristic risk assessment engine for USB Sentinel.

This module evaluates inspected files against heuristic threat detection rules,
such as high-risk execution and scripting extensions commonly utilized in
unauthorized removable media attacks (e.g. autorun payloads, batch scripts,
PowerShell execution vectors, or screensaver PE executables).

Design Decisions (for beginner developers):
1. **Heuristic vs. Malware Distinction**:
   Flagging a file extension is a heuristic indicator of an *execution risk vector*.
   It does NOT prove that a file contains malicious code. Conversely, files without
   flagged extensions are NOT certified as "safe".
2. **Case-Insensitive Matching**:
   Attackers often use mixed or upper-case extensions (e.g. `.BAT`, `.Exe`, `.Ps1`)
   to bypass naive string comparisons. Extensions are always normalized to lowercase.
3. **Double Extension Awareness**:
   Files named with deceptive suffixes (e.g., `document.pdf.exe`) resolve `suffix`
   to `.exe`, correctly matching the executable rule.
4. **Configurable & Extensible**:
   Rules are defined using the `ExtensionRiskRule` structure, allowing new extensions
   or custom severities to be added without modifying the core evaluation algorithm.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable, List, Optional, Set

from usb_sentinel.config import DEFAULT_SUSPICIOUS_EXTENSIONS, SentinelConfig, get_config
from usb_sentinel.models import (
    DetectionMethod,
    FileMetadata,
    RiskFinding,
    RiskSeverity,
    utc_now,
)


@dataclass(frozen=True)
class ExtensionRiskRule:
    """Definition of an extension-based heuristic threat detection rule.

    Attributes:
        rule_id: Unique string identifier for the rule (e.g. 'RULE_SUSPICIOUS_EXTENSION_EXE').
        target_extension: Lowercase extension with leading dot (e.g. '.exe').
        severity: Heuristic risk classification tier.
        description: Plain-English explanation of why this file type poses risk on removable media.
    """

    rule_id: str
    target_extension: str
    severity: RiskSeverity
    description: str

    def __post_init__(self) -> None:
        if not self.target_extension.startswith("."):
            raise ValueError(
                f"target_extension must start with leading dot, got '{self.target_extension}'"
            )
        if self.target_extension != self.target_extension.lower():
            raise ValueError(
                f"target_extension must be lowercase, got '{self.target_extension}'"
            )


# Default extension rules explaining the specific execution risk of each flagged file type
DEFAULT_EXTENSION_RULES: Final[tuple[ExtensionRiskRule, ...]] = (
    ExtensionRiskRule(
        rule_id="RULE_SUSPICIOUS_EXTENSION_EXE",
        target_extension=".exe",
        severity=RiskSeverity.SUSPICIOUS,
        description=(
            "Portable Executable (PE) binary detected on removable media. "
            "Executables can run arbitrary native machine code without script interpreter restrictions."
        ),
    ),
    ExtensionRiskRule(
        rule_id="RULE_SUSPICIOUS_EXTENSION_BAT",
        target_extension=".bat",
        severity=RiskSeverity.SUSPICIOUS,
        description=(
            "Windows Command Prompt batch script detected. "
            "Batch scripts can execute automated administrative commands and invoke secondary payloads."
        ),
    ),
    ExtensionRiskRule(
        rule_id="RULE_SUSPICIOUS_EXTENSION_VBS",
        target_extension=".vbs",
        severity=RiskSeverity.SUSPICIOUS,
        description=(
            "VBScript script file detected. "
            "VBS scripts run via Windows Script Host (wscript/cscript) and are common historical vectors for USB worms."
        ),
    ),
    ExtensionRiskRule(
        rule_id="RULE_SUSPICIOUS_EXTENSION_PS1",
        target_extension=".ps1",
        severity=RiskSeverity.SUSPICIOUS,
        description=(
            "PowerShell script file detected. "
            "PowerShell scripts possess deep operating system access and can download or execute remote commands."
        ),
    ),
    ExtensionRiskRule(
        rule_id="RULE_SUSPICIOUS_EXTENSION_SCR",
        target_extension=".scr",
        severity=RiskSeverity.SUSPICIOUS,
        description=(
            "Windows Screensaver binary detected. "
            "Screensaver files are executable PE binaries that run upon opening, frequently abused to disguise malware."
        ),
    ),
)


class RiskEngine:
    """Heuristic risk evaluation engine for inspected files."""

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        custom_rules: Optional[Iterable[ExtensionRiskRule]] = None,
    ) -> None:
        """Initialize the RiskEngine.

        Args:
            config: Optional application configuration. If omitted, DEFAULT_CONFIG is used.
            custom_rules: Optional custom iterable of ExtensionRiskRule objects.
                          If omitted, DEFAULT_EXTENSION_RULES is used.
        """
        self._config = config or get_config()
        self._rules: dict[str, ExtensionRiskRule] = {}

        if custom_rules is not None:
            for rule in custom_rules:
                self._rules[rule.target_extension.lower()] = rule
        else:
            for rule in DEFAULT_EXTENSION_RULES:
                self._rules[rule.target_extension.lower()] = rule

        # Ensure all configured suspicious extensions have at least a fallback rule
        for ext in self._config.suspicious_extensions:
            ext_clean = ext.lower()
            if ext_clean not in self._rules:
                clean_name = ext_clean.lstrip(".").upper()
                self._rules[ext_clean] = ExtensionRiskRule(
                    rule_id=f"RULE_SUSPICIOUS_EXTENSION_{clean_name}",
                    target_extension=ext_clean,
                    severity=RiskSeverity.SUSPICIOUS,
                    description=(
                        f"Heuristically flagged high-risk file extension '{ext_clean}' on removable media."
                    ),
                )

    @property
    def registered_rules(self) -> tuple[ExtensionRiskRule, ...]:
        """Return all registered risk evaluation rules."""
        return tuple(self._rules.values())

    def evaluate_file(self, metadata: FileMetadata) -> list[RiskFinding]:
        """Evaluate a single file's metadata against heuristic risk rules.

        Args:
            metadata: FileMetadata instance collected by the volume scanner.

        Returns:
            list[RiskFinding]: A list of findings matching the file. Empty if no rules match.
            Note: An empty list indicates no heuristic rules fired; it does NOT certify
            the file is harmless.
        """
        findings: list[RiskFinding] = []
        ext_normalized = metadata.extension.lower()

        # Files without extensions or empty strings will not match extension rules
        if not ext_normalized:
            return findings

        if ext_normalized in self._rules:
            rule = self._rules[ext_normalized]
            finding = RiskFinding(
                file_path=metadata.file_path,
                severity=rule.severity,
                matched_rule=rule.rule_id,
                explanation=rule.description,
                timestamp=utc_now(),
                detection_method=DetectionMethod.EXTENSION_HEURISTIC,
            )
            findings.append(finding)

        return findings
