"""Incident report generation for USB Sentinel (HTML and Plain-Text Formats).

This module generates structured incident and inspection reports following volume
scans and watchdog alerts. Reports capture device telemetry, scan statistics,
heuristic risk findings, error logs, and audit trails.

Security Guarantees:
1. **Strict HTML Escaping**:
   All filesystem-derived strings (filenames, paths, labels, error messages)
   are escaped with `html.escape(..., quote=True)` to eliminate HTML/script injection.
2. **Zero Secret Exposure**:
   Cryptographic keys, passphrases, and sensitive tokens are strictly excluded.
3. **No Fabricated Telemetry**:
   Missing fields are clearly marked as 'UNAVAILABLE' or 'N/A' rather than guessing.
4. **Heuristic Clarification**:
   Reports prominently distinguish heuristic execution vectors from confirmed malware.
5. **Atomic Durability**:
   Reports are written to temporary files and atomically replaced (`os.replace`) to
   prevent corrupted half-written reports.
"""

from __future__ import annotations

import html
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final, List, Optional, Sequence

from usb_sentinel.audit import format_utc_timestamp
from usb_sentinel.config import SentinelConfig, get_config
from usb_sentinel.models import (
    AuditEvent,
    AuditEventType,
    AuditStatus,
    DetectionConfidence,
    DeviceClassification,
    DeviceTelemetry,
    FileMetadata,
    RiskFinding,
    RiskSeverity,
    ScanResult,
    ScanStatus,
    utc_now,
)
from usb_sentinel.scanner import ScanReport

DISCLAIMER_TEXT: Final[str] = (
    "DISCLAIMER: USB Sentinel identifies potential threat vectors heuristically based on "
    "execution/scripting extensions and volume characteristics. Flagging an item indicates "
    "an unverified execution vector on removable media; it does NOT establish proof of "
    "malicious code. Conversely, unflagged files are NOT certified safe. USB Sentinel is a "
    "defensive boundary monitor and quarantine watchdog, not a signature-based antivirus."
)


@dataclass(frozen=True)
class IncidentData:
    """Structured container holding all information needed to compile an incident report."""

    incident_id: str
    generated_at: datetime = field(default_factory=utc_now)
    telemetry: Optional[DeviceTelemetry] = None
    scan_report: Optional[ScanReport] = None
    audit_events: list[AuditEvent] = field(default_factory=list)
    action_taken: str = "ALERT_AND_LOG_ONLY: Logged findings to audit ledger. Source files retained intact."
    recommended_action: str = (
        "Inspect flagged files. If unverified or unauthorized, use CLI Option [3] to quarantine."
    )


class IncidentReportGenerator:
    """Compiles styled HTML and monospace plain-text incident reports."""

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self._config = config or get_config()

    @property
    def config(self) -> SentinelConfig:
        return self._config

    def generate_incident_data(
        self,
        scan_report: Optional[ScanReport] = None,
        telemetry: Optional[DeviceTelemetry] = None,
        audit_events: Optional[Sequence[AuditEvent]] = None,
        incident_id: Optional[str] = None,
        action_taken: Optional[str] = None,
    ) -> IncidentData:
        """Create an IncidentData container from scan and telemetry inputs."""
        inc_id = incident_id or f"INC-{utc_now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        events = list(audit_events) if audit_events else []
        action = action_taken or "ALERT_AND_LOG_ONLY: Recorded findings in audit ledger. No files modified or deleted."

        return IncidentData(
            incident_id=inc_id,
            generated_at=utc_now(),
            telemetry=telemetry,
            scan_report=scan_report,
            audit_events=events,
            action_taken=action,
        )

    def render_text_report(self, data: IncidentData) -> str:
        """Render a clean, monospace plain-text report suitable for console or text logs."""
        sep_double = "=" * 76
        sep_single = "-" * 76

        lines: list[str] = [
            sep_double,
            f"   USB SENTINEL INCIDENT & VOLUME INSPECTION REPORT",
            f"   Incident ID : {data.incident_id}",
            f"   Generated   : {format_utc_timestamp(data.generated_at)}",
            sep_double,
            "",
            "[1] TARGET DEVICE TELEMETRY",
            sep_single,
        ]

        if data.telemetry:
            t = data.telemetry
            lines.extend([
                f" Drive Letter / Path : {t.device_id} ({t.mount_point or 'N/A'})",
                f" Volume Label        : {t.volume_label or 'NO_LABEL'}",
                f" Filesystem          : {t.filesystem or 'UNKNOWN'}",
                f" Classification      : {t.classification.value}",
                f" Bus Type / Model    : {t.bus_type or 'UNKNOWN'} / {t.device_model or 'GENERIC'}",
                f" Detection Confidence: {t.confidence.value} (Backend: {t.detection_backend or 'N/A'})",
                f" Capacity (Free/Tot) : {self._format_bytes(t.free_bytes)} free / {self._format_bytes(t.total_bytes)} total",
            ])
            if t.warning:
                lines.append(f" Telemetry Warning   : {t.warning}")
        else:
            lines.append(" Device telemetry was not provided or unavailable for this session.")

        lines.extend([
            "",
            "[2] VOLUME SCAN EXECUTION SUMMARY",
            sep_single,
        ])

        if data.scan_report:
            res = data.scan_report.result
            lines.extend([
                f" Scan Session ID     : {res.scan_id}",
                f" Target Directory    : {res.target_path}",
                f" Execution Window    : {format_utc_timestamp(res.started_at)} -> {format_utc_timestamp(res.completed_at)}",
                f" Scan Status         : {res.status.value}",
                f" Files Inspected     : {res.files_inspected}",
                f" Flagged Risk Items  : {res.findings_count}",
                f" Scan Error Count    : {res.errors_count}",
            ])
            if res.error_summary:
                lines.append(f" Errors Encountered  : {res.error_summary}")
        else:
            lines.append(" No scan execution report attached to this incident.")

        lines.extend([
            "",
            "[3] HEURISTIC RISK FINDINGS",
            sep_single,
        ])

        findings = data.scan_report.findings if data.scan_report else []
        if findings:
            for idx, f in enumerate(findings, start=1):
                lines.extend([
                    f" Item #{idx:02d}:",
                    f"   File Path   : {f.file_path}",
                    f"   Severity    : {f.severity.value}",
                    f"   Rule ID     : {f.matched_rule}",
                    f"   Explanation : {f.explanation}",
                    f"   Timestamp   : {format_utc_timestamp(f.timestamp)}",
                    "",
                ])
        else:
            lines.append(" No heuristic threat vectors or suspicious execution extensions were flagged.")

        lines.extend([
            "",
            "[4] ACTIONS TAKEN & RECOMMENDATIONS",
            sep_single,
            f" Action Taken   : {data.action_taken}",
            f" Recommendation : {data.recommended_action}",
            "",
            "[5] RELEVANT AUDIT TRAIL ENTRIES",
            sep_single,
        ])

        if data.audit_events:
            for ev in data.audit_events[:15]:
                lines.append(
                    f" [{format_utc_timestamp(ev.timestamp)}] {ev.event_id:<16} {ev.event_type.value:<18} "
                    f"{ev.status.value:<12} {ev.details or ''}"
                )
        else:
            lines.append(" No associated audit ledger events recorded for this report.")

        lines.extend([
            "",
            sep_double,
            " NOTICE & DISCLAIMER:",
            f" {DISCLAIMER_TEXT}",
            sep_double,
            "",
        ])

        return "\n".join(lines)

    def render_html_report(self, data: IncidentData) -> str:
        """Render a modern, standalone HTML5 incident report with strict escaping."""
        esc = lambda val: html.escape(str(val) if val is not None else "N/A", quote=True)

        findings = data.scan_report.findings if data.scan_report else []
        findings_count = len(findings)

        # Telemetry fields
        telem = data.telemetry
        device_label = esc(telem.volume_label if telem else "N/A")
        device_id = esc(telem.device_id if telem else "N/A")
        mount_point = esc(telem.mount_point if telem else "N/A")
        classification = esc(telem.classification.value if telem else "N/A")
        bus_type = esc(telem.bus_type if telem else "N/A")
        confidence = esc(telem.confidence.value if telem else "N/A")

        # Scan report fields
        sr = data.scan_report
        scan_id = esc(sr.result.scan_id if sr else "N/A")
        scan_status = esc(sr.result.status.value if sr else "N/A")
        files_inspected = esc(sr.result.files_inspected if sr else "0")
        scan_errors = esc(sr.result.errors_count if sr else "0")
        target_dir = esc(sr.result.target_path if sr else "N/A")

        # Compile HTML findings rows
        findings_html_rows = []
        if findings:
            for idx, f in enumerate(findings, start=1):
                badge_class = "badge-high" if f.severity == RiskSeverity.HIGH else "badge-warn"
                findings_html_rows.append(f"""
                <tr>
                    <td class="num">{idx}</td>
                    <td><code>{esc(f.file_path)}</code></td>
                    <td><span class="{badge_class}">{esc(f.severity.value)}</span></td>
                    <td><code>{esc(f.matched_rule)}</code></td>
                    <td>{esc(f.explanation)}</td>
                </tr>
                """)
        else:
            findings_html_rows.append("""
            <tr>
                <td colspan="5" class="empty-msg">No suspicious files or execution vectors flagged during inspection.</td>
            </tr>
            """)

        # Compile audit rows
        audit_html_rows = []
        if data.audit_events:
            for ev in data.audit_events[:20]:
                audit_html_rows.append(f"""
                <tr>
                    <td class="timestamp">{esc(format_utc_timestamp(ev.timestamp))}</td>
                    <td><code>{esc(ev.event_id)}</code></td>
                    <td><code>{esc(ev.event_type.value)}</code></td>
                    <td><span class="status-{esc(ev.status.value.lower())}">{esc(ev.status.value)}</span></td>
                    <td>{esc(ev.details or ev.error_message or '')}</td>
                </tr>
                """)
        else:
            audit_html_rows.append("""
            <tr>
                <td colspan="5" class="empty-msg">No audit ledger entries captured for this report.</td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>USB Sentinel Incident Report - {esc(data.incident_id)}</title>
<style>
  :root {{
    --bg-color: #f8fafc;
    --card-bg: #ffffff;
    --border-color: #e2e8f0;
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --accent: #2563eb;
    --danger: #dc2626;
    --warning: #d97706;
    --success: #16a34a;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-color);
    color: var(--text-primary);
    line-height: 1.5;
    margin: 0;
    padding: 24px;
  }}
  .container {{
    max-width: 1000px;
    margin: 0 auto;
  }}
  .header {{
    background: #1e293b;
    color: #ffffff;
    padding: 24px;
    border-radius: 8px;
    margin-bottom: 24px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
  }}
  .header h1 {{ margin: 0 0 8px 0; font-size: 24px; font-weight: 600; letter-spacing: -0.5px; }}
  .header .meta {{ font-size: 14px; color: #94a3b8; display: flex; gap: 24px; flex-wrap: wrap; }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px 0 rgba(0,0,0,0.05);
  }}
  .card h2 {{
    margin: 0 0 16px 0;
    font-size: 18px;
    font-weight: 600;
    border-bottom: 2px solid #f1f5f9;
    padding-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
  }}
  .stat-label {{ font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; }}
  .stat-value {{ font-size: 16px; font-weight: 500; margin-top: 2px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 8px; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }}
  th {{ background: #f8fafc; font-weight: 600; color: var(--text-secondary); }}
  code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; word-break: break-all; }}
  .badge-high {{ background: #fee2e2; color: var(--danger); font-weight: 600; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
  .badge-warn {{ background: #fef3c7; color: var(--warning); font-weight: 600; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
  .status-success {{ color: var(--success); font-weight: 600; }}
  .status-warning {{ color: var(--warning); font-weight: 600; }}
  .status-error {{ color: var(--danger); font-weight: 600; }}
  .status-informational {{ color: var(--accent); font-weight: 600; }}
  .disclaimer {{
    background: #f1f5f9;
    border-left: 4px solid #64748b;
    padding: 12px 16px;
    font-size: 13px;
    color: var(--text-secondary);
    border-radius: 0 4px 4px 0;
    margin-top: 24px;
  }}
  .empty-msg {{ text-align: center; color: var(--text-secondary); padding: 24px 0; font-style: italic; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>USB Sentinel Incident Report</h1>
    <div class="meta">
      <div><strong>Incident ID:</strong> {esc(data.incident_id)}</div>
      <div><strong>Generated:</strong> {esc(format_utc_timestamp(data.generated_at))}</div>
      <div><strong>Watchdog Policy:</strong> ALERT_AND_LOG_ONLY</div>
    </div>
  </div>

  <div class="card">
    <h2>[1] Target Storage Device Telemetry</h2>
    <div class="grid">
      <div>
        <div class="stat-label">Device / Mount</div>
        <div class="stat-value">{device_id} ({mount_point})</div>
      </div>
      <div>
        <div class="stat-label">Volume Label</div>
        <div class="stat-value">{device_label}</div>
      </div>
      <div>
        <div class="stat-label">Classification</div>
        <div class="stat-value">{classification}</div>
      </div>
      <div>
        <div class="stat-label">Physical Bus</div>
        <div class="stat-value">{bus_type}</div>
      </div>
      <div>
        <div class="stat-label">Detection Confidence</div>
        <div class="stat-value">{confidence}</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>[2] Volume Scan Summary</h2>
    <div class="grid">
      <div>
        <div class="stat-label">Scan Status</div>
        <div class="stat-value">{scan_status}</div>
      </div>
      <div>
        <div class="stat-label">Files Inspected</div>
        <div class="stat-value">{files_inspected}</div>
      </div>
      <div>
        <div class="stat-label">Flagged Risk Items</div>
        <div class="stat-value">{findings_count}</div>
      </div>
      <div>
        <div class="stat-label">Scan Errors</div>
        <div class="stat-value">{scan_errors}</div>
      </div>
      <div>
        <div class="stat-label">Target Root</div>
        <div class="stat-value"><code>{target_dir}</code></div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>[3] Heuristic Risk Findings ({findings_count})</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 40px;">#</th>
          <th>Flagged File Path</th>
          <th style="width: 100px;">Severity</th>
          <th style="width: 220px;">Rule Identifier</th>
          <th>Risk Explanation</th>
        </tr>
      </thead>
      <tbody>
        {"".join(findings_html_rows)}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>[4] Actions & Recommendations</h2>
    <p><strong>Action Taken:</strong> {esc(data.action_taken)}</p>
    <p><strong>Recommended Next Steps:</strong> {esc(data.recommended_action)}</p>
  </div>

  <div class="card">
    <h2>[5] Audit Trail Highlights</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 180px;">Timestamp (UTC)</th>
          <th style="width: 140px;">Event ID</th>
          <th style="width: 180px;">Event Type</th>
          <th style="width: 100px;">Status</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {"".join(audit_html_rows)}
      </tbody>
    </table>
  </div>

  <div class="disclaimer">
    <strong>Security Notice &amp; Disclaimer:</strong><br>
    {esc(DISCLAIMER_TEXT)}
  </div>
</div>
</body>
</html>
"""
        return html_content

    def save_reports(
        self,
        data: IncidentData,
        destination_dir: Optional[Path] = None,
    ) -> tuple[Path, Path]:
        """Compile and atomically write both HTML and TXT incident reports.

        Args:
            data: IncidentData to compile.
            destination_dir: Directory to save reports (defaults to config.reports_dir).

        Returns:
            tuple[Path, Path]: Paths to the created (html_path, txt_path).

        Raises:
            OSError: On filesystem write or directory creation failure.
        """
        out_dir = destination_dir or self._config.reports_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        base_stem = f"incident_{data.incident_id}"
        html_file = out_dir / f"{base_stem}.html"
        txt_file = out_dir / f"{base_stem}.txt"

        html_text = self.render_html_report(data)
        txt_text = self.render_text_report(data)

        # Atomic publication using unique temporary files
        self._atomic_write(html_file, html_text.encode("utf-8"))
        self._atomic_write(txt_file, txt_text.encode("utf-8"))

        return html_file, txt_file

    def _atomic_write(self, target_path: Path, data_bytes: bytes) -> None:
        """Write bytes to a unique temporary file and atomically replace target."""
        parent_dir = target_path.parent
        parent_dir.mkdir(parents=True, exist_ok=True)

        fd, temp_path = tempfile.mkstemp(
            prefix=".rep_",
            suffix=".tmp",
            dir=parent_dir,
        )
        try:
            with open(fd, "wb") as f:
                f.write(data_bytes)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, target_path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _format_bytes(byte_count: Optional[int]) -> str:
        """Format raw byte counts to human-readable string (e.g. 14.5 GB)."""
        if byte_count is None:
            return "N/A"
        if byte_count < 1024:
            return f"{byte_count} B"
        elif byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.1f} KB"
        elif byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.1f} MB"
        else:
            return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"
