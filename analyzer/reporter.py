"""
reporter.py
Generates analysis reports in multiple formats: text, JSON, CSV, HTML.
"""

from __future__ import annotations

import csv
import json
import io
from datetime import datetime
from typing import List, Dict, Optional

from analyzer.anomaly_detector import Anomaly, Severity, AnomalyDetector, IPStats


# ─── Severity colours (ANSI) ──────────────────────────────────────────────────

_ANSI = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH:     "\033[0;31m",  # red
    Severity.MEDIUM:   "\033[0;33m",  # yellow
    Severity.LOW:      "\033[0;36m",  # cyan
    "RESET":           "\033[0m",
    "BOLD":            "\033[1m",
    "DIM":             "\033[2m",
}


def _coloured(text: str, sev: Severity) -> str:
    return f"{_ANSI[sev]}{text}{_ANSI['RESET']}"


# ─── Text / Terminal Reporter ─────────────────────────────────────────────────

class TextReporter:
    def __init__(self, use_colour: bool = True):
        self.use_colour = use_colour

    def render(
        self,
        anomalies: List[Anomaly],
        summary: dict,
        stats: Optional[Dict[str, IPStats]] = None,
        source_files: Optional[List[str]] = None,
    ) -> str:
        lines = []
        B = _ANSI["BOLD"]
        D = _ANSI["DIM"]
        R = _ANSI["RESET"]

        # ── Header ────────────────────────────────────────────────────────────
        lines.append(f"\n{B}{'═'*65}{R}")
        lines.append(f"{B}  🔍 LOG ANALYSIS REPORT  –  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}")
        lines.append(f"{B}{'═'*65}{R}")

        if source_files:
            lines.append(f"{D}  Files: {', '.join(source_files)}{R}")

        # ── Overview ──────────────────────────────────────────────────────────
        lines.append(f"\n{B}OVERVIEW{R}")
        lines.append(f"  Entries processed : {summary['total_entries_processed']:,}")
        lines.append(f"  Unique IPs        : {summary['unique_ips']:,}")
        lines.append(f"  Anomalies found   : {summary['total_anomalies']:,}")

        # Severity breakdown
        sev_map = summary.get("by_severity", {})
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_map.get(sev, 0)
            if count:
                label = _coloured(f"  {sev:<10}", Severity[sev]) if self.use_colour else f"  {sev:<10}"
                lines.append(f"{label}: {count}")

        # ── Top Offenders ─────────────────────────────────────────────────────
        top = summary.get("top_offenders", [])
        if top:
            lines.append(f"\n{B}TOP OFFENDERS{R}")
            lines.append(f"  {'IP':<18} {'Risk':>5}  {'Anomaly Types'}")
            lines.append(f"  {'─'*17} {'─'*5}  {'─'*30}")
            for o in top:
                types = ", ".join(o["anomaly_types"])
                lines.append(f"  {o['ip']:<18} {o['risk_score']:>5}  {types}")

        # ── Anomaly Details ───────────────────────────────────────────────────
        if anomalies:
            lines.append(f"\n{B}ANOMALY DETAILS{R}")
            lines.append(f"  {'SEV':<10} {'TYPE':<22} {'IP':<18} DESCRIPTION")
            lines.append(f"  {'─'*9} {'─'*21} {'─'*17} {'─'*30}")
            for a in anomalies:
                sev_str = f"[{a.severity.value}]"
                if self.use_colour:
                    sev_str = _coloured(sev_str, a.severity)
                lines.append(
                    f"  {sev_str:<10} {a.anomaly_type.value:<22} {a.ip:<18} {a.description}"
                )
                # Evidence (compact)
                for k, v in a.evidence.items():
                    val_str = str(v)[:80]
                    lines.append(f"  {D}           {'':22} {'':18} ↳ {k}: {val_str}{R}")

        else:
            lines.append(f"\n  ✅  No anomalies detected.")

        lines.append(f"\n{B}{'═'*65}{R}\n")
        return "\n".join(lines)


# ─── JSON Reporter ────────────────────────────────────────────────────────────

class JSONReporter:
    def render(
        self,
        anomalies: List[Anomaly],
        summary: dict,
        **_,
    ) -> str:
        def default_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, set):
                return list(obj)
            return str(obj)

        payload = {
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "anomalies": [
                {
                    "ip": a.ip,
                    "type": a.anomaly_type.value,
                    "severity": a.severity.value,
                    "description": a.description,
                    "evidence": a.evidence,
                    "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                }
                for a in anomalies
            ],
        }
        return json.dumps(payload, indent=2, default=default_serializer)


# ─── CSV Reporter ─────────────────────────────────────────────────────────────

class CSVReporter:
    def render(self, anomalies: List[Anomaly], summary=None, **_) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "IP", "Severity", "Type", "Description",
            "First Seen", "Last Seen", "Evidence",
        ])
        for a in anomalies:
            writer.writerow([
                a.ip,
                a.severity.value,
                a.anomaly_type.value,
                a.description,
                a.first_seen.isoformat() if a.first_seen else "",
                a.last_seen.isoformat() if a.last_seen else "",
                json.dumps(a.evidence),
            ])
        return buf.getvalue()


# ─── HTML Reporter ────────────────────────────────────────────────────────────

_SEV_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Log Analysis Report</title>
<style>
  body {{ font-family: 'Consolas', monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #79c0ff; margin-top: 30px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; text-align: center; }}
  .stat-card .value {{ font-size: 2rem; font-weight: bold; }}
  .stat-card .label {{ font-size: 0.8rem; color: #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{ background: #161b22; text-align: left; padding: 8px 12px; border-bottom: 2px solid #30363d; color: #8b949e; }}
  td {{ padding: 7px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.78rem; color: #000; }}
  .evidence {{ font-size: 0.78rem; color: #8b949e; }}
  .meta {{ color: #8b949e; font-size: 0.8rem; margin-bottom: 16px; }}
</style>
</head>
<body>
<h1>🔍 Log Analysis Report</h1>
<p class="meta">Generated: {generated_at} &nbsp;|&nbsp; Files: {files}</p>

<h2>Overview</h2>
<div class="summary-grid">
  <div class="stat-card"><div class="value">{total_entries}</div><div class="label">Entries Processed</div></div>
  <div class="stat-card"><div class="value">{unique_ips}</div><div class="label">Unique IPs</div></div>
  <div class="stat-card"><div class="value" style="color:#ff4444">{critical}</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="value" style="color:#ff8800">{high}</div><div class="label">High</div></div>
</div>

<h2>Anomalies ({total_anomalies})</h2>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Type</th><th>IP Address</th>
      <th>Description</th><th>First Seen</th><th>Last Seen</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
</body>
</html>
"""

_ROW_TEMPLATE = """\
<tr>
  <td><span class="badge" style="background:{color}">{severity}</span></td>
  <td>{atype}</td>
  <td><code>{ip}</code></td>
  <td>{description}<br><span class="evidence">{evidence}</span></td>
  <td>{first_seen}</td>
  <td>{last_seen}</td>
</tr>"""


class HTMLReporter:
    def render(
        self,
        anomalies: List[Anomaly],
        summary: dict,
        source_files: Optional[List[str]] = None,
        **_,
    ) -> str:
        sev_counts = summary.get("by_severity", {})
        rows = []
        for a in anomalies:
            ev_str = "; ".join(f"{k}={v}" for k, v in a.evidence.items())[:200]
            rows.append(_ROW_TEMPLATE.format(
                color=_SEV_COLOR.get(a.severity.value, "#888"),
                severity=a.severity.value,
                atype=a.anomaly_type.value,
                ip=a.ip,
                description=a.description,
                evidence=ev_str,
                first_seen=a.first_seen.strftime("%Y-%m-%d %H:%M") if a.first_seen else "–",
                last_seen=a.last_seen.strftime("%Y-%m-%d %H:%M") if a.last_seen else "–",
            ))

        return _HTML_TEMPLATE.format(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            files=", ".join(source_files) if source_files else "–",
            total_entries=f"{summary['total_entries_processed']:,}",
            unique_ips=f"{summary['unique_ips']:,}",
            critical=sev_counts.get("CRITICAL", 0),
            high=sev_counts.get("HIGH", 0),
            total_anomalies=summary["total_anomalies"],
            rows="\n".join(rows) or "<tr><td colspan='6'>✅ No anomalies found.</td></tr>",
        )


# ─── Factory ──────────────────────────────────────────────────────────────────

REPORTERS = {
    "text": TextReporter,
    "json": JSONReporter,
    "csv":  CSVReporter,
    "html": HTMLReporter,
}

def get_reporter(fmt: str):
    cls = REPORTERS.get(fmt.lower())
    if not cls:
        raise ValueError(f"Unknown report format '{fmt}'. Choose: {list(REPORTERS)}")
    return cls()
