#!/usr/bin/env python3
"""
recon_engine.report -- generates report.html from normalized records
ONLY.

This module never opens anything under raw/ -- that's a deliberate
separation of concerns (per the phase 3 brief: "keep raw evidence
immutable and separate from normalized records and report
generation"). The report is a view over assets.jsonl; if you want to
inspect what a service actually sent back byte-for-byte, that's what
source_file (under raw/) is for, and this module only ever prints that
filename as a reference, never its contents.
"""

from __future__ import annotations

import html
import json
from pathlib import Path


def generate_report(output_dir: Path) -> Path:
    """Read <output_dir>/normalized/assets.jsonl and write
    <output_dir>/report.html. Returns the report path. Safe to call
    with zero records (writes an empty-state report, not an error)."""
    assets_path = output_dir / "normalized" / "assets.jsonl"
    records = []
    if assets_path.exists():
        with open(assets_path) as f:
            records = [json.loads(line) for line in f if line.strip()]

    rows = "\n".join(_render_row(r) for r in records) or (
        "<tr><td colspan='7'><em>No records yet.</em></td></tr>"
    )

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Recon Engine Discovery Report</title>
<style>
  body {{ font-family: -apple-system, sans-serif; margin: 2rem; color: #1a1a1a; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }}
  th {{ background: #f2f2f2; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  code {{ font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>Recon Engine Discovery Report</h1>
<p>{len(records)} normalized record(s). Generated from
<code>normalized/assets.jsonl</code> only -- raw evidence under
<code>raw/</code> is untouched by report generation.</p>
<table>
<thead>
<tr>
  <th>Observed at</th><th>Target</th><th>Protocol</th><th>Service</th>
  <th>Notes</th><th>Status</th><th>Source file</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""
    report_path = output_dir / "report.html"
    report_path.write_text(report_html)
    return report_path


def _render_row(record: dict) -> str:
    def esc(value) -> str:
        return html.escape(str(value)) if value is not None else ""

    status = record.get("status", record.get("tls_available", ""))
    return (
        "<tr>"
        f"<td>{esc(record.get('observed_at'))}</td>"
        f"<td>{esc(record.get('target'))}</td>"
        f"<td>{esc(record.get('protocol'))}</td>"
        f"<td>{esc(record.get('service'))}</td>"
        f"<td>{esc(record.get('notes'))}</td>"
        f"<td>{esc(status)}</td>"
        f"<td><code>{esc(record.get('source_file'))}</code></td>"
        "</tr>"
    )
