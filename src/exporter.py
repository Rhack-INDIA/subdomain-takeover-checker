"""Export scan findings to text, JSON, CSV, and interactive HTML formats."""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    from src.signatures import get_signature_by_name
except ImportError:
    try:
        from signatures import get_signature_by_name
    except ImportError:
        get_signature_by_name = lambda name: None  # type: ignore


@dataclass
class Finding:
    """Represents a potential subdomain takeover lead with risk analysis."""

    hostname: str
    service: str | None = None
    cname: str | None = None
    reason: str = ""
    status_code: int | None = None
    severity: str = "HIGH"
    confidence: str = "HIGH"
    remediation: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

        # Deduce severity and remediation if not explicitly specified
        if self.service:
            sig = get_signature_by_name(self.service)
            if sig:
                if self.severity == "HIGH" and sig.severity:
                    self.severity = sig.severity
                if self.confidence == "HIGH" and sig.confidence:
                    self.confidence = sig.confidence
                if not self.remediation and sig.remediation:
                    self.remediation = sig.remediation
        elif "NXDOMAIN" in self.reason:
            if not self.service and not self.cname:
                self.severity = "MEDIUM"
                self.confidence = "TENTATIVE"
                if not self.remediation:
                    self.remediation = (
                        "Verify DNS zone configuration. If the domain is no longer used, "
                        "remove the stale DNS record to prevent unauthorized registration."
                    )
            elif self.cname and not self.remediation:
                self.severity = "HIGH"
                self.confidence = "HIGH"
                self.remediation = (
                    f"Remove dangling CNAME pointing to {self.cname} or verify ownership "
                    "of the destination resource."
                )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __iter__(self):
        return iter((self.hostname, self.reason))

    def __getitem__(self, idx: int):
        return (self.hostname, self.reason)[idx]

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, tuple) and len(other) == 2:
            return (self.hostname, self.reason) == other
        if isinstance(other, Finding):
            return (
                self.hostname == other.hostname
                and self.service == other.service
                and self.cname == other.cname
                and self.reason == other.reason
                and self.status_code == other.status_code
            )
        return False


def format_text(findings: Sequence[Finding]) -> str:
    """Format findings as clean tab-delimited text."""
    lines: list[str] = []
    for f in findings:
        service_label = f.service or "N/A"
        cname_label = f.cname or "None"
        lines.append(f"{f.hostname}\t{service_label}\t{cname_label}\t{f.reason}")
    return "\n".join(lines) + ("\n" if lines else "")


def format_legacy_text(findings: Sequence[Finding]) -> str:
    """Format findings in legacy two-column tab format: hostname\\treason."""
    lines = [f"{f.hostname}\t{f.reason}" for f in findings]
    return "\n".join(lines) + ("\n" if lines else "")


def format_json(findings: Sequence[Finding], indent: int = 2) -> str:
    """Format findings as pretty JSON string."""
    data = [f.to_dict() for f in findings]
    return json.dumps(data, indent=indent)


def format_csv(findings: Sequence[Finding]) -> str:
    """Format findings as RFC 4180 CSV string."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "hostname",
            "service",
            "cname",
            "reason",
            "status_code",
            "timestamp",
            "severity",
            "confidence",
            "remediation",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for f in findings:
        writer.writerow(f.to_dict())
    return output.getvalue()


def format_html(findings: Sequence[Finding], report_title: str = "Subdomain Takeover Assessment Report") -> str:
    """Generate a self-contained, responsive, dark-mode HTML security report."""
    total = len(findings)
    critical_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")
    medium_count = sum(1 for f in findings if f.severity.upper() in ("MEDIUM", "LOW", "INFO"))
    unique_services = sorted({f.service for f in findings if f.service})
    crit_pct = int((critical_count / total * 100)) if total else 0
    high_pct = int((high_count / total * 100)) if total else 0
    med_pct = max(0, 100 - crit_pct - high_pct) if (total and critical_count + high_count < total) else (int((medium_count / total * 100)) if total else 0)

    rows_html: list[str] = []
    for f in findings:
        sev = html.escape(f.severity.upper())
        sev_class = {
            "CRITICAL": "badge-critical",
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low",
        }.get(sev, "badge-info")

        service_str = html.escape(f.service) if f.service else '<span class="text-muted">Unknown / NX</span>'
        cname_str = html.escape(f.cname) if f.cname else '<span class="text-muted">None</span>'
        hostname_esc = html.escape(f.hostname)
        reason_esc = html.escape(f.reason)
        remediation_esc = html.escape(f.remediation) or '<span class="text-muted">Verify target configuration</span>'
        code_str = str(f.status_code) if f.status_code is not None else "-"

        rows_html.append(f"""
        <tr class="finding-row" data-severity="{sev}">
            <td>
                <a href="https://{hostname_esc}" target="_blank" rel="noopener noreferrer" class="host-link">
                    {hostname_esc}
                </a>
            </td>
            <td><span class="badge {sev_class}">{sev}</span></td>
            <td><strong>{service_str}</strong></td>
            <td><code class="cname-text">{cname_str}</code></td>
            <td><span class="reason-text">{reason_esc}</span></td>
            <td><code>{code_str}</code></td>
            <td class="remediation-cell">{remediation_esc}</td>
        </tr>
        """)

    table_body = "\n".join(rows_html) if rows_html else """
        <tr>
            <td colspan="7" style="text-align: center; padding: 2rem; color: #94a3b8;">
                No takeover vulnerabilities or candidates were detected during this scan.
            </td>
        </tr>
    """

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(report_title)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --card-bg: #111827;
            --border: #1f2937;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --critical: #ef4444;
            --critical-bg: rgba(239, 68, 68, 0.15);
            --high: #f97316;
            --high-bg: rgba(249, 115, 22, 0.15);
            --medium: #eab308;
            --medium-bg: rgba(234, 179, 8, 0.15);
            --low: #10b981;
            --low-bg: rgba(16, 185, 129, 0.15);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        h1 {{ font-size: 1.85rem; font-weight: 700; color: #fff; letter-spacing: -0.02em; }}
        .header-meta {{ color: var(--text-muted); font-size: 0.875rem; margin-top: 0.35rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .risk-meter-section {{
            margin-bottom: 2rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 1.25rem;
        }}
        .risk-bar-container {{ display: flex; flex-direction: column; gap: 0.5rem; }}
        .risk-bar-label {{ display: flex; justify-content: space-between; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); }}
        .risk-bar {{ display: flex; height: 12px; border-radius: 6px; overflow: hidden; background: #1f2937; }}
        .bar-crit {{ background: var(--critical); }}
        .bar-high {{ background: var(--high); }}
        .bar-med {{ background: var(--medium); }}
        .stat-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 1.25rem;
            position: relative;
            overflow: hidden;
        }}
        .stat-card .label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}
        .stat-card .value {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}
        .card-total .value {{ color: var(--primary); }}
        .card-critical .value {{ color: var(--critical); }}
        .card-high .value {{ color: var(--high); }}
        .card-medium .value {{ color: var(--medium); }}
        .toolbar {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1.25rem;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
        }}
        .search-box {{
            flex: 1;
            min-width: 260px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.65rem 1rem;
            border-radius: 0.375rem;
            font-size: 0.9rem;
        }}
        .search-box:focus {{ outline: 2px solid var(--primary); }}
        .filter-buttons {{ display: flex; gap: 0.5rem; }}
        .btn {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.5rem 0.85rem;
            border-radius: 0.375rem;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s ease;
        }}
        .btn:hover, .btn.active {{ background: var(--primary); border-color: var(--primary); color: #fff; }}
        .table-wrapper {{
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            overflow-x: auto;
        }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem; }}
        th {{
            background-color: #162032;
            padding: 0.85rem 1rem;
            font-weight: 600;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }}
        td {{ padding: 0.9rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
        tr:hover td {{ background-color: rgba(255, 255, 255, 0.02); }}
        .host-link {{ color: #60a5fa; text-decoration: none; font-weight: 600; }}
        .host-link:hover {{ text-decoration: underline; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 0.25rem;
            font-size: 0.725rem;
            font-weight: 700;
            letter-spacing: 0.03em;
        }}
        .badge-critical {{ background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }}
        .badge-info {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid #3b82f6; }}
        code {{
            background: #1f2937;
            padding: 0.15rem 0.35rem;
            border-radius: 0.25rem;
            font-size: 0.8rem;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }}
        .text-muted {{ color: var(--text-muted); }}
        .remediation-cell {{ font-size: 0.825rem; color: #d1d5db; max-width: 320px; }}
        footer {{
            margin-top: 2.5rem;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .toolbar {{ display: none; }}
            .stat-card, .table-wrapper {{ border: 1px solid #ddd; background: #fff; }}
            th {{ background: #f3f4f6; color: #333; }}
            td {{ border-bottom: 1px solid #eee; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Subdomain Takeover Assessment</h1>
                <div class="header-meta">Generated: {now_iso} &bull; Red Team Vulnerability Report</div>
            </div>
            <div>
                <button class="btn" onclick="window.print()">Print / Export PDF</button>
            </div>
        </header>

        <section class="stats-grid">
            <div class="stat-card card-total">
                <div class="label">Total Vulnerable Hosts</div>
                <div class="value">{total}</div>
            </div>
            <div class="stat-card card-critical">
                <div class="label">Critical Findings</div>
                <div class="value">{critical_count}</div>
            </div>
            <div class="stat-card card-high">
                <div class="label">High Findings</div>
                <div class="value">{high_count}</div>
            </div>
            <div class="stat-card card-medium">
                <div class="label">Medium Candidates</div>
                <div class="value">{medium_count}</div>
            </div>
        </section>

        <section class="risk-meter-section">
            <div class="risk-bar-container">
                <div class="risk-bar-label">
                    <span>Severity Composition</span>
                    <span>{critical_count} Critical ({crit_pct}%) &bull; {high_count} High ({high_pct}%) &bull; {medium_count} Medium ({med_pct}%)</span>
                </div>
                <div class="risk-bar">
                    <div class="bar-crit" style="width: {crit_pct}%;"></div>
                    <div class="bar-high" style="width: {high_pct}%;"></div>
                    <div class="bar-med" style="width: {med_pct}%;"></div>
                </div>
            </div>
        </section>

        <section class="toolbar">
            <input type="text" id="searchInput" class="search-box" placeholder="Filter by hostname, service, CNAME, or reason..." onkeyup="filterTable()">
            <div class="filter-buttons">
                <button class="btn active" onclick="filterSeverity('ALL', this)">All</button>
                <button class="btn" onclick="filterSeverity('CRITICAL', this)">Critical</button>
                <button class="btn" onclick="filterSeverity('HIGH', this)">High</button>
                <button class="btn" onclick="filterSeverity('MEDIUM', this)">Medium</button>
            </div>
        </section>

        <div class="table-wrapper">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Target Subdomain</th>
                        <th>Severity</th>
                        <th>Cloud Provider</th>
                        <th>CNAME Chain</th>
                        <th>Detection Signal</th>
                        <th>Status</th>
                        <th>Remediation Advice</th>
                    </tr>
                </thead>
                <tbody>
                    {table_body}
                </tbody>
            </table>
        </div>

        <footer>
            Subdomain Takeover Scanner &bull; Authorized Penetration Testing &amp; Bug Bounty Defense &bull; Rudra Pratap Dalei
        </footer>
    </div>

    <script>
        let currentSeverity = 'ALL';

        function filterSeverity(sev, btn) {{
            currentSeverity = sev;
            document.querySelectorAll('.filter-buttons .btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterTable();
        }}

        function filterTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('.finding-row');

            rows.forEach(row => {{
                const rowSev = row.getAttribute('data-severity');
                const text = row.innerText.toLowerCase();
                const matchesSearch = text.includes(query);
                const matchesSev = (currentSeverity === 'ALL' || rowSev === currentSeverity);

                if (matchesSearch && matchesSev) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    return template


def export_findings(
    path: Path,
    findings: Iterable[Finding],
    export_format: str = "text",
    report_title: str = "Subdomain Takeover Assessment Report",
) -> int:
    """Write findings to the given path in the specified format (text, json, csv, html, legacy)."""
    results = list(findings)
    path.parent.mkdir(parents=True, exist_ok=True)

    fmt = export_format.lower()
    if fmt == "json":
        content = format_json(results)
    elif fmt == "csv":
        content = format_csv(results)
    elif fmt == "html":
        content = format_html(results, report_title=report_title)
    elif fmt == "legacy":
        content = format_legacy_text(results)
    else:  # text
        content = format_text(results)

    try:
        path.write_text(content, encoding="utf-8")
    except OSError as error:
        raise OSError(f"cannot write output file {path}: {error}") from error

    return len(results)
