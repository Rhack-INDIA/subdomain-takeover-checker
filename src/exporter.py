"""Export scan findings to text, JSON, and CSV formats."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


@dataclass
class Finding:
    """Represents a potential subdomain takeover lead."""

    hostname: str
    service: str | None = None
    cname: str | None = None
    reason: str = ""
    status_code: int | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

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
        fieldnames=["hostname", "service", "cname", "reason", "status_code", "timestamp"],
        lineterminator="\n",
    )
    writer.writeheader()
    for f in findings:
        writer.writerow(f.to_dict())
    return output.getvalue()


def export_findings(path: Path, findings: Iterable[Finding], export_format: str = "text") -> int:
    """Write findings to the given path in the specified format (text, json, csv, legacy)."""
    results = list(findings)
    path.parent.mkdir(parents=True, exist_ok=True)

    fmt = export_format.lower()
    if fmt == "json":
        content = format_json(results)
    elif fmt == "csv":
        content = format_csv(results)
    elif fmt == "legacy":
        content = format_legacy_text(results)
    else:  # text
        content = format_text(results)

    try:
        path.write_text(content, encoding="utf-8")
    except OSError as error:
        raise OSError(f"cannot write output file {path}: {error}") from error

    return len(results)
