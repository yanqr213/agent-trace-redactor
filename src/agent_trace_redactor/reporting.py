"""Report rendering."""

from __future__ import annotations

import json
from typing import Iterable

from .models import RunReport


def render_json_report(report: RunReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_markdown_report(report: RunReport) -> str:
    data = report.to_dict()
    stats = data["stats"]
    lines = [
        "# Agent Trace Redaction Report",
        "",
        "## Summary",
        "",
        f"- Files scanned: {stats['files']}",
        f"- Changed files: {stats['changed_files']}",
        f"- Findings: {stats['findings']}",
        "",
        "## Findings by Category",
        "",
    ]
    if stats["by_category"]:
        for category, count in stats["by_category"].items():
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- None")
    lines.extend(["", "## Files", ""])
    for file_info in data["files"]:
        lines.append(
            f"- `{file_info['output_name']}`: {file_info['findings']} finding(s), "
            f"format `{file_info['input_format']}`, changed `{str(file_info['changed']).lower()}`"
        )
        for parse_error in file_info["parse_errors"]:
            lines.append(f"  - Parse warning: {parse_error}")
    lines.extend(["", "## Findings", ""])
    findings = data["findings"]
    if findings:
        lines.append("| File | Location | Category | Rule | Placeholder | Context |")
        lines.append("| --- | ---: | --- | --- | --- | --- |")
        for finding in findings:
            location = f"{finding['line']}:{finding['column']}"
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md(finding["file"]),
                        _md(location),
                        _md(finding["category"]),
                        _md(finding["rule"]),
                        _md(finding["placeholder"]),
                        _md(finding["context"]),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No findings.")
    if report.warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in report.warnings:
            lines.append(f"- {warning}")
    return "\n".join(lines) + "\n"


def _md(value: object) -> str:
    text = str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
