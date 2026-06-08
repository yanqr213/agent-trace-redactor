"""Diff generation without leaking raw sensitive values."""

from __future__ import annotations

from typing import Iterable, List


def safe_diff(source_name: str, redacted_text: str, findings_count: int, changed: bool) -> str:
    """Return a compact diff-like summary that never includes original lines."""

    status = "changed" if changed else "unchanged"
    lines = [
        f"--- {source_name} (original omitted)",
        f"+++ {source_name} (redacted)",
        f"@@ status={status} findings={findings_count} @@",
    ]
    if changed:
        for line in _preview_lines(redacted_text.splitlines()):
            lines.append(f"+ {line}")
    return "\n".join(lines) + "\n"


def _preview_lines(lines: Iterable[str], limit: int = 80) -> List[str]:
    result = []
    for index, line in enumerate(lines):
        if index >= limit:
            result.append("... diff preview truncated ...")
            break
        result.append(line)
    return result
