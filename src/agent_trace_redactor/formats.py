"""Input format detection and structured parsing helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, List, Tuple


TEXT_FORMATS = {"text", "log", "markdown", "env", "unknown"}


def detect_format(path: str, text: str) -> str:
    suffix = Path(path).suffix.lower()
    stripped = text.lstrip()
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix in {".log", ".out", ".err", ".trace"}:
        return "log"
    if suffix == ".env":
        return "env"
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    return "text"


def redact_structured_text(
    text: str,
    input_format: str,
    redact_leaf: Callable[[str], str],
    strict_json: bool = False,
) -> Tuple[str, List[str]]:
    """Redact text while preserving JSON/JSONL formatting when possible."""

    if input_format == "json":
        return _redact_json(text, redact_leaf, strict_json)
    if input_format == "jsonl":
        return _redact_jsonl(text, redact_leaf, strict_json)
    return redact_leaf(text), []


def _redact_json(text: str, redact_leaf: Callable[[str], str], strict_json: bool) -> Tuple[str, List[str]]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        if strict_json:
            return "", [f"invalid json: {exc}"]
        return redact_leaf(text), [f"treated invalid json as text: {exc}"]
    redacted = _walk_json(value, redact_leaf)
    return json.dumps(redacted, ensure_ascii=False, indent=2, sort_keys=False) + "\n", []


def _redact_jsonl(text: str, redact_leaf: Callable[[str], str], strict_json: bool) -> Tuple[str, List[str]]:
    output_lines = []
    errors = []
    trailing_newline = text.endswith("\n")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            output_lines.append(line)
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            message = f"line {line_number}: invalid jsonl record: {exc}"
            errors.append(message)
            if strict_json:
                continue
            output_lines.append(redact_leaf(line))
            continue
        output_lines.append(json.dumps(_walk_json(value, redact_leaf), ensure_ascii=False, sort_keys=False))
    result = "\n".join(output_lines)
    if trailing_newline:
        result += "\n"
    return result, errors


def _walk_json(value: Any, redact_leaf: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return redact_leaf(value)
    if isinstance(value, list):
        return [_walk_json(item, redact_leaf) for item in value]
    if isinstance(value, dict):
        return {key: _walk_json(item, redact_leaf) for key, item in value.items()}
    return value
