"""Utility helpers."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Iterable, Iterator, List, Tuple


def sha256_short(value: str, salt: str = "", length: int = 12) -> str:
    digest = hashlib.sha256((salt + "\0" + value).encode("utf-8", "surrogatepass")).hexdigest()
    return digest[:length]


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def line_column_for_offset(text: str, offset: int) -> Tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    if last_newline < 0:
        column = offset + 1
    else:
        column = offset - last_newline
    return line, column


def context_snippet(text: str, start: int, end: int, chars: int) -> str:
    left = max(0, start - chars)
    right = min(len(text), end + chars)
    snippet = text[left:start] + text[start:end] + text[end:right]
    snippet = snippet.replace("\n", "\\n").replace("\t", "\\t")
    if left > 0:
        snippet = "..." + snippet
    if right < len(text):
        snippet += "..."
    return snippet


def safe_relpath(path: Path, root: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        rel = Path(path.name)
    rel_text = rel.as_posix()
    if rel_text in {"", "."}:
        return path.name
    return rel_text


def sanitize_output_name(name: str) -> str:
    name = name.replace("\\", "/")
    parts = [part for part in name.split("/") if part not in {"", ".", ".."}]
    if not parts:
        return "stdin.txt"
    safe_parts = [re.sub(r"[^A-Za-z0-9._-]+", "_", part) or "file" for part in parts]
    return "/".join(safe_parts)


def iter_input_files(paths: Iterable[Path], ignore_dirs: Iterable[str]) -> Iterator[Path]:
    ignore = set(ignore_dirs)
    for path in paths:
        path = Path(path)
        if path.is_dir():
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames[:] = [item for item in dirnames if item not in ignore]
                for filename in filenames:
                    yield Path(dirpath) / filename
        else:
            yield path


def count_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def unique_preserving_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
