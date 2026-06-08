"""Input and output orchestration."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from .config import RedactorConfig
from .defaults import DEFAULT_SCHEMA_VERSION
from .diff import safe_diff
from .engine import RedactionEngine
from .errors import InputError
from .formats import detect_format, redact_structured_text
from .models import BundleResult, FileResult, RedactionStats, RunReport
from .reporting import render_json_report, render_markdown_report
from .utils import iter_input_files, safe_relpath, sanitize_output_name


def read_text_file(path: Path, config: RedactorConfig) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputError(f"cannot stat {path}: {exc}") from exc
    if size > config.max_file_bytes:
        raise InputError(f"{path} exceeds max_file_bytes ({config.max_file_bytes})")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    if b"\0" in data:
        raise InputError(f"{path} appears to be binary")
    return data.decode("utf-8", "replace")


def should_include(path: Path, config: RedactorConfig) -> bool:
    suffix = path.suffix.lower()
    return suffix in set(config.include_extensions) or path.name in {".env", ".npmrc", ".pypirc"}


def redact_file(path: Path, root: Path, engine: RedactionEngine, config: RedactorConfig) -> FileResult:
    source_name = safe_relpath(path, root)
    text = read_text_file(path, config)
    input_format = detect_format(source_name, text)
    findings = []

    def redact_leaf(value: str) -> str:
        result = engine.redact_text(value, source=source_name)
        findings.extend(result.findings)
        return result.text

    if config.preserve_json:
        redacted_text, parse_errors = redact_structured_text(text, input_format, redact_leaf, config.strict_json)
    else:
        redaction = engine.redact_text(text, source=source_name)
        redacted_text = redaction.text
        findings.extend(redaction.findings)
        parse_errors = []
    if not findings and input_format in {"json", "jsonl"} and not config.strict_json:
        redacted_text = text
    return FileResult(
        source=str(path),
        output_name=sanitize_output_name(source_name),
        input_format=input_format,
        redacted_text=redacted_text,
        findings=findings,
        changed=redacted_text != text,
        bytes_in=len(text.encode("utf-8")),
        bytes_out=len(redacted_text.encode("utf-8")),
        parse_errors=parse_errors,
    )


def redact_stdin(text: str, engine: RedactionEngine, config: RedactorConfig, source_name: str = "stdin.txt") -> FileResult:
    input_format = detect_format(source_name, text)
    findings = []

    def redact_leaf(value: str) -> str:
        result = engine.redact_text(value, source=source_name)
        findings.extend(result.findings)
        return result.text

    if config.preserve_json:
        redacted_text, parse_errors = redact_structured_text(text, input_format, redact_leaf, config.strict_json)
    else:
        redaction = engine.redact_text(text, source=source_name)
        redacted_text = redaction.text
        findings.extend(redaction.findings)
        parse_errors = []
    if not findings and input_format in {"json", "jsonl"} and not config.strict_json:
        redacted_text = text
    return FileResult(
        source="<stdin>",
        output_name=sanitize_output_name(source_name),
        input_format=input_format,
        redacted_text=redacted_text,
        findings=findings,
        changed=redacted_text != text,
        bytes_in=len(text.encode("utf-8")),
        bytes_out=len(redacted_text.encode("utf-8")),
        parse_errors=parse_errors,
    )


def redact_paths(paths: Iterable[Path], config: RedactorConfig) -> RunReport:
    engine = RedactionEngine(config)
    input_paths = list(paths)
    root = _common_root(input_paths)
    file_results: List[FileResult] = []
    warnings: List[str] = []
    for path in iter_input_files(input_paths, config.ignore_dirs):
        path = Path(path)
        if not should_include(path, config):
            continue
        try:
            file_results.append(redact_file(path, root, engine, config))
        except InputError as exc:
            warnings.append(str(exc))
    return make_report(file_results, engine, config, warnings)


def make_report(
    file_results: List[FileResult],
    engine: RedactionEngine,
    config: RedactorConfig,
    warnings: Optional[List[str]] = None,
) -> RunReport:
    stats = RedactionStats(files=len(file_results), changed_files=sum(1 for item in file_results if item.changed))
    for item in file_results:
        for finding in item.findings:
            stats.record(finding)
    return RunReport(
        schema_version=DEFAULT_SCHEMA_VERSION,
        stats=stats,
        files=file_results,
        placeholders=engine.placeholder_map.to_public_dict(),
        config=config.to_public_dict(),
        warnings=warnings or [],
    )


def write_bundle(
    report: RunReport,
    output_dir: Path,
    include_diff: bool = True,
    zip_bundle: bool = False,
) -> BundleResult:
    output_dir = Path(output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    redacted_dir = output_dir / "redacted"
    diff_dir = output_dir / "diffs"
    report_dir = output_dir / "reports"
    redacted_dir.mkdir(parents=True, exist_ok=True)
    if include_diff:
        diff_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    for file_result in report.files:
        target = redacted_dir / file_result.output_name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file_result.redacted_text, encoding="utf-8", newline="")
        if include_diff:
            diff_name = sanitize_output_name(file_result.output_name).replace("/", "__") + ".diff"
            (diff_dir / diff_name).write_text(
                safe_diff(file_result.output_name, file_result.redacted_text, len(file_result.findings), file_result.changed),
                encoding="utf-8",
                newline="",
            )

    (report_dir / "report.json").write_text(render_json_report(report), encoding="utf-8", newline="")
    (report_dir / "report.md").write_text(render_markdown_report(report), encoding="utf-8", newline="")
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": report.schema_version,
        "files": [item.to_summary() for item in report.files],
        "report": "reports/report.json",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="")

    zip_path = None
    if zip_bundle:
        archive_base = str(output_dir)
        zip_path = shutil.make_archive(archive_base, "zip", root_dir=output_dir)
    return BundleResult(output_dir=str(output_dir), report=report, zip_path=zip_path)


def _common_root(paths: List[Path]) -> Path:
    if not paths:
        return Path.cwd()
    resolved = [path.resolve() if path.exists() else path for path in paths]
    existing = [path if path.is_dir() else path.parent for path in resolved]
    if len(existing) == 1:
        return existing[0] if existing[0].is_dir() else existing[0].parent
    try:
        return Path(os.path.commonpath([str(path) for path in existing]))
    except ValueError:
        return Path.cwd()
