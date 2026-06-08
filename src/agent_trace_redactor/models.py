"""Small data models for redaction runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Rule:
    """A redaction rule compiled from defaults or user config."""

    name: str
    pattern: str
    category: str
    description: str = ""
    flags: int = 0
    enabled: bool = True


@dataclass
class Finding:
    """A single redaction finding without storing the sensitive value."""

    category: str
    rule: str
    placeholder: str
    file: str
    line: int
    column: int
    length: int
    fingerprint: str
    context: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "rule": self.rule,
            "placeholder": self.placeholder,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "length": self.length,
            "fingerprint": self.fingerprint,
            "context": self.context,
        }


@dataclass
class FileResult:
    """Redaction result for one input file or stream."""

    source: str
    output_name: str
    input_format: str
    redacted_text: str
    findings: List[Finding] = field(default_factory=list)
    changed: bool = False
    bytes_in: int = 0
    bytes_out: int = 0
    parse_errors: List[str] = field(default_factory=list)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "output_name": self.output_name,
            "input_format": self.input_format,
            "changed": self.changed,
            "findings": len(self.findings),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "parse_errors": list(self.parse_errors),
        }


@dataclass
class RedactionStats:
    """Aggregate counters for a redaction run."""

    files: int = 0
    changed_files: int = 0
    findings: int = 0
    by_category: Dict[str, int] = field(default_factory=dict)
    by_rule: Dict[str, int] = field(default_factory=dict)

    def record(self, finding: Finding) -> None:
        self.findings += 1
        self.by_category[finding.category] = self.by_category.get(finding.category, 0) + 1
        self.by_rule[finding.rule] = self.by_rule.get(finding.rule, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files": self.files,
            "changed_files": self.changed_files,
            "findings": self.findings,
            "by_category": dict(sorted(self.by_category.items())),
            "by_rule": dict(sorted(self.by_rule.items())),
        }


@dataclass
class RunReport:
    """Machine-readable report for a redaction run."""

    schema_version: str
    stats: RedactionStats
    files: List[FileResult]
    placeholders: Dict[str, Dict[str, str]]
    config: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "stats": self.stats.to_dict(),
            "files": [item.to_summary() for item in self.files],
            "findings": [finding.to_dict() for item in self.files for finding in item.findings],
            "placeholders": self.placeholders,
            "config": self.config,
            "warnings": list(self.warnings),
        }


@dataclass
class BundleResult:
    """Information returned after writing a bundle."""

    output_dir: str
    report: RunReport
    zip_path: Optional[str] = None
