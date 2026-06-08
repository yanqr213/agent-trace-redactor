"""Importable API for applications and tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Union

from .config import RedactorConfig, load_config
from .engine import RedactionEngine
from .io import make_report, redact_paths, redact_stdin, write_bundle
from .models import BundleResult, FileResult, Finding, RunReport


@dataclass
class RedactionResult:
    """Convenient API result for text redaction."""

    text: str
    findings: List[Finding]
    report: RunReport

    @property
    def changed(self) -> bool:
        return bool(self.report.stats.changed_files)


class Redactor:
    """Reusable redactor instance.

    The instance keeps a placeholder map, so repeated calls on the same instance
    produce stable placeholders for the same sensitive values.
    """

    def __init__(self, config: Optional[RedactorConfig] = None):
        self.config = config or load_config()
        self.engine = RedactionEngine(self.config)

    @classmethod
    def from_config_file(cls, path: Union[str, Path]) -> "Redactor":
        return cls(load_config(str(path)))

    def redact_text(self, text: str, source_name: str = "memory.txt") -> RedactionResult:
        file_result = redact_stdin(text, self.engine, self.config, source_name=source_name)
        report = make_report([file_result], self.engine, self.config)
        return RedactionResult(text=file_result.redacted_text, findings=file_result.findings, report=report)

    def redact_paths(self, paths: Iterable[Union[str, Path]]) -> RunReport:
        return redact_paths([Path(path) for path in paths], self.config)

    def write_bundle(
        self,
        paths: Iterable[Union[str, Path]],
        output_dir: Union[str, Path],
        include_diff: bool = True,
        zip_bundle: bool = False,
    ) -> BundleResult:
        report = self.redact_paths(paths)
        return write_bundle(report, Path(output_dir), include_diff=include_diff, zip_bundle=zip_bundle)


def redact_text(text: str, config: Optional[RedactorConfig] = None, source_name: str = "memory.txt") -> RedactionResult:
    return Redactor(config).redact_text(text, source_name=source_name)


def redact_path(
    paths: Iterable[Union[str, Path]],
    output_dir: Optional[Union[str, Path]] = None,
    config: Optional[RedactorConfig] = None,
) -> Union[RunReport, BundleResult]:
    redactor = Redactor(config)
    report = redactor.redact_paths(paths)
    if output_dir is None:
        return report
    return write_bundle(report, Path(output_dir))
