"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List, Optional

from . import __version__
from .config import load_config
from .defaults import DEFAULT_CONTEXT_CHARS, DEFAULT_EXTENSIONS, DEFAULT_HASH_SALT, DEFAULT_IGNORE_DIRS
from .engine import RedactionEngine
from .errors import ConfigError, InputError, RedactorError
from .io import make_report, redact_paths, redact_stdin, write_bundle
from .models import FileResult
from .reporting import render_json_report, render_markdown_report

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_CONFIG = 3
EXIT_INPUT = 4
EXIT_RUNTIME = 5


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "check-config":
            return _check_config(args)
        if args.command == "default-config":
            return _default_config(args)
        if args.command == "scan":
            return _scan(args)
        parser.print_help()
        return EXIT_OK
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except RedactorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-trace-redactor",
        description="Redact secrets, PII, internal paths, customer domains, and private repo URLs from AI agent traces.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="redact files, directories, or stdin")
    scan.add_argument("paths", nargs="*", help="input files or directories")
    scan.add_argument("-c", "--config", help="JSON config file")
    scan.add_argument("-o", "--output", default="redacted-bundle", help="output bundle directory")
    scan.add_argument("--stdin", action="store_true", help="read a single input from stdin")
    scan.add_argument("--stdin-name", default="stdin.txt", help="virtual filename for stdin format detection")
    scan.add_argument("--json", action="store_true", help="print machine-readable report JSON to stdout")
    scan.add_argument("--markdown", action="store_true", help="print Markdown report to stdout")
    scan.add_argument("--no-write", action="store_true", help="do not write output bundle")
    scan.add_argument("--no-diff", action="store_true", help="skip safe diff files in bundle")
    scan.add_argument("--zip", action="store_true", help="also create a zip archive of the bundle")
    scan.add_argument("--fail-on-findings", action="store_true", help="exit 2 when findings are detected")
    scan.add_argument("--strict-json", action="store_true", help="treat invalid JSON/JSONL as parse errors")
    scan.add_argument("--reveal-placeholder-map", action="store_true", help="include original values in report placeholder map; unsafe for CI")

    check = sub.add_parser("check-config", help="validate a config file")
    check.add_argument("config", help="JSON config file")

    default = sub.add_parser("default-config", help="print a starter JSON config")
    default.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    return parser


def _scan(args: argparse.Namespace) -> int:
    overrides = {}
    if args.strict_json:
        overrides["strict_json"] = True
    if args.reveal_placeholder_map:
        overrides["reveal_placeholder_map"] = True
    config = load_config(args.config, overrides=overrides)
    if args.stdin:
        text = sys.stdin.read()
        engine = RedactionEngine(config)
        file_result = redact_stdin(text, engine, config, source_name=args.stdin_name)
        report = make_report([file_result], engine, config)
    else:
        if not args.paths:
            raise InputError("scan requires at least one path or --stdin")
        report = redact_paths([Path(path) for path in args.paths], config)

    if not args.no_write:
        bundle = write_bundle(report, Path(args.output), include_diff=not args.no_diff, zip_bundle=args.zip)
        print(f"wrote bundle: {bundle.output_dir}", file=sys.stderr)
        if bundle.zip_path:
            print(f"wrote archive: {bundle.zip_path}", file=sys.stderr)

    if args.json:
        sys.stdout.write(render_json_report(report))
    elif args.markdown:
        sys.stdout.write(render_markdown_report(report))
    else:
        _print_summary(report)

    if args.fail_on_findings and report.stats.findings:
        return EXIT_FINDINGS
    return EXIT_OK


def _check_config(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(f"ok: {len(config.rules)} rule(s), {sum(1 for rule in config.rules if rule.enabled)} enabled")
    return EXIT_OK


def _default_config(args: argparse.Namespace) -> int:
    data = {
        "context_chars": DEFAULT_CONTEXT_CHARS,
        "hash_salt": DEFAULT_HASH_SALT,
        "preserve_json": True,
        "strict_json": False,
        "max_file_bytes": 10 * 1024 * 1024,
        "include_extensions": sorted(DEFAULT_EXTENSIONS),
        "ignore_dirs": sorted(DEFAULT_IGNORE_DIRS),
        "disable_rules": [],
        "rules": [
            {
                "name": "company_ticket",
                "pattern": "\\bACME-[0-9]{4,}\\b",
                "category": "internal_id",
                "description": "Example internal ticket id",
                "flags": [],
                "enabled": True,
            }
        ],
    }
    if args.pretty:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    return EXIT_OK


def _print_summary(report) -> None:
    stats = report.stats
    print(
        f"scanned={stats.files} changed={stats.changed_files} findings={stats.findings}",
        file=sys.stdout,
    )
    for category, count in sorted(stats.by_category.items()):
        print(f"{category}={count}", file=sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
