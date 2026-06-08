import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_trace_redactor import __version__
from agent_trace_redactor.cli import EXIT_CONFIG, EXIT_FINDINGS, EXIT_INPUT, EXIT_OK, main


class CliTests(unittest.TestCase):
    def run_cli(self, argv, stdin=""):
        out = io.StringIO()
        err = io.StringIO()
        with patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_default_config_prints_json(self):
        code, out, err = self.run_cli(["default-config"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("context_chars", json.loads(out))

    def test_default_config_pretty(self):
        code, out, err = self.run_cli(["default-config", "--pretty"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("\n  ", out)

    def test_check_config_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{}", encoding="utf-8")
            code, out, err = self.run_cli(["check-config", str(path)])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("ok:", out)

    def test_check_config_bad(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{", encoding="utf-8")
            code, out, err = self.run_cli(["check-config", str(path)])
            self.assertEqual(code, EXIT_CONFIG)
            self.assertIn("config error", err)

    def test_scan_requires_path_or_stdin(self):
        code, out, err = self.run_cli(["scan"])
        self.assertEqual(code, EXIT_INPUT)

    def test_scan_stdin_json(self):
        code, out, err = self.run_cli(
            ["scan", "--stdin", "--stdin-name", "trace.log", "--json", "--no-write"],
            "alice@example.test",
        )
        self.assertEqual(code, EXIT_OK)
        data = json.loads(out)
        self.assertEqual(data["stats"]["findings"], 1)

    def test_scan_stdin_markdown(self):
        code, out, err = self.run_cli(
            ["scan", "--stdin", "--stdin-name", "trace.log", "--markdown", "--no-write"],
            "alice@example.test",
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("# Agent Trace Redaction Report", out)

    def test_scan_summary(self):
        code, out, err = self.run_cli(["scan", "--stdin", "--no-write"], "clean")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("scanned=1", out)

    def test_fail_on_findings(self):
        code, out, err = self.run_cli(["scan", "--stdin", "--no-write", "--fail-on-findings"], "alice@example.test")
        self.assertEqual(code, EXIT_FINDINGS)

    def test_no_fail_without_findings(self):
        code, out, err = self.run_cli(["scan", "--stdin", "--no-write", "--fail-on-findings"], "clean")
        self.assertEqual(code, EXIT_OK)

    def test_scan_writes_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "trace.log"
            out_dir = Path(tmp) / "bundle"
            src.write_text("alice@example.test", encoding="utf-8")
            code, out, err = self.run_cli(["scan", str(src), "-o", str(out_dir)])
            self.assertEqual(code, EXIT_OK)
            self.assertTrue((out_dir / "reports" / "report.json").exists())
            self.assertIn("wrote bundle", err)

    def test_scan_with_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.json"
            src = Path(tmp) / "trace.log"
            cfg.write_text(json.dumps({"disable_rules": ["email"]}), encoding="utf-8")
            src.write_text("alice@example.test", encoding="utf-8")
            code, out, err = self.run_cli(["scan", str(src), "-c", str(cfg), "--json", "--no-write"])
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(json.loads(out)["stats"]["findings"], 0)

    def test_strict_json_cli_sets_parse_warning(self):
        code, out, err = self.run_cli(
            ["scan", "--stdin", "--stdin-name", "trace.json", "--json", "--no-write", "--strict-json"],
            "{bad",
        )
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(json.loads(out)["files"][0]["parse_errors"])

    def test_reveal_placeholder_map_cli(self):
        code, out, err = self.run_cli(
            ["scan", "--stdin", "--json", "--no-write", "--reveal-placeholder-map"],
            "alice@example.test",
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("alice@example.test", out)


if __name__ == "__main__":
    unittest.main()
