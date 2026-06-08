import json
import tempfile
import unittest
from pathlib import Path

from agent_trace_redactor import Redactor, redact_path, redact_text
from agent_trace_redactor.config import validate_config
from agent_trace_redactor.formats import detect_format, redact_structured_text
from agent_trace_redactor.io import read_text_file, redact_paths, should_include, write_bundle
from agent_trace_redactor.errors import InputError


FAKE_TOKEN_ASSIGNMENT = "token" + "=" + "demoTokenForDocsOnly123"


class FormatIoApiTests(unittest.TestCase):
    def test_detect_json_by_extension(self):
        self.assertEqual(detect_format("a.json", "{}"), "json")

    def test_detect_jsonl_by_extension(self):
        self.assertEqual(detect_format("a.jsonl", "{}\n"), "jsonl")

    def test_detect_log(self):
        self.assertEqual(detect_format("a.log", "x"), "log")

    def test_json_preserves_structure(self):
        redacted, errors = redact_structured_text(
            '{"email":"alice@example.test","n":1}',
            "json",
            lambda text: text.replace("alice@example.test", "<PII_X>"),
        )
        parsed = json.loads(redacted)
        self.assertEqual(parsed["email"], "<PII_X>")
        self.assertEqual(parsed["n"], 1)
        self.assertFalse(errors)

    def test_jsonl_preserves_records(self):
        redacted, errors = redact_structured_text(
            '{"email":"alice@example.test"}\n{"email":"bob@example.test"}\n',
            "jsonl",
            lambda text: "<PII_X>" if "@" in text else text,
        )
        self.assertEqual(len(redacted.splitlines()), 2)
        self.assertFalse(errors)

    def test_invalid_json_falls_back_to_text(self):
        redacted, errors = redact_structured_text("{bad " + FAKE_TOKEN_ASSIGNMENT, "json", lambda text: text.replace("token", "x"))
        self.assertIn("x=", redacted)
        self.assertTrue(errors)

    def test_invalid_json_strict(self):
        redacted, errors = redact_structured_text("{bad", "json", lambda text: text, strict_json=True)
        self.assertEqual(redacted, "")
        self.assertTrue(errors)

    def test_redact_text_api(self):
        result = redact_text("alice@example.test")
        self.assertTrue(result.changed)
        self.assertEqual(result.report.stats.findings, 1)

    def test_redactor_paths_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.log"
            path.write_text("alice@example.test", encoding="utf-8")
            report = Redactor().redact_paths([path])
            self.assertEqual(report.stats.files, 1)
            self.assertEqual(report.stats.findings, 1)

    def test_redact_path_bundle_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "trace.log"
            out = Path(tmp) / "bundle"
            src.write_text("alice@example.test", encoding="utf-8")
            bundle = redact_path([src], output_dir=out)
            self.assertTrue((Path(bundle.output_dir) / "reports" / "report.json").exists())

    def test_write_bundle_creates_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "trace.log"
            out = Path(tmp) / "bundle"
            src.write_text("alice@example.test", encoding="utf-8")
            report = redact_paths([src], validate_config({}))
            bundle = write_bundle(report, out)
            self.assertTrue((Path(bundle.output_dir) / "reports" / "report.md").exists())
            self.assertTrue((Path(bundle.output_dir) / "redacted" / "trace.log").exists())

    def test_bundle_diff_does_not_include_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "trace.log"
            out = Path(tmp) / "bundle"
            src.write_text("alice@example.test", encoding="utf-8")
            report = redact_paths([src], validate_config({}))
            write_bundle(report, out)
            diff_text = next((out / "diffs").glob("*.diff")).read_text(encoding="utf-8")
            self.assertNotIn("alice@example.test", diff_text)
            self.assertIn("<PII_", diff_text)

    def test_bundle_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "trace.log"
            out = Path(tmp) / "bundle"
            src.write_text("alice@example.test", encoding="utf-8")
            report = redact_paths([src], validate_config({}))
            bundle = write_bundle(report, out, zip_bundle=True)
            self.assertTrue(Path(bundle.zip_path).exists())

    def test_should_include_known_extension(self):
        self.assertTrue(should_include(Path("trace.jsonl"), validate_config({})))

    def test_should_skip_unknown_extension(self):
        self.assertFalse(should_include(Path("image.png"), validate_config({})))

    def test_read_binary_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.log"
            path.write_bytes(b"a\0b")
            with self.assertRaises(InputError):
                read_text_file(path, validate_config({}))

    def test_max_file_size_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.log"
            path.write_text("abc", encoding="utf-8")
            with self.assertRaises(InputError):
                read_text_file(path, validate_config({"max_file_bytes": 1}))

    def test_directory_scan_ignores_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "trace.log").write_text("alice@example.test", encoding="utf-8")
            (root / "image.png").write_text("alice@example.test", encoding="utf-8")
            report = redact_paths([root], validate_config({}))
            self.assertEqual(report.stats.files, 1)

    def test_json_file_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.json"
            path.write_text(json.dumps({"content": "alice@example.test"}), encoding="utf-8")
            report = redact_paths([path], validate_config({}))
            self.assertEqual(report.files[0].input_format, "json")
            self.assertIn("<PII_", report.files[0].redacted_text)

    def test_clean_json_not_marked_changed_by_formatting(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.json"
            original = json.dumps({"content": "clean"})
            path.write_text(original, encoding="utf-8")
            report = redact_paths([path], validate_config({}))
            self.assertFalse(report.files[0].changed)
            self.assertEqual(report.files[0].redacted_text, original)

    def test_jsonl_file_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.jsonl"
            path.write_text('{"content":"alice@example.test"}\n', encoding="utf-8")
            report = redact_paths([path], validate_config({}))
            self.assertEqual(report.files[0].input_format, "jsonl")
            self.assertIn("<PII_", report.files[0].redacted_text)

    def test_report_stats_by_category(self):
        result = redact_text("alice@example.test " + FAKE_TOKEN_ASSIGNMENT)
        stats = result.report.stats.to_dict()
        self.assertIn("pii", stats["by_category"])
        self.assertIn("secret", stats["by_category"])

    def test_report_file_summary(self):
        result = redact_text("alice@example.test")
        summary = result.report.files[0].to_summary()
        self.assertEqual(summary["findings"], 1)


if __name__ == "__main__":
    unittest.main()
