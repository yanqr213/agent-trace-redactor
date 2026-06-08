import json
import tempfile
import unittest
from pathlib import Path

from agent_trace_redactor.config import load_config, validate_config
from agent_trace_redactor.errors import ConfigError


class ConfigTests(unittest.TestCase):
    def test_default_config_loads(self):
        config = load_config()
        self.assertGreater(len(config.rules), 10)
        self.assertTrue(config.preserve_json)

    def test_unknown_key_rejected(self):
        with self.assertRaises(ConfigError):
            validate_config({"unknown": True})

    def test_rules_must_be_list(self):
        with self.assertRaises(ConfigError):
            validate_config({"rules": {}})

    def test_rule_must_be_object(self):
        with self.assertRaises(ConfigError):
            validate_config({"rules": ["bad"]})

    def test_rule_name_required(self):
        with self.assertRaises(ConfigError):
            validate_config({"rules": [{"pattern": "x"}]})

    def test_rule_pattern_required(self):
        with self.assertRaises(ConfigError):
            validate_config({"rules": [{"name": "x"}]})

    def test_bad_regex_rejected(self):
        with self.assertRaises(ConfigError):
            validate_config({"rules": [{"name": "bad", "pattern": "(", "category": "x"}]})

    def test_duplicate_rule_rejected(self):
        with self.assertRaises(ConfigError):
            validate_config(
                {
                    "rules": [
                        {"name": "dup", "pattern": "a", "category": "x"},
                        {"name": "dup", "pattern": "b", "category": "x"},
                    ]
                }
            )

    def test_disable_rule(self):
        config = validate_config({"disable_rules": ["email"]})
        email = [rule for rule in config.rules if rule.name == "email"][0]
        self.assertFalse(email.enabled)

    def test_context_chars_must_be_int(self):
        with self.assertRaises(ConfigError):
            validate_config({"context_chars": "48"})

    def test_max_file_bytes_must_be_positive(self):
        with self.assertRaises(ConfigError):
            validate_config({"max_file_bytes": 0})

    def test_hash_salt_required(self):
        with self.assertRaises(ConfigError):
            validate_config({"hash_salt": ""})

    def test_extensions_must_start_with_dot(self):
        with self.assertRaises(ConfigError):
            validate_config({"include_extensions": ["json"]})

    def test_flags_parse(self):
        config = validate_config({"rules": [{"name": "case", "pattern": "abc", "category": "x", "flags": ["IGNORECASE"]}]})
        self.assertTrue(config.rules[-1].flags)

    def test_bad_flag_rejected(self):
        with self.assertRaises(ConfigError):
            validate_config({"rules": [{"name": "case", "pattern": "abc", "category": "x", "flags": ["BAD"]}]})

    def test_load_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"context_chars": 12}), encoding="utf-8")
            config = load_config(str(path))
            self.assertEqual(config.context_chars, 12)

    def test_load_config_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(str(path))

    def test_overrides_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"context_chars": 12}), encoding="utf-8")
            config = load_config(str(path), overrides={"strict_json": True})
            self.assertEqual(config.context_chars, 12)
            self.assertTrue(config.strict_json)


if __name__ == "__main__":
    unittest.main()
