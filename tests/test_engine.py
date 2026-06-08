import unittest

from agent_trace_redactor import Redactor, redact_text
from agent_trace_redactor.config import validate_config
from agent_trace_redactor.engine import RedactionEngine
from agent_trace_redactor.placeholders import PlaceholderMap


FAKE_OPENAI_KEY = "sk-" + "demoDocsOnlyKeyWithEnoughCharacters123"
FAKE_TOKEN_ASSIGNMENT = "token" + "=" + "demoTokenForDocsOnly123"
FAKE_PASSWORD_ASSIGNMENT = "password" + "=" + "demoPasswordOnly"


class EngineTests(unittest.TestCase):
    def test_redacts_openai_key(self):
        result = redact_text("key " + FAKE_OPENAI_KEY)
        self.assertIn("<SECRET_", result.text)
        self.assertNotIn(FAKE_OPENAI_KEY, result.text)

    def test_redacts_bearer_value_only(self):
        result = redact_text("Authorization: Bearer demoBearerTokenForDocsOnly123456")
        self.assertIn("Authorization: Bearer <SECRET_", result.text)

    def test_redacts_password_value_only(self):
        result = redact_text(FAKE_PASSWORD_ASSIGNMENT)
        self.assertIn("password" + "=<SECRET_", result.text)
        self.assertNotIn("demoPasswordOnly", result.text)

    def test_redacts_email(self):
        result = redact_text("contact alice@example.test")
        self.assertIn("<PII_", result.text)

    def test_redacts_phone(self):
        result = redact_text("call 555-123-4567")
        self.assertIn("<PII_", result.text)

    def test_redacts_private_ipv4(self):
        result = redact_text("host 192.168.1.20 failed")
        self.assertIn("<INTERNAL_NETWORK_", result.text)

    def test_redacts_windows_path(self):
        result = redact_text(r"C:\Users\alice\repo\file.txt")
        self.assertIn("<INTERNAL_PATH_", result.text)

    def test_redacts_unix_home_path(self):
        result = redact_text("/home/alice/repo/file.txt")
        self.assertIn("<INTERNAL_PATH_", result.text)

    def test_redacts_repo_url(self):
        result = redact_text("git@github.example.test:acme/private-agent.git")
        self.assertIn("<REPO_", result.text)

    def test_redacts_customer_domain(self):
        result = redact_text("https://acme-customer.prod.example.test/api")
        self.assertIn("<CUSTOMER_DOMAIN_", result.text)

    def test_stable_placeholder_same_value(self):
        redactor = Redactor()
        one = redactor.redact_text(FAKE_TOKEN_ASSIGNMENT).text
        two = redactor.redact_text(FAKE_TOKEN_ASSIGNMENT).text
        self.assertEqual(one, two)

    def test_same_value_repeated_same_placeholder(self):
        result = redact_text(FAKE_TOKEN_ASSIGNMENT + " " + FAKE_TOKEN_ASSIGNMENT)
        placeholders = [part for part in result.text.split() if "<SECRET_" in part]
        self.assertEqual(placeholders[0], placeholders[1])

    def test_custom_rule(self):
        config = validate_config({"rules": [{"name": "ticket", "pattern": r"\bACME-[0-9]+\b", "category": "internal_id"}]})
        result = Redactor(config).redact_text("ticket ACME-1234")
        self.assertIn("<INTERNAL_ID_", result.text)

    def test_disabled_email_rule(self):
        config = validate_config({"disable_rules": ["email"]})
        result = Redactor(config).redact_text("alice@example.test")
        self.assertEqual("alice@example.test", result.text)

    def test_finding_has_location(self):
        result = redact_text("hello\nalice@example.test")
        finding = result.findings[0]
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.column, 1)

    def test_context_uses_placeholder(self):
        result = redact_text("before alice@example.test after")
        self.assertNotIn("alice@example.test", result.findings[0].context)
        self.assertIn("<PII_", result.findings[0].context)

    def test_report_does_not_reveal_value_by_default(self):
        result = redact_text("alice@example.test")
        text = str(result.report.to_dict())
        self.assertNotIn("alice@example.test", text)

    def test_reveal_placeholder_map_opt_in(self):
        config = validate_config({"reveal_placeholder_map": True})
        result = Redactor(config).redact_text("alice@example.test")
        self.assertIn("alice@example.test", str(result.report.to_dict()["placeholders"]))

    def test_private_key_block(self):
        text = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
        result = redact_text(text)
        self.assertEqual(result.text.strip(), result.findings[0].placeholder)

    def test_no_findings_when_clean(self):
        result = redact_text("normal debug output")
        self.assertFalse(result.findings)
        self.assertEqual(result.text, "normal debug output")

    def test_placeholder_map_fingerprint(self):
        mapping = PlaceholderMap("salt")
        placeholder = mapping.placeholder_for("secret", "value")
        self.assertIn(placeholder, mapping.to_public_dict())
        self.assertNotIn("value", str(mapping.to_public_dict()))

    def test_engine_can_reuse_placeholder_map(self):
        config = validate_config({})
        engine = RedactionEngine(config)
        one = engine.redact_text("alice@example.test").text
        two = engine.redact_text("alice@example.test").text
        self.assertEqual(one, two)


if __name__ == "__main__":
    unittest.main()
