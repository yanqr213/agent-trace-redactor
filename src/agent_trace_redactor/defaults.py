"""Default rules and config values."""

from __future__ import annotations

from .models import Rule

DEFAULT_CONTEXT_CHARS = 48
DEFAULT_HASH_SALT = "agent-trace-redactor-v1"
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_SCHEMA_VERSION = "agent-trace-redactor.report.v1"

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "dist",
    "build",
}

DEFAULT_EXTENSIONS = {
    ".json",
    ".jsonl",
    ".log",
    ".txt",
    ".md",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".trace",
    ".out",
    ".err",
}

DEFAULT_RULES = [
    Rule(
        name="aws_access_key_id",
        pattern=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        category="secret",
        description="AWS access key id",
    ),
    Rule(
        name="aws_secret_assignment",
        pattern=r"(?i)\b(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{32,64})",
        category="secret",
        description="AWS secret value in assignment",
    ),
    Rule(
        name="openai_api_key",
        pattern=r"\bsk-[A-Za-z0-9_-]{20,}\b",
        category="secret",
        description="OpenAI-style API key",
    ),
    Rule(
        name="anthropic_api_key",
        pattern=r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
        category="secret",
        description="Anthropic-style API key",
    ),
    Rule(
        name="github_token",
        pattern=r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
        category="secret",
        description="GitHub token",
    ),
    Rule(
        name="bearer_token",
        pattern=r"(?i)\b(Authorization\s*[:=]\s*Bearer\s+)([A-Za-z0-9._~+/=-]{16,})",
        category="secret",
        description="Bearer authorization token",
    ),
    Rule(
        name="password_assignment",
        pattern=r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret)\b(\s*[:=]\s*)([^\s,;\"']{6,})",
        category="secret",
        description="Common secret assignment",
    ),
    Rule(
        name="private_key_block",
        pattern=r"-----BEGIN [A-Z ]*PRIVATE[ ]KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE[ ]KEY-----",
        category="secret",
        description="PEM private key block",
    ),
    Rule(
        name="ssh_private_key_start",
        pattern=r"-----BEGIN OPENSSH PRIVATE[ ]KEY-----[\s\S]*?-----END OPENSSH PRIVATE[ ]KEY-----",
        category="secret",
        description="OpenSSH private key block",
    ),
    Rule(
        name="private_repo_url",
        pattern=r"\b(?:git@|ssh://git@|https://)[A-Za-z0-9._-]+(?::|/)[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(?:\.git)?\b",
        category="repo",
        description="Private repository URL",
    ),
    Rule(
        name="email",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        category="pii",
        description="Email address",
    ),
    Rule(
        name="phone",
        pattern=r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)",
        category="pii",
        description="Phone number",
    ),
    Rule(
        name="ipv4_private",
        pattern=r"\b(?:(?:10)\.(?:\d{1,3}\.){2}\d{1,3}|(?:172)\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|(?:192\.168)\.\d{1,3}\.\d{1,3})\b",
        category="internal_network",
        description="Private IPv4 address",
    ),
    Rule(
        name="windows_user_path",
        pattern=r"\b[A-Za-z]:\\Users\\[^\\\r\n]+(?:\\[^\r\n\t :;,'\"]+)*",
        category="internal_path",
        description="Windows user path",
    ),
    Rule(
        name="unix_home_path",
        pattern=r"(?<![\w/])/(?:Users|home)/[A-Za-z0-9._-]+(?:/[^\s\"'<>]+)*",
        category="internal_path",
        description="Unix home path",
    ),
    Rule(
        name="workspace_path",
        pattern=r"(?<![\w/])/(?:workspace|workspaces|repo|repos|src|var/tmp|tmp)/[A-Za-z0-9._/-]+",
        category="internal_path",
        description="Common workspace path",
    ),
    Rule(
        name="customer_domain_hint",
        pattern=r"\b[A-Za-z0-9-]+(?:corp|internal|customer|client|tenant|prod|staging|dev)[A-Za-z0-9-]*\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        category="customer_domain",
        description="Likely customer or internal domain",
    ),
]
