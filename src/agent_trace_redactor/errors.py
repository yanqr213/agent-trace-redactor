"""Error types used by the redactor."""


class RedactorError(Exception):
    """Base exception for agent-trace-redactor."""


class ConfigError(RedactorError):
    """Raised when a config file is invalid."""


class InputError(RedactorError):
    """Raised when an input path or stream cannot be read."""
