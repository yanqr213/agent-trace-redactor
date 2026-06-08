"""Public API for agent-trace-redactor."""

from .api import RedactionResult, Redactor, redact_path, redact_text
from .config import RedactorConfig, load_config
from .errors import ConfigError, RedactorError

__all__ = [
    "ConfigError",
    "RedactionResult",
    "Redactor",
    "RedactorConfig",
    "RedactorError",
    "load_config",
    "redact_path",
    "redact_text",
]

__version__ = "0.1.0"
