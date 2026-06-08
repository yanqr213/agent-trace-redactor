"""Config loading and validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .defaults import (
    DEFAULT_CONTEXT_CHARS,
    DEFAULT_EXTENSIONS,
    DEFAULT_HASH_SALT,
    DEFAULT_IGNORE_DIRS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_RULES,
)
from .errors import ConfigError
from .models import Rule


@dataclass
class RedactorConfig:
    """Validated redactor configuration."""

    rules: List[Rule] = field(default_factory=lambda: list(DEFAULT_RULES))
    context_chars: int = DEFAULT_CONTEXT_CHARS
    hash_salt: str = DEFAULT_HASH_SALT
    preserve_json: bool = True
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    include_extensions: List[str] = field(default_factory=lambda: sorted(DEFAULT_EXTENSIONS))
    ignore_dirs: List[str] = field(default_factory=lambda: sorted(DEFAULT_IGNORE_DIRS))
    reveal_placeholder_map: bool = False
    strict_json: bool = False

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "context_chars": self.context_chars,
            "preserve_json": self.preserve_json,
            "max_file_bytes": self.max_file_bytes,
            "include_extensions": list(self.include_extensions),
            "ignore_dirs": list(self.ignore_dirs),
            "reveal_placeholder_map": self.reveal_placeholder_map,
            "strict_json": self.strict_json,
            "rules": [
                {
                    "name": rule.name,
                    "category": rule.category,
                    "description": rule.description,
                    "enabled": rule.enabled,
                }
                for rule in self.rules
            ],
        }


def load_config(path: Optional[str] = None, overrides: Optional[Mapping[str, Any]] = None) -> RedactorConfig:
    data: Dict[str, Any] = {}
    if path:
        config_path = Path(path)
        try:
            text = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read config {config_path}: {exc}") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"config must be JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError("config root must be an object")

    if overrides:
        data = _deep_merge(data, dict(overrides))

    return validate_config(data)


def validate_config(data: Mapping[str, Any]) -> RedactorConfig:
    unknown = set(data) - {
        "rules",
        "disable_rules",
        "context_chars",
        "hash_salt",
        "preserve_json",
        "max_file_bytes",
        "include_extensions",
        "ignore_dirs",
        "reveal_placeholder_map",
        "strict_json",
    }
    if unknown:
        raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")

    rules = list(DEFAULT_RULES)
    disabled = _string_list(data.get("disable_rules", []), "disable_rules")
    if disabled:
        rules = [
            Rule(
                name=rule.name,
                pattern=rule.pattern,
                category=rule.category,
                description=rule.description,
                flags=rule.flags,
                enabled=rule.name not in disabled,
            )
            for rule in rules
        ]

    custom_rules = data.get("rules", [])
    if "rules" in data and not isinstance(custom_rules, list):
        raise ConfigError("rules must be a list")
    if custom_rules:
        rules.extend(_parse_rule(item, index) for index, item in enumerate(custom_rules))

    context_chars = _int_value(data.get("context_chars", DEFAULT_CONTEXT_CHARS), "context_chars", 0)
    max_file_bytes = _int_value(data.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES), "max_file_bytes", 1)
    hash_salt = data.get("hash_salt", DEFAULT_HASH_SALT)
    if not isinstance(hash_salt, str) or not hash_salt:
        raise ConfigError("hash_salt must be a non-empty string")

    include_extensions = _extension_list(data.get("include_extensions", sorted(DEFAULT_EXTENSIONS)))
    ignore_dirs = _string_list(data.get("ignore_dirs", sorted(DEFAULT_IGNORE_DIRS)), "ignore_dirs")

    config = RedactorConfig(
        rules=rules,
        context_chars=context_chars,
        hash_salt=hash_salt,
        preserve_json=_bool_value(data.get("preserve_json", True), "preserve_json"),
        max_file_bytes=max_file_bytes,
        include_extensions=include_extensions,
        ignore_dirs=ignore_dirs,
        reveal_placeholder_map=_bool_value(data.get("reveal_placeholder_map", False), "reveal_placeholder_map"),
        strict_json=_bool_value(data.get("strict_json", False), "strict_json"),
    )
    _validate_unique_rules(config.rules)
    _validate_regexes(config.rules)
    return config


def _parse_rule(item: Any, index: int) -> Rule:
    if not isinstance(item, dict):
        raise ConfigError(f"rules[{index}] must be an object")
    allowed = {"name", "pattern", "category", "description", "flags", "enabled"}
    unknown = set(item) - allowed
    if unknown:
        raise ConfigError(f"rules[{index}] has unknown keys: {', '.join(sorted(unknown))}")
    name = item.get("name")
    pattern = item.get("pattern")
    category = item.get("category", "custom")
    description = item.get("description", "")
    flags = item.get("flags", [])
    enabled = item.get("enabled", True)
    if not isinstance(name, str) or not name:
        raise ConfigError(f"rules[{index}].name must be a non-empty string")
    if not re.match(r"^[A-Za-z0-9_.-]+$", name):
        raise ConfigError(f"rules[{index}].name contains unsupported characters")
    if not isinstance(pattern, str) or not pattern:
        raise ConfigError(f"rules[{index}].pattern must be a non-empty string")
    if not isinstance(category, str) or not category:
        raise ConfigError(f"rules[{index}].category must be a non-empty string")
    if not isinstance(description, str):
        raise ConfigError(f"rules[{index}].description must be a string")
    if not isinstance(enabled, bool):
        raise ConfigError(f"rules[{index}].enabled must be a boolean")
    return Rule(name=name, pattern=pattern, category=category, description=description, flags=_regex_flags(flags), enabled=enabled)


def _regex_flags(flags: Any) -> int:
    if flags in (None, []):
        return 0
    if not isinstance(flags, list):
        raise ConfigError("rule flags must be a list")
    result = 0
    for flag in flags:
        if flag == "IGNORECASE":
            result |= re.IGNORECASE
        elif flag == "MULTILINE":
            result |= re.MULTILINE
        elif flag == "DOTALL":
            result |= re.DOTALL
        else:
            raise ConfigError(f"unsupported regex flag: {flag}")
    return result


def _validate_regexes(rules: Iterable[Rule]) -> None:
    for rule in rules:
        if not rule.enabled:
            continue
        try:
            re.compile(rule.pattern, rule.flags)
        except re.error as exc:
            raise ConfigError(f"invalid regex for rule {rule.name}: {exc}") from exc


def _validate_unique_rules(rules: Iterable[Rule]) -> None:
    names = set()
    for rule in rules:
        if rule.name in names:
            raise ConfigError(f"duplicate rule name: {rule.name}")
        names.add(rule.name)


def _int_value(value: Any, name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


def _bool_value(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be a boolean")
    return value


def _string_list(value: Any, name: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"{name} must be a list of non-empty strings")
    return list(value)


def _extension_list(value: Any) -> List[str]:
    items = _string_list(value, "include_extensions")
    normalized = []
    for item in items:
        if not item.startswith("."):
            raise ConfigError("include_extensions entries must start with '.'")
        normalized.append(item.lower())
    return sorted(set(normalized))


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
