"""Stable placeholder mapping."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .utils import sha256_short


@dataclass
class PlaceholderMap:
    """Maps sensitive values to stable placeholders without exposing originals."""

    salt: str
    reveal_values: bool = False
    _by_key: Dict[str, str] = field(default_factory=dict)
    _metadata: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def placeholder_for(self, category: str, value: str) -> str:
        fingerprint = sha256_short(value, self.salt)
        key = f"{category}:{fingerprint}"
        if key not in self._by_key:
            placeholder = f"<{_category_label(category)}_{fingerprint.upper()}>"
            self._by_key[key] = placeholder
            record = {
                "category": category,
                "fingerprint": fingerprint,
            }
            if self.reveal_values:
                record["value"] = value
            self._metadata[placeholder] = record
        return self._by_key[key]

    def fingerprint_for(self, value: str) -> str:
        return sha256_short(value, self.salt)

    def to_public_dict(self) -> Dict[str, Dict[str, str]]:
        return dict(sorted(self._metadata.items()))


def _category_label(category: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in category.upper())
    cleaned = "_".join(part for part in cleaned.split("_") if part)
    return cleaned or "REDACTED"
