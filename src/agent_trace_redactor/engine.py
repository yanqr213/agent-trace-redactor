"""Redaction engine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Pattern, Tuple

from .config import RedactorConfig
from .models import Finding, Rule
from .placeholders import PlaceholderMap
from .utils import context_snippet, line_column_for_offset


@dataclass(frozen=True)
class CompiledRule:
    rule: Rule
    regex: Pattern[str]


@dataclass
class TextRedaction:
    text: str
    findings: List[Finding]
    changed: bool


class RedactionEngine:
    """Applies configured regex rules to text."""

    def __init__(self, config: RedactorConfig, placeholder_map: Optional[PlaceholderMap] = None):
        self.config = config
        self.placeholder_map = placeholder_map or PlaceholderMap(config.hash_salt, config.reveal_placeholder_map)
        self.rules = [CompiledRule(rule, re.compile(rule.pattern, rule.flags)) for rule in config.rules if rule.enabled]

    def redact_text(self, text: str, source: str = "<memory>", base_offset: int = 0) -> TextRedaction:
        findings: List[Finding] = []
        changed = False
        current = text
        for compiled in self.rules:
            current, rule_findings, rule_changed = self._apply_rule(compiled, current, source, base_offset)
            findings.extend(rule_findings)
            changed = changed or rule_changed
        return TextRedaction(text=current, findings=findings, changed=changed)

    def _apply_rule(
        self,
        compiled: CompiledRule,
        text: str,
        source: str,
        base_offset: int,
    ) -> Tuple[str, List[Finding], bool]:
        findings: List[Finding] = []
        changed = False
        pieces = []
        last = 0
        for match in compiled.regex.finditer(text):
            target_span = _target_span(match)
            if target_span[0] < last:
                continue
            secret_value = text[target_span[0] : target_span[1]]
            if not secret_value:
                continue
            placeholder = self.placeholder_map.placeholder_for(compiled.rule.category, secret_value)
            pieces.append(text[last : target_span[0]])
            pieces.append(placeholder)
            line, column = line_column_for_offset(text, target_span[0])
            findings.append(
                Finding(
                    category=compiled.rule.category,
                    rule=compiled.rule.name,
                    placeholder=placeholder,
                    file=source,
                    line=line,
                    column=column,
                    length=len(secret_value),
                    fingerprint=self.placeholder_map.fingerprint_for(secret_value),
                    context=_context_with_placeholder(text, target_span[0], target_span[1], placeholder, self.config.context_chars),
                )
            )
            last = target_span[1]
            changed = True
        if not changed:
            return text, [], False
        pieces.append(text[last:])
        return "".join(pieces), findings, True


def _target_span(match: re.Match[str]) -> Tuple[int, int]:
    if match.lastindex:
        for index in range(match.lastindex, 0, -1):
            try:
                value = match.group(index)
            except IndexError:
                continue
            if value is not None:
                return match.span(index)
    return match.span(0)


def _context_with_placeholder(text: str, start: int, end: int, placeholder: str, chars: int) -> str:
    snippet = context_snippet(text, start, end, chars)
    secret = text[start:end].replace("\n", "\\n").replace("\t", "\\t")
    return snippet.replace(secret, placeholder, 1)
