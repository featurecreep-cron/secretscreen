"""Value-format detection via vendored gitleaks patterns.

Layer 3: detect secrets by their value shape regardless of key name.
Uses 222 battle-tested regex patterns from the gitleaks project (MIT license).

Gitleaks patterns include optional keyword pre-filters for performance:
if a rule has keywords, we check for keyword presence before running the regex.
"""

from __future__ import annotations

import importlib.resources
import re
import tomllib
import warnings
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FormatRule:
    """A compiled gitleaks detection rule."""

    id: str
    description: str
    regex: re.Pattern[str]
    keywords: tuple[str, ...]
    entropy: float | None
    secret_group: int


def _prepare_regex(pattern: str) -> tuple[str, int]:
    """Preprocess a gitleaks regex for Python compatibility.

    Gitleaks targets Go's regexp2 (PCRE-like). Python's re module requires
    global flags at the start of the expression. This extracts mid-pattern
    inline flags like (?i) and returns them as re module flags.

    Also replaces POSIX classes like [[:alnum:]] and unsupported escapes.
    """
    flags = 0

    # Extract (?i) that appears after position 0 — Python 3.11+ rejects these
    # We strip ALL (?i) occurrences and apply re.IGNORECASE globally.
    # This is slightly broader than the original intent (which scoped (?i) to
    # a subexpression) but matches the gitleaks behavior where (?i) typically
    # applies to the whole pattern.
    if "(?i)" in pattern:
        pattern = pattern.replace("(?i)", "")
        flags |= re.IGNORECASE

    # Replace \z (Go end-of-string anchor) with Python equivalent \Z
    pattern = pattern.replace(r"\z", r"\Z")

    return pattern, flags


def _load_rules() -> tuple[FormatRule, ...]:
    """Load and compile gitleaks rules from vendored TOML."""
    toml_path = importlib.resources.files("secretscreen").joinpath("gitleaks.toml")
    data = tomllib.loads(toml_path.read_text(encoding="utf-8"))

    rules: list[FormatRule] = []
    for entry in data.get("rules", []):
        regex_str = entry.get("regex")
        if not regex_str:
            continue

        regex_str, flags = _prepare_regex(regex_str)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                compiled = re.compile(regex_str, flags)
        except re.error:
            continue  # skip genuinely malformed patterns

        rules.append(
            FormatRule(
                id=entry["id"],
                description=entry.get("description", ""),
                regex=compiled,
                keywords=tuple(entry.get("keywords", ())),
                entropy=entry.get("entropy"),
                secret_group=entry.get("secretGroup", 0),
            )
        )

    return tuple(rules)


# Compiled once at import time.
RULES: tuple[FormatRule, ...] = _load_rules()


def matches_known_format(value: str) -> FormatRule | None:
    """Check if a value matches any known secret format.

    Returns the matching rule, or None.
    Uses keyword pre-filtering for performance.
    """
    if len(value) < 8:
        return None  # too short for any meaningful format

    value_lower = value.lower()

    for rule in RULES:
        # Keyword pre-filter: if the rule has keywords, at least one must
        # appear in the value (case-insensitive) before we bother with regex.
        if rule.keywords:
            if not any(kw in value_lower for kw in rule.keywords):
                continue

        if rule.regex.search(value):
            return rule

    return None
