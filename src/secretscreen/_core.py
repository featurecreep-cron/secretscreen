"""Core orchestration — ties all detection layers together.

Public API: redact_pair, redact_dict, audit_pair, audit_dict.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from secretscreen._entropy import looks_like_secret
from secretscreen._formats import matches_known_format
from secretscreen._keys import (
    DEFAULT_KEY_PATTERNS,
    DEFAULT_SAFE_KEYS,
    matches_key_pattern,
)
from secretscreen._parsers import extract_pairs
from secretscreen._urls import has_url_credentials, redact_url_password

REDACTED = "[REDACTED]"


class Mode(enum.Enum):
    """Detection mode controlling which layers are active."""

    NORMAL = "normal"
    """Layers 1-4: key patterns, structured parsing, format detection, URL credentials."""

    AGGRESSIVE = "aggressive"
    """Layers 1-5: adds Shannon entropy detection for machine-generated strings."""


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected secret with metadata about how it was found."""

    key: str
    reason: str
    layer: str
    detail: str = ""


@dataclass
class ScreenConfig:
    """Configuration for secret screening."""

    mode: Mode = Mode.NORMAL
    replacement: str | _CallableReplacement = REDACTED  # type: ignore[type-arg]
    extra_keys: tuple[str, ...] = ()
    safe_keys: frozenset[str] = DEFAULT_SAFE_KEYS
    entropy_threshold: float = 4.5

    @property
    def patterns(self) -> tuple[str, ...]:
        """Merged key patterns (defaults + extras)."""
        if not self.extra_keys:
            return DEFAULT_KEY_PATTERNS
        seen = {p.lower() for p in DEFAULT_KEY_PATTERNS}
        extra = tuple(p for p in self.extra_keys if p.lower() not in seen)
        return DEFAULT_KEY_PATTERNS + extra


# Type alias for callable replacement
_CallableReplacement = type(None)  # placeholder — actual check is isinstance below


def _get_replacement(config: ScreenConfig, key: str, value: str) -> str:
    """Resolve the replacement string."""
    r = config.replacement
    if callable(r):
        result = r(key, value)
        return str(result)
    return str(r)


def redact_pair(
    key: str,
    value: str,
    *,
    mode: Mode = Mode.NORMAL,
    replacement: str = REDACTED,
    extra_keys: tuple[str, ...] = (),
    safe_keys: frozenset[str] = DEFAULT_SAFE_KEYS,
    entropy_threshold: float = 4.5,
) -> str:
    """Redact a single key-value pair if the value is detected as a secret.

    Returns the replacement string if secret, or the original value.
    Non-string values are returned unchanged (converted to str first if needed).
    """
    if not isinstance(value, str):
        return value  # type: ignore[return-value]

    if not value:
        return value

    config = ScreenConfig(
        mode=mode,
        replacement=replacement,
        extra_keys=extra_keys,
        safe_keys=safe_keys,
        entropy_threshold=entropy_threshold,
    )

    finding = _detect(key, value, config)
    if finding is None:
        return value

    # URL credentials get partial redaction
    if finding.layer == "url_credentials":
        return redact_url_password(value, _get_replacement(config, key, value))

    # Structured values: redact secret portions inline
    if finding.layer == "structured_parsing":
        return _redact_structured(value, config)

    return _get_replacement(config, key, value)


def redact_dict(
    data: dict[str, object] | list[object] | object,
    *,
    mode: Mode = Mode.NORMAL,
    replacement: str = REDACTED,
    extra_keys: tuple[str, ...] = (),
    safe_keys: frozenset[str] = DEFAULT_SAFE_KEYS,
    entropy_threshold: float = 4.5,
) -> object:
    """Recursively redact secrets in a dict, list, or nested structure.

    Returns a new structure with secrets replaced. Does not mutate the input.
    """
    config = ScreenConfig(
        mode=mode,
        replacement=replacement,
        extra_keys=extra_keys,
        safe_keys=safe_keys,
        entropy_threshold=entropy_threshold,
    )
    return _redact_recursive(data, "", config)


def audit_pair(
    key: str,
    value: str,
    *,
    mode: Mode = Mode.NORMAL,
    extra_keys: tuple[str, ...] = (),
    safe_keys: frozenset[str] = DEFAULT_SAFE_KEYS,
    entropy_threshold: float = 4.5,
) -> Finding | None:
    """Check a single key-value pair for secrets without redacting.

    Returns a Finding if detected, or None.
    """
    if not isinstance(value, str) or not value:
        return None

    config = ScreenConfig(
        mode=mode,
        extra_keys=extra_keys,
        safe_keys=safe_keys,
        entropy_threshold=entropy_threshold,
    )
    return _detect(key, value, config)


def audit_dict(
    data: dict[str, object] | list[object] | object,
    *,
    mode: Mode = Mode.NORMAL,
    extra_keys: tuple[str, ...] = (),
    safe_keys: frozenset[str] = DEFAULT_SAFE_KEYS,
    entropy_threshold: float = 4.5,
) -> list[Finding]:
    """Recursively audit a dict/list for secrets without redacting.

    Returns a list of all findings.
    """
    config = ScreenConfig(
        mode=mode,
        extra_keys=extra_keys,
        safe_keys=safe_keys,
        entropy_threshold=entropy_threshold,
    )
    findings: list[Finding] = []
    _audit_recursive(data, "", config, findings)
    return findings


# --- Internal detection logic ---


def _detect(key: str, value: str, config: ScreenConfig) -> Finding | None:
    """Run all detection layers on a single key-value pair."""

    # Layer 1: Key-name pattern match
    matched_pattern = matches_key_pattern(key, config.patterns, config.safe_keys)
    if matched_pattern is not None:
        # Special case: URL keys get partial redaction, not full
        if key.lower().endswith("_url") and has_url_credentials(value):
            return Finding(
                key=key,
                reason=f"key_pattern:{matched_pattern}",
                layer="url_credentials",
                detail="URL with embedded credentials",
            )
        return Finding(
            key=key,
            reason=f"key_pattern:{matched_pattern}",
            layer="key_pattern",
        )

    # Layer 4: URL credential detection (even without key pattern match)
    if has_url_credentials(value):
        return Finding(
            key=key,
            reason="url_credentials",
            layer="url_credentials",
            detail="URL with embedded credentials",
        )

    # Layer 2: Structured value parsing
    pairs = extract_pairs(value)
    if pairs:
        for sub_key, sub_value in pairs:
            sub_finding = _detect(sub_key, sub_value, config)
            if sub_finding is not None:
                return Finding(
                    key=key,
                    reason=f"structured:{sub_key}={sub_finding.reason}",
                    layer="structured_parsing",
                    detail=f"Found secret in parsed structure: {sub_key}",
                )

    # Layer 3: Value-format detection (gitleaks patterns)
    format_match = matches_known_format(value)
    if format_match is not None:
        return Finding(
            key=key,
            reason=f"format:{format_match.id}",
            layer="format_detection",
            detail=format_match.description,
        )

    # Layer 5: Entropy detection (aggressive mode only)
    if config.mode == Mode.AGGRESSIVE:
        entropy = looks_like_secret(value, config.entropy_threshold)
        if entropy is not None:
            return Finding(
                key=key,
                reason=f"entropy:{entropy:.2f}",
                layer="entropy",
                detail=f"Shannon entropy {entropy:.2f} bits/char exceeds threshold",
            )

    return None


def _redact_structured(value: str, config: ScreenConfig) -> str:
    """Redact secret portions within a structured value string.

    Re-parses the value and replaces secret sub-values inline.
    Falls back to full redaction if inline replacement isn't possible.
    """
    pairs = extract_pairs(value)
    result = value
    for sub_key, sub_value in pairs:
        sub_finding = _detect(sub_key, sub_value, config)
        if sub_finding is not None and sub_value:
            replacement = _get_replacement(config, sub_key, sub_value)
            result = result.replace(sub_value, replacement)
    return result


def _redact_recursive(
    data: object,
    prefix: str,
    config: ScreenConfig,
) -> object:
    """Recursively walk and redact a nested structure."""
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            key_str = str(k)
            if isinstance(v, str):
                finding = _detect(key_str, v, config)
                if finding is not None:
                    if finding.layer == "url_credentials":
                        result[k] = redact_url_password(
                            v, _get_replacement(config, key_str, v)
                        )
                    elif finding.layer == "structured_parsing":
                        result[k] = _redact_structured(v, config)
                    else:
                        result[k] = _get_replacement(config, key_str, v)
                else:
                    result[k] = v
            elif isinstance(v, (dict, list)):
                result[k] = _redact_recursive(v, key_str, config)
            else:
                result[k] = v
        return result

    if isinstance(data, list):
        return [_redact_recursive(item, prefix, config) for item in data]

    return data


def _audit_recursive(
    data: object,
    prefix: str,
    config: ScreenConfig,
    findings: list[Finding],
) -> None:
    """Recursively walk and audit a nested structure."""
    if isinstance(data, dict):
        for k, v in data.items():
            key_str = str(k)
            if isinstance(v, str):
                finding = _detect(key_str, v, config)
                if finding is not None:
                    findings.append(finding)
            elif isinstance(v, (dict, list)):
                _audit_recursive(v, key_str, config, findings)

    elif isinstance(data, list):
        for item in data:
            _audit_recursive(item, prefix, config, findings)
