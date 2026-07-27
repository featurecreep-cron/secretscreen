"""Core orchestration — ties all detection layers together.

Public API: redact_pair, redact_dict, audit_pair, audit_dict.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from secretscreen._entropy import looks_like_secret
from secretscreen._formats import matches_known_format
from secretscreen._keys import (
    DEFAULT_KEY_PATTERNS,
    DEFAULT_SAFE_SUFFIXES,
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
    replacement: str = REDACTED
    extra_keys: tuple[str, ...] = ()
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES
    entropy_threshold: float = 4.5

    def __post_init__(self) -> None:
        """Pre-compute merged patterns to avoid recomputation per key."""
        if not self.extra_keys:
            self._patterns = DEFAULT_KEY_PATTERNS
        else:
            seen = {p.lower() for p in DEFAULT_KEY_PATTERNS}
            extra = tuple(p for p in self.extra_keys if p.lower() not in seen)
            self._patterns = DEFAULT_KEY_PATTERNS + extra

    @property
    def patterns(self) -> tuple[str, ...]:
        """Merged key patterns (defaults + extras)."""
        return self._patterns


def redact_pair(
    key: str,
    value: str,
    *,
    mode: Mode = Mode.NORMAL,
    replacement: str = REDACTED,
    extra_keys: tuple[str, ...] = (),
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES,
    entropy_threshold: float = 4.5,
) -> str:
    """Redact a single key-value pair if the value is detected as a secret.

    Returns the replacement string if secret, or the original value.
    """
    if not isinstance(value, str) or not value:
        return value

    config = ScreenConfig(
        mode=mode,
        replacement=replacement,
        extra_keys=extra_keys,
        safe_suffixes=safe_suffixes,
        entropy_threshold=entropy_threshold,
    )

    finding, cached_pairs = _detect_with_pairs(key, value, config)
    if finding is None:
        return value

    return _apply_redaction(finding, key, value, config, cached_pairs)


def redact_dict(
    data: dict[str, object] | list[object] | object,
    *,
    mode: Mode = Mode.NORMAL,
    replacement: str = REDACTED,
    extra_keys: tuple[str, ...] = (),
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES,
    entropy_threshold: float = 4.5,
) -> object:
    """Recursively redact secrets in a dict, list, or nested structure.

    Returns a new structure with secrets replaced. Does not mutate the input.
    """
    config = ScreenConfig(
        mode=mode,
        replacement=replacement,
        extra_keys=extra_keys,
        safe_suffixes=safe_suffixes,
        entropy_threshold=entropy_threshold,
    )
    return _redact_recursive(data, config)


def audit_pair(
    key: str,
    value: str,
    *,
    mode: Mode = Mode.NORMAL,
    extra_keys: tuple[str, ...] = (),
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES,
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
        safe_suffixes=safe_suffixes,
        entropy_threshold=entropy_threshold,
    )
    return _detect(key, value, config)


def audit_dict(
    data: dict[str, object] | list[object] | object,
    *,
    mode: Mode = Mode.NORMAL,
    extra_keys: tuple[str, ...] = (),
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES,
    entropy_threshold: float = 4.5,
) -> list[Finding]:
    """Recursively audit a dict/list for secrets without redacting.

    Returns a list of all findings.
    """
    config = ScreenConfig(
        mode=mode,
        extra_keys=extra_keys,
        safe_suffixes=safe_suffixes,
        entropy_threshold=entropy_threshold,
    )
    findings: list[Finding] = []
    _audit_recursive(data, config, findings)
    return findings


# Maximum recursion depth for structured parsing detection.
# Prevents stack overflow from crafted nested JSON/Python literals.
_MAX_DETECT_DEPTH = 3

# Maximum value length for the value-scanning layers (2-5). Values beyond this
# are likely data dumps, not config values. Prevents DoS via large inputs hitting
# 221+ regex patterns. Layer 1 (key-name match) is deliberately exempt: it reads
# only the key, so an oversized value under a secret-named key is still redacted.
# Residual gap: an oversized value under an innocuous key name is not scanned and
# passes through unredacted. Callers that print values (e.g. a CLI) should surface
# that skip rather than let it look screened.
_MAX_DETECT_LENGTH = 1_048_576  # 1 MB


def _detect(key: str, value: str, config: ScreenConfig, _depth: int = 0) -> Finding | None:
    """Run all detection layers on a single key-value pair.

    For callers that only need the verdict. Redaction paths should use
    _detect_with_pairs to avoid re-parsing structured values.
    """
    return _detect_with_pairs(key, value, config, _depth)[0]


def _detect_with_pairs(
    key: str, value: str, config: ScreenConfig, _depth: int = 0
) -> tuple[Finding | None, list[tuple[str, str]] | None]:
    """Run all detection layers, also returning parsed pairs on a structured hit.

    _redact_structured reuses those pairs instead of parsing the value a second
    time. The pairs are None for every other layer and for a clean value.
    """
    oversized = len(value) > _MAX_DETECT_LENGTH

    # Layer 1: Key-name pattern match. Runs even when oversized — it reads the key,
    # not the value, so it costs nothing and still catches SECRET_KEY=<huge blob>.
    matched_pattern = matches_key_pattern(key, config.patterns, config.safe_suffixes)
    if matched_pattern is not None:
        # URL keys get partial redaction, not full. Skipped when oversized:
        # partial redaction has to scan the value, and a 50 MB URL is not a URL.
        if not oversized and key.lower().endswith("_url") and has_url_credentials(value):
            return (
                Finding(
                    key=key,
                    reason=f"key_pattern:{matched_pattern}",
                    layer="url_credentials",
                    detail="URL with embedded credentials",
                ),
                None,
            )
        return (
            Finding(
                key=key,
                reason=f"key_pattern:{matched_pattern}",
                layer="key_pattern",
            ),
            None,
        )

    # Layers 2-5 all scan the value itself. Stop here for oversized input.
    if oversized:
        return (None, None)

    # Layer 4: URL credential detection (even without key pattern match)
    if has_url_credentials(value):
        return (
            Finding(
                key=key,
                reason="url_credentials",
                layer="url_credentials",
                detail="URL with embedded credentials",
            ),
            None,
        )

    # Layer 2: Structured value parsing (depth-limited to prevent recursion bombs)
    if _depth < _MAX_DETECT_DEPTH:
        pairs = extract_pairs(value)
    else:
        pairs = []
    if pairs:
        for sub_key, sub_value in pairs:
            sub_finding = _detect(sub_key, sub_value, config, _depth + 1)
            if sub_finding is not None:
                finding = Finding(
                    key=key,
                    reason=f"structured:{sub_key}={sub_finding.reason}",
                    layer="structured_parsing",
                    detail=f"Found secret in parsed structure: {sub_key}",
                )
                return (finding, pairs)

    # Layer 3: Value-format detection (gitleaks patterns)
    format_match = matches_known_format(value)
    if format_match is not None:
        return (
            Finding(
                key=key,
                reason=f"format:{format_match.id}",
                layer="format_detection",
                detail=format_match.description,
            ),
            None,
        )

    # Layer 5: Entropy detection (aggressive mode only)
    if config.mode == Mode.AGGRESSIVE:
        entropy = looks_like_secret(value, config.entropy_threshold)
        if entropy is not None:
            return (
                Finding(
                    key=key,
                    reason=f"entropy:{entropy:.2f}",
                    layer="entropy",
                    detail=f"Shannon entropy {entropy:.2f} bits/char exceeds threshold",
                ),
                None,
            )

    return (None, None)


def _apply_redaction(
    finding: Finding,
    key: str,
    value: str,
    config: ScreenConfig,
    cached_pairs: list[tuple[str, str]] | None = None,
) -> str:
    """Apply the appropriate redaction strategy based on finding layer.

    Single source of truth for layer-specific redaction behavior.
    Used by both redact_pair and _redact_recursive.
    """
    if finding.layer == "url_credentials":
        return redact_url_password(value, config.replacement)

    if finding.layer == "structured_parsing":
        return _redact_structured(value, config, cached_pairs)

    return config.replacement


def _redact_structured(
    value: str,
    config: ScreenConfig,
    cached_pairs: list[tuple[str, str]] | None = None,
) -> str:
    """Redact secret portions within a structured value string.

    Uses pre-parsed pairs from detection when available to avoid
    re-parsing the value. Replaces only exact secret values, tracking
    which values have been replaced to avoid collateral damage when a
    secret string appears as a substring of a non-secret value.
    """
    pairs = cached_pairs if cached_pairs else extract_pairs(value)
    # Collect secret values and their replacements
    secrets_to_redact: dict[str, str] = {}
    for sub_key, sub_value in pairs:
        if not sub_value:
            continue
        sub_finding = _detect(sub_key, sub_value, config)
        if sub_finding is not None:
            secrets_to_redact[sub_value] = config.replacement

    if not secrets_to_redact:
        return value

    # Replace longest secrets first to avoid partial matches
    # when one secret is a substring of another
    redacted = value
    for secret in sorted(secrets_to_redact, key=len, reverse=True):
        redacted = redacted.replace(secret, secrets_to_redact[secret])
    return redacted


_MAX_RECURSIVE_DEPTH = 100


def _redact_recursive(
    data: object,
    config: ScreenConfig,
    _depth: int = 0,
) -> object:
    """Recursively walk and redact a nested structure."""
    if _depth >= _MAX_RECURSIVE_DEPTH:
        return data

    if isinstance(data, dict):
        out: dict[object, object] = {}
        for k, v in data.items():
            key_str = str(k)
            if isinstance(v, str):
                finding, cached_pairs = _detect_with_pairs(key_str, v, config)
                if finding is not None:
                    out[k] = _apply_redaction(finding, key_str, v, config, cached_pairs)
                else:
                    out[k] = v
            elif isinstance(v, (dict, list)):
                out[k] = _redact_recursive(v, config, _depth + 1)
            else:
                out[k] = v
        return out

    if isinstance(data, list):
        return [_redact_recursive(item, config, _depth + 1) for item in data]

    return data


def _audit_recursive(
    data: object,
    config: ScreenConfig,
    findings: list[Finding],
    _depth: int = 0,
) -> None:
    """Recursively walk and audit a nested structure."""
    if _depth >= _MAX_RECURSIVE_DEPTH:
        return

    if isinstance(data, dict):
        for k, v in data.items():
            key_str = str(k)
            if isinstance(v, str):
                finding = _detect(key_str, v, config)
                if finding is not None:
                    findings.append(finding)
            elif isinstance(v, (dict, list)):
                _audit_recursive(v, config, findings, _depth + 1)

    elif isinstance(data, list):
        for item in data:
            _audit_recursive(item, config, findings, _depth + 1)
