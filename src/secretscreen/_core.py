"""Core orchestration — ties all detection layers together.

Public API: redact_pair, redact_dict, audit_pair, audit_dict.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace

from secretscreen._entropy import MIN_ENTROPY_LENGTH, looks_like_secret, shannon_entropy
from secretscreen._formats import matches_known_format
from secretscreen._keys import (
    DEFAULT_KEY_PATTERNS,
    DEFAULT_SAFE_SUFFIXES,
    matches_key_pattern,
)
from secretscreen._parsers import extract_pairs
from secretscreen._urls import credential_position, has_url_credentials, redact_url_credentials

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

# Maximum value length for the value-scanning layers (2-5). Prevents DoS via large
# inputs hitting 221+ regex patterns, at least one of which backtracks badly.
#
# The threshold is set from measured worst-case input — random high-entropy text,
# which is what a secret-shaped blob looks like — not from a run of one character.
# Cost is roughly quadratic above ~128KB:
#
#     64KB   0.57s        256KB   14s
#     128KB  1.00s        1MB    107s
#
# This was originally 1MB, chosen against a benign benchmark (a run of 'x', which
# is ~500x faster at the same size). That admitted exactly the input that hurts:
# a value one byte under the cap pinned a core for nearly two minutes. 64KB matches
# MAX_PARSE_LENGTH in _parsers.py, which already bounded layer 2 — so this only
# narrows layers 3-5, and only for values big enough to be data dumps, not config.
#
# Layer 1 (key-name match) is deliberately exempt: it reads only the key, so an
# oversized value under a secret-named key is still redacted. Residual gap: an
# oversized value under an innocuous key name is not scanned and passes through
# unredacted. Callers that print values (e.g. a CLI) should surface that skip
# rather than let it look screened.
_MAX_DETECT_LENGTH = 65_536  # 64 KB


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
        return redact_url_credentials(value, config.replacement)

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


# Depth at which the structure walkers stop descending. A guard against crafted
# input, so what it returns at the limit is a security decision rather than a
# housekeeping one: everything below the cap is replaced wholesale, because the
# alternative is handing back a subtree nothing has looked at.
_MAX_RECURSIVE_DEPTH = 100

_TOO_DEEP = f"nested deeper than {_MAX_RECURSIVE_DEPTH} levels; not scanned"


def _redact_recursive(
    data: object,
    config: ScreenConfig,
    _depth: int = 0,
    _key: str = "",
) -> object:
    """Recursively walk and redact a nested structure.

    A string inside a list is screened under the key the list belongs to:
    ``{"tokens": ["ghp_..."]}`` is the same claim about the same secret as
    ``{"token": "ghp_..."}``, and losing the key on the way into the list
    would take layer 1 out of the decision entirely.

    At the depth cap the whole remaining subtree becomes the replacement. It
    used to be returned as it arrived, which made the one guard against
    crafted input the one place a secret was printed unexamined.
    """
    if _depth >= _MAX_RECURSIVE_DEPTH:
        return config.replacement

    if isinstance(data, dict):
        out: dict[object, object] = {}
        for k, v in data.items():
            key_str = str(k)
            if isinstance(v, str):
                out[k] = _redact_string(key_str, v, config)
            elif isinstance(v, (dict, list)):
                out[k] = _redact_recursive(v, config, _depth + 1, key_str)
            else:
                out[k] = v
        return out

    if isinstance(data, list):
        return [
            _redact_string(_key, item, config)
            if isinstance(item, str)
            else _redact_recursive(item, config, _depth + 1, _key)
            for item in data
        ]

    return data


def _redact_string(key: str, value: str, config: ScreenConfig) -> str:
    """Redact one string, or return it unchanged when nothing matched."""
    finding, cached_pairs = _detect_with_pairs(key, value, config)
    if finding is None:
        return value
    return _apply_redaction(finding, key, value, config, cached_pairs)


# Explanation states. A value is either redacted, deliberately not redacted,
# not scanned, or nothing matched it — and the middle two are the ones worth
# reading, because they are where the tool made a decision to stay quiet.
STATE_REDACTED = "redacted"
STATE_VETOED = "vetoed"
STATE_CLEAN = "clean"
STATE_UNSCANNED = "unscanned"


@dataclass(frozen=True, slots=True)
class Explanation:
    """Why one key-value pair was or was not redacted. Never holds the value.

    ``key`` is for reading — inside a structure it is a path such as
    ``services[0].db.password``. ``name`` is the plain key that path ends at,
    which is what a caller matches rules against. Keeping both apart matters:
    matching a rule against the path is how an account of what happened ends
    up disagreeing with what was printed.
    """

    key: str
    state: str
    layer: str
    reason: str
    name: str = ""


def _vetoed_by_safe_suffix(key: str, config: ScreenConfig) -> tuple[str, str] | None:
    """Return (pattern, suffix) when a safe suffix suppressed a layer-1 match."""
    matched = matches_key_pattern(key, config.patterns, safe_suffixes=())
    if matched is None:
        return None
    key_lower = key.lower()
    for suffix in config.safe_suffixes:
        if key_lower.endswith(suffix):
            return matched, suffix
    return None


def _describe_finding(finding: Finding, value: str) -> str:
    """Render a finding as a reason phrase, without quoting the value."""
    detail = finding.reason.partition(":")[2]
    if finding.layer == "key_pattern":
        return f"matched {detail!r}"
    if finding.layer == "url_credentials":
        position = credential_position(value)
        return f"credential in {position} position" if position else "URL with embedded credentials"
    if finding.layer == "format_detection":
        return f"matches known format {detail}"
    if finding.layer == "entropy":
        return f"entropy {detail}"
    if finding.layer == "structured_parsing":
        return finding.detail or finding.reason
    return finding.reason


def _clean_reason(value: str, config: ScreenConfig) -> str:
    """Explain why nothing matched, quoting the nearest miss rather than silence.

    The entropy figure is computed even in normal mode, where layer 5 never
    runs. It is a single pass over the value and it is the one number that says
    what --aggressive would do differently, so the mode choice can be measured
    instead of guessed.
    """
    chars = "".join(value.split())
    if len(chars) < MIN_ENTROPY_LENGTH:
        return f"{len(chars)} chars, below the {MIN_ENTROPY_LENGTH}-char entropy floor"

    entropy = shannon_entropy(value, _stripped=chars)
    threshold = config.entropy_threshold
    if config.mode == Mode.NORMAL:
        verdict = "aggressive WOULD flag" if entropy >= threshold else "aggressive would not flag"
        return f"entropy {entropy:.2f} ({verdict}; threshold {threshold:.2f})"
    return f"entropy {entropy:.2f}, below threshold {threshold:.2f}"


def explain_pair(
    key: str,
    value: str,
    *,
    mode: Mode = Mode.NORMAL,
    extra_keys: tuple[str, ...] = (),
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES,
    entropy_threshold: float = 4.5,
) -> Explanation:
    """Account for one pair: what happened to it, and why.

    Reports on values that were *not* redacted as well as values that were.
    An undetected secret is invisible by definition, so the only defence
    against one is making the non-detections reviewable.
    """
    config = ScreenConfig(
        mode=mode,
        extra_keys=extra_keys,
        safe_suffixes=safe_suffixes,
        entropy_threshold=entropy_threshold,
    )
    return _explain(key, value, config)


def _explain(key: str, value: str, config: ScreenConfig) -> Explanation:
    if not isinstance(value, str) or not value:
        return Explanation(key, STATE_CLEAN, "", "empty value")

    finding = _detect(key, value, config)
    if finding is not None:
        return Explanation(key, STATE_REDACTED, finding.layer, _describe_finding(finding, value))

    # Order matters: layer 1 still redacts an oversized value under a secret
    # key name, so the size skip is only reported once detection has declined.
    if len(value) > _MAX_DETECT_LENGTH:
        return Explanation(
            key,
            STATE_UNSCANNED,
            "",
            f"{len(value)} bytes exceeds the {_MAX_DETECT_LENGTH}-byte scan cap",
        )

    vetoed = _vetoed_by_safe_suffix(key, config)
    if vetoed is not None:
        pattern, suffix = vetoed
        return Explanation(
            key,
            STATE_VETOED,
            "key_pattern",
            f"matched {pattern!r}, suppressed by safe suffix {suffix!r}",
        )

    return Explanation(key, STATE_CLEAN, "", _clean_reason(value, config))


def explain_dict(
    data: dict[str, object] | list[object] | object,
    *,
    mode: Mode = Mode.NORMAL,
    extra_keys: tuple[str, ...] = (),
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES,
    entropy_threshold: float = 4.5,
) -> list[Explanation]:
    """Account for every string value in a nested structure."""
    config = ScreenConfig(
        mode=mode,
        extra_keys=extra_keys,
        safe_suffixes=safe_suffixes,
        entropy_threshold=entropy_threshold,
    )
    explanations: list[Explanation] = []
    _explain_recursive(data, config, explanations)
    return explanations


def _explain_recursive(
    data: object,
    config: ScreenConfig,
    explanations: list[Explanation],
    _depth: int = 0,
    _prefix: str = "",
    _name: str = "",
) -> None:
    """Walk a structure, accounting for every string value it contains.

    Two keys are carried down, not one: the display path, and the plain key
    it ends at. A list element inherits the name of the key its list belongs
    to, the same key redaction screened it under.
    """
    if _depth >= _MAX_RECURSIVE_DEPTH:
        # "Accounts for every value" has to include the ones the cap stopped
        # it reaching. Returning quietly is the failure --explain exists for.
        explanations.append(Explanation(_prefix, STATE_UNSCANNED, "", _TOO_DEEP))
        return

    if isinstance(data, dict):
        for k, v in data.items():
            key_str = f"{_prefix}.{k}" if _prefix else str(k)
            if isinstance(v, str):
                explanations.append(replace(_explain(key_str, v, config), name=str(k)))
            elif isinstance(v, (dict, list)):
                _explain_recursive(v, config, explanations, _depth + 1, key_str, str(k))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            key_str = f"{_prefix}[{i}]"
            if isinstance(item, str):
                explanations.append(replace(_explain(key_str, item, config), name=_name))
            elif isinstance(item, (dict, list)):
                _explain_recursive(item, config, explanations, _depth + 1, key_str, _name)


def _audit_recursive(
    data: object,
    config: ScreenConfig,
    findings: list[Finding],
    _depth: int = 0,
    _key: str = "",
) -> None:
    """Recursively walk and audit a nested structure.

    Strings inside a list are audited under the key the list belongs to, so
    that what --audit reports and what redaction does cannot disagree. The
    finding keeps the plain key rather than an indexed path: callers match
    show/hide rules against it, and a rule naming ``tokens`` has to cover
    every element of ``tokens``.
    """
    if _depth >= _MAX_RECURSIVE_DEPTH:
        # Redaction replaces this subtree wholesale, so --audit has to say
        # something rather than exit 0 on a document it never looked into.
        findings.append(Finding(key=_key, reason=_TOO_DEEP, layer="unscanned", detail=_TOO_DEEP))
        return

    if isinstance(data, dict):
        for k, v in data.items():
            key_str = str(k)
            if isinstance(v, str):
                finding = _detect(key_str, v, config)
                if finding is not None:
                    findings.append(finding)
            elif isinstance(v, (dict, list)):
                _audit_recursive(v, config, findings, _depth + 1, key_str)

    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                finding = _detect(_key, item, config)
                if finding is not None:
                    findings.append(finding)
            else:
                _audit_recursive(item, config, findings, _depth + 1, _key)
