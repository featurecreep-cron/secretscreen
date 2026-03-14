"""Detect and redact secrets in key-value pairs, dicts, and environment variables.

Best-effort defense-in-depth. Not a security boundary.

Five detection layers:
1. Key-name denylist — substring match against known secret key patterns.
2. Structured value parsing — JSON, Python literals, INI, DSN, URL query params.
3. Value-format detection — 222 known secret formats via vendored gitleaks patterns.
4. URL credential detection — partial redaction of embedded passwords.
5. Entropy detection — Shannon entropy for machine-generated strings (aggressive mode).

Two modes:
- NORMAL: layers 1-4, zero false positives target.
- AGGRESSIVE: layers 1-5, adds entropy detection.

audit_pair() and audit_dict() return structured findings without mutating values.
"""

from secretscreen._core import (
    Finding,
    Mode,
    audit_dict,
    audit_pair,
    redact_dict,
    redact_pair,
)

__all__ = [
    "Finding",
    "Mode",
    "audit_dict",
    "audit_pair",
    "redact_dict",
    "redact_pair",
]

__version__ = "0.1.0"
