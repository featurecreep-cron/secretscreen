"""Detect and redact secrets in key-value pairs, dicts, and environment variables.

Best-effort defense-in-depth. Not a security boundary.

Also ships a CLI for shell use — `secretscreen FILE...` redacts and prints,
`--audit` reports findings without values. See README.md.

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

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _metadata_version

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

# Read from installed metadata, which hatch-vcs derives from the git tag. A
# hardcoded literal here would be a second source of truth and would drift the
# moment a release is cut — `--version` would then report a version that is not
# the one the user installed.
try:
    __version__ = _metadata_version("secretscreen")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+dev"
