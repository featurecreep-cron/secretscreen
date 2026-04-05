"""URL credential detection and partial redaction.

Layer 4: detect and redact passwords embedded in URLs.
Only the password portion is replaced — username, host, path are preserved
for debugging utility.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

# Default replacement — matches _core.REDACTED but _urls is a leaf module,
# so we define our own default to avoid circular imports.
_DEFAULT_REPLACEMENT = "[REDACTED]"


# Multi-scheme URL prefixes that wrap a standard URL.
# urlsplit treats these as the scheme, making credentials invisible.
_URL_WRAPPERS = ("jdbc:", "odbc:")


def _strip_url_wrapper(value: str) -> str:
    """Strip multi-scheme prefixes so urlsplit can parse credentials."""
    lower = value.lower()
    for prefix in _URL_WRAPPERS:
        if lower.startswith(prefix):
            return value[len(prefix) :]
    return value


def has_url_credentials(value: str) -> bool:
    """Check if a value contains a URL with embedded credentials."""
    if "://" not in value:
        return False
    try:
        parsed = urlsplit(_strip_url_wrapper(value))
        return bool(parsed.scheme and parsed.password)
    except (ValueError, AttributeError):
        return False


def redact_url_password(value: str, replacement: str = _DEFAULT_REPLACEMENT) -> str:
    """Replace only the password portion of a credential URL.

    Preserves username, host, path, query, and fragment for debugging.
    """
    try:
        raw = _strip_url_wrapper(value)
        prefix = value[: len(value) - len(raw)]  # preserve original prefix casing
        parsed = urlsplit(raw)
        if not parsed.password:
            return value

        user = parsed.username or ""
        host = parsed.hostname or ""
        # Re-add brackets for IPv6 addresses
        if host and ":" in host:
            host = f"[{host}]"
        port_str = f":{parsed.port}" if parsed.port else ""
        new_netloc = f"{user}:{replacement}@{host}{port_str}"

        return prefix + urlunsplit(
            (
                parsed.scheme,
                new_netloc,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )
    except (ValueError, AttributeError):
        return _DEFAULT_REPLACEMENT
