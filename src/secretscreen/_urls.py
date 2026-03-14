"""URL credential detection and partial redaction.

Layer 4: detect and redact passwords embedded in URLs.
Only the password portion is replaced — username, host, path are preserved
for debugging utility.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

REDACTED = "[REDACTED]"


def has_url_credentials(value: str) -> bool:
    """Check if a value contains a URL with embedded credentials."""
    if "://" not in value:
        return False
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme and parsed.password)
    except (ValueError, AttributeError):
        return False


def redact_url_password(value: str, replacement: str = REDACTED) -> str:
    """Replace only the password portion of a credential URL.

    Preserves username, host, path, query, and fragment for debugging.
    """
    try:
        parsed = urlsplit(value)
        if not parsed.password:
            return value

        user = parsed.username or ""
        host = parsed.hostname or ""
        port_str = f":{parsed.port}" if parsed.port else ""
        new_netloc = f"{user}:{replacement}@{host}{port_str}"

        return urlunsplit((
            parsed.scheme,
            new_netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        ))
    except (ValueError, AttributeError):
        return replacement
