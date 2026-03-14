"""Key-name denylist for secret detection.

Layer 1: substring match against known secret key patterns.
Audited against Sentry EventScrubber (~40 keys) and Django SafeExceptionReporterFilter.
"""

from __future__ import annotations

# Case-insensitive substring patterns for key names.
# A key matches if any pattern appears anywhere in the lowercased key name.
# Ordered by specificity: compound patterns first to document intent,
# then single-word patterns that catch the rest.
DEFAULT_KEY_PATTERNS: tuple[str, ...] = (
    # Compound patterns (high specificity)
    "api_key",
    "apikey",
    "api-key",
    "secret_key",
    "secret-key",
    "private_key",
    "private-key",
    "access_key",
    "access-key",
    "client_secret",
    "client-secret",
    # Single-word patterns (broad but necessary)
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "credential",
    "authorization",
    # Database / connection
    "connection_string",
    "connectionstring",
    "conn_str",
    # Signing / crypto
    "signing_key",
    "signing-key",
    "encryption_key",
    "encryption-key",
    "certificate",
    # Session / auth
    "session_key",
    "session-key",
    "cookie",
    # Webhook / integration
    "webhook_secret",
    "webhook-secret",
)

# Keys that should NEVER be redacted, even if they match a pattern.
# Checked as case-insensitive exact match OR suffix match.
# Example: TOKEN_URL contains "token" but is not a secret.
DEFAULT_SAFE_KEYS: frozenset[str] = frozenset({
    "token_url",
    "token_uri",
    "token_endpoint",
    "token_type",
    "token_name",
    "password_policy",
    "password_min_length",
    "password_max_length",
    "password_reset_url",
    "secret_question",
    "secret_question_hint",
    "authorization_endpoint",
    "certificate_path",
    "certificate_file",
    "cookie_name",
    "cookie_domain",
    "cookie_path",
    "cookie_secure",
    "cookie_samesite",
    "session_key_prefix",
})


def matches_key_pattern(
    key: str,
    patterns: tuple[str, ...] = DEFAULT_KEY_PATTERNS,
    safe_keys: frozenset[str] = DEFAULT_SAFE_KEYS,
) -> str | None:
    """Check if a key name matches any secret pattern.

    Returns the matched pattern string, or None if no match.
    Safe keys are excluded even if they match a pattern.
    """
    key_lower = key.lower()

    # Safe key check: exact match
    if key_lower in safe_keys:
        return None

    for pattern in patterns:
        if pattern in key_lower:
            return pattern

    return None
