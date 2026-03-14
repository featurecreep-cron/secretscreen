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

# Suffixes that mark a key as safe even if it matches a pattern.
# Checked as case-insensitive suffix match against the key name.
# Example: GF_AUTH_GENERIC_OAUTH_TOKEN_URL ends with "token_url" → safe.
# Suffix matching catches prefixed variants (PGADMIN_CONFIG_*, GF_AUTH_*, etc.)
# that exact matching misses.
DEFAULT_SAFE_SUFFIXES: tuple[str, ...] = (
    # URL/endpoint suffixes — not secrets, just config pointing to auth endpoints
    "_url",  # catches TOKEN_URL, PASSWORD_RESET_URL, etc. when key has _url suffix
    "_uri",
    "_endpoint",
    # Type/name metadata
    "token_type",
    "token_name",
    # Policy/config (not the secret itself)
    "password_policy",
    "password_min_length",
    "password_max_length",
    "password_required",  # e.g. MASTER_PASSWORD_REQUIRED = "False"
    "password_file",  # path to a file, not the password itself
    "secret_question",
    "secret_question_hint",
    # File paths
    "certificate_path",
    "certificate_file",
    # Cookie metadata
    "cookie_name",
    "cookie_domain",
    "cookie_path",
    "cookie_secure",
    "cookie_samesite",
    # Session metadata
    "session_key_prefix",
)


def matches_key_pattern(
    key: str,
    patterns: tuple[str, ...] = DEFAULT_KEY_PATTERNS,
    safe_suffixes: tuple[str, ...] = DEFAULT_SAFE_SUFFIXES,
) -> str | None:
    """Check if a key name matches any secret pattern.

    Returns the matched pattern string, or None if no match.
    Keys ending with a safe suffix are excluded even if they match a pattern.
    """
    key_lower = key.lower()

    # Safe suffix check — catches prefixed variants like
    # GF_AUTH_GENERIC_OAUTH_TOKEN_URL, PGADMIN_CONFIG_MASTER_PASSWORD_REQUIRED
    for suffix in safe_suffixes:
        if key_lower.endswith(suffix):
            return None

    for pattern in patterns:
        if pattern in key_lower:
            return pattern

    return None
