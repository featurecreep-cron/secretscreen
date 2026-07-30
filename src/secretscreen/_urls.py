"""URL credential detection and partial redaction.

Layer 4: detect and redact credentials embedded in URLs.
Only the credential portion is replaced — username, host, path are preserved
for debugging utility, except where the username *is* the credential.

Credentials appear in two positions:

- ``scheme://user:password@host`` — the classic form. The password is the
  secret regardless of scheme.
- ``scheme://TOKEN@host`` — userinfo with no password. Notification and
  push services (shoutrrr, apprise) use this shape almost universally:
  ``discord://TOKEN@id``, ``ntfy://tk_xxx@ntfy.sh``, ``telegram://TOKEN@telegram``.

Only the second form needs a scheme judgement, because ``user@host`` is an
identity rather than a secret for the familiar transports — ``git@github.com``,
``https://user@github.com/repo.git``. Those are listed explicitly and every
other scheme is treated as credential-bearing, so a notification service
nobody here has heard of fails closed rather than printing its token.

Secrets in the *path* (``gotify://host/TOKEN``) are out of scope: detecting
them would require guessing that a long path segment is a token, which fires
on ordinary URLs. Those are a job for an explicit key rule.
"""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit, urlunsplit

# Default replacement — matches _core.REDACTED but _urls is a leaf module,
# so we define our own default to avoid circular imports.
_DEFAULT_REPLACEMENT = "[REDACTED]"


# Multi-scheme URL prefixes that wrap a standard URL.
# urlsplit treats these as the scheme, making credentials invisible.
_URL_WRAPPERS = ("jdbc:", "odbc:")


# Schemes where a username with no password is an identity, not a secret.
# Databases are included: a bare role name carries nothing, and the
# password form is caught by the password branch regardless of scheme.
_PLAIN_USERINFO_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "ssh",
        "sftp",
        "git",
        "rsync",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "rediss",
        "mongodb",
        "mongodb+srv",
        "amqp",
        "amqps",
    }
)

# Credential positions, in the order they are checked.
_KIND_PASSWORD = "password"
_KIND_USERINFO = "userinfo"


def _strip_url_wrapper(value: str) -> str:
    """Strip multi-scheme prefixes so urlsplit can parse credentials."""
    lower = value.lower()
    for prefix in _URL_WRAPPERS:
        if lower.startswith(prefix):
            return value[len(prefix) :]
    return value


def _netloc_safe(replacement: str) -> str:
    """Strip characters that make a replacement token unparseable inside a netloc.

    ``urlsplit`` treats any ``[`` in the netloc as the start of an IPv6 literal
    and raises, so the default ``[REDACTED]`` written into the userinfo position
    produces output that cannot be read back. Screening already-screened data
    would then collapse the whole URL to the bare token — no leak, but the host
    and path are lost for no reason. Redaction has to be idempotent.
    """
    stripped = replacement
    for char in "[]@/?#":
        stripped = stripped.replace(char, "")
    return stripped or "REDACTED"


def _credential_kind(parsed: SplitResult) -> str | None:
    """Classify where the credential sits in a parsed URL, or None if clean.

    An empty password (``foo://user:@host``) is not a secret, so it falls
    through to the userinfo rule rather than redacting nothing of value.
    """
    if not parsed.scheme:
        return None
    if parsed.password:
        return _KIND_PASSWORD
    if parsed.username and parsed.scheme.lower() not in _PLAIN_USERINFO_SCHEMES:
        return _KIND_USERINFO
    return None


def has_url_credentials(value: str) -> bool:
    """Check if a value contains a URL with embedded credentials.

    A value that looks like a URL but cannot be parsed counts as
    credential-bearing. urlsplit rejects malformed IPv6 brackets and invalid
    ports, and ``http://[user:pw@host`` is both unparseable and a credential —
    reporting it clean let it print verbatim. Redaction already failed closed
    on the same input, so the two halves disagreed and the safe half never ran.
    """
    if "://" not in value:
        return False
    try:
        return _credential_kind(urlsplit(_strip_url_wrapper(value))) is not None
    except (ValueError, AttributeError):
        return True


def redact_url_credentials(value: str, replacement: str = _DEFAULT_REPLACEMENT) -> str:
    """Replace only the credential portion of a URL.

    Preserves host, path, query, and fragment for debugging. The username is
    preserved when the password is the secret, and replaced when the username
    itself is the credential (``discord://TOKEN@id``).

    Returns the value unchanged when there is no credential to remove, and the
    bare replacement when the URL cannot be parsed at all — an unparseable
    value must not be echoed.
    """
    try:
        raw = _strip_url_wrapper(value)
        prefix = value[: len(value) - len(raw)]  # preserve original prefix casing
        parsed = urlsplit(raw)
        kind = _credential_kind(parsed)
        if kind is None:
            return value

        token = _netloc_safe(replacement)
        if kind == _KIND_PASSWORD:
            new_userinfo = f"{parsed.username or ''}:{token}"
        else:
            new_userinfo = token

        host = parsed.hostname or ""
        # Re-add brackets for IPv6 addresses
        if host and ":" in host:
            host = f"[{host}]"
        port_str = f":{parsed.port}" if parsed.port else ""
        new_netloc = f"{new_userinfo}@{host}{port_str}"

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
