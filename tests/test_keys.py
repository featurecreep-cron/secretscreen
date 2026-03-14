"""Tests for key-name pattern matching (Layer 1)."""

import pytest

from secretscreen._keys import DEFAULT_SAFE_SUFFIXES, matches_key_pattern


class TestKeyPatternMatching:
    """Key-name denylist detection."""

    @pytest.mark.parametrize(
        "key",
        [
            "DB_PASSWORD",
            "database_password",
            "PASSWORD",
            "my_passwd",
            "API_TOKEN",
            "access_token",
            "SECRET_KEY",
            "client_secret",
            "AWS_ACCESS_KEY_ID",
            "PRIVATE_KEY",
            "SMTP_CREDENTIAL",
            "SESSION_KEY",
        ],
    )
    def test_matches_secret_keys(self, key: str) -> None:
        assert matches_key_pattern(key) is not None

    @pytest.mark.parametrize(
        "key",
        [
            "APP_NAME",
            "DATABASE_HOST",
            "LOG_LEVEL",
            "PORT",
            "WORKERS",
            "TZ",
            "PGID",
            "PUID",
            "DOCKER_IMAGE",
        ],
    )
    def test_ignores_non_secret_keys(self, key: str) -> None:
        assert matches_key_pattern(key) is None

    def test_case_insensitive(self) -> None:
        assert matches_key_pattern("db_Password") is not None
        assert matches_key_pattern("DB_PASSWORD") is not None
        assert matches_key_pattern("Db_PaSsWoRd") is not None

    def test_substring_matching(self) -> None:
        """Pattern matches as substring — OAUTH2_CLIENT_SECRET matches 'secret'."""
        result = matches_key_pattern("OAUTH2_CLIENT_SECRET")
        assert result is not None

    def test_returns_matched_pattern(self) -> None:
        result = matches_key_pattern("DB_PASSWORD")
        assert result == "password"

    def test_returns_none_for_no_match(self) -> None:
        assert matches_key_pattern("APP_NAME") is None


class TestSafeSuffixes:
    """Safe suffix allowlist — prevents false positives on keys that match
    patterns but aren't secrets (e.g., TOKEN_URL, PASSWORD_REQUIRED)."""

    @pytest.mark.parametrize(
        "key",
        [
            # Exact safe suffix
            "TOKEN_URL",
            "TOKEN_URI",
            "TOKEN_ENDPOINT",
            "PASSWORD_POLICY",
            "CERTIFICATE_PATH",
            "COOKIE_NAME",
            # Prefixed variants — the real use case for suffix matching
            "GF_AUTH_GENERIC_OAUTH_TOKEN_URL",
            "PGADMIN_CONFIG_MASTER_PASSWORD_REQUIRED",
            "POSTGRES_PASSWORD_FILE",
            "AUTHENTIK_PASSWORD_RESET_URL",
        ],
    )
    def test_safe_suffixes_not_redacted(self, key: str) -> None:
        """Keys ending with a safe suffix are not redacted."""
        assert matches_key_pattern(key) is None

    def test_non_matching_key_also_not_redacted(self) -> None:
        """Keys that don't match any pattern aren't redacted regardless of suffixes."""
        assert matches_key_pattern("AUTH_URL") is None

    def test_custom_safe_suffixes(self) -> None:
        custom = ("_my_suffix",)
        assert matches_key_pattern("SECRET_MY_SUFFIX", safe_suffixes=custom) is None

    def test_safe_suffixes_case_insensitive(self) -> None:
        assert matches_key_pattern("Token_URL") is None
        assert matches_key_pattern("TOKEN_URL") is None

    def test_safe_suffixes_are_necessary(self) -> None:
        """Every default safe suffix should prevent at least one pattern match.

        If a suffix doesn't overlap with any pattern, it's unnecessary.
        """
        # Test representative keys for each suffix
        test_keys = {
            "_url": "TOKEN_URL",
            "_uri": "TOKEN_URI",
            "_endpoint": "TOKEN_ENDPOINT",
            "token_type": "TOKEN_TYPE",
            "token_name": "TOKEN_NAME",
            "password_policy": "PASSWORD_POLICY",
            "password_min_length": "PASSWORD_MIN_LENGTH",
            "password_max_length": "PASSWORD_MAX_LENGTH",
            "password_required": "PASSWORD_REQUIRED",
            "password_file": "PASSWORD_FILE",
            "secret_question": "SECRET_QUESTION",
            "secret_question_hint": "SECRET_QUESTION_HINT",
            "certificate_path": "CERTIFICATE_PATH",
            "certificate_file": "CERTIFICATE_FILE",
            "cookie_name": "COOKIE_NAME",
            "cookie_domain": "COOKIE_DOMAIN",
            "cookie_path": "COOKIE_PATH",
            "cookie_secure": "COOKIE_SECURE",
            "cookie_samesite": "COOKIE_SAMESITE",
            "session_key_prefix": "SESSION_KEY_PREFIX",
        }
        for suffix in DEFAULT_SAFE_SUFFIXES:
            test_key = test_keys.get(suffix)
            if test_key is None:
                pytest.fail(f"No test key for suffix {suffix!r} — add one")
            # Without safe suffixes, this key should match a pattern
            result = matches_key_pattern(test_key, safe_suffixes=())
            assert result is not None, (
                f"Safe suffix {suffix!r} (test key {test_key!r}) doesn't match any pattern — unnecessary"
            )


class TestCustomPatterns:
    """Custom key patterns."""

    def test_extra_patterns(self) -> None:
        patterns = ("password", "my_custom_field")
        assert matches_key_pattern("MY_CUSTOM_FIELD_NAME", patterns=patterns) is not None

    def test_defaults_still_work_with_extra(self) -> None:
        from secretscreen._keys import DEFAULT_KEY_PATTERNS

        patterns = DEFAULT_KEY_PATTERNS + ("custom",)
        assert matches_key_pattern("DB_PASSWORD", patterns=patterns) is not None
        assert matches_key_pattern("MY_CUSTOM", patterns=patterns) is not None
