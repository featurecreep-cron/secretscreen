"""Tests for key-name pattern matching (Layer 1)."""

import pytest

from secretscreen._keys import DEFAULT_SAFE_KEYS, matches_key_pattern


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
    def test_ignores_safe_keys(self, key: str) -> None:
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


class TestSafeKeys:
    """Safe key allowlist."""

    @pytest.mark.parametrize(
        "key",
        [
            "TOKEN_URL",
            "TOKEN_URI",
            "TOKEN_ENDPOINT",
            "PASSWORD_POLICY",
            "AUTH_URL",
            "CERTIFICATE_PATH",
            "COOKIE_NAME",
        ],
    )
    def test_safe_keys_not_redacted(self, key: str) -> None:
        assert matches_key_pattern(key) is None

    def test_custom_safe_keys(self) -> None:
        custom_safe = frozenset({"my_special_token"})
        assert matches_key_pattern("MY_SPECIAL_TOKEN", safe_keys=custom_safe) is None

    def test_safe_keys_case_insensitive(self) -> None:
        assert matches_key_pattern("Token_URL") is None
        assert matches_key_pattern("TOKEN_URL") is None

    def test_safe_keys_are_exhaustive(self) -> None:
        """Every default safe key should contain at least one pattern substring."""
        for safe_key in DEFAULT_SAFE_KEYS:
            # Verify the safe key would match a pattern if not excluded
            result = matches_key_pattern(safe_key, safe_keys=frozenset())
            assert result is not None, f"Safe key {safe_key!r} doesn't match any pattern — unnecessary"


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
