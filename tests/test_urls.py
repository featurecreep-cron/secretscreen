"""Tests for URL credential detection (Layer 4)."""

import pytest

from secretscreen._urls import has_url_credentials, redact_url_password


class TestUrlCredentialDetection:
    """URL credential detection."""

    @pytest.mark.parametrize(
        "url",
        [
            "postgres://admin:secret@localhost:5432/mydb",
            "mysql://root:password@db.host/database",
            "redis://:secretpass@redis.host:6379/0",
            "https://user:pass@api.example.com/v1",
        ],
    )
    def test_detects_url_credentials(self, url: str) -> None:
        assert has_url_credentials(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com",
            "postgres://localhost:5432/mydb",
            "redis://redis.host:6379/0",
            "not a url at all",
            "",
            "/var/lib/data",
        ],
    )
    def test_ignores_urls_without_credentials(self, url: str) -> None:
        assert has_url_credentials(url) is False


class TestUrlPasswordRedaction:
    """URL password partial redaction."""

    def test_postgres_url(self) -> None:
        result = redact_url_password("postgres://admin:secret@localhost:5432/mydb")
        assert "secret" not in result
        assert "admin" in result
        assert "localhost" in result
        assert "5432" in result
        assert "[REDACTED]" in result

    def test_preserves_path_and_query(self) -> None:
        result = redact_url_password("https://user:pass@host/path?q=1#frag")
        assert "/path" in result
        assert "q=1" in result
        assert "frag" in result
        assert "pass" not in result

    def test_custom_replacement(self) -> None:
        result = redact_url_password("postgres://admin:secret@host/db", replacement="***")
        assert "***" in result
        assert "secret" not in result

    def test_no_password_returns_unchanged(self) -> None:
        url = "postgres://localhost/mydb"
        assert redact_url_password(url) == url
