"""Tests for value-format detection (Layer 3)."""

import pytest

from secretscreen._formats import RULES, matches_known_format


class TestFormatDetection:
    """Known secret format detection via gitleaks patterns."""

    def test_rules_loaded(self) -> None:
        """Gitleaks TOML loads and compiles."""
        assert len(RULES) > 100

    @pytest.mark.parametrize(
        ("value", "expected_id"),
        [
            ("AKIAIOSFODNN7EXAMPLE", "aws-access-token"),
            ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github-pat"),
            # Slack and Stripe tokens omitted — GitHub push protection blocks them
            # even in test fixtures for a secret detection library.
        ],
    )
    def test_detects_known_formats(self, value: str, expected_id: str) -> None:
        result = matches_known_format(value)
        assert result is not None, f"Expected to detect {expected_id}"
        assert result.id == expected_id

    @pytest.mark.parametrize(
        "value",
        [
            "localhost",
            "true",
            "3306",
            "/var/lib/data",
            "application/json",
            "myapp",
            "production",
        ],
    )
    def test_ignores_normal_values(self, value: str) -> None:
        assert matches_known_format(value) is None

    def test_short_values_skipped(self) -> None:
        assert matches_known_format("abc") is None
        assert matches_known_format("") is None

    def test_returns_rule_with_metadata(self) -> None:
        result = matches_known_format("AKIAIOSFODNN7EXAMPLE")
        assert result is not None
        assert result.id == "aws-access-token"
        assert result.description  # non-empty
        assert result.regex is not None
