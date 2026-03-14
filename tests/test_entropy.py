"""Tests for Shannon entropy detection (Layer 5)."""

import pytest

from secretscreen._entropy import looks_like_secret, shannon_entropy


class TestShannonEntropy:
    """Entropy calculation."""

    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char_repeated(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_two_chars_equal(self) -> None:
        # 50/50 split = 1.0 bits
        result = shannon_entropy("abababababababababab")
        assert abs(result - 1.0) < 0.01

    def test_high_entropy_string(self) -> None:
        # Machine-generated secret should be high entropy
        result = shannon_entropy("a8Kz3mP9xQ2nR5tL7wB4yF6hJ0cV1dG")
        assert result > 4.0

    def test_low_entropy_string(self) -> None:
        # Human-readable words are low entropy
        result = shannon_entropy("hello world this is a test")
        assert result < 4.0

    def test_whitespace_stripped(self) -> None:
        """Spaces don't count toward entropy."""
        with_spaces = shannon_entropy("a b c d e f g h")
        without_spaces = shannon_entropy("abcdefgh")
        assert abs(with_spaces - without_spaces) < 0.01


class TestLooksLikeSecret:
    """Entropy-based secret detection."""

    def test_high_entropy_detected(self) -> None:
        result = looks_like_secret("a8Kz3mP9xQ2nR5tL7wB4yF6hJ0cV1dG")
        assert result is not None
        assert result > 4.0

    def test_normal_value_not_detected(self) -> None:
        assert looks_like_secret("hello world this is normal") is None

    def test_short_string_not_detected(self) -> None:
        assert looks_like_secret("abc") is None

    def test_custom_threshold(self) -> None:
        value = "a8Kz3mP9xQ2nR5tL7wB4yF6hJ0cV1dG"
        # Very high threshold — nothing matches
        assert looks_like_secret(value, threshold=6.0) is None
        # Very low threshold — everything matches
        assert looks_like_secret(value, threshold=2.0) is not None

    @pytest.mark.parametrize(
        "value",
        [
            "production",
            "localhost:5432",
            "application/json",
            "/var/lib/postgresql/data",
            "true",
        ],
    )
    def test_common_values_not_flagged(self, value: str) -> None:
        assert looks_like_secret(value) is None
