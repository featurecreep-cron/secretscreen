"""Tests for URL credential detection (Layer 4)."""

import pytest

from secretscreen._urls import has_url_credentials, redact_url_credentials


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


class TestUserinfoCredentials:
    """Userinfo with no password — the shape notification services use.

    ``discord://TOKEN@id`` has a username and no password, so a password-only
    check reports it clean and the token prints verbatim.
    """

    @pytest.mark.parametrize(
        ("url", "secret"),
        [
            ("discord://Mzk4NjYxMTIzNDU2.GxYzAb.tokenvalue@1234567890", "Mzk4NjYxMTIzNDU2.GxYzAb.tokenvalue"),
            ("ntfy://tk_ab12cd34@ntfy.sh", "tk_ab12cd34"),
            ("telegram://110201543:AAHdqTcv@telegram", "AAHdqTcv"),
            ("matrix://user:pass@matrix.org", "pass"),
            ("pushover://shoutrrr:apptoken@usertoken", "apptoken"),
            ("teams://token@ntfy.example.com", "token"),
        ],
    )
    def test_notification_schemes_are_credentials(self, url: str, secret: str) -> None:
        assert has_url_credentials(url) is True
        assert secret not in redact_url_credentials(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://username@github.com/org/repo.git",
            "ssh://git@github.com/org/repo.git",
            "git://git@example.com/repo",
            "ftp://anonymous@ftp.example.com/pub",
            "postgres://appuser@db.lan:5432/nextcloud",
            "redis://cacheuser@cache.lan:6379/0",
            "mongodb://reader@mongo.lan/analytics",
        ],
    )
    def test_plain_userinfo_schemes_are_identities_not_secrets(self, url: str) -> None:
        """A bare username on a familiar transport is an identity, not a token."""
        assert has_url_credentials(url) is False
        assert redact_url_credentials(url) == url

    def test_unknown_scheme_fails_closed(self) -> None:
        """A scheme nobody anticipated is treated as credential-bearing."""
        assert has_url_credentials("someservice://abc123token@host") is True

    def test_password_wins_over_plain_scheme(self) -> None:
        """The scheme judgement applies only to userinfo with no password."""
        url = "https://user:s3cr3t@api.example.com/v1"
        assert has_url_credentials(url) is True
        result = redact_url_credentials(url)
        assert "s3cr3t" not in result
        assert "user" in result

    def test_scheme_match_is_case_insensitive(self) -> None:
        assert has_url_credentials("HTTPS://username@github.com/repo") is False
        assert has_url_credentials("DISCORD://tokenvalue@1234567890") is True

    def test_empty_password_falls_through_to_userinfo_rule(self) -> None:
        """``foo://user:@host`` has no secret in the password position."""
        assert has_url_credentials("https://user:@host/path") is False
        assert has_url_credentials("discord://tokenvalue:@host") is True

    def test_empty_username_with_password(self) -> None:
        result = redact_url_credentials("redis://:secretpass@redis.host:6379/0")
        assert "secretpass" not in result
        assert "redis.host" in result
        assert "6379" in result


class TestUrlPasswordRedaction:
    """URL credential partial redaction."""

    def test_postgres_url(self) -> None:
        result = redact_url_credentials("postgres://admin:secret@localhost:5432/mydb")
        assert "secret" not in result
        assert "admin" in result
        assert "localhost" in result
        assert "5432" in result
        assert "REDACTED" in result

    def test_preserves_path_and_query(self) -> None:
        result = redact_url_credentials("https://user:pass@host/path?q=1#frag")
        assert "/path" in result
        assert "q=1" in result
        assert "frag" in result
        assert "pass" not in result

    def test_custom_replacement(self) -> None:
        result = redact_url_credentials("postgres://admin:secret@host/db", replacement="***")
        assert "***" in result
        assert "secret" not in result

    def test_no_password_returns_unchanged(self) -> None:
        url = "postgres://localhost/mydb"
        assert redact_url_credentials(url) == url

    def test_userinfo_redaction_preserves_everything_else(self) -> None:
        result = redact_url_credentials("gotify://apptoken@gotify.lan:8080/message?priority=5#top")
        assert "apptoken" not in result
        assert "gotify.lan" in result
        assert "8080" in result
        assert "/message" in result
        assert "priority=5" in result
        assert "top" in result

    def test_userinfo_redaction_drops_the_username(self) -> None:
        """The username IS the secret here, so preserving it would defeat the point."""
        result = redact_url_credentials("discord://tokenvalue123@987654321")
        assert "tokenvalue123" not in result
        assert "987654321" in result


class TestUrlRedactionEdgeCases:
    """Malformed, unusual, and adversarial URL shapes."""

    def test_ipv6_host_keeps_brackets(self) -> None:
        result = redact_url_credentials("redis://user:secret@[::1]:6379/0")
        assert "[::1]" in result
        assert "secret" not in result

    def test_ipv6_host_with_userinfo_only(self) -> None:
        result = redact_url_credentials("discord://tokenvalue@[2001:db8::1]:8443/path")
        assert "[2001:db8::1]" in result
        assert "tokenvalue" not in result

    @pytest.mark.parametrize("wrapper", ["jdbc:", "odbc:", "JDBC:"])
    def test_wrapped_schemes_with_userinfo(self, wrapper: str) -> None:
        """Wrapper prefixes hide the real scheme from urlsplit."""
        result = redact_url_credentials(f"{wrapper}postgresql://admin:S3cr3t@prod-db:5432/main")
        assert "S3cr3t" not in result
        assert result.startswith(wrapper)

    def test_missing_host(self) -> None:
        result = redact_url_credentials("discord://tokenvalue@")
        assert "tokenvalue" not in result

    def test_percent_encoded_password_is_removed(self) -> None:
        """urlsplit decodes userinfo; the encoded form must not survive either."""
        result = redact_url_credentials("postgres://admin:p%40ssw0rd@db.lan/app")
        assert "p%40ssw0rd" not in result
        assert "p@ssw0rd" not in result

    def test_unparseable_url_returns_replacement_not_the_value(self) -> None:
        """A value we cannot parse must never be echoed back verbatim."""
        # An invalid port makes urlsplit raise when .port is read.
        result = redact_url_credentials("discord://tokenvalue@host:notaport/path")
        assert "tokenvalue" not in result

    def test_scheme_relative_and_garbage_inputs(self) -> None:
        for value in ["://no-scheme@host", "http://", "://", "a://"]:
            redact_url_credentials(value)  # must not raise

    def test_redaction_is_idempotent(self) -> None:
        """Re-screening already-screened output must be stable."""
        once = redact_url_credentials("discord://tokenvalue@1234567890")
        twice = redact_url_credentials(once)
        assert once == twice

    def test_password_redaction_is_idempotent(self) -> None:
        once = redact_url_credentials("postgres://admin:secret@db.lan/app")
        twice = redact_url_credentials(once)
        assert once == twice

    def test_no_scheme_is_not_a_credential(self) -> None:
        assert has_url_credentials("user:password@host/path") is False

    @pytest.mark.parametrize(
        "url",
        [
            "http://[user:s3cr3t@internal.lan/db",  # unclosed IPv6 bracket
            "discord://tokenvalue@[::1",  # truncated IPv6 literal
        ],
    )
    def test_unparseable_url_shapes_fail_closed(self, url: str) -> None:
        """A URL-looking value we cannot parse must be treated as a credential.

        Reporting it clean let the whole value print verbatim, because the
        redaction half — which does fail closed — was never reached.
        """
        assert has_url_credentials(url) is True
        assert "s3cr3t" not in redact_url_credentials(url)
        assert "tokenvalue" not in redact_url_credentials(url)

    def test_unparseable_url_is_redacted_end_to_end(self) -> None:
        from secretscreen import audit_pair, redact_pair

        value = "http://[user:s3cr3t@internal.lan/db"
        assert audit_pair("NOTIFY", value) is not None
        assert "s3cr3t" not in redact_pair("NOTIFY", value)


class TestNetlocReplacementToken:
    """The replacement token is stripped of URL-structural characters.

    Inside a netloc the default ``[REDACTED]`` cannot be used verbatim: any
    ``[`` makes urlsplit read the netloc as an IPv6 literal and raise, so the
    redacted output would be unreadable on a second pass. Redaction inside a
    URL therefore prints ``REDACTED`` without brackets. This is deliberate and
    pinned here, because it is the one place the token differs from the rest
    of the output.
    """

    def test_default_token_loses_its_brackets_inside_a_url(self) -> None:
        assert redact_url_credentials("postgres://admin:secret@db.lan/app") == "postgres://admin:REDACTED@db.lan/app"

    def test_redacted_output_is_reparseable(self) -> None:
        from urllib.parse import urlsplit

        for url in ["postgres://admin:secret@db.lan/app", "discord://tokenvalue@1234567890"]:
            urlsplit(redact_url_credentials(url))  # must not raise

    @pytest.mark.parametrize("replacement", ["***", "<hidden>", "[hidden]", "XXX"])
    def test_custom_replacements_survive_sanitisation(self, replacement: str) -> None:
        result = redact_url_credentials("discord://tokenvalue@123", replacement=replacement)
        assert "tokenvalue" not in result
        assert replacement.strip("[]") in result

    def test_replacement_of_only_structural_characters_falls_back(self) -> None:
        """A replacement that sanitises to nothing must not produce empty userinfo."""
        result = redact_url_credentials("discord://tokenvalue@123", replacement="[]")
        assert "tokenvalue" not in result
        assert "REDACTED" in result

    @pytest.mark.parametrize(
        ("replacement", "expected"),
        [("a@b", "discord://ab@123"), ("x/y", "discord://xy@123"), ("@", "discord://REDACTED@123")],
    )
    def test_replacement_containing_netloc_delimiters(self, replacement: str, expected: str) -> None:
        """'@' and '/' would re-split the netloc, not just break the IPv6 check."""
        assert redact_url_credentials("discord://tokenvalue@123", replacement=replacement) == expected

    @pytest.mark.parametrize("url", ["discord://1234567890/path", "gotify://gotify.lan:8080/message"])
    def test_credential_bearing_scheme_without_userinfo_is_untouched(self, url: str) -> None:
        """The scheme rule applies to userinfo, not to the scheme alone."""
        assert has_url_credentials(url) is False
        assert redact_url_credentials(url) == url


class TestLayerOneUrlInteraction:
    """Keys that match a secret pattern *and* end in a safe '_url' suffix.

    The suffix vetoes layer 1's name match, so these reach layer 4 and get
    partial redaction rather than whole-value replacement. Pinned because the
    two rules interact and neither file makes that obvious on its own.
    """

    @pytest.mark.parametrize("key", ["NOTIFY_TOKEN_URL", "WEBHOOK_SECRET_URL", "APP_PASSWORD_URL"])
    def test_userinfo_credential_under_safe_suffix_key(self, key: str) -> None:
        from secretscreen import redact_pair

        result = redact_pair(key, "discord://tokenvalue@123")
        assert "tokenvalue" not in result
        assert "123" in result  # partial, not whole-value replacement
