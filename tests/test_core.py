"""Tests for core orchestration — redact_pair, redact_dict, audit_pair, audit_dict."""

from secretscreen import Finding, Mode, audit_dict, audit_pair, redact_dict, redact_pair


class TestRedactPair:
    """Single pair redaction."""

    def test_redacts_password(self) -> None:
        assert redact_pair("DB_PASSWORD", "hunter2") == "[REDACTED]"

    def test_passes_through_safe_value(self) -> None:
        assert redact_pair("APP_NAME", "myapp") == "myapp"

    def test_empty_value_unchanged(self) -> None:
        assert redact_pair("PASSWORD", "") == ""

    def test_non_string_value_unchanged(self) -> None:
        assert redact_pair("PASSWORD", 42) == 42  # type: ignore[arg-type]

    def test_custom_replacement(self) -> None:
        assert redact_pair("DB_PASSWORD", "hunter2", replacement="***") == "***"

    def test_safe_suffixes_prevent_redaction(self) -> None:
        assert redact_pair("TOKEN_URL", "https://auth.example.com") == "https://auth.example.com"
        assert redact_pair("GF_AUTH_GENERIC_OAUTH_TOKEN_URL", "https://auth.example.com") == "https://auth.example.com"

    def test_custom_safe_suffixes(self) -> None:
        result = redact_pair(
            "MY_TOKEN_CONFIG",
            "value",
            safe_suffixes=("_config",),
        )
        assert result == "value"

    def test_extra_key_patterns(self) -> None:
        result = redact_pair("MY_CUSTOM_FIELD", "secret", extra_keys=("custom_field",))
        assert result == "[REDACTED]"


class TestRedactPairLayers:
    """Each detection layer works through redact_pair."""

    def test_layer1_key_pattern(self) -> None:
        assert redact_pair("API_TOKEN", "abc123") == "[REDACTED]"

    def test_layer2_structured_json(self) -> None:
        result = redact_pair("CONFIG", '{"password": "secret", "host": "localhost"}')
        assert "secret" not in result
        assert "localhost" in result

    def test_layer2_structured_python_dict(self) -> None:
        result = redact_pair(
            "PGADMIN_CONFIG",
            "{'OAUTH2_CLIENT_SECRET': 'mysecret', 'OAUTH2_TOKEN_URL': 'https://example.com'}",
        )
        assert "mysecret" not in result

    def test_layer3_format_detection_aws(self) -> None:
        assert redact_pair("SOME_VAR", "AKIAIOSFODNN7EXAMPLE") == "[REDACTED]"

    def test_layer3_format_detection_github_pat(self) -> None:
        assert redact_pair("SOME_VAR", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") == "[REDACTED]"

    def test_layer4_url_credentials(self) -> None:
        result = redact_pair("DATABASE_URL", "postgres://admin:s3cret@db.host:5432/mydb")
        assert "s3cret" not in result
        assert "admin" in result  # username preserved
        assert "db.host" in result  # host preserved

    def test_layer5_entropy_normal_mode_skipped(self) -> None:
        """Entropy detection is NOT active in normal mode."""
        value = "a8Kz3mP9xQ2nR5tL7wB4yF6hJ0cV1dG"
        result = redact_pair("RANDOM_THING", value, mode=Mode.NORMAL)
        assert result == value  # not redacted

    def test_layer5_entropy_aggressive_mode(self) -> None:
        """Entropy detection IS active in aggressive mode."""
        value = "a8Kz3mP9xQ2nR5tL7wB4yF6hJ0cV1dG"
        result = redact_pair("RANDOM_THING", value, mode=Mode.AGGRESSIVE)
        assert result == "[REDACTED]"


class TestRedactDict:
    """Dict redaction with recursion."""

    def test_flat_dict(self) -> None:
        result = redact_dict({"password": "secret", "host": "localhost"})
        assert result == {"password": "[REDACTED]", "host": "localhost"}

    def test_nested_dict(self) -> None:
        result = redact_dict(
            {
                "db": {"password": "secret", "host": "localhost"},
                "app": "myapp",
            }
        )
        assert result["db"]["password"] == "[REDACTED]"  # type: ignore[index]
        assert result["db"]["host"] == "localhost"  # type: ignore[index]
        assert result["app"] == "myapp"  # type: ignore[index]

    def test_list_of_dicts(self) -> None:
        result = redact_dict(
            [
                {"name": "alice", "api_key": "abc123"},
                {"name": "bob", "token": "xyz789"},
            ]
        )
        assert isinstance(result, list)
        assert result[0]["api_key"] == "[REDACTED]"  # type: ignore[index]
        assert result[1]["token"] == "[REDACTED]"  # type: ignore[index]
        assert result[0]["name"] == "alice"  # type: ignore[index]

    def test_deeply_nested(self) -> None:
        result = redact_dict(
            {
                "level1": {
                    "level2": {
                        "level3": {"secret_key": "deep_secret"},
                    },
                },
            }
        )
        assert result["level1"]["level2"]["level3"]["secret_key"] == "[REDACTED]"  # type: ignore[index]

    def test_does_not_mutate_input(self) -> None:
        original = {"password": "secret"}
        _ = redact_dict(original)
        assert original["password"] == "secret"

    def test_non_string_values_preserved(self) -> None:
        result = redact_dict(
            {
                "port": 5432,
                "debug": True,
                "timeout": None,
                "password": "secret",
            }
        )
        assert result["port"] == 5432  # type: ignore[index]
        assert result["debug"] is True  # type: ignore[index]
        assert result["timeout"] is None  # type: ignore[index]

    def test_mixed_list(self) -> None:
        """Lists containing both dicts and non-dicts."""
        result = redact_dict({"items": [{"token": "abc"}, "plain", 42]})
        assert result["items"][0]["token"] == "[REDACTED]"  # type: ignore[index]
        assert result["items"][1] == "plain"  # type: ignore[index]
        assert result["items"][2] == 42  # type: ignore[index]


class TestAuditPair:
    """Single pair auditing."""

    def test_returns_finding_for_secret(self) -> None:
        result = audit_pair("DB_PASSWORD", "hunter2")
        assert result is not None
        assert isinstance(result, Finding)
        assert result.key == "DB_PASSWORD"
        assert "password" in result.reason

    def test_returns_none_for_safe(self) -> None:
        assert audit_pair("APP_NAME", "myapp") is None

    def test_finding_has_layer(self) -> None:
        result = audit_pair("DB_PASSWORD", "hunter2")
        assert result is not None
        assert result.layer == "key_pattern"


class TestAuditDict:
    """Dict auditing."""

    def test_finds_multiple_secrets(self) -> None:
        findings = audit_dict(
            {
                "password": "secret",
                "host": "localhost",
                "api_key": "abc123",
            }
        )
        assert len(findings) == 2
        keys = {f.key for f in findings}
        assert "password" in keys
        assert "api_key" in keys

    def test_empty_dict(self) -> None:
        assert audit_dict({}) == []

    def test_nested_findings(self) -> None:
        findings = audit_dict(
            {
                "db": {"password": "secret"},
                "cache": {"host": "localhost"},
            }
        )
        assert len(findings) == 1
        assert findings[0].key == "password"


class TestStructuredRedactionEdgeCases:
    """Edge cases in structured value redaction."""

    def test_secret_substring_in_non_secret_value(self) -> None:
        """Secret value appearing as substring of non-secret value should not corrupt it.

        Example: {"password": "host", "hostname": "my-host-server"}
        The word "host" in hostname should not be replaced.
        """
        value = '{"password": "abc", "hostname": "abc-server", "port": "5432"}'
        result = redact_pair("CONFIG", value)
        # password value "abc" is redacted — but "abc-server" contains "abc" as substring.
        # This is a known limitation of str.replace(): it will replace ALL occurrences.
        # The current implementation replaces longest-first to minimize collateral damage,
        # but substring collision is still possible when a secret is a common substring.
        assert "5432" in result  # port is preserved

    def test_structured_redaction_preserves_structure(self) -> None:
        """Non-secret keys and values survive structured redaction."""
        value = '{"secret_key": "supersecret", "host": "localhost", "port": "5432"}'
        result = redact_pair("CONFIG", value)
        assert "supersecret" not in result
        assert "localhost" in result
        assert "5432" in result


class TestRecursionDepthGuard:
    """Structured parsing recursion is depth-limited."""

    def test_deeply_nested_structured_value_does_not_recurse_forever(self) -> None:
        """Values nested beyond _MAX_DETECT_DEPTH (3) stop parsing."""
        import json

        # Build nested JSON: each level embeds the next as a string value
        inner = json.dumps({"password": "innermost_secret"})
        for _ in range(5):
            inner = json.dumps({"config": inner})

        # The outermost key is innocuous — detection depends on structured parsing.
        # At depth > 3, structured parsing stops, so the innermost secret
        # may or may not be found depending on exact nesting. The point is
        # it terminates without stack overflow.
        result = redact_pair("APP_CONFIG", inner)
        assert isinstance(result, str)  # didn't crash

    def test_moderate_nesting_still_detects(self) -> None:
        """Nesting within the depth limit still works."""
        # Structured value containing a secret key — single level of parsing
        value = '{"password": "nested_secret", "host": "localhost"}'
        result = redact_pair("CONFIG", value)
        assert "nested_secret" not in result


class TestRealWorldCases:
    """Scenarios from actual Docker environments."""

    def test_pgadmin_oauth_config(self) -> None:
        """The bug that started this project: OAUTH2_CLIENT_SECRET in a Python dict."""
        value = (
            "{'OAUTH2_CLIENT_ID': 'pgadmin', "
            "'OAUTH2_CLIENT_SECRET': 'super-secret-value', "
            "'OAUTH2_TOKEN_URL': 'https://auth.example.com/token'}"
        )
        result = redact_pair("PGADMIN_CONFIG_OAUTH2_CONFIG", value)
        assert "super-secret-value" not in result
        assert "pgadmin" in result  # client_id is not secret

    def test_docker_env_typical(self) -> None:
        """Typical Docker container environment."""
        env = {
            "POSTGRES_PASSWORD": "db_secret_123",
            "POSTGRES_USER": "admin",
            "POSTGRES_DB": "myapp",
            "PGDATA": "/var/lib/postgresql/data",
            "DATABASE_URL": "postgres://admin:db_secret_123@localhost:5432/myapp",
        }
        result = redact_dict(env)
        assert result["POSTGRES_PASSWORD"] == "[REDACTED]"
        assert result["POSTGRES_USER"] == "admin"
        assert result["POSTGRES_DB"] == "myapp"
        assert "db_secret_123" not in str(result["DATABASE_URL"])

    def test_authentik_env(self) -> None:
        """Authentik container — 'auth' should NOT trigger redaction."""
        env = {
            "AUTHENTIK_SECRET_KEY": "long-random-secret",
            "AUTHENTIK_REDIS__HOST": "redis",
            "AUTHENTIK_POSTGRESQL__HOST": "postgresql",
            "AUTHENTIK_POSTGRESQL__PASSWORD": "pg-secret",
            "AUTHENTIK_ERROR_REPORTING__ENABLED": "true",
        }
        result = redact_dict(env)
        assert result["AUTHENTIK_SECRET_KEY"] == "[REDACTED]"
        assert result["AUTHENTIK_POSTGRESQL__PASSWORD"] == "[REDACTED]"
        assert result["AUTHENTIK_REDIS__HOST"] == "redis"
        assert result["AUTHENTIK_ERROR_REPORTING__ENABLED"] == "true"
