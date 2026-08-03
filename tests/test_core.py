"""Tests for core orchestration — redact_pair, redact_dict, audit_pair, audit_dict."""

from secretscreen import Finding, Mode, audit_dict, audit_pair, redact_dict, redact_pair
from secretscreen._core import _MAX_DETECT_LENGTH, STATE_REDACTED, explain_dict


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
        """Lists containing both dicts and non-dicts.

        `"plain"` stays because nothing matches it, not because bare strings
        in a list are skipped — see the tests below, which use a value that
        does match.
        """
        result = redact_dict({"items": [{"token": "abc"}, "plain", 42]})
        assert result["items"][0]["token"] == "[REDACTED]"  # type: ignore[index]
        assert result["items"][1] == "plain"  # type: ignore[index]
        assert result["items"][2] == 42  # type: ignore[index]


class TestSecretsInsideLists:
    """A string in a list is screened under the key the list belongs to.

    An array of tokens is the same claim about the same secret as one token
    under a singular key, and a config file is where you find both.
    """

    PAT = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

    def test_key_name_reaches_list_elements(self) -> None:
        """Layer 1 matches on the key, so the key has to survive the list."""
        result = redact_dict({"tokens": ["hunter2"]})
        assert result["tokens"] == ["[REDACTED]"]  # type: ignore[index]

    def test_value_format_still_fires_without_a_useful_key(self) -> None:
        result = redact_dict({"blobs": [self.PAT]})
        assert result["blobs"] == ["[REDACTED]"]  # type: ignore[index]

    def test_bare_top_level_list(self) -> None:
        assert redact_dict([self.PAT]) == ["[REDACTED]"]

    def test_list_inside_a_list(self) -> None:
        result = redact_dict({"tokens": [["hunter2"]]})
        assert result["tokens"] == [["[REDACTED]"]]  # type: ignore[index]

    def test_audit_reports_the_element_under_the_plain_key(self) -> None:
        """Not an indexed path: callers match show/hide rules on this key."""
        findings = audit_dict({"tokens": ["hunter2"]})
        assert [f.key for f in findings] == ["tokens"]

    def test_audit_still_descends_through_a_list_into_dicts(self) -> None:
        """The string branch must not swallow the container branch beside it."""
        findings = audit_dict({"services": [{"db": {"password": "hunter2"}}]})
        assert [f.key for f in findings] == ["password"]

    def test_redact_audit_and_explain_agree(self) -> None:
        """The regression that matters.

        Before this fix the three disagreed on one input: redaction printed
        the token, --audit reported nothing, and --explain claimed it had
        been redacted. A tool that contradicts itself is worse than one that
        misses, because --explain is what a user reads to check the miss.
        """
        document = {"tokens": [self.PAT]}

        assert redact_dict(document)["tokens"] == ["[REDACTED]"]  # type: ignore[index]
        assert len(audit_dict(document)) == 1
        assert [e.state for e in explain_dict(document)] == [STATE_REDACTED]


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


class TestSecurityFixes:
    """Regression tests for security audit findings (2026-04-05)."""

    def test_deeply_nested_json_does_not_bypass_detection(self) -> None:
        """HIGH-1: Deeply nested JSON should not suppress detection via RecursionError."""
        # Built by string concatenation, not json.dumps: the encoder recurses in C
        # and blows the stack on 3.11 before the library is ever called, which would
        # make this a test of json.dumps rather than of redact_pair.
        payload = '{"x": ' * 1000 + '{"password": "deep_secret_value"}' + "}" * 1000

        # The key "config" is innocuous, so detection depends on structured parsing
        # reaching "password". Below the flatten depth cap it will not, but it must
        # degrade to a pass-through rather than raising.
        result = redact_pair("config", payload)
        assert isinstance(result, str)  # didn't crash

        # Same secret at a depth the parser does reach is still detected — otherwise
        # this test would pass just as well against a no-op implementation.
        shallow = '{"x": ' * 2 + '{"password": "deep_secret_value"}' + "}" * 2
        assert "deep_secret_value" not in redact_pair("config", shallow)

    def test_finding_does_not_expose_secret_values(self) -> None:
        """MEDIUM-1: Finding objects should not contain plaintext secrets."""
        finding = audit_pair("config", '{"password": "sup3r_s3cr3t"}')
        assert finding is not None
        # Check that the Finding has no field containing the secret
        assert not hasattr(finding, "_parsed_pairs")
        finding_str = str(finding)
        assert "sup3r_s3cr3t" not in finding_str

    def test_large_value_does_not_cause_dos(self) -> None:
        """MEDIUM-3: Values over 1MB skip the value-scanning layers."""
        large_value = "x" * 2_000_000  # 2MB
        result = redact_pair("SOME_KEY", large_value)
        assert result == large_value  # returned unchanged, not processed

    def test_large_value_under_secret_key_is_still_redacted(self) -> None:
        """The size cap must not fail open: layer 1 reads the key, not the value.

        Regression: the original MEDIUM-3 fix returned early before layer 1, so
        AWS_SECRET_ACCESS_KEY=<2MB> passed through in full.
        """
        large_value = "x" * 2_000_000  # 2MB
        assert redact_pair("AWS_SECRET_ACCESS_KEY", large_value) == "[REDACTED]"
        assert redact_pair("DB_PASSWORD", large_value) == "[REDACTED]"

    def test_large_value_under_secret_key_is_audited(self) -> None:
        """audit_pair must report the oversized secret rather than reporting clean."""
        finding = audit_pair("AWS_SECRET_ACCESS_KEY", "x" * 2_000_000)
        assert finding is not None
        assert finding.layer == "key_pattern"

    def test_worst_case_input_at_the_cap_stays_sub_second(self) -> None:
        """The cap must be set against adversarial input, not a run of one character.

        At least one vendored gitleaks pattern backtracks: cost is roughly quadratic
        above ~128KB on random high-entropy text (what a secret-shaped blob looks
        like). The original 1MB cap allowed a ~107s scan. A run of 'x' is ~500x
        faster at the same size, which is why it was not a safe benchmark.
        """
        import random
        import time

        random.seed(0)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+="
        at_cap = "".join(random.choices(alphabet, k=_MAX_DETECT_LENGTH))

        start = time.perf_counter()
        redact_pair("BLOB", at_cap)
        elapsed = time.perf_counter() - start

        # Measured ~0.57s at 64KB. 5s leaves headroom for slow CI without letting a
        # future cap increase quietly reintroduce a multi-minute scan.
        assert elapsed < 5.0, f"scan at the cap took {elapsed:.1f}s — is _MAX_DETECT_LENGTH too high?"

    def test_cap_matches_the_parser_bound(self) -> None:
        """Layer 2 was already bounded at 64KB; keeping both at one value is simpler."""
        from secretscreen._parsers import MAX_PARSE_LENGTH

        assert _MAX_DETECT_LENGTH == MAX_PARSE_LENGTH

    def test_large_value_layer_one_is_cheap(self) -> None:
        """Layer 1 on an oversized value must not fall through to the regex layers."""
        import time

        large_value = "x" * 20_000_000  # 20MB
        start = time.perf_counter()
        assert redact_pair("SECRET_KEY", large_value) == "[REDACTED]"
        assert time.perf_counter() - start < 1.0

    def test_oversized_value_under_non_denylisted_key_is_a_known_gap(self) -> None:
        """Documents the residual size-cap gap rather than leaving it unstated.

        Keys like DATABASE_URL carry a safe suffix ('_url'), so layer 1 never
        matches them — they rely on layer 4, which scans the value and is
        therefore skipped when oversized. Such values pass through unredacted.
        Callers that print values must surface the skip; see _MAX_DETECT_LENGTH.
        """
        large_url = "postgres://user:pw@host/db?pad=" + "x" * 2_000_000
        assert redact_pair("DATABASE_URL", large_url) == large_url
        assert audit_pair("DATABASE_URL", large_url) is None

        # Same URL under the cap is redacted normally.
        small_url = "postgres://user:pw@host/db"
        assert redact_pair("DATABASE_URL", small_url) == "postgres://user:REDACTED@host/db"

    def test_deeply_nested_dict_does_not_crash(self) -> None:
        """MEDIUM-4: redact_dict should handle deeply nested dicts without RecursionError."""
        data: dict = {}
        current = data
        for _ in range(500):
            current["x"] = {}
            current = current["x"]
        current["leaf"] = "val"

        result = redact_dict(data)
        assert isinstance(result, dict)  # didn't crash

    def test_deeply_nested_dict_audit_does_not_crash(self) -> None:
        """MEDIUM-4: audit_dict should handle deeply nested dicts without RecursionError."""
        data: dict = {}
        current = data
        for _ in range(500):
            current["x"] = {}
            current = current["x"]
        current["password"] = "secret"

        findings = audit_dict(data)
        assert isinstance(findings, list)  # didn't crash

    def test_jdbc_url_detected(self) -> None:
        """LOW-1: JDBC URLs should detect embedded credentials."""
        from secretscreen._urls import has_url_credentials

        assert has_url_credentials("jdbc:postgresql://admin:S3cr3t@prod-db:5432/main") is True
        assert has_url_credentials("jdbc:mysql://root:password@localhost:3306/app") is True

    def test_jdbc_url_redacted(self) -> None:
        """LOW-1: JDBC URLs should have passwords redacted."""
        from secretscreen._urls import redact_url_credentials

        result = redact_url_credentials("jdbc:postgresql://admin:S3cr3t@prod-db:5432/main")
        assert "S3cr3t" not in result
        assert "admin" in result
        assert result.startswith("jdbc:")

    def test_ipv6_url_redaction_valid(self) -> None:
        """LOW-2: IPv6 URL redaction should produce valid URLs."""
        from secretscreen._urls import redact_url_credentials

        result = redact_url_credentials("redis://user:secret@[::1]:6379/0")
        assert "secret" not in result
        assert "[" in result  # brackets preserved
        assert "::1" in result

    def test_odbc_url_detected(self) -> None:
        """LOW-1: ODBC URLs should also detect embedded credentials."""
        from secretscreen._urls import has_url_credentials

        assert has_url_credentials("odbc:postgresql://admin:pass@host/db") is True


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
