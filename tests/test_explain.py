"""Tests for --explain, the accounting of what was left alone and why.

An undetected secret is invisible by definition: the output looks screened and
nothing signals otherwise. The only defence is making the non-detections
reviewable, so most of these tests are about the values that were *not*
redacted — and about the guarantee that reporting on them never quotes them.
"""

from __future__ import annotations

import pytest

from secretscreen._cli import EXIT_FINDINGS, EXIT_OK, main
from secretscreen._core import (
    STATE_CLEAN,
    STATE_REDACTED,
    STATE_UNSCANNED,
    STATE_VETOED,
    Mode,
    explain_dict,
    explain_pair,
)

SENTINEL = "zQ7pLmXv3TdNhRkWbFgY9sJc2AeUoI4t"


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content)
    return str(path)


class TestRedactedState:
    """A value a layer fired on, and which layer it was."""

    @pytest.mark.parametrize(
        ("key", "value", "layer", "reason_fragment"),
        [
            ("DB_PASSWORD", "hunter2", "key_pattern", "matched 'password'"),
            ("AUTH", "postgres://admin:pw@db.lan/app", "url_credentials", "password position"),
            ("NOTIFY", "discord://tokenvalue@1234567890", "url_credentials", "userinfo position"),
            ("BLOB", '{"api_key": "abc123def456"}', "structured_parsing", "api_key"),
        ],
    )
    def test_layer_and_reason(self, key: str, value: str, layer: str, reason_fragment: str) -> None:
        explanation = explain_pair(key, value)
        assert explanation.state == STATE_REDACTED
        assert explanation.layer == layer
        assert reason_fragment in explanation.reason

    def test_entropy_layer_reports_the_score(self) -> None:
        explanation = explain_pair("BLOB", SENTINEL, mode=Mode.AGGRESSIVE)
        assert explanation.state == STATE_REDACTED
        assert explanation.layer == "entropy"
        assert "entropy" in explanation.reason


class TestVetoedState:
    """A layer would have fired and a rule suppressed it.

    This is the state worth reading — it is where the tool decided to stay
    quiet, as opposed to nothing matching at all.
    """

    @pytest.mark.parametrize(
        ("key", "suffix"),
        [
            ("GF_OAUTH_TOKEN_URL", "_url"),
            ("PASSWORD_FILE", "password_file"),
            ("SESSION_KEY_PREFIX", "session_key_prefix"),
        ],
    )
    def test_safe_suffix_veto_is_reported(self, key: str, suffix: str) -> None:
        explanation = explain_pair(key, "https://auth.example.com/o/token/")
        assert explanation.state == STATE_VETOED
        assert explanation.layer == "key_pattern"
        assert suffix in explanation.reason

    def test_veto_is_not_reported_when_a_later_layer_catches_it(self) -> None:
        """A vetoed layer-1 match still redacts if layer 4 fires — that is not a veto."""
        explanation = explain_pair("NOTIFY_TOKEN_URL", "discord://tokenvalue@123")
        assert explanation.state == STATE_REDACTED
        assert explanation.layer == "url_credentials"

    def test_key_matching_no_pattern_is_clean_not_vetoed(self) -> None:
        assert explain_pair("SMTP_HOST", "smtp.fastmail.com").state == STATE_CLEAN


class TestUnscannedState:
    """The size cap skipped the value-scanning layers."""

    def test_oversized_value_under_innocuous_key(self) -> None:
        explanation = explain_pair("PAYLOAD", "x" * 70_000)
        assert explanation.state == STATE_UNSCANNED
        assert "scan cap" in explanation.reason

    def test_oversized_value_under_secret_key_is_redacted_not_unscanned(self) -> None:
        """Layer 1 reads the key, not the value, so the cap never applies to it."""
        explanation = explain_pair("AWS_SECRET_ACCESS_KEY", "x" * 70_000)
        assert explanation.state == STATE_REDACTED
        assert explanation.layer == "key_pattern"


class TestCleanState:
    """Nothing matched — with the nearest miss, not just silence."""

    def test_below_entropy_floor_reports_length(self) -> None:
        explanation = explain_pair("TZ", "America/Los_Angeles")
        assert explanation.state == STATE_CLEAN
        assert "below the 20-char entropy floor" in explanation.reason

    def test_reports_entropy_and_what_aggressive_would_do(self) -> None:
        """The number is the point: it makes the mode choice measurable."""
        low = explain_pair("IMAGE_DIGEST", "sha256:" + "a1b2c3d4e5f6" * 5)
        assert "aggressive would not flag" in low.reason

        high = explain_pair("DEPLOY_PUBLIC_KEY", f"ssh-rsa AAAAB3Nza{SENTINEL}")
        assert "aggressive WOULD flag" in high.reason

    def test_aggressive_mode_omits_the_counterfactual(self) -> None:
        explanation = explain_pair("PATH_LIST", "/mnt/user/appdata:/mnt/user/documents", mode=Mode.AGGRESSIVE)
        assert "below threshold" in explanation.reason
        assert "aggressive" not in explanation.reason

    def test_empty_value(self) -> None:
        assert explain_pair("EMPTY", "").state == STATE_CLEAN

    def test_entropy_threshold_is_honoured(self) -> None:
        assert explain_pair("BLOB", SENTINEL, entropy_threshold=9.0).state == STATE_CLEAN
        assert explain_pair("BLOB", SENTINEL, mode=Mode.AGGRESSIVE, entropy_threshold=9.0).state == STATE_CLEAN


class TestNeverQuotesTheValue:
    """The guarantee that makes explain output safe to paste into an issue."""

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("DB_PASSWORD", SENTINEL),
            ("NOTIFY", f"discord://{SENTINEL}@1234567890"),
            ("AUTH", f"postgres://admin:{SENTINEL}@db.lan/app"),
            ("BLOB", '{"api_key": "' + SENTINEL + '"}'),
            ("PLAIN", SENTINEL),
            ("GF_OAUTH_TOKEN_URL", SENTINEL),
            ("PAYLOAD", SENTINEL * 3000),
        ],
    )
    @pytest.mark.parametrize("mode", [Mode.NORMAL, Mode.AGGRESSIVE])
    def test_value_never_appears_in_any_field(self, key: str, value: str, mode: Mode) -> None:
        explanation = explain_pair(key, value, mode=mode)
        rendered = f"{explanation.key} {explanation.state} {explanation.layer} {explanation.reason}"
        assert SENTINEL not in rendered


class TestExplainDict:
    """Structured input is accounted for the same way, with path-style keys."""

    def test_nested_keys_and_list_indices(self) -> None:
        data = {"db": {"password": "hunter2", "host": "db.lan"}, "tags": ["prod", "eu-west"]}
        by_key = {e.key: e for e in explain_dict(data)}

        assert by_key["db.password"].state == STATE_REDACTED
        assert by_key["db.host"].state == STATE_CLEAN
        assert by_key["tags[0]"].state == STATE_CLEAN
        assert by_key["tags[1]"].state == STATE_CLEAN

    def test_every_string_value_is_accounted_for(self) -> None:
        """The point of the feature: no value is silently omitted."""
        data = {"a": "one", "b": {"c": "two", "d": ["three", "four"]}}
        assert len(explain_dict(data)) == 4

    def test_structures_nested_inside_lists(self) -> None:
        data = {"services": [{"env": {"DB_PASSWORD": "hunter2"}}, ["nested", {"API_TOKEN": "abc"}]]}
        by_key = {e.key: e for e in explain_dict(data)}

        assert by_key["services[0].env.DB_PASSWORD"].state == STATE_REDACTED
        assert by_key["services[1][0]"].state == STATE_CLEAN
        assert by_key["services[1][1].API_TOKEN"].state == STATE_REDACTED

    def test_non_string_values_are_skipped(self) -> None:
        assert [e.key for e in explain_dict({"n": 1, "b": True, "s": "text", "z": None})] == ["s"]

    def test_deep_nesting_terminates(self) -> None:
        data: dict[str, object] = {"leaf": "value"}
        for _ in range(150):
            data = {"nest": data}
        explain_dict(data)  # must not raise


class TestExplainCli:
    """Stream separation, composition with --audit, and exit codes."""

    ENV = "DB_PASSWORD=hunter2\nLOG_LEVEL=debug\nGF_OAUTH_TOKEN_URL=https://auth.example.com/o/token/\n"

    def test_goes_to_stderr_not_stdout(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "a.env", self.ENV), "--explain"])
        captured = capsys.readouterr()

        assert "explain" in captured.err
        assert "redacted" in captured.err
        assert "explain" not in captured.out

    def test_stdout_is_byte_identical_with_and_without_explain(self, tmp_path, capsys) -> None:
        """stdout has to stay a usable redacted stream when explain is on."""
        path = _write(tmp_path, "a.env", self.ENV)
        main([path])
        plain = capsys.readouterr().out
        main([path, "--explain"])
        assert capsys.readouterr().out == plain

    def test_exit_code_is_unchanged(self, tmp_path, capsys) -> None:
        path = _write(tmp_path, "a.env", self.ENV)
        assert main([path, "--explain"]) == EXIT_OK
        capsys.readouterr()
        assert main([path, "--audit", "--explain"]) == EXIT_FINDINGS

    def test_composes_with_audit(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "a.env", self.ENV), "--audit", "--explain"])
        captured = capsys.readouterr()

        assert "DB_PASSWORD" in captured.out  # audit findings on stdout
        assert "LOG_LEVEL" in captured.err  # the complement on stderr
        assert "vetoed" in captured.err

    def test_never_prints_values(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "a.env", f"DB_PASSWORD={SENTINEL}\nPLAIN={SENTINEL}\n"), "--audit", "--explain"])
        captured = capsys.readouterr()
        assert SENTINEL not in captured.err
        assert SENTINEL not in captured.out

    def test_location_shown_only_for_multiple_inputs(self, tmp_path, capsys) -> None:
        one = _write(tmp_path, "a.env", self.ENV)
        two = _write(tmp_path, "b.env", "API_TOKEN=abc\n")

        main([one, "--explain"])
        assert "a.env:1" not in capsys.readouterr().err

        main([one, two, "--explain"])
        assert "a.env:1" in capsys.readouterr().err

    def test_no_header_when_nothing_to_report(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "empty.env", "# just a comment\n"), "--explain"])
        assert "explain" not in capsys.readouterr().err

    def test_absent_by_default(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "a.env", self.ENV)])
        assert "explain" not in capsys.readouterr().err

    def test_dsn_format(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "d.txt", "postgres://admin:pw@db:5432/prod\n"), "--format", "dsn", "--explain"])
        assert "url_credentials" in capsys.readouterr().err

    def test_json_format_uses_path_keys(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "c.json", '{"db": {"password": "hunter2"}}'), "--explain"])
        assert "db.password" in capsys.readouterr().err
