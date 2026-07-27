"""Tests for the command-line interface.

The CLI's contract is narrower than the library's: whatever reaches stdout has
been structurally parsed, and anything that has not been is both redacted and
reported. Most of these tests exist to pin that down.
"""

from __future__ import annotations

import json

import pytest

from secretscreen._cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

SAMPLE_ENV = """\
# comment
APP_NAME=myapp
DB_PASSWORD=hunter2
DATABASE_URL=postgres://admin:s3cr3t@db.internal:5432/prod
export API_TOKEN="ghp_16C7e42F292c6912E7710c838347Ae178B4a"
LOG_LEVEL=debug
"""


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content)
    return str(path)


class TestRedactMode:
    """Default cat-like behaviour."""

    def test_redacts_env_file(self, tmp_path, capsys) -> None:
        code = main([_write(tmp_path, "sample.env", SAMPLE_ENV)])
        out = capsys.readouterr().out

        assert code == EXIT_OK
        assert "hunter2" not in out
        assert "s3cr3t" not in out
        assert "ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in out
        # Non-secrets survive untouched.
        assert "APP_NAME=myapp" in out
        assert "LOG_LEVEL=debug" in out

    def test_preserves_comments_quotes_and_export(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "sample.env", SAMPLE_ENV)])
        out = capsys.readouterr().out

        assert "# comment" in out
        assert 'export API_TOKEN="[REDACTED]"' in out

    def test_preserves_spacing_around_separator(self, tmp_path, capsys) -> None:
        """The left-hand side is echoed verbatim, not reconstructed."""
        main([_write(tmp_path, "s.env", "SPACED =  value\n")])
        assert "SPACED =  value" in capsys.readouterr().out

    def test_partial_url_redaction_keeps_structure(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "sample.env", SAMPLE_ENV)])
        out = capsys.readouterr().out
        assert "postgres://admin:[REDACTED]@db.internal:5432/prod" in out

    def test_custom_replacement(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "s.env", "DB_PASSWORD=hunter2\n"), "--replacement", "XXX"])
        out = capsys.readouterr().out
        assert "DB_PASSWORD=XXX" in out
        assert "hunter2" not in out

    def test_reads_stdin_when_no_file(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin", _FakeStdin("DB_PASSWORD=hunter2\n"))
        code = main([])
        out = capsys.readouterr().out
        assert code == EXIT_OK
        assert "hunter2" not in out

    def test_aggressive_mode_catches_high_entropy(self, tmp_path, capsys) -> None:
        content = "OPAQUE=xQ7fJ2mNp9VzR4tLw8YbK3sHdG6aE5cU\n"
        main([_write(tmp_path, "s.env", content), "--aggressive"])
        assert "xQ7fJ2mNp9VzR4tLw8YbK3sHdG6aE5cU" not in capsys.readouterr().out


class TestUnparseableInputFailsLoudly:
    """The core safety property: nothing unparsed reaches stdout verbatim."""

    def test_line_without_separator_is_redacted_and_reported(self, tmp_path, capsys) -> None:
        code = main([_write(tmp_path, "s.env", "GOOD=1\nNOTAPAIR\n")])
        captured = capsys.readouterr()

        assert code == EXIT_ERROR
        assert "NOTAPAIR" not in captured.out
        assert "[REDACTED]" in captured.out
        assert "no key=value separator" in captured.err

    def test_invalid_json_prints_nothing(self, tmp_path, capsys) -> None:
        code = main([_write(tmp_path, "bad.json", '{"password": "hunter2"')])
        captured = capsys.readouterr()

        assert code == EXIT_ERROR
        assert captured.out == ""
        assert "hunter2" not in captured.out
        assert "invalid JSON" in captured.err

    def test_unreadable_file_is_reported(self, tmp_path, capsys) -> None:
        code = main([str(tmp_path / "does-not-exist.env")])
        captured = capsys.readouterr()

        assert code == EXIT_ERROR
        assert "cannot read" in captured.err

    def test_oversized_value_is_reported_not_silently_passed(self, tmp_path, capsys) -> None:
        """The size cap's residual gap must be visible, never silent."""
        code = main([_write(tmp_path, "big.env", "DATA=" + "x" * 1_100_000 + "\n")])
        captured = capsys.readouterr()

        assert code == EXIT_ERROR
        assert "not scanned" in captured.err

    def test_oversized_value_under_secret_key_is_still_redacted(self, tmp_path, capsys) -> None:
        code = main([_write(tmp_path, "big.env", "DB_PASSWORD=" + "x" * 1_100_000 + "\n")])
        captured = capsys.readouterr()

        assert code == EXIT_OK
        assert "DB_PASSWORD=[REDACTED]" in captured.out
        assert "xxxx" not in captured.out


class TestAuditMode:
    """Findings without values."""

    def test_reports_findings_and_exits_one(self, tmp_path, capsys) -> None:
        code = main([_write(tmp_path, "sample.env", SAMPLE_ENV), "--audit"])
        out = capsys.readouterr().out

        assert code == EXIT_FINDINGS
        assert "DB_PASSWORD" in out
        assert "DATABASE_URL" in out

    def test_never_prints_secret_values(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "sample.env", SAMPLE_ENV), "--audit"])
        captured = capsys.readouterr()

        for secret in ("hunter2", "s3cr3t", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"):
            assert secret not in captured.out
            assert secret not in captured.err

    def test_clean_input_exits_zero(self, tmp_path, capsys) -> None:
        code = main([_write(tmp_path, "s.env", "APP=ok\nLOG=debug\n"), "--audit"])
        assert code == EXIT_OK
        assert capsys.readouterr().out == ""

    def test_audit_does_not_print_redacted_content(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "s.env", "APP_NAME=myapp\nDB_PASSWORD=hunter2\n"), "--audit"])
        assert "APP_NAME=myapp" not in capsys.readouterr().out

    def test_audits_json(self, tmp_path, capsys) -> None:
        content = json.dumps({"db": {"password": "hunter2"}})
        code = main([_write(tmp_path, "a.json", content), "--audit"])
        captured = capsys.readouterr()

        assert code == EXIT_FINDINGS
        assert "password" in captured.out
        assert "hunter2" not in captured.out


class TestFormats:
    """Format handling and auto-detection."""

    def test_json_redaction_stays_valid_json(self, tmp_path, capsys) -> None:
        content = json.dumps({"service": "api", "db": {"host": "localhost", "password": "hunter2"}})
        main([_write(tmp_path, "app.json", content)])
        out = capsys.readouterr().out

        parsed = json.loads(out)
        assert parsed["db"]["password"] == "[REDACTED]"
        assert parsed["db"]["host"] == "localhost"

    def test_ini_preserves_sections_and_separator(self, tmp_path, capsys) -> None:
        content = "; note\n[database]\nhost = localhost\npassword : hunter2\n"
        main([_write(tmp_path, "cfg.ini", content)])
        out = capsys.readouterr().out

        assert "; note" in out
        assert "[database]" in out
        assert "host = localhost" in out
        assert "password : [REDACTED]" in out
        assert "hunter2" not in out

    def test_dsn_format(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "dsn.txt", "postgres://admin:s3cr3t@db:5432/prod\n"), "--format", "dsn"])
        out = capsys.readouterr().out
        assert out.strip() == "postgres://admin:[REDACTED]@db:5432/prod"

    @pytest.mark.parametrize(
        ("name", "content", "marker"),
        [
            ("app.json", '{"password": "hunter2"}', '"password": "[REDACTED]"'),
            ("cfg.ini", "[s]\npassword = hunter2\n", "password = [REDACTED]"),
            (".env", "DB_PASSWORD=hunter2\n", "DB_PASSWORD=[REDACTED]"),
            ("plain.txt", "DB_PASSWORD=hunter2\n", "DB_PASSWORD=[REDACTED]"),
        ],
    )
    def test_auto_detection(self, tmp_path, capsys, name: str, content: str, marker: str) -> None:
        main([_write(tmp_path, name, content)])
        out = capsys.readouterr().out
        assert marker in out
        assert "hunter2" not in out

    def test_explicit_format_overrides_extension(self, tmp_path, capsys) -> None:
        """A .json extension holding env content must not be parsed as JSON."""
        code = main([_write(tmp_path, "mislabelled.json", "DB_PASSWORD=hunter2\n"), "--format", "env"])
        out = capsys.readouterr().out

        assert code == EXIT_OK
        assert "DB_PASSWORD=[REDACTED]" in out

    def test_multiple_files(self, tmp_path, capsys) -> None:
        first = _write(tmp_path, "one.env", "DB_PASSWORD=hunter2\n")
        second = _write(tmp_path, "two.env", "API_TOKEN=s3cr3t\n")
        code = main([first, second])
        out = capsys.readouterr().out

        assert code == EXIT_OK
        assert out.count("[REDACTED]") == 2


class _FakeStdin:
    """Minimal stdin stand-in for pipe tests."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text
