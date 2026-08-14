"""Tests for YAML-shaped input and grep-style line prefixes.

Two failures motivated these. Piping `grep -n` output into the CLI redacted
every line, because grep's `file:NN:` prefix means a comment no longer starts
with '#' and a `key: value` line no longer splits where it looks like it should.
Teaching the format sniffer about colons *without* removing those prefixes is
worse than leaving it alone: the first colon then belongs to grep's line number,
the rest of the line becomes one opaque value, and the secret prints in full.

So the prefix handling is not a convenience feature. It is the precondition
that makes colon-separated auto-detection safe, and most of what follows is
there to keep it that way.
"""

from __future__ import annotations

import pytest

from secretscreen._cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

SECRET = "faketokenvalue123"

COMPOSE = f"""\
# Watchtower stack
services:
  watchtower:
    image: containrrr/watchtower
    environment:
      WATCHTOWER_NOTIFICATION_URL: discord://{SECRET}@1234567890
      WATCHTOWER_CLEANUP: "true"
    # keep an eye on this one
    restart: unless-stopped
"""


def _write(tmp_path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content)
    return str(path)


def _grep(text: str, delimiter: str = ":", filename: str = "") -> str:
    """Reproduce grep -n output. Context lines use '-', matches use ':'."""
    prefix = f"{filename}{delimiter}" if filename else ""
    return "".join(f"{prefix}{n}{delimiter}{line}\n" for n, line in enumerate(text.splitlines(), 1))


class TestYamlFormat:
    """Line-oriented YAML: structure and comments survive, values are screened."""

    def test_structure_comments_and_indentation_survive(self, tmp_path, capsys) -> None:
        code = main([_write(tmp_path, "compose.yaml", COMPOSE)])
        out = capsys.readouterr().out

        assert code == EXIT_OK
        assert SECRET not in out
        assert "# Watchtower stack" in out
        assert "    # keep an eye on this one" in out
        assert "  watchtower:" in out
        assert "    image: containrrr/watchtower" in out
        assert 'WATCHTOWER_CLEANUP: "true"' in out

    @pytest.mark.parametrize("name", ["compose.yaml", "docker-compose.yml", "stack.YAML"])
    def test_detected_from_extension(self, tmp_path, capsys, name: str) -> None:
        main([_write(tmp_path, name, COMPOSE)])
        assert SECRET not in capsys.readouterr().out

    def test_detected_from_content_without_an_extension(self, tmp_path, capsys) -> None:
        main([_write(tmp_path, "stackfile", COMPOSE)])
        out = capsys.readouterr().out
        assert SECRET not in out
        assert "  watchtower:" in out

    def test_key_only_lines_are_structural(self, tmp_path, capsys) -> None:
        """`services:` has no value slot, so there is nothing to vouch for."""
        main([_write(tmp_path, "c.yaml", "services:\n  app:\n    ports:\n")])
        assert capsys.readouterr().out == "services:\n  app:\n    ports:\n"

    def test_list_entries_with_a_separator(self, tmp_path, capsys) -> None:
        content = "environment:\n  - DB_PASSWORD=hunter2\n  - PUBLIC_HOST=example.com\n"
        main([_write(tmp_path, "c.yaml", content)])
        out = capsys.readouterr().out

        assert "hunter2" not in out
        assert "- PUBLIC_HOST=example.com" in out

    def test_bare_list_entries_are_scanned_not_redacted(self, tmp_path, capsys) -> None:
        """A bare item has a value but no key; it is screened, not discarded."""
        content = f"tags:\n  - prod\n  - eu-west-1\nsecrets:\n  - discord://{SECRET}@123\n"
        code = main([_write(tmp_path, "c.yaml", content)])
        out = capsys.readouterr().out

        assert "  - prod" in out
        assert "  - eu-west-1" in out
        assert SECRET not in out
        assert code == EXIT_OK

    def test_bare_list_entries_under_audit(self, tmp_path, capsys) -> None:
        content = f"secrets:\n  - discord://{SECRET}@123\n  - plainvalue\n"
        code = main([_write(tmp_path, "c.yaml", content), "--audit"])
        captured = capsys.readouterr()

        assert code == EXIT_FINDINGS
        assert "url_credentials" in captured.out
        assert SECRET not in captured.out

    def test_bare_list_entries_under_explain(self, tmp_path, capsys) -> None:
        content = f"secrets:\n  - discord://{SECRET}@123\n  - plainvalue\n"
        main([_write(tmp_path, "c.yaml", content), "--explain"])
        err = capsys.readouterr().err

        assert "redacted" in err
        assert "clean" in err
        assert SECRET not in err

    def test_oversized_bare_list_entry_is_reported_unscanned(self, tmp_path, capsys) -> None:
        content = "blobs:\n  - " + "x" * 70_000 + "\n"
        code = main([_write(tmp_path, "c.yaml", content)])

        assert code == EXIT_ERROR
        assert "scan cap" in capsys.readouterr().err

    def test_block_scalar_body_is_redacted_and_reported(self, tmp_path, capsys) -> None:
        """A documented limit: this is line-oriented, not a real YAML parse."""
        content = f"command: >\n  --token {SECRET}\n"
        code = main([_write(tmp_path, "c.yaml", content)])
        captured = capsys.readouterr()

        assert SECRET not in captured.out
        assert code == EXIT_ERROR
        assert "no key=value separator" in captured.err


class TestGrepPrefixes:
    """grep's `file:NN:` and `file-NN-` markers, stripped for parsing only."""

    @pytest.mark.parametrize("delimiter", [":", "-"])
    @pytest.mark.parametrize("filename", ["", "compose.yaml", "stacks/wt/compose.yaml"])
    def test_secret_never_survives_any_prefix_shape(self, monkeypatch, capsys, delimiter, filename) -> None:
        monkeypatch.setattr("sys.stdin", _Stdin(_grep(COMPOSE, delimiter, filename)))
        main([])
        assert SECRET not in capsys.readouterr().out

    def test_prefix_is_restored_on_output(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("sys.stdin", _Stdin(_grep(COMPOSE, ":", "compose.yaml")))
        main([])
        out = capsys.readouterr().out

        assert "compose.yaml:6:" in out
        assert "compose.yaml:1:# Watchtower stack" in out

    def test_comments_survive_a_prefix(self, monkeypatch, capsys) -> None:
        """The original bug: a prefixed comment no longer starts with '#'."""
        monkeypatch.setattr("sys.stdin", _Stdin("f.yaml:1:# a comment\nf.yaml:2:key: value\n"))
        code = main([])
        captured = capsys.readouterr()

        assert "f.yaml:1:# a comment" in captured.out
        assert code == EXIT_OK
        assert "redacted unscanned" not in captured.err

    def test_context_separator_passes_through(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("sys.stdin", _Stdin("f.env:1:A=1\n--\nf.env:9:B=2\n"))
        code = main([])

        assert "--" in capsys.readouterr().out
        assert code == EXIT_OK

    def test_mixed_match_and_context_delimiters(self, monkeypatch, capsys) -> None:
        """grep -A/-B/-C emits ':' and '-' markers in one stream.

        Matching only ':' drops the ratio below the threshold, which skips
        stripping and lets the colon format be chosen anyway — the leak.
        """
        stream = f'c.yaml:6:      URL: discord://{SECRET}@123\nc.yaml-7-      CLEANUP: "true"\nc.yaml-8-      X: y\n'
        monkeypatch.setattr("sys.stdin", _Stdin(stream))
        main([])
        out = capsys.readouterr().out

        assert SECRET not in out
        assert "c.yaml-7-" in out

    def test_a_note_announces_the_reinterpretation(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("sys.stdin", _Stdin(_grep(COMPOSE, ":", "compose.yaml")))
        main([])
        assert "grep-style line prefixes" in capsys.readouterr().err

    def test_detection_key_excludes_the_prefix(self, monkeypatch, capsys) -> None:
        """Explain reports the real key, not `compose.yaml:6:KEY`."""
        monkeypatch.setattr("sys.stdin", _Stdin("f.env:1:DB_PASSWORD=hunter2\nf.env:2:LOG=debug\n"))
        main(["--explain"])
        err = capsys.readouterr().err

        assert "  DB_PASSWORD " in err
        assert "f.env:1:DB_PASSWORD" not in err


class TestPrefixDetectionIsConservative:
    """Ordinary content must not be mistaken for grep output, and vice versa."""

    def test_content_resembling_a_prefix_is_left_alone(self, tmp_path, capsys) -> None:
        content = "command: run --port 8080-9090-x\nimage: nginx:1.25\nurl: http://host:8080/p\n"
        main([_write(tmp_path, "c.yaml", content)])
        assert capsys.readouterr().out == content

    def test_partially_prefixed_input_refuses_the_colon_format(self, monkeypatch, capsys) -> None:
        """Ambiguous input falls back to env: useless but loud beats quiet.

        Choosing the colon format here would split on grep's line number and
        hand the remainder to detection as one unmatched value.
        """
        stream = f"f.yaml:1:      URL: discord://{SECRET}@123\nplain: value\nanother: value\nmore: value\n"
        monkeypatch.setattr("sys.stdin", _Stdin(stream))
        main([])
        assert SECRET not in capsys.readouterr().out

    def test_single_line_input_is_not_treated_as_prefixed(self, monkeypatch, capsys) -> None:
        """One line starting with digits and a colon is a timestamp, not grep.

        The requirement is that it is never silently re-split into a key and a
        value nobody screened. Falling into the unparseable path is correct:
        redacted, reported, non-zero exit.
        """
        monkeypatch.setattr("sys.stdin", _Stdin("12:34:56 starting up\n"))
        code = main([])
        captured = capsys.readouterr()

        assert captured.out.strip() == "[REDACTED]"
        assert code == EXIT_ERROR
        assert "redacted unscanned" in captured.err

    def test_env_file_with_prefixes_still_parses(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("sys.stdin", _Stdin("a.env:1:DB_PASSWORD=hunter2\na.env:2:LOG_LEVEL=debug\n"))
        main([])
        out = capsys.readouterr().out

        assert "hunter2" not in out
        assert "a.env:2:LOG_LEVEL=debug" in out


class _Stdin:
    """Minimal stdin stand-in; the CLI reads it and asks whether it is a terminal."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text

    def isatty(self) -> bool:
        return False
