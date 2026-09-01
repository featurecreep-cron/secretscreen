"""Tests for config files, discovery, and the show/hide rules.

Config exists to stop the same false positive being re-diagnosed every run. It
cannot do the same for a false negative, which leaves no trace to configure
against — so the rules here are deliberately asymmetric, and most of these
tests are about the asymmetry holding rather than about loading TOML.

Every CLI test pins XDG_CONFIG_HOME at a temporary directory. Without that the
suite would read whatever config the developer happens to have, and a machine
with a `show` rule would quietly pass tests that should fail.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secretscreen._cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from secretscreen._config import (
    Config,
    ConfigError,
    discover,
    drops_show,
    load,
    merge,
    merge_tightening,
    user_config_path,
)


def _write(directory, name: str, content: str) -> str:
    path = directory / name
    path.write_text(content)
    return str(path)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """A config-free environment: no user config, no inherited rules."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    (tmp_path / "xdg").mkdir()
    return tmp_path


class TestLoading:
    """Parsing and validation of a single file."""

    def test_full_file(self, tmp_path) -> None:
        path = tmp_path / "c.toml"
        path.write_text(
            'show = ["DEPLOY_PUBLIC_KEY"]\n'
            'hide = ["*_NOTIFICATION_URL"]\n'
            "root = true\n"
            "[detection]\n"
            'mode = "aggressive"\n'
            "entropy_threshold = 4.2\n"
            '[files."demo.env"]\n'
            'show = ["API_TOKEN"]\n'
        )
        config = load(path)

        assert config.show == ("DEPLOY_PUBLIC_KEY",)
        assert config.hide == ("*_NOTIFICATION_URL",)
        assert config.root is True
        assert config.mode == "aggressive"
        assert config.entropy_threshold == 4.2
        assert config.files[0][0] == "demo.env"
        assert config.files[0][1].show == ("API_TOKEN",)

    def test_empty_file_is_valid(self, tmp_path) -> None:
        path = tmp_path / "c.toml"
        path.write_text("")
        assert load(path) == Config(sources=(str(path),))

    @pytest.mark.parametrize(
        ("content", "fragment"),
        [
            ('show = ["*_KEY"]', "wildcard"),
            ('show = ["A?B"]', "wildcard"),
            ('show = ["A[0-9]"]', "wildcard"),
            ('[files."x.env"]\nshow = ["*_KEY"]', "wildcard"),
            ('shwo = ["X"]', "unknown setting"),
            ("[detection]\nlevel = 3", "unknown setting"),
            ('[files."x.env"]\nmode = "normal"', "unknown setting"),
            ('[detection]\nmode = "paranoid"', "detection.mode"),
            ('[detection]\nentropy_threshold = "high"', "must be a number"),
            ("[detection]\nentropy_threshold = true", "must be a number"),
            ('root = "yes"', "must be true or false"),
            ('show = "KEY"', "must be a list of strings"),
            ("show = [1, 2]", "must be a list of strings"),
            ('detection = "aggressive"', "must be a table"),
            ('files = "x.env"', "must be a table"),
            ('[files]\nx = "not a table"', "must be a table"),
        ],
    )
    def test_rejects_bad_input(self, tmp_path, content: str, fragment: str) -> None:
        path = tmp_path / "c.toml"
        path.write_text(content)
        with pytest.raises(ConfigError, match=fragment):
            load(path)

    def test_wildcards_are_fine_in_hide(self, tmp_path) -> None:
        """Over-redaction is visible and harmless; under-redaction is not."""
        path = tmp_path / "c.toml"
        path.write_text('hide = ["*_URL", "TOKEN?", "X[0-9]"]')
        assert len(load(path).hide) == 3

    def test_malformed_toml(self, tmp_path) -> None:
        path = tmp_path / "c.toml"
        path.write_text("hide = [")
        with pytest.raises(ConfigError, match="invalid TOML"):
            load(path)

    def test_unreadable_file(self, tmp_path) -> None:
        with pytest.raises(ConfigError, match="cannot read"):
            load(tmp_path / "missing.toml")

    def test_nesting_that_exhausts_the_parser_is_an_error_not_a_crash(self, tmp_path) -> None:
        """tomllib raises RecursionError, which exits 1 — the code for findings."""
        path = tmp_path / "c.toml"
        path.write_text("a = " + "[" * 5000 + "]" * 5000)

        with pytest.raises(ConfigError, match="nested too deeply"):
            load(path)

    def test_oversized_file_is_refused_before_it_is_read(self, tmp_path) -> None:
        path = tmp_path / "c.toml"
        path.write_text('hide = ["X"]\n# ' + "padding " * 40_000)

        with pytest.raises(ConfigError, match="not a config file"):
            load(path)

    def test_file_section_names_glob(self, tmp_path) -> None:
        """`[files."*.env"]` used to load without complaint and never fire."""
        path = tmp_path / "c.toml"
        path.write_text('[files."*.env"]\nhide = ["DEPLOY_NOTE"]')
        config = load(path)

        assert config.for_file("app.env").hides("DEPLOY_NOTE") == "DEPLOY_NOTE"
        assert config.for_file("app.json").hides("DEPLOY_NOTE") is None


class TestMatching:
    """show is exact; hide is a glob. Both case-insensitive."""

    def test_show_is_exact(self) -> None:
        config = Config(show=("DEPLOY_PUBLIC_KEY",))
        assert config.shows("DEPLOY_PUBLIC_KEY") == "DEPLOY_PUBLIC_KEY"
        assert config.shows("deploy_public_key") == "DEPLOY_PUBLIC_KEY"
        assert config.shows("MY_DEPLOY_PUBLIC_KEY") is None
        assert config.shows("DEPLOY_PUBLIC_KEY_2") is None

    def test_hide_is_a_glob(self) -> None:
        config = Config(hide=("*_NOTIFICATION_URL",))
        assert config.hides("WATCHTOWER_NOTIFICATION_URL") == "*_NOTIFICATION_URL"
        assert config.hides("watchtower_notification_url") == "*_NOTIFICATION_URL"
        assert config.hides("NOTIFICATION_URL_BACKUP") is None

    def test_for_file_applies_a_section(self) -> None:
        config = Config(files=(("demo.env", Config(show=("API_TOKEN",))),))
        assert config.for_file("demo.env").shows("API_TOKEN") == "API_TOKEN"
        assert config.for_file("DEMO.ENV").shows("API_TOKEN") == "API_TOKEN"
        assert config.for_file("other.env").shows("API_TOKEN") is None


class TestMerging:
    def test_lists_union_and_scalars_take_the_overlay(self) -> None:
        base = Config(show=("A",), hide=("X*",), mode="normal", entropy_threshold=4.5)
        overlay = Config(show=("B",), hide=("Y*",), mode="aggressive")
        result = merge(base, overlay)

        assert result.show == ("A", "B")
        assert result.hide == ("X*", "Y*")
        assert result.mode == "aggressive"
        assert result.entropy_threshold == 4.5  # not overridden by None

    def test_union_drops_duplicates_and_keeps_order(self) -> None:
        assert merge(Config(show=("A", "B")), Config(show=("B", "C"))).show == ("A", "B", "C")

    def test_tightening_merge_strips_show_top_level_and_in_sections(self) -> None:
        untrusted = Config(show=("A",), hide=("X*",), files=(("f.env", Config(show=("B",), hide=("Y*",))),))
        merged = merge_tightening(Config(), untrusted)

        assert merged.show == ()
        assert merged.files[0][1].show == ()
        assert merged.hide == ("X*",)
        assert merged.files[0][1].hide == ("Y*",)
        assert drops_show(untrusted) is True


class TestDiscovery:
    def test_walks_upward_nearest_last(self, tmp_path) -> None:
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / ".secretscreen.toml").write_text('hide = ["OUTER"]')
        (tmp_path / "a" / "b" / ".secretscreen.toml").write_text('hide = ["INNER"]')

        found = discover(tmp_path / "a" / "b", stop_at=tmp_path)
        assert [p.parent.name for p in found] == [tmp_path.name, "b"]

    def test_root_flag_halts_the_walk(self, tmp_path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / ".secretscreen.toml").write_text('hide = ["OUTER"]')
        (tmp_path / "a" / ".secretscreen.toml").write_text("root = true")

        found = discover(tmp_path / "a", stop_at=tmp_path)
        assert len(found) == 1

    def test_no_configs(self, tmp_path) -> None:
        assert discover(tmp_path, stop_at=tmp_path) == []

    def test_broken_config_does_not_break_the_walk(self, tmp_path) -> None:
        """The file is still reported when loaded; the walk itself must survive."""
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / ".secretscreen.toml").write_text("hide = [")
        assert len(discover(tmp_path / "a", stop_at=tmp_path)) == 1

    def test_user_path_honours_xdg(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert user_config_path() == tmp_path / "secretscreen.toml"

    def test_user_path_falls_back_to_dot_config(self, monkeypatch) -> None:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        assert user_config_path().parent.name == ".config"


class TestRulesEndToEnd:
    ENV = "API_TOKEN=realsecret\nDEPLOY_KEY=ssh-rsa AAAAfake\nLOG_LEVEL=debug\n"

    def test_show_prevents_redaction(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["API_TOKEN"]')
        main([_write(isolated, "a.env", self.ENV)])
        assert "API_TOKEN=realsecret" in capsys.readouterr().out

    def test_hide_forces_redaction_of_a_clean_key(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('hide = ["LOG_*"]')
        main([_write(isolated, "a.env", self.ENV)])
        assert "LOG_LEVEL=[REDACTED]" in capsys.readouterr().out

    def test_hide_beats_show(self, isolated, capsys) -> None:
        """At every scope. A narrower rule must never make the tool quieter."""
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["API_TOKEN"]\nhide = ["API_*"]')
        main([_write(isolated, "a.env", self.ENV)])
        assert "realsecret" not in capsys.readouterr().out

    def test_rules_match_keys_behind_a_grep_prefix(self, isolated, capsys) -> None:
        """The normalised key is what rules see, not the line as grep wrote it.

        `grep -n` yields `a.env:1:API_TOKEN=...`, where the first colon belongs
        to the line number. An exact-match show rule would silently never fire
        against that, and the failure is invisible: the value stays redacted,
        which is what an unconfigured run looks like.
        """
        piped = "a.env:1:API_TOKEN=realsecret\na.env:2:LOG_LEVEL=debug\na.env:3:DEPLOY_KEY=ssh-rsa AAAAfake\n"
        main([_write(isolated, "piped.txt", piped), "--no-config", "--show", "API_TOKEN", "--hide", "LOG_*"])
        out = capsys.readouterr().out

        assert "a.env:1:API_TOKEN=realsecret" in out
        assert "a.env:2:LOG_LEVEL=[REDACTED]" in out

    def test_show_flag_rejects_wildcards_like_the_file_does(self, isolated, capsys) -> None:
        """Exact matching makes an unchecked wildcard a silent no-op, not an error."""
        code = main([_write(isolated, "a.env", self.ENV), "--no-config", "--show", "*_TOKEN"])
        captured = capsys.readouterr()

        assert code == EXIT_ERROR
        assert "must name keys exactly" in captured.err
        assert captured.out == ""

    def test_flags_work_without_any_file(self, isolated, capsys) -> None:
        main([_write(isolated, "a.env", self.ENV), "--no-config", "--hide", "LOG_*"])
        assert "LOG_LEVEL=[REDACTED]" in capsys.readouterr().out

    def test_explicit_config_replaces_discovery(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('hide = ["LOG_*"]')
        explicit = _write(isolated, "other.toml", 'show = ["API_TOKEN"]')
        main([_write(isolated, "a.env", self.ENV), "--config", explicit])
        out = capsys.readouterr().out

        assert "API_TOKEN=realsecret" in out
        assert "LOG_LEVEL=debug" in out

    def test_no_config_ignores_files(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["API_TOKEN"]')
        main([_write(isolated, "a.env", self.ENV), "--no-config"])
        assert "realsecret" not in capsys.readouterr().out

    def test_per_file_section(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('[files."demo.env"]\nshow = ["API_TOKEN"]')
        main([_write(isolated, "demo.env", self.ENV)])
        assert "API_TOKEN=realsecret" in capsys.readouterr().out

        main([_write(isolated, "prod.env", self.ENV)])
        assert "realsecret" not in capsys.readouterr().out

    def test_mode_and_threshold_from_config(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text(
            '[detection]\nmode = "aggressive"\nentropy_threshold = 3.0\n'
        )
        main([_write(isolated, "a.env", "BLOB=abcdefghijklmnopqrstuvwxyz012345\n")])
        assert "BLOB=[REDACTED]" in capsys.readouterr().out

    def test_flag_beats_config_for_threshold(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('[detection]\nmode = "aggressive"\nentropy_threshold = 3.0')
        main([_write(isolated, "a.env", "BLOB=abcdefghijklmnopqrstuvwxyz012345\n"), "--entropy-threshold", "9.0"])
        assert "BLOB=abcdefghijklmnopqrstuvwxyz012345" in capsys.readouterr().out


class TestDiscoveredConfigsCannotLoosen:
    """A file found on disk may tighten redaction but not relax it.

    A project config can arrive with a cloned repository. Letting it decide
    which of the reader's credentials get printed is not a decision the
    repository author should have.
    """

    def test_project_show_is_ignored_by_default(self, isolated, capsys) -> None:
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text('show = ["API_TOKEN"]')
        main([_write(stack, "a.env", "API_TOKEN=realsecret\n")])
        captured = capsys.readouterr()

        assert "realsecret" not in captured.out
        assert "show entries ignored" in captured.err
        # Every "loaded config" line names a file that was loaded. The marker
        # for the stripped show entries is a note, not a source.
        loaded = [line for line in captured.err.splitlines() if "loaded config" in line]
        assert all(line.endswith(".secretscreen.toml") for line in loaded), loaded

    def test_trust_config_honours_it(self, isolated, capsys) -> None:
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text('show = ["API_TOKEN"]')
        main([_write(stack, "a.env", "API_TOKEN=realsecret\n"), "--trust-config"])
        assert "API_TOKEN=realsecret" in capsys.readouterr().out

    def test_project_config_cannot_raise_the_entropy_threshold(self, isolated, capsys) -> None:
        """Turning a layer off is loosening, even though it names no key."""
        (isolated / "xdg" / "secretscreen.toml").write_text('[detection]\nmode = "aggressive"')
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text("[detection]\nentropy_threshold = 99.0")
        blob = "Zk9pQ3RYb1Jm7dQwLmA3ZcVbNxK2Ht4Ue8Sy1Gp0Ij6Rw"
        main([_write(stack, "a.env", f"BLOB={blob}\n")])

        assert blob not in capsys.readouterr().out

    def test_project_config_cannot_lower_the_entropy_threshold_below_the_users(self, isolated, capsys) -> None:
        """Tightening in the other direction is fine, and stays fine."""
        (isolated / "xdg" / "secretscreen.toml").write_text('[detection]\nmode = "aggressive"')
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text("[detection]\nentropy_threshold = 1.0")
        main([_write(stack, "a.env", "SHORTISH=abcdefghijklmnopqrstuvwx\n")])

        assert "abcdefghijklmnopqrstuvwx" not in capsys.readouterr().out

    def test_project_config_cannot_downgrade_the_mode(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('[detection]\nmode = "aggressive"')
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text('[detection]\nmode = "normal"')
        blob = "Zk9pQ3RYb1Jm7dQwLmA3ZcVbNxK2Ht4Ue8Sy1Gp0Ij6Rw"
        main([_write(stack, "a.env", f"BLOB={blob}\n")])

        assert blob not in capsys.readouterr().out

    def test_project_config_may_upgrade_the_mode(self, isolated, capsys) -> None:
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text('[detection]\nmode = "aggressive"')
        blob = "Zk9pQ3RYb1Jm7dQwLmA3ZcVbNxK2Ht4Ue8Sy1Gp0Ij6Rw"
        main([_write(stack, "a.env", f"BLOB={blob}\n")])

        assert blob not in capsys.readouterr().out

    def test_planted_root_cannot_strand_a_rule_from_further_up(self, isolated, capsys) -> None:
        """`root = true` needs no rules of its own to delete someone else's.

        It ends the walk before the config one level up is read, and the
        output looks the same either way.
        """
        (isolated / ".secretscreen.toml").write_text('hide = ["DEPLOY_*"]')
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text("root = true")
        main([_write(stack, "a.env", "DEPLOY_NOTE=hello\n")])
        captured = capsys.readouterr()

        assert "DEPLOY_NOTE=[REDACTED]" in captured.out
        assert "root ignored" in captured.err

    def test_trust_config_honours_root(self, isolated, capsys) -> None:
        (isolated / ".secretscreen.toml").write_text('hide = ["DEPLOY_*"]')
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text("root = true")
        main([_write(stack, "a.env", "DEPLOY_NOTE=hello\n"), "--trust-config"])

        assert "DEPLOY_NOTE=hello" in capsys.readouterr().out

    def test_a_show_entry_in_a_file_section_is_announced_too(self, isolated, capsys) -> None:
        """Stripped silently is still stripped, but the user learns nothing."""
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text('[files."a.env"]\nshow = ["API_TOKEN"]')
        main([_write(stack, "a.env", "API_TOKEN=realsecret\n")])
        captured = capsys.readouterr()

        assert "realsecret" not in captured.out
        assert "show entries ignored" in captured.err

    def test_project_hide_always_applies(self, isolated, capsys) -> None:
        stack = isolated / "stack"
        stack.mkdir()
        (stack / ".secretscreen.toml").write_text('hide = ["LOG_*"]')
        main([_write(stack, "a.env", "LOG_LEVEL=debug\n")])
        assert "LOG_LEVEL=[REDACTED]" in capsys.readouterr().out

    def test_user_config_may_show(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["API_TOKEN"]')
        main([_write(isolated, "a.env", "API_TOKEN=realsecret\n")])
        assert "API_TOKEN=realsecret" in capsys.readouterr().out


class TestPerInputDiscovery:
    """Discovery runs per input, not once per process."""

    def test_two_files_in_different_directories_get_different_rules(self, isolated, capsys) -> None:
        one, two = isolated / "watchtower", isolated / "nextcloud"
        one.mkdir()
        two.mkdir()
        (one / ".secretscreen.toml").write_text('hide = ["POLL_INTERVAL"]')
        (two / ".secretscreen.toml").write_text('hide = ["TRUSTED_DOMAINS"]')

        body = "POLL_INTERVAL=86400\nTRUSTED_DOMAINS=cloud.example.com\n"
        main([_write(one, "compose.yaml", body), _write(two, "compose.yaml", body)])
        out = capsys.readouterr().out

        first, second = out.split("POLL_INTERVAL", 2)[1], out.split("POLL_INTERVAL", 2)[2]
        assert "[REDACTED]" in first  # watchtower's rule
        assert "86400" in second  # and not applied to nextcloud
        assert "TRUSTED_DOMAINS=cloud.example.com" in first
        assert "TRUSTED_DOMAINS=[REDACTED]" in second


class TestRulesInEveryMode:
    def test_explain_reports_rules_distinctly(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["API_TOKEN"]\nhide = ["LOG_*"]')
        main([_write(isolated, "a.env", "API_TOKEN=realsecret\nLOG_LEVEL=debug\n"), "--explain"])
        err = capsys.readouterr().err

        assert "show rule 'API_TOKEN' — not examined" in err
        assert "hide rule 'LOG_*'" in err
        assert "realsecret" not in err

    def test_audit_skips_shown_and_reports_hidden(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["API_TOKEN"]\nhide = ["LOG_*"]')
        code = main([_write(isolated, "a.env", "API_TOKEN=realsecret\nLOG_LEVEL=debug\n"), "--audit"])
        out = capsys.readouterr().out

        assert code == EXIT_FINDINGS
        assert "LOG_LEVEL" in out
        assert "API_TOKEN" not in out
        assert "realsecret" not in out

    def test_json_honours_rules(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["password"]\nhide = ["host"]')
        main([_write(isolated, "c.json", '{"password": "hunter2", "host": "db.lan"}')])
        out = capsys.readouterr().out

        assert "hunter2" in out
        assert "db.lan" not in out

    def test_json_without_rules_is_unchanged(self, isolated, capsys) -> None:
        main([_write(isolated, "c.json", '{"password": "hunter2", "host": "db.lan"}')])
        out = capsys.readouterr().out

        assert "hunter2" not in out
        assert "db.lan" in out

    def test_json_rules_reach_nested_structures(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["password"]\nhide = ["region"]')
        document = '{"services": [{"db": {"password": "hunter2", "region": "eu-west"}}, {"tags": ["a", "b"]}]}'
        main([_write(isolated, "c.json", document)])
        out = capsys.readouterr().out

        assert "hunter2" in out  # shown despite being nested two levels down
        assert "eu-west" not in out  # hidden despite being otherwise clean
        assert '"a"' in out  # untouched leaves survive the overlay

    def test_json_audit_reports_nested_hidden_keys(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('hide = ["region"]')
        document = '{"services": [{"db": {"region": "eu-west"}}]}'
        code = main([_write(isolated, "c.json", document), "--audit"])
        out = capsys.readouterr().out

        assert code == EXIT_FINDINGS
        assert "region" in out
        assert "eu-west" not in out

    def test_json_audit_agrees_with_redaction_on_case(self, isolated, capsys) -> None:
        """A rule that stops redaction must also stop the finding, in either spelling.

        Everything else matches keys case-insensitively. An --audit that
        reported a key the redact pass prints would send a script chasing a
        finding that the tool itself has already decided to vouch for.
        """
        body = '{"DB_PASSWORD": "hunter2"}'
        code = main([_write(isolated, "a.json", body), "--no-config", "--audit", "--show", "db_password"])
        captured = capsys.readouterr()

        assert code == EXIT_OK
        assert captured.out == ""

    def test_explain_names_the_rule_that_hid_a_nested_key(self, isolated, capsys) -> None:
        """Rules match the plain key; --explain displays a path. Never confuse them.

        Matching `hide = ["region"]` against `services[0].db.region` fails, and
        the account then says `clean` about a value stdout printed as
        [REDACTED].
        """
        document = '{"services": [{"db": {"password": "hunter2", "region": "eu-west"}}]}'
        main([_write(isolated, "a.json", document), "--no-config", "--hide", "region", "--explain"])
        captured = capsys.readouterr()

        assert '"region": "[REDACTED]"' in captured.out
        assert "hide rule 'region'" in captured.err
        assert "clean     services[0].db.region" not in captured.err

    def test_explain_never_claims_a_redaction_a_show_rule_prevented(self, isolated, capsys) -> None:
        """The direction that matters: stdout prints it, so the account must say so."""
        document = '{"services": [{"db": {"password": "hunter2"}}]}'
        main([_write(isolated, "a.json", document), "--no-config", "--show", "password", "--explain"])
        captured = capsys.readouterr()

        assert '"password": "hunter2"' in captured.out
        assert "show rule 'password'" in captured.err
        assert "redacted" not in captured.err

    def test_audit_reports_a_key_once_when_a_rule_and_a_layer_both_flag_it(self, isolated, capsys) -> None:
        """A hide rule on a key detection also catches is one finding, not two."""
        document = '{"password": "hunter2"}'
        code = main([_write(isolated, "a.json", document), "--no-config", "--audit", "--hide", "password"])
        out = capsys.readouterr().out

        assert code == EXIT_FINDINGS
        assert len(out.strip().splitlines()) == 1

    def test_hide_covers_an_object_and_everything_in_it(self, isolated, capsys) -> None:
        """Redacting only the leaves would leave the subtree's shape on display."""
        document = '{"creds": {"note": "plaintext", "seat": "12"}}'
        main([_write(isolated, "a.json", document), "--no-config", "--hide", "creds", "--explain"])
        captured = capsys.readouterr()

        assert '"creds": "[REDACTED]"' in captured.out
        assert "plaintext" not in captured.out
        assert "note" not in captured.out
        assert captured.err.count("hide rule 'creds'") == 2  # the account still covers both leaves

    def test_hide_covers_a_value_that_is_not_a_string(self, isolated, capsys) -> None:
        main([_write(isolated, "a.json", '{"port": 5432}'), "--no-config", "--hide", "port"])
        assert '"port": "[REDACTED]"' in capsys.readouterr().out

    def test_show_refuses_a_value_that_is_not_a_string_and_says_so(self, isolated, capsys) -> None:
        """Vouching for a subtree vouches for values nobody has added yet."""
        document = '{"creds": {"note": "plaintext"}}'
        code = main([_write(isolated, "a.json", document), "--no-config", "--show", "creds"])
        captured = capsys.readouterr()

        assert code == EXIT_OK
        assert "names a value that is not a string; ignored" in captured.err

    def test_audit_reports_a_hidden_object_once(self, isolated, capsys) -> None:
        document = '{"creds": {"note": "plaintext", "seat": "12"}}'
        code = main([_write(isolated, "a.json", document), "--no-config", "--audit", "--hide", "creds"])
        out = capsys.readouterr().out

        assert code == EXIT_FINDINGS
        assert len(out.strip().splitlines()) == 1
        assert "note" not in out

    def test_json_explain_reports_rules(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('hide = ["host"]')
        main([_write(isolated, "c.json", '{"host": "db.lan"}'), "--explain"])
        assert "hide rule 'host'" in capsys.readouterr().err

    def test_dsn_honours_rules(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('hide = ["dsn"]')
        main([_write(isolated, "d.txt", "postgres://u:p@h/db\n"), "--format", "dsn"])
        assert capsys.readouterr().out.strip() == "[REDACTED]"


class TestEachConfigIsReadOnce:
    """Discovery repeats per input; the reads behind it must not.

    The root check and the load parsed the same file separately, and the walk
    started again for every input. Fifty files in a twelve-deep tree came to
    twelve hundred reads of twelve files.
    """

    def test_one_read_per_file_across_many_inputs(self, isolated, monkeypatch, capsys) -> None:
        (isolated / ".secretscreen.toml").write_text('hide = ["LOG_*"]')
        inputs = [_write(isolated, f"a{i}.env", "LOG_LEVEL=debug\n") for i in range(5)]

        reads = []
        original = Path.read_text

        def counted(self, *args, **kwargs):
            if self.name == ".secretscreen.toml":
                reads.append(str(self))
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", counted)
        main(inputs)

        assert capsys.readouterr().out.count("[REDACTED]") == 5
        assert len(reads) == 1, reads


class TestConfigErrorsAreFatal:
    def test_bad_config_exits_two_and_prints_nothing(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('show = ["*_KEY"]')
        code = main([_write(isolated, "a.env", "API_TOKEN=realsecret\n")])
        captured = capsys.readouterr()

        assert code == EXIT_ERROR
        assert captured.out == ""
        assert "wildcard" in captured.err

    def test_loaded_configs_are_announced(self, isolated, capsys) -> None:
        (isolated / "xdg" / "secretscreen.toml").write_text('hide = ["LOG_*"]')
        main([_write(isolated, "a.env", "LOG_LEVEL=debug\n")])
        assert "loaded config" in capsys.readouterr().err

    def test_no_announcement_when_there_is_no_config(self, isolated, capsys) -> None:
        code = main([_write(isolated, "a.env", "LOG_LEVEL=debug\n")])
        captured = capsys.readouterr()

        assert code == EXIT_OK
        assert "loaded config" not in captured.err
