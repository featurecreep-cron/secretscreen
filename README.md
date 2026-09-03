# secretscreen

[![CI](https://github.com/featurecreep-cron/secretscreen/actions/workflows/ci.yml/badge.svg)](https://github.com/featurecreep-cron/secretscreen/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/featurecreep-cron/secretscreen/graph/badge.svg)](https://codecov.io/gh/featurecreep-cron/secretscreen)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/featurecreep-cron/secretscreen/badge)](https://scorecard.dev/viewer/?uri=github.com/featurecreep-cron/secretscreen)
[![License: MIT](https://img.shields.io/github/license/featurecreep-cron/secretscreen)](https://github.com/featurecreep-cron/secretscreen/blob/main/LICENSE)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Ffeaturecreep-cron%2Fsecretscreen%2Fmain%2Fpyproject.toml)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/secretscreen)](https://pypi.org/project/secretscreen/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Detect and redact secrets in key-value pairs, dicts, and environment variables.

Best-effort defense-in-depth. Not a security boundary.

## Install

As a library:

```
pip install secretscreen
```

As a command-line tool — `pipx` or `uv` keep it in its own environment and put `secretscreen` on your PATH everywhere, rather than only in whichever venv is active:

```
pipx install secretscreen
uv tool install secretscreen
```

Zero dependencies, Python 3.11+.

## Quick start

```python
from secretscreen import redact_pair, redact_dict, audit_dict, Mode

# Single pair
redact_pair("DB_PASSWORD", "hunter2")  # → "[REDACTED]"
redact_pair("APP_NAME", "myapp")  # → "myapp"

# Dict with recursion
redact_dict({"db": {"password": "x", "host": "localhost"}})
# → {"db": {"password": "[REDACTED]", "host": "localhost"}}

# Aggressive mode (adds entropy detection)
redact_dict(env, mode=Mode.AGGRESSIVE)

# Audit mode (structured findings, no mutation)
findings = audit_dict(env)
# → [Finding(key="DB_PASSWORD", reason="key_pattern:password", ...)]

# Custom safe suffixes (keys ending with these are never redacted)
redact_dict(env, safe_suffixes=("_config", "_enabled"))
```

## Command line

The library only helps Python callers. The CLI covers the shell side — `docker exec`, Makefiles, CI logs, anything you are about to paste somewhere.

```
secretscreen tandoor.env                    # redact and print, cat-like
docker exec app env | secretscreen          # scrub a stream before it hits your terminal
secretscreen --audit config.json            # findings only, no values, exit 1 if any
```

```
secretscreen [FILE...]              reads stdin when FILE is omitted or '-'
  --audit                           report findings without values; exit 1 if any
  --format env|json|ini|yaml|dsn|auto  default: auto-detect from extension, then content
  --aggressive                      add entropy detection; more false positives
  --explain                         account on stderr for every value, including the untouched ones
  --replacement TEXT                default: [REDACTED]
```

Redaction is structural, not line-based: it parses the format, so it catches `DB_PASSWORD=hunter2` on the key name and rewrites `postgres://admin:s3cr3t@host/db` to `postgres://admin:REDACTED@host/db` without destroying the rest of the line. Comments, blank lines, quoting, `export` prefixes, INI sections and `:` separators all survive the round trip.

Inside a URL the replacement drops its brackets, because `[` in that position makes the result unparseable — screening already-screened output would otherwise destroy it.

### Compose files and grep output

```
$ secretscreen compose.yaml
# Watchtower stack
services:
  watchtower:
    image: containrrr/watchtower
    environment:
      WATCHTOWER_NOTIFICATION_URL: discord://REDACTED@1234567890
      WATCHTOWER_CLEANUP: "true"
    # keep an eye on this one
    restart: unless-stopped
```

Indentation, comments, and block openers (`services:`) survive; only values are touched. List entries are screened whether they carry a key (`- DB_PASSWORD=hunter2`) or not (`- discord://token@id`).

This is **line-oriented, not a real YAML parse** — a parser would mean a third-party dependency, and this package is stdlib-only on purpose. Block scalars (`|`, `>`) are the visible consequence: their bodies are not `key: value`, so they are redacted and reported rather than quietly passed through.

grep's `file:NN:` and `file-NN-` markers are recognised and stripped before parsing, then put back on output, so `grep -rn SECRET ~/stacks | secretscreen` keeps its file-and-line context:

```
$ grep -n 'NOTIFICATION' compose.yaml | secretscreen
secretscreen: detected grep-style line prefixes; stripped before parsing, restored on output
6:      WATCHTOWER_NOTIFICATION_URL: discord://REDACTED@1234567890
```

That stripping is what makes colon-separated detection safe to attempt at all. Without it the first colon on the line belongs to grep's line number, the key becomes `6`, and the whole remainder — secret included — becomes one value that matches nothing. So when the input is only partly prefixed and the shape is ambiguous, the sniffer refuses the colon format and falls back to `env`, which redacts what it cannot parse. Useless output beats quiet output.

One case stays deliberately blunt: a single stream mixing formats, such as `grep -rn` across both `.env` and `.yaml` files, picks the majority format and redacts the rest wholesale. Loud and safe rather than half-parsed.

### Config

Once you have found a false positive, `--explain` tells you which key it was. A config file stops you diagnosing it again next run.

```toml
# ~/.config/secretscreen.toml   or   .secretscreen.toml beside a stack

# Never redact these. Exact key names — no wildcards.
show = ["DEPLOY_PUBLIC_KEY"]

# Always redact these. Globs are fine.
hide = ["*_NOTIFICATION_URL", "*_WEBHOOK_URL"]

[detection]
mode = "normal"            # normal | aggressive
entropy_threshold = 4.5

# Applies only while this filename is being processed.
[files."demo.env"]
show = ["API_TOKEN"]
```

Order: user config, then `.secretscreen.toml` files discovered upward from **each input file**, nearest last, then flags. Lists union rather than replace, so a closer file extends the broader one instead of silently discarding it. Discovery runs per input, so `secretscreen a/compose.yaml b/compose.yaml` can pick up a different config beside each. Add `root = true` to stop the upward walk.

**`hide` takes globs. `show` does not.** `show = ["*_KEY"]` would print `AWS_SECRET_ACCESS_KEY`, and it would go on matching keys nobody has written yet. Every show entry is a credential you are choosing to print, so every entry gets named in full. `hide` always wins over `show`, at every scope.

The same asymmetry decides what a rule can cover in JSON. `hide` names a key and takes whatever that key holds — a string, a port number, a whole object — and replaces all of it, because the shape and key names of a hidden subtree are usually the half worth hiding. `show` is honoured for a string and refused for anything else, with a note on stderr: vouching for one named key is a decision about one value, and vouching for an object is a decision about values nobody has added yet. In a `--format dsn` stream the whole line is the value, and rules match the key `dsn`.

**A discovered project config may tighten redaction but not relax it.** A `.secretscreen.toml` can arrive with a repository you cloned five minutes ago, or be dropped in a shared directory by anyone who can write there, so every setting one carries is read as a request to tighten:

| setting | from a discovered config |
|---|---|
| `hide` | applied |
| `show` | ignored |
| `[detection] mode` | only `normal` → `aggressive` |
| `[detection] entropy_threshold` | only downward |
| `root` | ignored |

`--trust-config` honours all five. Each ignored setting is named on stderr, so a rule that did not fire says so rather than looking like one that did.

The three settings below `show` matter as much as `show` does. `show` prints a credential and is the obvious one; `entropy_threshold = 99` and `mode = "normal"` stop a credential being *found*, and `root = true` needs no rules of its own — it ends the upward walk before your own config one directory up is ever read. All four end with a secret on stdout and `--audit` exiting 0.

Only your own `~/.config` file, or a file you name yourself with `--config`, can loosen anything.

Every loaded config is named on stderr, and a malformed one — bad TOML, an unknown setting, a wildcard where none is allowed — is fatal rather than skipped. A typo that silently disabled a `hide` rule would leave you believing you had configured something you had not.

Equivalent flags exist for one-off use: `--show KEY`, `--hide GLOB`, `--entropy-threshold N`, `--no-config`, and `--config FILE` — which uses that file *only*, skipping both discovery and your own `~/.config`, and trusts it because you named it.

### Knowing what was left alone

A missed secret is invisible: the output looks screened and nothing says otherwise. `--explain` writes an account of every value to **stderr**, so stdout stays a usable redacted stream and `secretscreen app.env --explain > clean.env` still works.

```
$ secretscreen watchtower.env --explain > screened.env
secretscreen: explain — key names and reasons only, no values
  redacted   WATCHTOWER_NOTIFICATION_URL  url_credentials  credential in userinfo position
  vetoed     GF_OAUTH_TOKEN_URL           key_pattern      matched 'token', suppressed by safe suffix '_url'
  clean      IMAGE_DIGEST                 -                entropy 4.14 (aggressive would not flag; threshold 4.50)
  clean      DEPLOY_PUBLIC_KEY            -                entropy 4.67 (aggressive WOULD flag; threshold 4.50)
  unscanned  BACKUP_BLOB                  -                2202009 bytes exceeds the 65536-byte scan cap
```

Four states. `redacted` and `clean` are self-explanatory; the two in between are the ones worth reading. **`vetoed`** means a rule fired and something suppressed it — that is where the tool decided to stay quiet. **`unscanned`** means the size cap skipped the value-scanning layers, so the value is redacted on the grounds that it was never examined — an unscanned value is not a clean one.

Clean lines carry the nearest miss rather than silence. The entropy figure is computed even in normal mode, where that layer never runs, so you can see what `--aggressive` would change before turning it on.

Like `--audit`, this never prints a value — paste it into a bug report as-is.

**What the exit code means:**

| Code | Meaning |
|------|---------|
| 0 | Everything was parsed and screened |
| 1 | `--audit` found secrets |
| 2 | Something could not be parsed or read — see stderr |

That third case is the one that matters. This is best-effort defense-in-depth, and a cat-replacement is exactly the tool people stop thinking about, so the CLI never prints unparsed content verbatim: a line it cannot structure is replaced with the redaction token, named on stderr, and turns the exit code non-zero. The same applies to values above the 64 KB detection cap — they are redacted and reported as unscanned rather than passed off as clean. That holds in the library too, not just the CLI: `redact_pair` returns the replacement and `audit_pair` returns a `size_cap` finding, so a consumer cannot mistake *not examined* for *examined and clean*.

If you are scanning a git repository rather than config-shaped data, use [gitleaks](https://github.com/gitleaks/gitleaks) instead. That is a different job.

## Detection layers

1. **Key-name denylist** — substring match against ~30 known secret key patterns
2. **Structured value parsing** — JSON, Python literals, DSN, INI, URL query params
3. **Value-format detection** — 222 known formats via vendored [gitleaks](https://github.com/gitleaks/gitleaks) patterns (MIT)
4. **URL credential detection** — partial redaction of `user:pass@host` URLs
5. **Entropy detection** — Shannon entropy for machine-generated strings (aggressive mode only)

## Contributing

Bug reports and pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support

If you find secretscreen useful, consider [buying us a coffee](https://buymeacoffee.com/featurecreep).

## License

MIT. Gitleaks patterns are also MIT-licensed.
